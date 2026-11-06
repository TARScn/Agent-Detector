"""Discovery orchestration: collect facts, run detectors, persist the inventory.

One scan is one short SQLite transaction; a failing detector is recorded as a
scan error instead of aborting the run (design section 2). After the component
assets are stored, the Agent inventory step builds the V0.2 view of the machine
— logical Agent assets, running instances, hook state and protection status.

Self-built agent discovery runs as its own isolated stage: resolve interpreter
processes to project directories, read AI-relevant dependency metadata, match
framework rules. A failure there degrades to a scan error like any detector.
"""
import hashlib
import logging
import os
import re
from collections import defaultdict
from pathlib import Path

from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from agent_detector.aggregation.scan_evidence import write_scan_evidence
from agent_detector.aggregation.trace_evidence import write_controlled_trace
from agent_detector.coverage import build_scan_coverage
from agent_detector.monitoring.collectors.host.process import collect_host_facts
from agent_detector.core.config import (CONTROLLED_TRACE_MAX_RECORDS,
                                        CONTROLLED_TRACE_PATH, DOCKER_ENABLED,
                                        DOCKER_MAX_CONTAINERS, MAX_PROBES,
                                        MAX_PROJECT_PROBES)
from agent_detector.discovery.sources.agents import LoadedMatrix
from agent_detector.discovery.scanner.build import build_detectors
from agent_detector.discovery.sources.deps import interest_names, scan_project_dependencies
from agent_detector.discovery.sources.frameworks import ApplicationBundle, detect_frameworks
from agent_detector.discovery.scanner.identity_shadow import write_identity_shadow
from agent_detector.discovery.scanner.inventory import InventoryBuilder
from agent_detector.discovery.scanner.registry import Detector
from agent_detector.discovery.scanner.resolver import resolve_projects, runtime_of
from agent_detector.discovery.sources.docker_agents import scan_docker_agents
from agent_detector.core.models import DetectedAsset, HostFacts
from agent_detector.discovery.probes.http import probe_facts
from agent_detector.storage import (CoverageRepository, IdentityRepository,
                                    ScanRepository)

logger = logging.getLogger(__name__)


def run_scan(engine: Engine, active: bool = False,
             detectors: list[Detector] | None = None,
             home: Path | None = None,
             matrix: LoadedMatrix | None = None,
             framework_rules: list | None = None,
             client_rules: list | None = None,
             docker_enabled: bool = True) -> dict:
    if detectors is None:
        detectors = build_detectors()
    if framework_rules is None or client_rules is None:
        from agent_detector.discovery.fingerprints.loader import load_rules
        loaded = load_rules()
        if framework_rules is None:
            framework_rules = loaded.framework_rules
        if client_rules is None:
            client_rules = loaded.client_rules
    with Session(engine) as session:
        scan_repo = ScanRepository(session)
        mode = "agent+traffic" if active else "agent"
        scan_id = scan_repo.create(mode)
        facts = collect_host_facts()
        assets: list[DetectedAsset] = []
        errors: list[dict] = []
        for detector in detectors:
            try:
                assets.extend(detector.detect(facts))
            except Exception as exc:  # detector isolation (plan section 8.1)
                logger.warning("detector %s failed: %s", detector.name, exc)
                errors.append({"detector": detector.name, "error": str(exc)})
        if active:
            try:
                assets.extend(probe_facts(facts, MAX_PROBES))
            except Exception as exc:
                logger.warning("http probe failed: %s", exc)
                errors.append({"detector": "http-probe", "error": str(exc)})
        bundles, project_stats = _discover_self_built(facts, framework_rules)
        docker_bundles, docker_assets, docker_ctx, docker_stats = _discover_docker(
            framework_rules, client_rules, facts.hostname, enabled=docker_enabled)
        bundles = bundles + docker_bundles
        assets.extend(docker_assets)
        assets.extend(bundle.asset for bundle in bundles)
        for bundle in bundles:
            assets.extend(bundle.frameworks)
        merged = correlate_assets(merge_assets(assets))
        failed_detectors = {error["detector"] for error in errors}
        if project_stats.get("error"):
            failed_detectors.add("frameworks")  # stage failed: absence proves nothing
        if docker_ctx["failed"]:
            failed_detectors.add("docker")  # same guard for the container channel

        docker_scope_key = os.getenv("DOCKER_HOST", "").strip() or "local"
        docker_ctx["scope_key"] = docker_scope_key
        coverage_repo = CoverageRepository(session)
        coverage_scope_ids: dict[tuple[str, str], int] = {}
        coverage = None
        try:
            with session.begin_nested():
                coverage = build_scan_coverage(
                    processes_count=len(facts.processes),
                    process_source=facts.process_source,
                    detector_names=[detector.name for detector in detectors],
                    failed_detectors=failed_detectors,
                    project_stats=project_stats,
                    docker_stats=docker_stats,
                    docker_ctx=docker_ctx,
                    docker_enabled=docker_enabled and DOCKER_ENABLED,
                    max_projects=MAX_PROJECT_PROBES,
                    max_containers=DOCKER_MAX_CONTAINERS,
                    docker_scope_key=docker_scope_key)
                coverage_repo.add_graph(scan_id, coverage)
                coverage_scope_ids = {
                    (row["scope_type"], row["scope_key"]): row["id"]
                    for row in coverage_repo.list_scopes(scan_id)}
        except Exception as exc:  # no coverage means no absence verdicts
            logger.exception("coverage build failed")
            errors.append({"detector": "coverage", "error": str(exc)})
            coverage = None

        agent_inventory, inventory_warnings, removal_candidates, unverified = (
            _build_inventory(
                session, merged, facts, home=home, matrix=matrix,
                app_links={framework.asset_id: {"app_id": bundle.app_id,
                                                "app_name": bundle.project.name}
                           for bundle in bundles for framework in bundle.frameworks},
                failed_detectors=failed_detectors,
                docker_context=docker_ctx,
                coverage=coverage))
        coverage_repo.record_candidates(scan_id, removal_candidates)
        identity_shadow = write_identity_shadow(session, engine, merged, facts)
        if identity_shadow.get("error"):
            errors.append({"detector": "identity-shadow",
                           "error": identity_shadow["error"]})
        try:
            controlled_trace = write_controlled_trace(
                session, scan_id=scan_id, assets=merged,
                host_key=identity_shadow.get("host_key") or "unknown",
                path=CONTROLLED_TRACE_PATH,
                max_records=CONTROLLED_TRACE_MAX_RECORDS)
        except Exception as exc:  # opt-in trace failure must not void the scan
            logger.exception("controlled trace ingest failed")
            errors.append({"detector": "controlled-trace", "error": str(exc)})
            controlled_trace = {"enabled": bool(CONTROLLED_TRACE_PATH),
                                "events": 0, "runtime": 0, "protocol": 0,
                                "claims": 0, "unattributed": 0,
                                "error": str(exc)}
        rule_digests = _rule_digests(framework_rules, client_rules)
        try:
            evidence_stats = write_scan_evidence(
                session, scan_id=scan_id, assets=merged,
                inventory=agent_inventory,
                coverage_summary=(coverage.summary() if coverage is not None
                                  else {}),
                rule_digests=rule_digests,
                framework_ids={rule.id for rule in framework_rules},
                host_key=identity_shadow.get("host_key") or "unknown",
                engine_key=identity_shadow.get("engine_key") or "unknown",
                docker_scope_key=docker_scope_key,
                coverage_scope_ids=coverage_scope_ids,
                removal_candidates=removal_candidates,
                unverified=unverified,
                coverage=coverage)
        except Exception as exc:  # evidence ledger failure must not void the scan
            logger.exception("scan evidence ledger failed")
            errors.append({"detector": "evidence-ledger", "error": str(exc)})
            evidence_stats = {"observations": 0, "claims": 0, "entities": 0,
                              "statuses": {}, "error": str(exc)}
        identities = IdentityRepository(session)
        entity_of = {asset.asset_id: identities.resolve_alias(asset.asset_id)
                     for asset in merged}
        stats = {
            "observations": {"processes": len(facts.processes),
                             "listening_sockets": len(facts.sockets),
                             "process_source": facts.process_source},
            "self_built": {**project_stats,
                           "applications": len(bundles),
                           "framework_assets": sum(len(b.frameworks) for b in bundles)},
            "docker": docker_stats,
            "detections": len(merged),
            "coverage": (coverage.summary() if coverage is not None
                         else {"scopes": 0}),
            "removal_candidates": len(removal_candidates),
            "evidence": evidence_stats,
            "controlled_trace": controlled_trace,
            "identity_shadow": identity_shadow,
            "entity_inventory": [_inventory_entry(item, entity_of)
                                 for item in agent_inventory],
            "agent_instances": sum(item["instance_count"] for item in agent_inventory),
            "entity_summaries": [_entity_summary(asset, entity_of.get(asset.asset_id))
                                 for asset in merged],
            "errors": errors + [{"detector": "inventory", "error": warning}
                                for warning in inventory_warnings],
        }
        scan_repo.finish(scan_id, "completed", stats)
        session.commit()
        return {"scan_id": scan_id, "mode": mode, "status": "completed", **stats}


def _discover_self_built(facts: HostFacts,
                         framework_rules: list) -> tuple[list[ApplicationBundle], dict]:
    """Resolve → dependency scan → framework match; failures degrade to stats.

    Unresolved projects stay counted in the returned stats — the design
    forbids the discovery layer from silently dropping candidates.
    """
    try:
        candidates = sum(1 for proc in facts.processes
                         if runtime_of(proc) == "python" and not proc.container_id)
        truncated = MAX_PROJECT_PROBES > 0 and candidates >= MAX_PROJECT_PROBES
        projects = resolve_projects(facts)
        stats = {"projects": len(projects),
                 "projects_resolved": sum(1 for project in projects
                                          if project.resolver_status == "resolved"),
                 "candidate_processes": candidates,
                 "truncated": truncated}
        if not projects:
            return [], stats
        interest = interest_names({name for rule in framework_rules
                                   for name in (*rule.dependencies.any,
                                                *rule.dependencies.all)})
        components_by_project = scan_project_dependencies(projects, interest)
        processes_by_pid = {proc.pid: proc for proc in facts.processes}
        ports_by_pid: dict[int, list[int]] = defaultdict(list)
        for sock in facts.sockets:
            if sock.pid:
                ports_by_pid[sock.pid].append(sock.port)
        bundles = detect_frameworks(projects, components_by_project, framework_rules,
                                    facts.hostname, processes_by_pid=processes_by_pid,
                                    ports_by_pid=dict(ports_by_pid))
        return bundles, stats
    except Exception as exc:  # isolated like a failing detector
        logger.warning("self-built agent discovery failed: %s", exc)
        return [], {"projects": 0, "projects_resolved": 0,
                    "candidate_processes": 0, "truncated": False,
                    "error": str(exc)}


def _discover_docker(framework_rules: list, client_rules: list, hostname: str, *,
                     enabled: bool = True
                     ) -> tuple[list[ApplicationBundle], list[DetectedAsset], dict, dict]:
    """Docker channel stage, isolated like ``_discover_self_built``.

    The returned context carries the inventory guards: ``failed`` (the
    channel said nothing this round — error or disabled — so the absence of
    container assets proves nothing) plus the container ids seen and deep
    scanned, which drive the container branch of stale verification.
    """
    empty_ctx = {"failed": True, "containers_seen": set(),
                 "candidates_seen": set(), "links": {}}
    if not enabled or not DOCKER_ENABLED:
        return [], [], dict(empty_ctx), {"containers_total": 0, "candidates": 0,
                                         "agents": 0, "error": "disabled"}
    try:
        outcome = scan_docker_agents(framework_rules, hostname,
                                     client_rules=client_rules)
    except Exception as exc:  # isolated like a failing detector
        logger.warning("docker discovery failed: %s", exc)
        return [], [], dict(empty_ctx), {"containers_total": 0, "candidates": 0,
                                         "agents": 0, "error": str(exc)}
    context = {"failed": bool(outcome.stats.get("error")),
               "containers_seen": set(outcome.containers_seen),
               "candidates_seen": set(outcome.candidates_seen),
               "links": outcome.container_links}
    return outcome.bundles, outcome.assets, context, outcome.stats


def _build_inventory(session: Session, merged: list[DetectedAsset], facts: HostFacts,
                     *, home: Path | None, matrix: LoadedMatrix | None,
                     app_links: dict[str, dict] | None = None,
                     failed_detectors: set[str] | None = None,
                     docker_context: dict | None = None,
                     coverage=None
                     ) -> tuple[list[dict], list[str], list[dict], dict[str, str]]:
    """Agent-level view of the same scan; a failure here never voids the scan."""
    try:
        builder = InventoryBuilder(home=home, matrix=matrix)
        items = builder.apply_scan(session, merged, facts, app_links=app_links,
                                   failed_detectors=failed_detectors or set(),
                                   docker_context=docker_context,
                                   coverage=coverage)
        return (items, builder.warnings, builder.removal_candidates,
                dict(builder.unverified))
    except Exception as exc:
        logger.exception("agent inventory build failed")
        return [], [str(exc)], [], {}


def merge_assets(assets: list[DetectedAsset]) -> list[DetectedAsset]:
    """Fold detector output by stable asset_id, keeping every piece of evidence."""
    by_id: dict[str, DetectedAsset] = {}
    for asset in assets:
        current = by_id.get(asset.asset_id)
        if current is None:
            by_id[asset.asset_id] = asset
            continue
        current.states |= asset.states
        current.confidence = max(current.confidence, asset.confidence)
        current.evidence.extend(asset.evidence)
        for pid in asset.running_pids:
            if pid not in current.running_pids:
                current.running_pids.append(pid)
        for port in asset.listening_ports:
            if port not in current.listening_ports:
                current.listening_ports.append(port)
        if asset.version.confidence > current.version.confidence:
            current.version = asset.version
    return list(by_id.values())


_INFRA_SCOPES = frozenset({"compose", "container"})
_PROBE_SCOPE = "listen-port"


def _name_key(name: str) -> str:
    """Loose product-name key for cross-source matching: 'Dify' / 'dify' /
    'Open WebUI' / 'openwebui' collapse to one token string."""
    return re.sub(r"[^a-z0-9]+", "", name.lower())


def correlate_assets(assets: list[DetectedAsset]) -> list[DetectedAsset]:
    """Fold port-scoped HTTP-probe sightings into their infrastructure twin.

    The active probe anchors identity on ``listen-port:{port}``; the same
    deployment that Docker discovery keys as ``compose:{project}`` or
    ``container:{id}`` would otherwise stay two assets forever, because
    merge_assets only folds identical ids. Matching is by normalized product
    name on the same host: the probe's evidence and ports join the infra
    asset and the probe row disappears. An unmatched probe keeps its own row
    — a real sighting without a known backend is still evidence.
    """
    infra: dict[str, DetectedAsset] = {}
    for asset in assets:
        if asset.scope_kind in _INFRA_SCOPES:
            infra.setdefault(_name_key(asset.name), asset)
    if not infra:
        return assets
    kept: list[DetectedAsset] = []
    for asset in assets:
        twin = (infra.get(_name_key(asset.name))
                if asset.scope_kind == _PROBE_SCOPE else None)
        if twin is not None:
            twin.evidence.extend(asset.evidence)
            for port in asset.listening_ports:
                if port not in twin.listening_ports:
                    twin.listening_ports.append(port)
            continue
        kept.append(asset)
    return kept


def _rule_digests(*rule_groups) -> dict[str, str]:
    """Content digest per rule id; provenance for every claim."""
    digests: dict[str, str] = {}
    for rules in rule_groups:
        for rule in rules or ():
            try:
                payload = rule.model_dump_json()
            except AttributeError:
                payload = str(rule)
            digests[rule.id] = hashlib.sha256(
                payload.encode("utf-8")).hexdigest()[:48]
    return digests


def _inventory_entry(item: dict, entity_of: dict[str, str | None]) -> dict:
    """Agent-level scan row on the canonical key (detector ids stay internal)."""
    return {"entity_id": entity_of.get(item["asset_id"]),
            "agent_type": item["agent_type"], "name": item["name"],
            "protection_status": item["protection_status"],
            "hook_state": item["hook_state"],
            "capabilities": item["capabilities"],
            "llm_endpoints": item["llm_endpoints"],
            "instance_count": item["instance_count"]}


def _entity_summary(asset: DetectedAsset, entity_id: str | None) -> dict:
    return {"entity_id": entity_id, "name": asset.name,
            "asset_type": asset.asset_type.value,
            "states": sorted(state.value for state in asset.states),
            "confidence": asset.confidence, "version": asset.version.value,
            "version_source": asset.version.source.value,
            "running_pids": asset.running_pids,
            "listening_ports": asset.listening_ports, "detector": asset.detector}
