"""Turn one discovery scan into observations, claims and status snapshots.

P1 writes beside the legacy inventory: no legacy row changes. Claims are
positive discovery facts (installed/configured/running/product identity);
negative claims and removal verdicts remain P0-B candidates until the
reconfirmation loop is wired into the ledger.
"""
from __future__ import annotations

import json

from sqlalchemy import select

from agent_detector.aggregation.evidence_ledger import (EvidenceLedger,
                                                        running_claim_valid_to,
                                                        static_claim_valid_to)
from agent_detector.aggregation.state_resolver import (ABSENT, FAILED,
                                                       NOT_CHECKED, PRESENT,
                                                       ScopeRef,
                                                       entity_context,
                                                       invalidate_on_absence,
                                                       resolve)
from agent_detector.aggregation.status_projection import write_resolved
from agent_detector.core.enums import AssetState, AssetType, HookState
from agent_detector.core.models import DetectedAsset
from agent_detector.identity.entity import legacy_identity_for_asset
from agent_detector.storage.component_repository import ComponentRepository
from agent_detector.storage.identity_repository import IdentityRepository
from agent_detector.storage.models import (AgentInstanceRow,
                                           EntityAttributeRow,
                                           EntityLocationRow, utc_now_iso)

_EVIDENCE_STATE_CLASS = {
    AssetState.INSTALLED: ("E2", "package_metadata"),
    AssetState.CONFIGURED: ("E2", "config_probe"),
    AssetState.RUNNING: ("E3", "process_evidence"),
}
_HOOK_ORDER = (
    HookState.INSTALLED.value, HookState.PARTIAL.value,
    HookState.CONFLICT.value, HookState.NOT_INSTALLED.value,
    HookState.UNSUPPORTED.value, HookState.UNKNOWN.value,
)
# Snapshot vocabulary (P1): configuration presence only. HOOK_OBSERVED and
# ENFORCEMENT_VERIFIED require runtime evidence the scan does not have.
_SNAPSHOT_HOOK_STATE = {
    HookState.INSTALLED.value: "CONFIGURED",
    # PARTIAL/CONFLICT describe the configuration itself; do not collapse them
    # to UNKNOWN, otherwise the console cannot explain why protection is
    # conservative.
    HookState.PARTIAL.value: "PARTIAL",
    HookState.CONFLICT.value: "CONFLICT",
    HookState.NOT_INSTALLED.value: "NOT_CONFIGURED",
    HookState.UNSUPPORTED.value: "UNKNOWN",
    HookState.UNKNOWN.value: "UNKNOWN",
}


def _scope_for(asset: DetectedAsset, host_key: str, engine_key: str) -> str:
    if asset.scope_kind in ("compose", "container") \
            or asset.identity_scope.startswith("container:"):
        return engine_key or host_key
    return host_key


def _coverage_id(asset: DetectedAsset, docker_scope_key: str,
                 scope_ids: dict[tuple[str, str], int]) -> int | None:
    scope = asset.scope_kind
    if scope == "user-home":
        key = ("product_rule", asset.detector)
    elif scope == "project":
        key = ("project_candidate_universe", "scan")
    elif scope == "container":
        key = ("container_deep_scan", asset.identity_scope)
    elif scope == "compose":
        key = ("docker_engine_enumeration", docker_scope_key)
    else:
        return None
    return scope_ids.get(key)


def _closure_allowed(coverage, entity_id: str,
                     container_ids: dict[str, set[str]],
                     host_scoped: set[str], docker_scope_key: str) -> bool:
    """Dependency invalidation needs complete coverage for the entity's scopes."""
    if coverage is None:
        return False
    if entity_id in host_scoped:
        if not coverage.is_complete("project_candidate_universe", "scan",
                                    "application_presence"):
            return False
        if not coverage.is_complete("host_process_enumeration", "host",
                                    "process_inventory"):
            return False
    if entity_id in container_ids:
        if not coverage.is_complete("docker_engine_enumeration",
                                    docker_scope_key, "container_presence"):
            return False
        for container_id in container_ids[entity_id]:
            if container_id and not coverage.is_complete(
                    "container_deep_scan", container_id, "component_presence"):
                return False
    return True


def _write_claim(ledger: EvidenceLedger, *, scan_id: int, entity_id: str,
                 scope_key: str, predicate: str, object_ref: str,
                 evidence_class: str, method: str, asset: DetectedAsset,
                 rule_digests: dict[str, str],
                 coverage_scope_id: int | None,
                 valid_to: str | None = None) -> str:
    now = utc_now_iso()
    uid = f"scan:{scan_id}:{asset.asset_id}:{predicate}:{object_ref}"
    observation_id = ledger.record_observation(
        source="discovery", source_event_uid=uid, scope_key=scope_key,
        fact_type=predicate,
        payload={"asset_id": asset.asset_id, "name": asset.name,
                 "asset_type": asset.asset_type.value,
                 "detector": asset.detector,
                 "scope_kind": asset.scope_kind,
                 "identity_scope": asset.identity_scope,
                 "version": asset.version.value,
                 "version_source": asset.version.source.value,
                 "running_pids": list(asset.running_pids),
                 "predicate": predicate, "object": object_ref,
                 "states": sorted(state.value for state in asset.states)},
        observed_at=now, collection_run_id=scan_id)
    return ledger.add_claim(
        subject_ref=entity_id, predicate=predicate, object_ref=object_ref,
        evidence_class=evidence_class, verification_method=method,
        rule_id=asset.detector or "",
        rule_digest=rule_digests.get(asset.detector or "", ""),
        rule_generation=scan_id, collection_run_id=scan_id,
        coverage_scope_id=coverage_scope_id, observed_at=now,
        valid_from=now, valid_to=valid_to, observation_id=observation_id)


def _link_named_component(components: ComponentRepository, entity_id: str,
                          name: str, kind: str, claim_id: str, *,
                          relation_type: str, status: str,
                          version: str = "UNKNOWN",
                          version_source: str = "unknown") -> str:
    key = components.upsert_component(
        name, kind=kind, version=version, version_source=version_source)
    components.upsert_relation(
        entity_id, key, relation_type=relation_type, version=version,
        version_source=version_source, status=status,
        evidence_claim_id=claim_id)
    return key


def _link_component(components: ComponentRepository, entity_id: str,
                    asset: DetectedAsset, claim_id: str, *,
                    relation_type: str, status: str) -> str:
    name = (asset.name or "").split(" · ")[0].strip() or (asset.detector or "unknown")
    return _link_named_component(
        components, entity_id, name, asset.asset_type.value, claim_id,
        relation_type=relation_type, status=status,
        version=asset.version.value,
        version_source=asset.version.source.value)


def _write_canonical_inventory(session, assets: list[DetectedAsset],
                               inventory: list[dict],
                               entity_by_asset: dict[str, str],
                               stats: dict) -> None:
    """Keep the canonical attributes/locations/instances fresh on each scan."""
    items = {item.get("asset_id"): item for item in inventory}
    now = utc_now_iso()
    for asset in assets:
        entity_id = entity_by_asset.get(asset.asset_id)
        if not entity_id:
            continue
        # Only Agent-level assets own an inventory row. Services (LLM/MCP) and
        # application bundles are evidence, not list entries; writing them
        # here would smuggle them into the Agent list as inventory_kind=agent.
        item = items.get(asset.asset_id)
        if item is None:
            continue
        attr = session.get(EntityAttributeRow, entity_id)
        if attr is None:
            attr = EntityAttributeRow(entity_id=entity_id)
            session.add(attr)
            attr.first_seen_at = now
        docker = (asset.scope_kind in ("compose", "container")
                  or asset.identity_scope.startswith("container:"))
        attr.agent_type = (item.get("agent_type") or asset.detector
                           or asset.asset_type.value.lower())
        attr.name = item.get("name") or asset.name
        attr.vendor = item.get("vendor") or ""
        attr.version = asset.version.value
        attr.version_source = asset.version.source.value
        attr.origin = "docker" if docker else "host"
        # A compose aggregate has no single container id of its own: keep the
        # primary container recorded earlier instead of erasing the only key
        # the container branch could later re-verify.
        container_id = item.get("container_id")
        if not container_id and asset.scope_kind == "container":
            container_id = asset.identity_scope
        if not container_id and docker:
            container_id = attr.container_id
        attr.container_id = container_id
        attr.executable = asset.executable
        attr.config_paths_json = json.dumps(asset.config_paths,
                                            ensure_ascii=False)
        attr.mcp_servers_json = json.dumps(asset.mcp_servers,
                                           ensure_ascii=False)
        attr.llm_endpoints_json = json.dumps(
            item.get("llm_endpoints") or [], ensure_ascii=False)
        attr.listening_ports_json = json.dumps(
            list(asset.listening_ports), ensure_ascii=False)
        attr.notes_json = json.dumps(item.get("notes") or [], ensure_ascii=False)
        attr.capabilities_json = json.dumps(
            item.get("capabilities") or {}, ensure_ascii=False)
        attr.inventory_kind = "agent"
        attr.status = "active"
        attr.last_seen_at = now
        stats["attributes"] = stats.get("attributes", 0) + 1

        if asset.scope_kind in ("project", "compose", "container"):
            location = session.get(EntityLocationRow, entity_id)
            if location is None:
                location = EntityLocationRow(entity_id=entity_id)
                session.add(location)
                location.first_seen_at = now
            location.root_path = asset.identity_scope
            runtime = ((asset.executable or "").lower())
            if "python" in runtime:
                location.runtime = "python"
            elif "node" in runtime:
                location.runtime = "node"
            location.container_id = attr.container_id
            location.status = "active"
            location.last_seen_at = now
            stats["locations"] = stats.get("locations", 0) + 1

        for instance in session.scalars(
                select(AgentInstanceRow).where(
                    AgentInstanceRow.asset_id == asset.asset_id)):
            instance.entity_id = entity_id
            stats["instance_refs"] = stats.get("instance_refs", 0) + 1


def _write_presence_claim(ledger: EvidenceLedger, *, scan_id: int,
                          entity_id: str, scope_key: str, presence: str,
                          evidence_class: str, method: str,
                          source_ref: str,
                          coverage_scope_id: int | None = None) -> str:
    """PRESENT/ABSENT are per-run observations, not durable state claims."""
    now = utc_now_iso()
    uid = f"scan:{scan_id}:{entity_id}:entity_presence:{presence}"
    observation_id = ledger.record_observation(
        source="discovery", source_event_uid=uid, scope_key=scope_key,
        fact_type="entity_presence",
        payload={"entity_id": entity_id, "presence": presence,
                 "source_ref": source_ref},
        observed_at=now, collection_run_id=scan_id)
    return ledger.add_claim(
        subject_ref=entity_id, predicate="entity_presence", object_ref="entity",
        polarity=("support" if presence == PRESENT else "refute"),
        evidence_class=evidence_class, verification_method=method,
        rule_id="", rule_digest="", rule_generation=scan_id,
        collection_run_id=scan_id, coverage_scope_id=coverage_scope_id,
        observed_at=now, valid_from=now, valid_to=static_claim_valid_to(),
        observation_id=observation_id)


def _snapshot_hook_state(entity_hook: dict[str, set[str]],
                         ledger: EvidenceLedger, entity_id: str) -> str:
    states = entity_hook.get(entity_id)
    if states:
        hook_state = next((state for state in _HOOK_ORDER if state in states),
                          HookState.UNKNOWN.value)
        return _SNAPSHOT_HOOK_STATE.get(hook_state, "UNKNOWN")
    previous = ledger.latest_snapshot(entity_id)
    return previous.hook_state if previous is not None else "UNKNOWN"


def write_scan_evidence(session, *, scan_id: int, assets: list[DetectedAsset],
                        inventory: list[dict], coverage_summary: dict,
                        rule_digests: dict[str, str],
                        framework_ids: set[str], host_key: str,
                        engine_key: str, docker_scope_key: str,
                        coverage_scope_ids: dict[tuple[str, str], int] | None = None,
                        observations: list[dict] | None = None,
                        coverage=None
                        ) -> dict:
    ledger = EvidenceLedger(session)
    identities = IdentityRepository(session)
    components = ComponentRepository(session)
    inventory_by_asset = {item["asset_id"]: item for item in inventory}
    scope_ids = coverage_scope_ids or {}
    entity_hook: dict[str, set[str]] = {}
    entity_by_asset: dict[str, str] = {}
    seen_entities: set[str] = set()
    active_components: dict[str, set[str]] = {}
    entity_container_ids: dict[str, set[str]] = {}
    entity_host_scoped: set[str] = set()
    observations_count = 0
    claims = 0
    stats: dict = {}
    running_valid_to = running_claim_valid_to()
    static_valid_to = static_claim_valid_to()

    for asset in assets:
        scope_key = _scope_for(asset, host_key, engine_key)
        entity_id = identities.resolve_alias(asset.asset_id)
        if entity_id is None:
            legacy = legacy_identity_for_asset(asset, scope_key)
            entity_id = identities.ensure_entity(
                legacy.entity_kind, legacy.key_type, legacy.canonical_key,
                scope_key=scope_key, confidence_basis=legacy.confidence_basis)
            identities.alias_legacy(asset.asset_id, entity_id,
                                    reason="evidence:scan")
        seen_entities.add(entity_id)
        entity_by_asset[asset.asset_id] = entity_id
        if (asset.scope_kind in ("compose", "container")
                or asset.identity_scope.startswith("container:")):
            entity_container_ids.setdefault(entity_id, set()).add(
                asset.identity_scope if asset.scope_kind == "container" else "")
        else:
            entity_host_scoped.add(entity_id)
        coverage_id = _coverage_id(asset, docker_scope_key, scope_ids)
        is_component = (asset.asset_type is AssetType.AGENT_RUNTIME
                        and asset.detector in framework_ids)
        is_service = asset.asset_type in (AssetType.LLM_SERVICE,
                                          AssetType.MCP_SERVER,
                                          AssetType.AGENT_SERVICE)
        product_object = asset.detector or asset.name

        # Product identity is independent of install/running state.
        _write_claim(
            ledger, scan_id=scan_id, entity_id=entity_id, scope_key=scope_key,
            predicate="product_identity", object_ref=product_object,
            evidence_class=("E3" if asset.asset_type is AssetType.LLM_SERVICE
                            and asset.listening_ports else "E2"),
            method=("http_probe" if asset.scope_kind == "listen-port"
                    else "scan_rule"),
            asset=asset, rule_digests=rule_digests,
            coverage_scope_id=coverage_id, valid_to=static_valid_to)
        observations_count += 1
        claims += 1

        # This scan saw the entity: record presence for this generation.
        _write_presence_claim(
            ledger, scan_id=scan_id, entity_id=entity_id, scope_key=scope_key,
            presence=PRESENT,
            evidence_class=("E3" if asset.scope_kind in ("compose", "container")
                            or asset.scope_kind == "project" else "E2"),
            method="scan_rule", source_ref=asset.asset_id,
            coverage_scope_id=coverage_id)
        observations_count += 1
        claims += 1

        for state in sorted(asset.states, key=lambda item: item.value):
            if state is AssetState.INSTALLED:
                predicate = "component_installed" if is_component else "installed"
                evidence_class, method = _EVIDENCE_STATE_CLASS[state]
                object_ref = (f"component:{product_object}" if is_component
                              else product_object)
                claim_id = _write_claim(
                    ledger, scan_id=scan_id, entity_id=entity_id,
                    scope_key=scope_key, predicate=predicate,
                    object_ref=object_ref, evidence_class=evidence_class,
                    method=method, asset=asset, rule_digests=rule_digests,
                    coverage_scope_id=coverage_id, valid_to=static_valid_to)
                if is_component:
                    key = _link_component(components, entity_id, asset, claim_id,
                                          relation_type="DEPENDS_ON",
                                          status="confirmed")
                    active_components.setdefault(entity_id, set()).add(key)
                observations_count += 1
                claims += 1
            elif state is AssetState.CONFIGURED:
                predicate = ("component_configured" if is_component
                             else "configured")
                evidence_class, method = _EVIDENCE_STATE_CLASS[state]
                object_ref = (f"component:{product_object}" if is_component
                              else product_object)
                claim_id = _write_claim(
                    ledger, scan_id=scan_id, entity_id=entity_id,
                    scope_key=scope_key, predicate=predicate,
                    object_ref=object_ref, evidence_class=evidence_class,
                    method=method, asset=asset, rule_digests=rule_digests,
                    coverage_scope_id=coverage_id, valid_to=static_valid_to)
                if is_component:
                    key = _link_component(components, entity_id, asset, claim_id,
                                          relation_type="DECLARES",
                                          status="candidate")
                    active_components.setdefault(entity_id, set()).add(key)
                observations_count += 1
                claims += 1
            elif state is AssetState.RUNNING:
                if is_component:
                    predicate = "component_running"
                elif is_service:
                    predicate = "service_running"
                else:
                    predicate = "running"
                evidence_class, method = _EVIDENCE_STATE_CLASS[state]
                if asset.listening_ports and not asset.running_pids:
                    method = "service_endpoint"
                _write_claim(
                    ledger, scan_id=scan_id, entity_id=entity_id,
                    scope_key=scope_key, predicate=predicate,
                    object_ref=product_object, evidence_class=evidence_class,
                    method=method, asset=asset, rule_digests=rule_digests,
                    coverage_scope_id=coverage_id,
                    valid_to=running_valid_to)
                observations_count += 1
                claims += 1
            elif state is AssetState.EXECUTION_CONFIRMED:
                _write_claim(
                    ledger, scan_id=scan_id, entity_id=entity_id,
                    scope_key=scope_key, predicate="agent_capability",
                    object_ref="AGENT_EXECUTION_OBSERVED", evidence_class="E5",
                    method="execution_evidence", asset=asset,
                    rule_digests=rule_digests,
                    coverage_scope_id=coverage_id, valid_to=static_valid_to)
                observations_count += 1
                claims += 1

        # Capability tags: conservative minimum evidence sets.
        tags: set[str] = set()
        if is_component or asset.asset_type in (
                AssetType.AI_APPLICATION, AssetType.AGENT_RUNTIME,
                AssetType.MCP_SERVER, AssetType.LLM_SERVICE,
                AssetType.AGENT_CLIENT, AssetType.AGENT_PLATFORM,
                AssetType.AGENT_SERVICE):
            tags.add("AI_RELATED")
        if asset.asset_type in (AssetType.AGENT_CLIENT,
                                AssetType.AGENT_PLATFORM,
                                AssetType.AGENT_SERVICE):
            tags.add("AGENT_CAPABLE")
        item = inventory_by_asset.get(asset.asset_id) or {}
        hook_state = str(item.get("hook_state") or HookState.UNKNOWN.value)
        for tag in sorted(tags):
            _write_claim(
                ledger, scan_id=scan_id, entity_id=entity_id,
                scope_key=scope_key, predicate="agent_capability",
                object_ref=tag,
                evidence_class=("E5" if tag == "AGENT_EXECUTION_OBSERVED"
                                else "E2"),
                method=("hook_observed" if tag == "AGENT_EXECUTION_OBSERVED"
                        else "capability_rule"),
                asset=asset, rule_digests=rule_digests,
                coverage_scope_id=coverage_id, valid_to=static_valid_to)
            observations_count += 1
            claims += 1

        if hook_state not in ("", HookState.UNKNOWN.value,
                              HookState.UNSUPPORTED.value,
                              HookState.NOT_INSTALLED.value):
            _write_claim(
                ledger, scan_id=scan_id, entity_id=entity_id,
                scope_key=scope_key, predicate="hook_configured",
                object_ref=hook_state, evidence_class="E2",
                method="hook_config", asset=asset,
                rule_digests=rule_digests, coverage_scope_id=coverage_id,
                valid_to=static_valid_to)
            observations_count += 1
            claims += 1
        entity_hook.setdefault(entity_id, set()).add(hook_state)

        for server_name in item.get("mcp_servers") or ():
            server_name = str(server_name).strip()
            if not server_name:
                continue
            claim_id = _write_claim(
                ledger, scan_id=scan_id, entity_id=entity_id,
                scope_key=scope_key, predicate="component_configured",
                object_ref=f"mcp:{server_name}", evidence_class="E2",
                method="mcp_config", asset=asset, rule_digests=rule_digests,
                coverage_scope_id=coverage_id, valid_to=static_valid_to)
            key = _link_named_component(
                components, entity_id, server_name, "MCP_SERVER", claim_id,
                relation_type="DECLARES", status="candidate")
            active_components.setdefault(entity_id, set()).add(key)
            observations_count += 1
            claims += 1

    for entity_id in sorted(seen_entities):
        if _closure_allowed(coverage, entity_id, entity_container_ids,
                            entity_host_scoped, docker_scope_key):
            components.close_stale(
                entity_id, active_components.get(entity_id, set()))

    _write_canonical_inventory(session, assets, inventory, entity_by_asset,
                               stats)

    # Presence observations from the re-confirmation loop: the only path that
    # may conclude ABSENT for an entity this scan did not see.
    observations_by_entity: dict[str, dict] = {}
    for observation in observations or ():
        asset_id = str(observation.get("asset_id") or "")
        entity_id = (observation.get("entity_id")
                     or (identities.resolve_alias(asset_id) if asset_id else None))
        if not entity_id:
            continue
        observations_by_entity[entity_id] = observation
        presence = str(observation.get("presence") or "").upper()
        if presence not in (PRESENT, ABSENT):
            continue
        context = entity_context(session, entity_id)
        scope_key = (engine_key if context.entity_kind in (
            "COMPOSE_DEPLOYMENT", "CONTAINER_DEPLOYMENT") else host_key)
        _write_presence_claim(
            ledger, scan_id=scan_id, entity_id=entity_id, scope_key=scope_key,
            presence=presence,
            evidence_class=("E3" if context.entity_kind in (
                "COMPOSE_DEPLOYMENT", "CONTAINER_DEPLOYMENT") else "E2"),
            method="static_reconfirm", source_ref=asset_id or entity_id)
        observations_count += 1
        claims += 1

    for entity_id, observation in observations_by_entity.items():
        if observation.get("presence") != ABSENT:
            continue
        refs = [ref for ref in observation.get("required_scopes") or ()
                if isinstance(ref, dict)]
        confirmed = (coverage is not None and bool(refs) and all(
            coverage.is_complete(ref.get("scope_type", ""),
                                 ref.get("scope_key", ""),
                                 ref.get("predicate", "")) for ref in refs))
        if confirmed:
            invalidate_on_absence(session, entity_id, generation_id=scan_id)

    for rule_id, rule_digest in rule_digests.items():
        ledger.upsert_rule_revision(rule_id, rule_digest, "packaged")

    # Resolve every entity this run has an opinion about: what was seen, what
    # was re-confirmed, and what could not be checked (kept with a marker).
    project_inputs: dict[str, dict] = {}
    for entity_id in seen_entities:
        project_inputs[entity_id] = {"marker": None, "required": None}
    for entity_id, observation in observations_by_entity.items():
        if entity_id in project_inputs:
            continue
        presence = str(observation.get("presence") or "").upper()
        marker = None
        if presence not in (PRESENT, ABSENT):
            marker = {
                "reason": observation.get("reason") or "本轮无法复核",
                "verification": observation.get("verification") or "FAILED",
                "reason_code": observation.get("reason_code") or "scope_failed",
            }
        elif observation.get("verification") in (FAILED, NOT_CHECKED):
            # Degraded re-confirm (T2): the enumeration proved the object is
            # still there, but the round could not verify its interior (e.g.
            # a docker stall). The PRESENT claim goes out as usual above; the
            # marker carries the specific Chinese reason onto the snapshot so
            # the console shows "容器仍在…深探测失联未复核" instead of the
            # generic scope failure text.
            marker = {
                "reason": observation.get("reason") or "本轮无法复核",
                "verification": observation.get("verification") or "FAILED",
                "reason_code": observation.get("reason_code") or "scope_failed",
            }
        refs = tuple(ScopeRef(ref["scope_type"], ref["scope_key"],
                              ref["predicate"])
                     for ref in observation.get("required_scopes") or ()
                     if isinstance(ref, dict))
        project_inputs[entity_id] = {"marker": marker,
                                     "required": refs or None}

    statuses: dict[str, int] = {}
    resolved: dict[str, object] = {}
    for entity_id in sorted(project_inputs):
        spec = project_inputs[entity_id]
        snapshot_hook = _snapshot_hook_state(entity_hook, ledger, entity_id)
        state = resolve(
            session, entity_id=entity_id, generation_id=scan_id,
            context=entity_context(session, entity_id), coverage=coverage,
            coverage_summary=coverage_summary,
            docker_scope_key=docker_scope_key,
            required=spec["required"], unverified=spec["marker"],
            hook_state=snapshot_hook)
        write_resolved(session, state, generation_id=scan_id,
                       coverage_summary=coverage_summary)
        resolved[entity_id] = state
        statuses[state.agent_status] = statuses.get(state.agent_status, 0) + 1

    candidates = _absence_candidates(resolved, observations_by_entity)
    _apply_instance_states(session, resolved, entity_by_asset,
                           observations_by_entity)
    _apply_attribute_states(session, resolved)
    session.flush()
    return {"observations": observations_count, "claims": claims,
            "entities": len(seen_entities),
            "resolved": len(resolved),
            "unverified": sum(1 for state in resolved.values()
                              if state.verification in ("FAILED", "NOT_CHECKED",
                                                        "STALE")),
            "statuses": statuses,
            "removal_candidates": candidates,
            **stats}


def _absence_candidates(resolved: dict, observations: dict[str, dict]
                        ) -> list[dict]:
    candidates: list[dict] = []
    for entity_id, state in sorted(resolved.items()):
        if state.presence != ABSENT:
            continue
        observation = observations.get(entity_id) or {}
        refs = [ref for ref in observation.get("required_scopes") or ()
                if isinstance(ref, dict)]
        candidates.append({
            "asset_id": entity_id,
            "entity_id": entity_id,
            "entity_kind": observation.get("entity_kind") or "UNKNOWN",
            "predicate": observation.get("predicate") or "entity_presence",
            "status": ("CONFIRMED_ABSENT"
                       if state.lifecycle == "ARCHIVED" else "UNVERIFIED"),
            "reason": state.reason or observation.get("reason") or "",
            "coverage_refs": [
                f"{ref.get('scope_type')}:{ref.get('scope_key')}:"
                f"{ref.get('predicate')}" for ref in refs],
        })
    return candidates


def _apply_instance_states(session, resolved: dict, entity_by_asset: dict,
                           observations: dict[str, dict]) -> None:
    """Close instance rows in one place instead of trusting attr.status.

    A seen entity is already handled by ``upsert_instances``. Everything else
    follows the resolved presence: gone → stopped, not re-verifiable →
    unverified, present but no process observed → stopped.
    """
    seen_entities = set(entity_by_asset.values())
    for entity_id, state in resolved.items():
        if entity_id in seen_entities:
            continue
        rows = session.scalars(select(AgentInstanceRow).where(
            AgentInstanceRow.entity_id == entity_id,
            AgentInstanceRow.status.in_(("running", "unverified"))))
        for row in rows:
            if state.presence == ABSENT:
                row.status = "stopped"
            elif state.presence == PRESENT:
                row.status = ("stopped" if state.verification == "VERIFIED"
                              else "unverified")
            else:
                row.status = "unverified"


def _apply_attribute_states(session, resolved: dict) -> None:
    for entity_id, state in resolved.items():
        attr = session.get(EntityAttributeRow, entity_id)
        if attr is None:
            continue
        if state.presence == ABSENT:
            attr.status = "inactive"
        elif state.presence == PRESENT:
            attr.status = "active"
        # UNKNOWN keeps the last recorded status: the run proved nothing.
