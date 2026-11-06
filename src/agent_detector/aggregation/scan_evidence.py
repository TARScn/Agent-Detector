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
from agent_detector.aggregation.status_projection import project_entity
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
        item = items.get(asset.asset_id) or {}
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
        attr.container_id = (item.get("container_id")
                             or (asset.identity_scope
                                 if asset.scope_kind == "container" else None))
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


def write_scan_evidence(session, *, scan_id: int, assets: list[DetectedAsset],
                        inventory: list[dict], coverage_summary: dict,
                        rule_digests: dict[str, str],
                        framework_ids: set[str], host_key: str,
                        engine_key: str, docker_scope_key: str,
                        coverage_scope_ids: dict[tuple[str, str], int] | None = None,
                        removal_candidates: list[dict] | None = None,
                        unverified: dict[str, str] | None = None,
                        coverage=None
                        ) -> dict:
    ledger = EvidenceLedger(session)
    identities = IdentityRepository(session)
    components = ComponentRepository(session)
    inventory_by_asset = {item["asset_id"]: item for item in inventory}
    scope_ids = coverage_scope_ids or {}
    entity_hook: dict[str, set[str]] = {}
    entity_removal: dict[str, str] = {}
    entity_by_asset: dict[str, str] = {}
    for candidate in removal_candidates or ():
        asset_id = str(candidate.get("asset_id") or "")
        entity_id = identities.resolve_alias(asset_id) if asset_id else None
        if not entity_id:
            continue
        verdict = ("CONFIRMED" if candidate.get("status") == "CONFIRMED_ABSENT"
                   else "CANDIDATE")
        if entity_removal.get(entity_id) != "CONFIRMED":
            entity_removal[entity_id] = verdict
    seen_entities: set[str] = set()
    active_components: dict[str, set[str]] = {}
    entity_container_ids: dict[str, set[str]] = {}
    entity_host_scoped: set[str] = set()
    observations = 0
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
        observations += 1
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
                observations += 1
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
                observations += 1
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
                observations += 1
                claims += 1
            elif state is AssetState.EXECUTION_CONFIRMED:
                _write_claim(
                    ledger, scan_id=scan_id, entity_id=entity_id,
                    scope_key=scope_key, predicate="agent_capability",
                    object_ref="AGENT_EXECUTION_OBSERVED", evidence_class="E5",
                    method="execution_evidence", asset=asset,
                    rule_digests=rule_digests,
                    coverage_scope_id=coverage_id, valid_to=static_valid_to)
                observations += 1
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
            observations += 1
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
            observations += 1
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
            observations += 1
            claims += 1

    for entity_id in sorted(seen_entities):
        if _closure_allowed(coverage, entity_id, entity_container_ids,
                            entity_host_scoped, docker_scope_key):
            components.close_stale(
                entity_id, active_components.get(entity_id, set()))

    _write_canonical_inventory(session, assets, inventory, entity_by_asset,
                               stats)

    for rule_id, rule_digest in rule_digests.items():
        ledger.upsert_rule_revision(rule_id, rule_digest, "packaged")

    statuses: dict[str, int] = {}
    for entity_id in sorted(seen_entities | set(entity_removal)):
        states = entity_hook.get(entity_id) or {HookState.UNKNOWN.value}
        hook_state = next((state for state in _HOOK_ORDER if state in states),
                          HookState.UNKNOWN.value)
        snapshot_hook = _SNAPSHOT_HOOK_STATE.get(hook_state, "UNKNOWN")
        result = project_entity(
            session, entity_id, scan_id, hook_state=snapshot_hook,
            coverage_summary=coverage_summary,
            removal_verdict=entity_removal.get(entity_id, "NONE"))
        statuses[result["agent_status"]] = statuses.get(
            result["agent_status"], 0) + 1
    # Entities this run could not check still get a snapshot: without one the
    # console would fall back to the last generation and keep the old status.
    for entity_id, reason in sorted((unverified or {}).items()):
        if entity_id in seen_entities or entity_id in entity_removal:
            continue
        result = project_entity(
            session, entity_id, scan_id, coverage_summary=coverage_summary,
            removal_verdict=entity_removal.get(entity_id, "NONE"),
            unverified=reason)
        statuses[result["agent_status"]] = statuses.get(
            result["agent_status"], 0) + 1
    session.flush()
    return {"observations": observations, "claims": claims,
            "entities": len(seen_entities),
            "unverified": len(unverified or {}),
            "statuses": statuses,
            **stats}