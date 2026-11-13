"""P2.4: replay stored observations into a new generation without re-collecting.

Observations retain the normalized discovery facts needed to rebuild the
asset candidates (type, states, detector, version, scope). Re-running the
evidence writer against a fresh generation therefore applies current predicate
policy/rule digests to the same facts. It is evidence replay, not a byte-level
replay of file probes or process sweeps.
"""
from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_detector.aggregation.scan_evidence import write_scan_evidence
from agent_detector.core.enums import AssetState, AssetType, VersionSource
from agent_detector.core.models import DetectedAsset, VersionInfo
from agent_detector.storage.models import ObservationRow


def _asset_from(asset_id: str, facts: dict) -> DetectedAsset | None:
    try:
        asset_type = AssetType(facts.get("asset_type") or "UNKNOWN")
    except ValueError:
        asset_type = AssetType.UNKNOWN
    states: set[AssetState] = set()
    for value in facts.get("states") or ():
        try:
            states.add(AssetState(value))
        except ValueError:
            continue
    if not states:
        return None
    try:
        version_source = VersionSource(facts.get("version_source")
                                       or "unknown")
    except ValueError:
        version_source = VersionSource.UNKNOWN
    return DetectedAsset(
        asset_id=asset_id,
        name=str(facts.get("name") or asset_id),
        asset_type=asset_type,
        states=states,
        confidence=0.7,
        version=VersionInfo(str(facts.get("version") or "UNKNOWN"),
                            version_source),
        evidence=[],
        running_pids=[int(pid) for pid in (facts.get("running_pids") or ())
                      if str(pid).isdigit()],
        detector=str(facts.get("detector") or ""),
        scope_kind=str(facts.get("scope_kind") or ""),
        identity_scope=str(facts.get("identity_scope") or ""),
    )


def replay_scan_evidence(session: Session, source_scan_id: int,
                         target_scan_id: int, *,
                         rule_digests: dict[str, str] | None = None,
                         framework_ids: set[str] | None = None,
                         host_key: str = "replay",
                         engine_key: str = "replay") -> dict:
    observations = session.scalars(
        select(ObservationRow).where(
            ObservationRow.collection_run_id == source_scan_id,
            ObservationRow.source == "discovery")).all()
    facts_by_asset: dict[str, dict] = {}
    for observation in observations:
        try:
            payload = json.loads(observation.normalized_payload_json or "{}")
        except json.JSONDecodeError:
            continue
        asset_id = str(payload.get("asset_id") or "")
        if not asset_id:
            continue
        current = facts_by_asset.setdefault(asset_id, {})
        for key in ("name", "asset_type", "detector", "scope_kind",
                    "identity_scope", "version", "version_source"):
            if payload.get(key) and not current.get(key):
                current[key] = payload[key]
        states = set(current.get("states") or ())
        states.update(payload.get("states") or ())
        current["states"] = states
        pids = set(current.get("running_pids") or ())
        pids.update(payload.get("running_pids") or ())
        current["running_pids"] = pids

    assets = [asset for asset_id, facts in facts_by_asset.items()
              if (asset := _asset_from(asset_id, facts)) is not None]
    if framework_ids is None:
        framework_ids = {asset.detector for asset in assets
                         if asset.asset_type is AssetType.AGENT_RUNTIME}
    stats = write_scan_evidence(
        session, scan_id=target_scan_id, assets=assets, inventory=[],
        coverage_summary={}, rule_digests=rule_digests or {},
        framework_ids=framework_ids, host_key=host_key,
        engine_key=engine_key, docker_scope_key="replay", coverage=None)
    stats["source_scan_id"] = source_scan_id
    stats["target_scan_id"] = target_scan_id
    stats["replayed_assets"] = len(assets)
    return stats