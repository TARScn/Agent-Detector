"""Discovery orchestration: collect facts, run detectors, persist the inventory.

One scan is one short SQLite transaction; a failing detector is recorded as a
scan error instead of aborting the run (design section 2). After the component
assets are stored, the Agent inventory step builds the V0.2 view of the machine
— logical Agent assets, running instances, hook state and protection status.
"""
import logging
from pathlib import Path

from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from agent_detector.collectors.process import collect_host_facts
from agent_detector.common.config import MAX_PROBES
from agent_detector.discovery.agents import LoadedMatrix
from agent_detector.discovery.build import build_detectors
from agent_detector.discovery.inventory import InventoryBuilder
from agent_detector.discovery.registry import Detector
from agent_detector.domain.models import DetectedAsset, HostFacts
from agent_detector.probes.http import probe_facts
from agent_detector.storage.repositories import (AssetRepository, EvidenceRepository,
                                                 ScanRepository)

logger = logging.getLogger(__name__)


def run_scan(engine: Engine, active: bool = False,
             detectors: list[Detector] | None = None,
             home: Path | None = None,
             matrix: LoadedMatrix | None = None) -> dict:
    if detectors is None:
        detectors = build_detectors()
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
        merged = merge_assets(assets)
        asset_repo = AssetRepository(session)
        evidence_repo = EvidenceRepository(session)
        for asset in merged:
            asset_repo.upsert(asset, scan_id)
            evidence_repo.add_all(scan_id, asset)
        agent_inventory, inventory_warnings = _build_inventory(
            session, merged, facts, home=home, matrix=matrix)
        stats = {
            "observations": {"processes": len(facts.processes),
                             "listening_sockets": len(facts.sockets)},
            "assets": len(merged),
            "agent_assets": agent_inventory,
            "agent_instances": sum(item["instance_count"] for item in agent_inventory),
            "asset_summaries": [_summary(asset) for asset in merged],
            "errors": errors + [{"detector": "inventory", "error": warning}
                                for warning in inventory_warnings],
        }
        scan_repo.finish(scan_id, "completed", stats)
        session.commit()
        return {"scan_id": scan_id, "mode": mode, "status": "completed", **stats}


def _build_inventory(session: Session, merged: list[DetectedAsset], facts: HostFacts,
                     *, home: Path | None, matrix: LoadedMatrix | None) -> tuple[list[dict], list[str]]:
    """Agent-level view of the same scan; a failure here never voids the scan."""
    try:
        builder = InventoryBuilder(home=home, matrix=matrix)
        items = builder.apply_scan(session, merged, facts)
        return items, builder.warnings
    except Exception as exc:
        logger.exception("agent inventory build failed")
        return [], [str(exc)]


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


def _summary(asset: DetectedAsset) -> dict:
    return {"asset_id": asset.asset_id, "name": asset.name,
            "asset_type": asset.asset_type.value,
            "states": sorted(state.value for state in asset.states),
            "confidence": asset.confidence, "version": asset.version.value,
            "version_source": asset.version.source.value,
            "running_pids": asset.running_pids,
            "listening_ports": asset.listening_ports, "detector": asset.detector}
