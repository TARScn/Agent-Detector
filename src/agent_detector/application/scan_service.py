"""Scan orchestration: collect facts, run detectors, persist merged results.

One scan is one short SQLite transaction; a failing detector is recorded as a
scan error instead of aborting the run (plan sections 5.1, 8.1).
"""
import logging

from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from agent_detector.collectors.process import collect_host_facts
from agent_detector.common.config import MAX_PROBES
from agent_detector.detectors import build_detectors
from agent_detector.detectors.registry import Detector
from agent_detector.domain.models import DetectedAsset, HostFacts
from agent_detector.persistence.repositories import (AssetRepository, EvidenceRepository,
                                                     ScanRepository)
from agent_detector.probes.http import probe_facts

logger = logging.getLogger(__name__)


def run_scan(engine: Engine, active: bool = False,
             detectors: list[Detector] | None = None) -> dict:
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
        stats = {
            "observations": {"processes": len(facts.processes),
                             "listening_sockets": len(facts.sockets)},
            "assets": len(merged),
            "asset_summaries": [_summary(asset) for asset in merged],
            "errors": errors,
        }
        scan_repo.finish(scan_id, "completed", stats)
        session.commit()
        return {"scan_id": scan_id, "mode": mode, "status": "completed", **stats}


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
