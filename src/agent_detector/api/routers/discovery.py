"""Discovery endpoints: run a scan, browse component assets (§8).

These are the V0.1 endpoints with the V0.2 shape: a scan still produces
component assets (Agent clients, MCP servers, model services) with evidence,
and it now also refreshes the Agent inventory (agent_assets/instances).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from agent_detector.api.deps import Services, get_services
from agent_detector.api.schemas import ScanRequest
from agent_detector.discovery.scanner import run_scan
from agent_detector.storage.repositories import (AgentInventoryRepository, AssetRepository,
                                                 EvidenceRepository, ScanRepository)

router = APIRouter(prefix="/api/v1", tags=["discovery"])


def _services() -> Services:
    return get_services()


@router.post("/discovery/scan")
def create_scan(body: ScanRequest, services: Services = Depends(_services)):
    if not services.scan_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="已有扫描在进行中")
    try:
        return run_scan(services.engine, active=body.active, matrix=services.matrix)
    finally:
        services.scan_lock.release()


@router.get("/discovery/scans")
def list_scans(limit: int = 30, services: Services = Depends(_services)):
    with Session(services.engine) as session:
        return {"items": ScanRepository(session).list(limit=limit)}


@router.get("/discovery/assets")
def list_assets(scan_id: int | None = None, services: Services = Depends(_services)):
    """Latest (or per-scan) component assets from the detection pipeline."""
    with Session(services.engine) as session:
        repository = AssetRepository(session)
        items = (repository.list_snapshots(scan_id) if scan_id is not None
                 else repository.latest_snapshots())
    return {"items": items, "total": len(items)}


@router.get("/discovery/summary")
def discovery_summary(services: Services = Depends(_services)):
    """Counts by asset type, plus whether the inventory has been built yet."""
    with Session(services.engine) as session:
        assets = AssetRepository(session).latest_snapshots()
        latest_scan = ScanRepository(session).latest_id()
        agents = AgentInventoryRepository(session).list_assets()
    by_type: dict[str, int] = {}
    for asset in assets:
        by_type[asset["asset_type"]] = by_type.get(asset["asset_type"], 0) + 1
    return {"assets": len(assets), "by_type": by_type, "agent_assets": len(agents),
            "latest_scan_id": latest_scan}