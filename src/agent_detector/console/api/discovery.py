"""Discovery endpoints on the canonical V1.2 read model."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agent_detector.console.api.deps import Services, get_services
from agent_detector.console.api.schemas import ScanRequest
from agent_detector.discovery.scanner.scan import run_scan
from agent_detector.storage import EntityRepository, ScanRepository
from agent_detector.storage.models import (ComponentRelationRow,
                                           EntityAttributeRow,
                                           EntityLocationRow, utc_now_iso)

router = APIRouter(prefix="/api/v1", tags=["discovery"])


def _services() -> Services:
    return get_services()


@router.post("/discovery/scan")
def create_scan(body: ScanRequest, services: Services = Depends(_services)):
    if not services.scan_lock.acquire(blocking=False):
        from fastapi import HTTPException
        raise HTTPException(status_code=409, detail="已有扫描在进行中")
    mode = "agent+traffic" if body.active else "agent"
    services.scan_run.started_at = utc_now_iso()
    services.scan_run.mode = mode
    try:
        result = run_scan(services.engine, active=body.active,
                          matrix=services.matrix, docker_enabled=body.docker)
        with Session(services.engine) as session:
            entities = EntityRepository(session).list_agents()
            components = session.scalar(
                select(func.count()).select_from(ComponentRelationRow).where(
                    ComponentRelationRow.valid_to.is_(None))) or 0
        return {"scan_id": result["scan_id"], "mode": result["mode"],
                "status": result["status"], "entities": len(entities),
                "components": int(components),
                "errors": result.get("errors", [])}
    finally:
        services.scan_run.started_at = None
        services.scan_lock.release()


@router.get("/discovery/scan/status")
def scan_status(services: Services = Depends(_services)):
    """Whether a scan is running right now.

    The console reloads its mutation state on navigation, so the running flag
    must come from the process that owns the scan, not from browser memory.
    """
    running = services.scan_lock.locked()
    return {"running": running,
            "started_at": services.scan_run.started_at if running else None,
            "mode": services.scan_run.mode if running else None}


@router.get("/discovery/scans")
def list_scans(limit: int = 30, services: Services = Depends(_services)):
    with Session(services.engine) as session:
        return {"items": ScanRepository(session).list(limit=limit)}


@router.get("/discovery/assets")
def list_assets(services: Services = Depends(_services)):
    """Canonical entity inventory (legacy asset snapshots are gone)."""
    with Session(services.engine) as session:
        items = EntityRepository(session).list_agents(include_hidden=True)
    return {"items": items, "total": len(items)}


@router.get("/discovery/applications")
def list_applications(services: Services = Depends(_services)):
    """Self-built/container applications from canonical entity locations."""
    with Session(services.engine) as session:
        components = {entity_id: count for entity_id, count in session.execute(
            select(ComponentRelationRow.entity_id, func.count()).where(
                ComponentRelationRow.valid_to.is_(None)).group_by(
                    ComponentRelationRow.entity_id))}
        items = []
        for location in session.scalars(select(EntityLocationRow)):
            attr = session.get(EntityAttributeRow, location.entity_id)
            items.append({
                "entity_id": location.entity_id,
                "name": attr.name if attr else "",
                "agent_type": attr.agent_type if attr else "",
                "root_path": location.root_path,
                "environment_path": location.environment_path,
                "runtime": location.runtime,
                "entrypoint": location.entrypoint,
                "entry_kind": location.entry_kind,
                "status": location.status,
                "components": int(components.get(location.entity_id, 0)),
                "first_seen_at": location.first_seen_at,
                "last_seen_at": location.last_seen_at,
            })
    return {"items": items, "total": len(items)}


@router.get("/discovery/summary")
def discovery_summary(services: Services = Depends(_services)):
    with Session(services.engine) as session:
        entities = EntityRepository(session).list_agents(include_hidden=True)
        components = session.scalar(
            select(func.count()).select_from(ComponentRelationRow).where(
                ComponentRelationRow.valid_to.is_(None))) or 0
        applications = session.scalar(
            select(func.count()).select_from(EntityLocationRow)) or 0
        latest_scan = ScanRepository(session).latest_id()
    return {"entities": len(entities), "components": int(components),
            "applications": int(applications), "latest_scan_id": latest_scan}