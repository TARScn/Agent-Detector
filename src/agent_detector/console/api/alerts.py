"""Security alert endpoints (design section 8: /api/v1/alerts)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from agent_detector.console.api.deps import Services, get_services
from agent_detector.console.api.schemas import AlertUpdateRequest
from agent_detector.storage import AlertRepository

router = APIRouter(prefix="/api/v1", tags=["alerts"])


def _services() -> Services:
    return get_services()


@router.get("/alerts")
def list_alerts(limit: int = Query(default=100, ge=1, le=500), status: str | None = None,
                risk_level: str | None = None, asset_id: str | None = None,
                services: Services = Depends(_services)):
    with Session(services.engine) as session:
        repository = AlertRepository(session)
        items = repository.list_alerts(limit=limit, status=status,
                                       risk_level=risk_level, asset_id=asset_id)
        stats = repository.stats()
    return {"items": items, "total": len(items), "stats": stats}


@router.patch("/alerts/{alert_id}")
def update_alert(alert_id: int, body: AlertUpdateRequest,
                 services: Services = Depends(_services)):
    with Session(services.engine) as session:
        repository = AlertRepository(session)
        updated = repository.update_status(alert_id, body.status)
        session.commit()
    if updated is None:
        raise HTTPException(status_code=404, detail="未找到该告警")
    return updated