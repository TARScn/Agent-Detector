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
def list_alerts(limit: int = Query(default=100, ge=1, le=500),
                offset: int = Query(default=0, ge=0),
                status: str | None = None, risk_level: str | None = None,
                entity_id: str | None = None, event_id: int | None = None,
                services: Services = Depends(_services)):
    with Session(services.engine) as session:
        repository = AlertRepository(session)
        items = repository.list_alerts(limit=limit, status=status,
                                       risk_level=risk_level, entity_id=entity_id,
                                       event_id=event_id, offset=offset)
        stats = repository.stats()
    return {"items": items, "total": len(items), "stats": stats,
            "limit": limit, "offset": offset}


@router.get("/alerts/{alert_id}")
def alert_detail(alert_id: int, services: Services = Depends(_services)):
    with Session(services.engine) as session:
        item = AlertRepository(session).get_alert(alert_id)
    if item is None:
        raise HTTPException(status_code=404, detail="未找到该告警")
    return item


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