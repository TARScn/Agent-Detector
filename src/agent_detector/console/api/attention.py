"""One ranked "needs attention" feed for the overview (contract §5.11.1).

The frontend must not invent this list from several endpoints: severity and
routes live here so every client shows the same priorities.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from agent_detector.console.api.deps import Services, get_services
from agent_detector.console.api.telemetry import telemetry_status
from agent_detector.storage import (AlertRepository, CoverageRepository,
                                    EntityRepository, ScanRepository)
from agent_detector.storage.models import IdentityReviewCaseRow

router = APIRouter(prefix="/api/v1", tags=["attention"])

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _services() -> Services:
    return get_services()


@router.get("/attention")
def attention(limit: int = Query(default=5, ge=1, le=20),
              services: Services = Depends(_services)):
    items: list[dict] = []
    with Session(services.engine) as session:
        alerts = AlertRepository(session).list_alerts(status="open", limit=50)
        for alert in alerts:
            risk = alert.get("risk_level") or "medium"
            if risk not in ("high", "critical"):
                continue
            items.append({
                "kind": "alert",
                "severity": risk,
                "title": alert.get("title") or "高风险告警",
                "description": alert.get("reason") or "",
                "subject": {"entity_id": alert.get("entity_id"),
                            "label": alert.get("agent_label") or "未归属"},
                "occurred_at": alert.get("created_at"),
                "route": f"#/alerts?alert={alert['id']}",
            })

        entities = EntityRepository(session).list_agents(include_hidden=True)
        for asset in entities:
            conflicts = (asset.get("status_basis") or {}).get("conflicts") or []
            if conflicts:
                items.append({
                    "kind": "claim_conflict",
                    "severity": "high",
                    "title": "状态证据存在冲突",
                    "description": "、".join(str(item) for item in conflicts),
                    "subject": {"entity_id": asset["entity_id"],
                                "label": asset.get("name") or "未命名实体"},
                    "occurred_at": asset.get("last_seen_at"),
                    "route": f"#/assets/{asset['entity_id']}?tab=evidence",
                })
        review_cases = session.query(IdentityReviewCaseRow).count()
        if review_cases:
            items.append({
                "kind": "identity_review",
                "severity": "high",
                "title": "身份待复核",
                "description": f"{review_cases} 个历史身份未收敛；不会自动合并。",
                "subject": {"entity_id": None, "label": "身份复核"},
                "occurred_at": None,
                "route": "#/assets",
            })

        latest_scan = ScanRepository(session).latest_id()
        scan = ScanRepository(session).get(latest_scan) if latest_scan else None
        if scan is None:
            stale, stamp = True, None
        else:
            stamp = scan.get("finished_at") or scan.get("started_at")
            stale = _older_than(stamp, hours=24)
        if latest_scan is not None:
            scopes = CoverageRepository(session).list_scopes(latest_scan)
            bad = [scope for scope in scopes
                   if scope.get("own_status") in ("PARTIAL", "FAILED")]
            if bad:
                items.append({
                    "kind": "coverage_gap",
                    "severity": "medium",
                    "title": "本次扫描覆盖不足",
                    "description": f"{len(bad)} 个采集范围未完整完成",
                    "subject": {"entity_id": None,
                                "label": f"扫描 #{latest_scan}"},
                    "occurred_at": stamp,
                    "route": "#/collectors?tab=coverage",
                })

    health = telemetry_status(services=services).get("health", {})
    if health.get("state") in ("DEGRADED", "NOT_RUNNING"):
        items.append({
            "kind": "collector_unhealthy",
            "severity": "high" if health.get("state") == "DEGRADED" else "medium",
            "title": "采集通道异常" if health.get("state") == "DEGRADED"
                     else "尚未开启采集",
            "description": "；".join(health.get("basis") or []),
            "subject": {"entity_id": None,
                        "label": "本机采集"},
            "occurred_at": health.get("last_event_at"),
            "route": "#/collectors",
        })
    if stale:
        items.append({
            "kind": "scan_stale",
            "severity": "low",
            "title": "资产清单可能过期",
            "description": "超过 24 小时未完成扫描" if stamp else "尚未扫描",
            "subject": {"entity_id": None, "label": "扫描"},
            "occurred_at": stamp,
            "route": "#/overview",
        })

    items.sort(key=lambda item: item.get("occurred_at") or "", reverse=True)
    items.sort(key=lambda item: _SEVERITY_ORDER.get(item["severity"], 9))
    return {"items": items[:limit],
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}


def _older_than(value: str | None, *, hours: int) -> bool:
    if not value:
        return True
    try:
        stamp = datetime.fromisoformat(value)
    except ValueError:
        return True
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp < datetime.now(timezone.utc) - timedelta(hours=hours)