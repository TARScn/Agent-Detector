"""Read/write access to ``security_alerts`` (design section 7).

Alerts are raised from two sources: a hook verdict that denies a tool call
(``decision="deny"``) and a telemetry event whose risk level crosses the
configured bar. Both land here with a link back to the event that caused them.
"""
import json

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agent_detector.storage.models import SecurityAlertRow, utc_now_iso


class AlertRepository:
    def __init__(self, session: Session):
        self._session = session

    def raise_alert(self, *, title: str, reason: str, risk_level: str,
                    decision: str, asset_id: str | None = None,
                    agent_type: str | None = None, agent_label: str = "",
                    session_id: str | None = None, event_id: int | None = None,
                    policy_id: str | None = None,
                    detail: dict | None = None) -> int:
        row = SecurityAlertRow(
            created_at=utc_now_iso(), asset_id=asset_id, agent_type=agent_type,
            agent_label=agent_label, session_id=session_id, event_id=event_id,
            policy_id=policy_id, risk_level=risk_level, decision=decision,
            title=title[:200], reason=reason,
            detail_json=json.dumps(detail or {}, ensure_ascii=False))
        self._session.add(row)
        self._session.flush()
        return row.id

    def list_alerts(self, limit: int = 100, status: str | None = None,
                    risk_level: str | None = None,
                    asset_id: str | None = None) -> list[dict]:
        statement = select(SecurityAlertRow)
        if status:
            statement = statement.where(SecurityAlertRow.status == status)
        if risk_level:
            statement = statement.where(SecurityAlertRow.risk_level == risk_level)
        if asset_id:
            statement = statement.where(SecurityAlertRow.asset_id == asset_id)
        statement = statement.order_by(SecurityAlertRow.id.desc()).limit(
            min(max(int(limit), 1), 500))
        return [self._to_dict(row) for row in self._session.scalars(statement)]

    def update_status(self, alert_id: int, status: str) -> dict | None:
        row = self._session.get(SecurityAlertRow, alert_id)
        if row is None:
            return None
        row.status = status
        row.resolved_at = utc_now_iso() if status == "resolved" else None
        return self._to_dict(row)

    def stats(self) -> dict:
        total = self._session.scalar(
            select(func.count()).select_from(SecurityAlertRow)) or 0
        by_status = {status: count for status, count in self._session.execute(
            select(SecurityAlertRow.status, func.count()).group_by(
                SecurityAlertRow.status))}
        by_risk = {risk: count for risk, count in self._session.execute(
            select(SecurityAlertRow.risk_level, func.count()).group_by(
                SecurityAlertRow.risk_level))}
        open_high = self._session.scalar(
            select(func.count()).select_from(SecurityAlertRow).where(
                SecurityAlertRow.status == "open",
                SecurityAlertRow.risk_level.in_(("high", "critical")))) or 0
        return {"alert_count": total, "by_status": by_status, "by_risk": by_risk,
                "open_high": open_high}

    @staticmethod
    def _to_dict(row: SecurityAlertRow) -> dict:
        return {"id": row.id, "created_at": row.created_at, "asset_id": row.asset_id,
                "agent_type": row.agent_type, "agent_label": row.agent_label,
                "session_id": row.session_id, "event_id": row.event_id,
                "policy_id": row.policy_id, "risk_level": row.risk_level,
                "decision": row.decision, "status": row.status, "title": row.title,
                "reason": row.reason,
                "detail": json.loads(row.detail_json or "{}"),
                "resolved_at": row.resolved_at}