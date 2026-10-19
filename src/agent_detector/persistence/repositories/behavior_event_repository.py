import json

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agent_detector.persistence.models import BehaviorEventRow


class BehaviorEventRepository:
    """Read side of behavior_events; writers (currently the netmon monitor)
    insert rows directly, so this repository deliberately has no write API."""

    def __init__(self, session: Session):
        self._session = session

    def list_events(self, limit: int = 100, protocol: str | None = None,
                    source: str | None = None) -> list[dict]:
        statement = select(BehaviorEventRow)
        if protocol:
            statement = statement.where(BehaviorEventRow.protocol == protocol)
        if source:
            statement = statement.where(BehaviorEventRow.source == source)
        statement = statement.order_by(BehaviorEventRow.id.desc()).limit(
            min(max(int(limit), 1), 500))
        return [self._to_dict(row) for row in self._session.scalars(statement)]

    def stats(self, source: str | None = None) -> dict:
        def filtered(statement):
            return statement.where(BehaviorEventRow.source == source) if source else statement

        count = self._session.scalar(
            select(func.count()).select_from(
                filtered(select(BehaviorEventRow)).subquery())) or 0
        by_protocol = {protocol: n for protocol, n in self._session.execute(filtered(
            select(BehaviorEventRow.protocol, func.count()).group_by(BehaviorEventRow.protocol)))}
        by_agent = {label: n for label, n in self._session.execute(filtered(
            select(BehaviorEventRow.agent_label, func.count()).group_by(BehaviorEventRow.agent_label)))}
        return {"event_count": count, "by_protocol": by_protocol, "by_agent": by_agent}

    @staticmethod
    def _to_dict(row: BehaviorEventRow) -> dict:
        return {"id": row.id, "observed_at": row.observed_at, "source": row.source,
                "agent_label": row.agent_label, "asset_id": row.asset_id,
                "flow_id": row.flow_id, "upstream_host": row.upstream_host,
                "protocol": row.protocol, "event_type": row.event_type,
                "operation": row.operation, "confidence": row.confidence,
                "endpoint": row.endpoint, "protocol_version": row.protocol_version,
                "component_version": row.component_version, "model": row.model,
                "tool": row.tool, "http_status": row.http_status,
                "evidence": json.loads(row.evidence_json or "[]")}
