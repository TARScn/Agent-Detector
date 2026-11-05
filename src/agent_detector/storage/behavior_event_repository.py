import json

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agent_detector.storage.models import BehaviorEventRow


class BehaviorEventRepository:
    """Read side of behavior_events; the stream collectors (netmon monitor,
    auditd/poll/sysmon ingest) insert rows directly, so the only write API here
    is :meth:`record_tool_call`, used by the hook decision endpoint.
    """

    def __init__(self, session: Session):
        self._session = session

    def list_events(self, limit: int = 100, protocol: str | None = None,
                    source: str | None = None, agent_label: str | None = None,
                    asset_id: str | None = None, event_type: str | None = None,
                    session_id: str | None = None, risk_level: str | None = None,
                    decision: str | None = None, since: str | None = None,
                    before_id: int | None = None) -> list[dict]:
        """Newest first. ``before_id`` walks further back in history: the feed
        asks for one page at a time instead of loading the whole table."""
        statement = select(BehaviorEventRow)
        if protocol:
            statement = statement.where(BehaviorEventRow.protocol == protocol)
        if source:
            statement = statement.where(BehaviorEventRow.source == source)
        if agent_label:
            statement = statement.where(BehaviorEventRow.agent_label == agent_label)
        if asset_id:
            statement = statement.where(BehaviorEventRow.asset_id == asset_id)
        if event_type:
            statement = statement.where(BehaviorEventRow.event_type == event_type)
        if session_id:
            statement = statement.where(BehaviorEventRow.session_id == session_id)
        if risk_level:
            statement = statement.where(BehaviorEventRow.risk_level == risk_level)
        if decision:
            statement = statement.where(BehaviorEventRow.decision == decision)
        if since:
            statement = statement.where(BehaviorEventRow.observed_at >= since)
        if before_id:
            statement = statement.where(BehaviorEventRow.id < int(before_id))
        statement = statement.order_by(BehaviorEventRow.id.desc()).limit(
            min(max(int(limit), 1), 500))
        return [self._to_dict(row) for row in self._session.scalars(statement)]

    def record_tool_call(self, *, observed_at: str, agent_label: str, tool: str,
                         operation: str, target: str | None = None,
                         asset_id: str | None = None,
                         session_id: str | None = None,
                         instance_id: str | None = None,
                         decision: str | None = None,
                         execution_status: str | None = None,
                         risk_level: str | None = None,
                         policy_id: str | None = None,
                         confidence: str = "high",
                         event_type: str = "tool_call",
                         pid: int | None = None,
                         evidence: list[str] | None = None) -> int:
        """Append one Agent tool-call event (source="native_hook").

        Hook events are the highest-confidence feed: the Agent itself told us
        what it was about to do, so ``confidence`` defaults to *high*.
        """
        row = BehaviorEventRow(
            observed_at=observed_at, source="native_hook", agent_label=agent_label,
            asset_id=asset_id, flow_id=f"hook-{session_id or 'nosession'}",
            upstream_host="", protocol="HOOK", event_type=event_type,
            operation=operation, confidence=confidence,
            endpoint="", tool=tool, target=target, pid=pid,
            session_id=session_id, instance_id=instance_id,
            decision=decision, execution_status=execution_status,
            risk_level=risk_level, policy_id=policy_id,
            evidence_json=json.dumps(evidence or [], ensure_ascii=False))
        self._session.add(row)
        self._session.flush()
        return row.id

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
        by_operation = {operation: n for operation, n in self._session.execute(filtered(
            select(BehaviorEventRow.operation, func.count()).group_by(BehaviorEventRow.operation)))}
        by_source = {name: n for name, n in self._session.execute(
            select(BehaviorEventRow.source, func.count()).group_by(BehaviorEventRow.source))}
        by_risk = {risk or "unrated": n for risk, n in self._session.execute(filtered(
            select(BehaviorEventRow.risk_level, func.count()).group_by(
                BehaviorEventRow.risk_level)))}
        return {"event_count": count, "by_protocol": by_protocol, "by_agent": by_agent,
                "by_operation": by_operation, "by_source": by_source, "by_risk": by_risk}

    def summary(self, since: str) -> dict:
        """Counters for the dashboard: events since ``since`` plus blocked calls."""
        total = self._session.scalar(
            select(func.count()).select_from(BehaviorEventRow).where(
                BehaviorEventRow.observed_at >= since)) or 0
        blocked = self._session.scalar(
            select(func.count()).select_from(BehaviorEventRow).where(
                BehaviorEventRow.observed_at >= since,
                BehaviorEventRow.decision == "deny")) or 0
        by_source = {name: n for name, n in self._session.execute(
            select(BehaviorEventRow.source, func.count()).where(
                BehaviorEventRow.observed_at >= since).group_by(BehaviorEventRow.source))}
        agents = self._session.scalar(
            select(func.count(func.distinct(BehaviorEventRow.agent_label))).where(
                BehaviorEventRow.observed_at >= since)) or 0
        last_event_at = self._session.scalar(select(func.max(BehaviorEventRow.observed_at)))
        return {"events_since": total, "blocked_since": blocked,
                "by_source": by_source, "agents_since": agents,
                "last_event_at": last_event_at}

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
                "pid": row.pid, "ppid": row.ppid, "process_name": row.process_name,
                "target": row.target, "result": row.result,
                "session_id": row.session_id, "instance_id": row.instance_id,
                "process_guid": row.process_guid, "risk_level": row.risk_level,
                "decision": row.decision, "execution_status": row.execution_status,
                "policy_id": row.policy_id, "container_id": row.container_id,
                "evidence": json.loads(row.evidence_json or "[]")}