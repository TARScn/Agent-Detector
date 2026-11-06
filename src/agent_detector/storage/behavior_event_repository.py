import json
import uuid

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.orm import Session, aliased

from agent_detector.storage.models import BehaviorEventRow, EntityAliasRow


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
                    until: str | None = None, before_id: int | None = None,
                    after_id: int | None = None,
                    entity_id: str | None = None,
                    execution_status: str | None = None) -> list[dict]:
        """Newest first by default. ``before_id`` walks back; ``after_id``
        walks forward (oldest first) and is the reliable SSE catch-up path."""
        actor_alias = aliased(EntityAliasRow)
        target_alias = aliased(EntityAliasRow)
        statement = (select(BehaviorEventRow, actor_alias.entity_id,
                            actor_alias.status, target_alias.entity_id,
                            target_alias.status)
                     .outerjoin(actor_alias,
                                BehaviorEventRow.asset_id == actor_alias.old_id)
                     .outerjoin(target_alias,
                                BehaviorEventRow.target_asset_id == target_alias.old_id))
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
        if until:
            statement = statement.where(BehaviorEventRow.observed_at <= until)
        if before_id:
            statement = statement.where(BehaviorEventRow.id < int(before_id))
        if after_id:
            statement = statement.where(BehaviorEventRow.id > int(after_id))
        if entity_id:
            statement = statement.where(or_(
                BehaviorEventRow.actor_entity_id == entity_id,
                and_(actor_alias.entity_id == entity_id,
                     actor_alias.status == "OK")))
        if execution_status:
            statement = statement.where(
                BehaviorEventRow.execution_status == execution_status)
        statement = statement.order_by(
            BehaviorEventRow.id.asc() if after_id else BehaviorEventRow.id.desc()
        ).limit(min(max(int(limit), 1), 500))
        return [self._to_dict(row, actor_entity, actor_status,
                              target_entity, target_status)
                for row, actor_entity, actor_status, target_entity, target_status
                in self._session.execute(statement)]

    def get_event(self, event_id: int) -> dict | None:
        actor_alias = aliased(EntityAliasRow)
        target_alias = aliased(EntityAliasRow)
        statement = (select(BehaviorEventRow, actor_alias.entity_id,
                            actor_alias.status, target_alias.entity_id,
                            target_alias.status)
                     .outerjoin(actor_alias,
                                BehaviorEventRow.asset_id == actor_alias.old_id)
                     .outerjoin(target_alias,
                                BehaviorEventRow.target_asset_id == target_alias.old_id)
                     .where(BehaviorEventRow.id == int(event_id)))
        row = self._session.execute(statement).first()
        if row is None:
            return None
        return self._to_dict(*row)

    def record_tool_call(self, *, observed_at: str, agent_label: str, tool: str,
                         operation: str, target: str | None = None,
                         asset_id: str | None = None,
                         entity_id: str | None = None,
                         session_id: str | None = None,
                         instance_id: str | None = None,
                         decision: str | None = None,
                         execution_status: str | None = None,
                         risk_level: str | None = None,
                         policy_id: str | None = None,
                         confidence: str = "high",
                         event_type: str = "tool_call",
                         protocol: str = "HOOK",
                         mcp_server: str | None = None,
                         pid: int | None = None,
                         evidence: list[str] | None = None) -> int:
        """Append one Agent tool-call event (source="native_hook").

        Hook events are the highest-confidence feed: the Agent itself told us
        what it was about to do, so ``confidence`` defaults to *high*.
        """
        source_event_uid = f"hook-{uuid.uuid4().hex}"
        row = BehaviorEventRow(
            observed_at=observed_at, source="native_hook", agent_label=agent_label,
            asset_id=asset_id or entity_id,
            actor_asset_id=asset_id or entity_id,
            actor_entity_id=entity_id,
            actor_instance_id=instance_id,
            attribution_method="verified_session",
            attribution_state="verified",
            source_event_uid=source_event_uid,
            flow_id=f"hook-{session_id or 'nosession'}",
            upstream_host="", protocol=protocol, event_type=event_type,
            mcp_server=mcp_server,
            operation=operation, confidence=confidence,
            endpoint="", tool=tool, target=target, pid=pid,
            session_id=session_id, instance_id=instance_id,
            decision=decision, execution_status=execution_status,
            risk_level=risk_level, policy_id=policy_id,
            evidence_json=json.dumps(evidence or [], ensure_ascii=False))
        self._session.add(row)
        self._session.flush()
        return row.id

    def stats(self, source: str | None = None, since: str | None = None) -> dict:
        def filtered(statement):
            if source:
                statement = statement.where(BehaviorEventRow.source == source)
            if since:
                statement = statement.where(BehaviorEventRow.observed_at >= since)
            return statement

        count = self._session.scalar(
            select(func.count()).select_from(
                filtered(select(BehaviorEventRow)).subquery())) or 0
        by_protocol = {protocol: n for protocol, n in self._session.execute(filtered(
            select(BehaviorEventRow.protocol, func.count()).group_by(BehaviorEventRow.protocol)))}
        by_agent = {label: n for label, n in self._session.execute(filtered(
            select(BehaviorEventRow.agent_label, func.count()).group_by(BehaviorEventRow.agent_label)))}
        by_operation = {operation: n for operation, n in self._session.execute(filtered(
            select(BehaviorEventRow.operation, func.count()).group_by(BehaviorEventRow.operation)))}
        by_source = {name: n for name, n in self._session.execute(filtered(
            select(BehaviorEventRow.source, func.count()).group_by(BehaviorEventRow.source)))}
        by_risk = {risk or "unrated": n for risk, n in self._session.execute(filtered(
            select(BehaviorEventRow.risk_level, func.count()).group_by(
                BehaviorEventRow.risk_level)))}
        by_decision = {decision or "none": n for decision, n in self._session.execute(
            filtered(select(BehaviorEventRow.decision, func.count()).group_by(
                BehaviorEventRow.decision)))}
        by_execution = {
            status or "unknown": n for status, n in self._session.execute(
                filtered(select(BehaviorEventRow.execution_status, func.count())
                         .group_by(BehaviorEventRow.execution_status)))}
        return {"event_count": count, "by_protocol": by_protocol, "by_agent": by_agent,
                "by_operation": by_operation, "by_source": by_source,
                "by_risk": by_risk, "by_decision": by_decision,
                "by_execution_status": by_execution}

    def timeseries_counts(self, *, since: str, until: str,
                          bucket: str = "hour", source: str | None = None,
                          risk_level: str | None = None,
                          entity_id: str | None = None) -> dict[str, dict]:
        """Counts keyed by UTC bucket start (substring of observed_at)."""
        length = 13 if bucket == "hour" else 10
        bucket_expr = func.substr(BehaviorEventRow.observed_at, 1, length)
        actor_alias = aliased(EntityAliasRow)
        statement = (select(
            bucket_expr,
            func.count(),
            func.sum(case((BehaviorEventRow.decision == "deny", 1), else_=0)),
        ).select_from(BehaviorEventRow)
            .outerjoin(actor_alias,
                       BehaviorEventRow.asset_id == actor_alias.old_id)
            .where(BehaviorEventRow.observed_at >= since,
                   BehaviorEventRow.observed_at < until))
        if source:
            statement = statement.where(BehaviorEventRow.source == source)
        if risk_level:
            statement = statement.where(BehaviorEventRow.risk_level == risk_level)
        if entity_id:
            statement = statement.where(or_(
                BehaviorEventRow.actor_entity_id == entity_id,
                and_(actor_alias.entity_id == entity_id,
                     actor_alias.status == "OK")))
        statement = statement.group_by(bucket_expr)
        return {bucket: {"events": int(events), "blocked": int(blocked or 0)}
                for bucket, events, blocked in self._session.execute(statement)}

    def count_after(self, after_id: int, source: str | None = None) -> int:
        statement = select(func.count()).select_from(BehaviorEventRow).where(
            BehaviorEventRow.id > int(after_id))
        if source:
            statement = statement.where(BehaviorEventRow.source == source)
        return int(self._session.scalar(statement) or 0)

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
    def _to_dict(row: BehaviorEventRow, actor_entity_id: str | None = None,
                 actor_alias_status: str | None = None,
                 target_entity_id: str | None = None,
                 target_alias_status: str | None = None) -> dict:
        actor_entity = actor_entity_id or row.actor_entity_id
        target_entity = target_entity_id or row.target_entity_id
        return {"id": row.id, "observed_at": row.observed_at, "source": row.source,
                "entity_id": actor_entity,
                "entity_alias_status": "OK" if actor_entity else "MISSING",
                "target_entity_id": target_entity,
                "target_alias_status": "OK" if target_entity else "MISSING",
                "agent_label": row.agent_label,
                "scope_key": row.scope_key,
                "actor_instance_id": row.actor_instance_id,
                "actor_process_key": row.actor_process_key,
                "target_endpoint_id": row.target_endpoint_id,
                "target_instance_id": row.target_instance_id,
                "attribution_method": row.attribution_method,
                "attribution_state": row.attribution_state,
                "source_event_uid": row.source_event_uid,
                "mcp_server": row.mcp_server,
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
                "actor": {
                    "entity_id": actor_entity,
                    "instance_id": row.actor_instance_id or row.instance_id,
                    "label": row.agent_label or "未归属",
                    "alias_status": "OK" if actor_entity else "MISSING",
                    "attribution_state": row.attribution_state or "unattributed",
                },
                "target_ref": {
                    "entity_id": target_entity,
                    "endpoint_id": row.target_endpoint_id,
                    "instance_id": row.target_instance_id,
                    "label": None,
                    "alias_status": "OK" if target_entity else "MISSING",
                },
                "evidence": json.loads(row.evidence_json or "[]")}