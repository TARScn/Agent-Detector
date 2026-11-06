"""Runtime instances and sessions (canonical entity_id cutover).

The legacy asset table is gone; this repository only manages live process
instances and native Hook sessions.
"""
from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_detector.core.models import AgentInstance
from agent_detector.storage.models import (AgentInstanceRow, AgentSessionRow,
                                           utc_now_iso)


class AgentInventoryRepository:
    def __init__(self, session: Session):
        self._session = session

    def upsert_instances(self, instances: list[AgentInstance],
                         seen_asset_ids: set[str] | None = None) -> int:
        now = utc_now_iso()
        for instance in instances:
            row = self._session.get(AgentInstanceRow, instance.instance_id)
            if row is None:
                row = AgentInstanceRow(instance_id=instance.instance_id,
                                       asset_id=instance.asset_id,
                                       agent_type=instance.agent_type,
                                       pid=instance.pid)
                self._session.add(row)
            row.ppid = instance.ppid
            row.process_guid = instance.process_guid
            row.process_name = instance.process_name
            row.executable = instance.executable
            row.cmdline = instance.cmdline
            row.cwd = instance.cwd
            row.parent_chain_json = json.dumps(list(instance.parent_chain))
            row.origin = instance.origin
            row.container_id = instance.container_id
            row.status = instance.status
            row.evidence_json = json.dumps(list(instance.evidence),
                                          ensure_ascii=False)
            row.started_at = instance.started_at or row.started_at
            row.last_seen_at = now
        if seen_asset_ids:
            live = {instance.instance_id for instance in instances}
            statement = select(AgentInstanceRow).where(
                AgentInstanceRow.asset_id.in_(seen_asset_ids))
            for row in self._session.scalars(statement):
                if row.instance_id not in live:
                    row.status = "stopped"
        return len(instances)

    def list_instances(self, asset_id: str | None = None,
                       include_stopped: bool = False,
                       entity_id: str | None = None) -> list[dict]:
        statement = select(AgentInstanceRow)
        if asset_id:
            statement = statement.where(AgentInstanceRow.asset_id == asset_id)
        if entity_id:
            statement = statement.where(AgentInstanceRow.entity_id == entity_id)
        if not include_stopped:
            statement = statement.where(AgentInstanceRow.status == "running")
        statement = statement.order_by(AgentInstanceRow.last_seen_at.desc())
        return [self._instance_dict(row)
                for row in self._session.scalars(statement)]

    def find_instance_by_pid(self, pid: int) -> dict | None:
        row = self._session.scalar(select(AgentInstanceRow).where(
            AgentInstanceRow.pid == pid,
            AgentInstanceRow.status == "running").order_by(
                AgentInstanceRow.last_seen_at.desc()).limit(1))
        return self._instance_dict(row) if row else None

    def touch_session(self, session_id: str, agent_type: str, *,
                      asset_id: str | None = None,
                      entity_id: str | None = None,
                      instance_id: str | None = None,
                      cwd: str | None = None, tool: str | None = None,
                      source: str = "native_hook",
                      closed: bool = False) -> None:
        now = utc_now_iso()
        row = self._session.get(AgentSessionRow, session_id)
        if row is None:
            row = AgentSessionRow(session_id=session_id,
                                  agent_type=agent_type,
                                  source=source, started_at=now)
            self._session.add(row)
        if asset_id:
            row.asset_id = asset_id
        if entity_id:
            row.entity_id = entity_id
        if instance_id:
            row.instance_id = instance_id
        if cwd:
            row.cwd = cwd
        if tool:
            row.last_tool = tool
        row.event_count = (row.event_count or 0) + 1
        row.last_event_at = now
        if closed:
            row.ended_at = now

    def list_sessions(self, agent_type: str | None = None,
                      asset_id: str | None = None,
                      entity_id: str | None = None,
                      limit: int = 50) -> list[dict]:
        statement = select(AgentSessionRow)
        if agent_type:
            statement = statement.where(
                AgentSessionRow.agent_type == agent_type)
        if asset_id:
            statement = statement.where(AgentSessionRow.asset_id == asset_id)
        if entity_id:
            statement = statement.where(AgentSessionRow.entity_id == entity_id)
        statement = statement.order_by(
            AgentSessionRow.last_event_at.desc()).limit(
                min(max(int(limit), 1), 500))
        return [self._session_dict(row)
                for row in self._session.scalars(statement)]

    def count_sessions(self, asset_id: str | None = None,
                       entity_id: str | None = None) -> int:
        return len(self.list_sessions(asset_id=asset_id, entity_id=entity_id,
                                      limit=500))

    @staticmethod
    def _instance_dict(row: AgentInstanceRow) -> dict:
        return {"instance_id": row.instance_id, "asset_id": row.asset_id,
                "entity_id": row.entity_id,
                "agent_type": row.agent_type, "pid": row.pid, "ppid": row.ppid,
                "process_guid": row.process_guid,
                "process_name": row.process_name, "executable": row.executable,
                "cmdline": row.cmdline, "cwd": row.cwd,
                "parent_chain": json.loads(row.parent_chain_json or "[]"),
                "origin": row.origin or "host",
                "container_id": row.container_id,
                "status": row.status,
                "evidence": json.loads(row.evidence_json or "[]"),
                "started_at": row.started_at, "last_seen_at": row.last_seen_at}

    @staticmethod
    def _session_dict(row: AgentSessionRow) -> dict:
        return {"session_id": row.session_id, "asset_id": row.asset_id,
                "entity_id": row.entity_id,
                "agent_type": row.agent_type, "instance_id": row.instance_id,
                "source": row.source, "cwd": row.cwd,
                "last_tool": row.last_tool, "event_count": row.event_count,
                "started_at": row.started_at,
                "last_event_at": row.last_event_at, "ended_at": row.ended_at}