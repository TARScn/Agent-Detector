"""Repositories for the V0.2 Agent inventory (design section 3.4).

Three tables, three lifetimes: ``agent_assets`` is the logical product the user
sees, ``agent_instances`` are the processes it currently runs as, and
``agent_sessions`` are native sessions learned from hook events. Instances go
``stopped`` when a later scan no longer sees their PID — the asset stays.
"""
import json

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from agent_detector.core.enums import HookState, ProtectionStatus
from agent_detector.core.models import AgentInstance, AgentInventoryItem
from agent_detector.storage.models import (AgentAssetRow, AgentInstanceRow,
                                          AgentSessionRow, utc_now_iso)


class AgentInventoryRepository:
    def __init__(self, session: Session):
        self._session = session

    # -- assets ------------------------------------------------------------

    def upsert_asset(self, item: AgentInventoryItem) -> None:
        now = utc_now_iso()
        row = self._session.get(AgentAssetRow, item.asset_id)
        if row is None:
            row = AgentAssetRow(asset_id=item.asset_id, first_seen_at=now,
                                agent_type=item.agent_type, name=item.name)
            self._session.add(row)
        row.agent_type = item.agent_type
        row.name = item.name
        row.vendor = item.vendor
        row.version = item.version.value
        row.version_source = item.version.source.value
        row.states_json = json.dumps(sorted(state.value for state in item.states))
        row.confidence = item.confidence
        row.executable = item.executable
        row.config_paths_json = json.dumps(list(item.config_paths))
        row.mcp_servers_json = json.dumps(list(item.mcp_servers))
        row.llm_endpoints_json = json.dumps(
            [dict(e) for e in item.llm_endpoints], ensure_ascii=False)
        row.app_id = item.app_id
        row.origin = item.origin
        row.container_id = item.container_id
        row.capabilities_json = json.dumps(item.capabilities, ensure_ascii=False)
        row.protection_status = item.protection.value
        row.hook_state = item.hook_state.value
        row.notes_json = json.dumps(list(item.notes), ensure_ascii=False)
        row.status = "active"  # seen again this scan: any earlier removal is overturned
        row.last_seen_at = now

    def update_protection(self, asset_id: str, protection: ProtectionStatus,
                          hook_state: HookState, detail: dict | None = None) -> bool:
        row = self._session.get(AgentAssetRow, asset_id)
        if row is None:
            return False
        row.protection_status = protection.value
        row.hook_state = hook_state.value
        row.hook_detail_json = json.dumps(detail or {}, ensure_ascii=False)
        row.last_seen_at = utc_now_iso()
        return True

    def list_assets(self, *, include_removed: bool = False) -> list[dict]:
        statement = select(AgentAssetRow).order_by(AgentAssetRow.name)
        if not include_removed:
            statement = statement.where(AgentAssetRow.status != "removed")
        rows = self._session.scalars(statement)
        return [self._asset_dict(row) for row in rows]

    def set_status(self, asset_id: str, status: str) -> bool:
        """Post-scan verification verdict for an asset not seen in this scan.

        Both verdicts ("inactive", "removed") mean "no live process", so the
        RUNNING state claim must go with them — the row keeps its INSTALLED /
        CONFIGURED evidence, but a stale 运行中 badge on an inactive asset is
        exactly the ghost this verification exists to prevent (its instances
        are stopped separately). A later scan that re-sees the asset live
        restores RUNNING through the normal upsert.
        """
        row = self._session.get(AgentAssetRow, asset_id)
        if row is None:
            return False
        row.status = status
        if status != "active":
            states = json.loads(row.states_json or "[]")
            if "RUNNING" in states:
                states.remove("RUNNING")
                row.states_json = json.dumps(states)
        return True

    def delete_asset(self, asset_id: str) -> None:
        """Hard delete of a verified-gone self-built asset: logical view forgets
        it (asset + its instances); scan evidence history stays untouched in
        assets/evidence, so old scans remain auditable."""
        self._session.execute(delete(AgentInstanceRow).where(
            AgentInstanceRow.asset_id == asset_id))
        row = self._session.get(AgentAssetRow, asset_id)
        if row is not None:
            self._session.delete(row)

    def get_asset(self, asset_id: str) -> dict | None:
        row = self._session.get(AgentAssetRow, asset_id)
        return self._asset_dict(row) if row else None

    def find_asset_by_type(self, agent_type: str) -> dict | None:
        row = self._session.scalar(select(AgentAssetRow).where(
            AgentAssetRow.agent_type == agent_type).order_by(
                AgentAssetRow.last_seen_at.desc()).limit(1))
        return self._asset_dict(row) if row else None

    # -- instances ---------------------------------------------------------

    def upsert_instances(self, instances: list[AgentInstance],
                         seen_asset_ids: set[str] | None = None) -> int:
        """Record the processes a scan saw; retire the ones it no longer sees.

        ``seen_asset_ids`` limits retirement to the assets this scan covered, so
        a partial scan never marks another Agent's live instances as stopped.
        """
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
            row.evidence_json = json.dumps(list(instance.evidence), ensure_ascii=False)
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
                       include_stopped: bool = False) -> list[dict]:
        statement = select(AgentInstanceRow)
        if asset_id:
            statement = statement.where(AgentInstanceRow.asset_id == asset_id)
        if not include_stopped:
            statement = statement.where(AgentInstanceRow.status == "running")
        statement = statement.order_by(AgentInstanceRow.last_seen_at.desc())
        return [self._instance_dict(row) for row in self._session.scalars(statement)]

    def stop_instances_of_unrunnable_assets(self) -> int:
        """Retire running instance rows whose asset is removed or inactive.

        The dashboard counts 运行中 from these rows, so an asset whose
        re-verification concluded "no live process" must not keep rows that
        say otherwise. Retirement in ``upsert_instances`` only covers assets
        the scan re-saw — a removed/inactive asset by definition was not
        re-seen, so this sweep closes that gap and self-heals rows left
        running by earlier versions. Assets skipped because their detector
        crashed keep status active and their instances untouched.
        """
        stopped = 0
        for row in self._session.scalars(
                select(AgentInstanceRow).where(AgentInstanceRow.status == "running")):
            asset = self._session.get(AgentAssetRow, row.asset_id)
            if asset is None or asset.status in ("removed", "inactive"):
                row.status = "stopped"
                stopped += 1
        return stopped

    def find_instance_by_pid(self, pid: int) -> dict | None:
        row = self._session.scalar(select(AgentInstanceRow).where(
            AgentInstanceRow.pid == pid, AgentInstanceRow.status == "running"
        ).order_by(AgentInstanceRow.last_seen_at.desc()).limit(1))
        return self._instance_dict(row) if row else None

    # -- sessions ----------------------------------------------------------

    def touch_session(self, session_id: str, agent_type: str, *,
                      asset_id: str | None = None, instance_id: str | None = None,
                      cwd: str | None = None, tool: str | None = None,
                      source: str = "native_hook", closed: bool = False) -> None:
        """Create the session on first hook event, then refresh its counters."""
        now = utc_now_iso()
        row = self._session.get(AgentSessionRow, session_id)
        if row is None:
            row = AgentSessionRow(session_id=session_id, agent_type=agent_type,
                                  source=source, started_at=now)
            self._session.add(row)
        if asset_id:
            row.asset_id = asset_id
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
                      asset_id: str | None = None, limit: int = 50) -> list[dict]:
        statement = select(AgentSessionRow)
        if agent_type:
            statement = statement.where(AgentSessionRow.agent_type == agent_type)
        if asset_id:
            statement = statement.where(AgentSessionRow.asset_id == asset_id)
        statement = statement.order_by(AgentSessionRow.last_event_at.desc()).limit(
            min(max(int(limit), 1), 500))
        return [self._session_dict(row) for row in self._session.scalars(statement)]

    def count_sessions(self, asset_id: str) -> int:
        return len(self.list_sessions(asset_id=asset_id, limit=500))

    # -- serialization -----------------------------------------------------

    @staticmethod
    def _asset_dict(row: AgentAssetRow) -> dict:
        return {"asset_id": row.asset_id, "agent_type": row.agent_type,
                "name": row.name, "vendor": row.vendor, "version": row.version,
                "version_source": row.version_source,
                "states": json.loads(row.states_json or "[]"),
                "confidence": row.confidence, "executable": row.executable,
                "config_paths": json.loads(row.config_paths_json or "[]"),
                "mcp_servers": json.loads(row.mcp_servers_json or "[]"),
                "llm_endpoints": json.loads(row.llm_endpoints_json or "[]"),
                "app_id": row.app_id,
                "origin": row.origin or "host",
                "container_id": row.container_id,
                "status": row.status or "active",
                "capabilities": json.loads(row.capabilities_json or "{}"),
                "protection_status": row.protection_status,
                "hook_state": row.hook_state,
                "hook_detail": json.loads(row.hook_detail_json or "{}"),
                "notes": json.loads(row.notes_json or "[]"),
                "first_seen_at": row.first_seen_at, "last_seen_at": row.last_seen_at}

    @staticmethod
    def _instance_dict(row: AgentInstanceRow) -> dict:
        return {"instance_id": row.instance_id, "asset_id": row.asset_id,
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
                "agent_type": row.agent_type, "instance_id": row.instance_id,
                "source": row.source, "cwd": row.cwd, "last_tool": row.last_tool,
                "event_count": row.event_count, "started_at": row.started_at,
                "last_event_at": row.last_event_at, "ended_at": row.ended_at}