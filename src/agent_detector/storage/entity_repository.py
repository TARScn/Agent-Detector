"""Canonical entity read model for the console (V1.2 cutover).

The asset list is now one row per canonical entity. Framework/application
legacy rows have already been merged into ``entity_attributes`` by the v12
migration; this module only reads the canonical tables.
"""
from __future__ import annotations

import json
from collections import defaultdict

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agent_detector.storage.models import (AgentInstanceRow, AgentSessionRow,
                                           ComponentRelationRow, CoverageScopeRow,
                                           EntityAttributeRow, EntityLocationRow,
                                           EntityRow, EntitySnapshotRow)


def _normalize_status_basis(value: dict) -> dict:
    """Legacy databases stored ``false`` for "no evidence"; keep it tri-state."""
    if not value:
        return {}
    result = dict(value)
    for key in ("installed", "configured", "running"):
        if result.get(key) is False and not result.get("basis_version"):
            result[key] = None
    return result


def _json(value: str | None, default):
    try:
        return json.loads(value or "")
    except (TypeError, ValueError):
        return default


def _durable_from_snapshot(snapshot: EntitySnapshotRow) -> str:
    """Recover the durable part of a snapshot written before V1.3.

    RUNNING is never durable: it describes one observation window. Keep the
    strongest static status the basis proves.
    """
    basis = _json(snapshot.status_basis_json, {})
    if not isinstance(basis, dict):
        basis = {}
    if basis.get("configured") is True or snapshot.agent_status == "CONFIGURED":
        return "CONFIGURED"
    if basis.get("installed") is True or snapshot.agent_status == "INSTALLED":
        return "INSTALLED"
    return "UNKNOWN"


class EntityRepository:
    def __init__(self, session: Session):
        self._session = session

    def _latest_snapshots(self) -> tuple[dict[str, EntitySnapshotRow], int | None]:
        """Newest snapshot per entity, plus the newest generation seen.

        Freshness itself is judged per owning scope (see ``_is_current``):
        a global counter would mark every entity stale whenever one unrelated
        scope ran, and would hide the fact that an entity's own scope never
        re-ran at all.
        """
        latest: dict[str, EntitySnapshotRow] = {}
        generation: int | None = None
        for row in self._session.scalars(
                select(EntitySnapshotRow).order_by(
                    EntitySnapshotRow.generation_id,
                    EntitySnapshotRow.id)):
            latest[row.entity_id] = row
            if generation is None or row.generation_id > generation:
                generation = row.generation_id
        return latest, generation

    def _latest_scope_runs(self) -> dict[tuple[str, str], int]:
        """Last run that evaluated each coverage scope, one grouped query."""
        rows = self._session.execute(
            select(CoverageScopeRow.scope_type, CoverageScopeRow.scope_key,
                   func.max(CoverageScopeRow.run_id)).group_by(
                       CoverageScopeRow.scope_type, CoverageScopeRow.scope_key))
        return {(scope_type, scope_key): int(run_id)
                for scope_type, scope_key, run_id in rows}

    @staticmethod
    def _is_current(snapshot: EntitySnapshotRow | None,
                    latest_generation: int | None,
                    scope_runs: dict[tuple[str, str], int]) -> bool:
        if snapshot is None:
            return False
        owner = (snapshot.owner_scope_type, snapshot.owner_scope_key)
        if owner[0] and owner[1]:
            latest_run = scope_runs.get(owner)
            if latest_run is not None:
                return snapshot.generation_id >= latest_run
        return (latest_generation is None
                or snapshot.generation_id == latest_generation)

    def _counts(self) -> tuple[dict[str, int], dict[str, int],
                               dict[str, int]]:
        instances: dict[str, int] = defaultdict(int)
        for entity_id, count in self._session.execute(
                select(AgentInstanceRow.entity_id, func.count()).where(
                    AgentInstanceRow.entity_id.is_not(None),
                    AgentInstanceRow.status == "running").group_by(
                        AgentInstanceRow.entity_id)):
            instances[entity_id] = int(count)
        sessions: dict[str, int] = defaultdict(int)
        for entity_id, count in self._session.execute(
                select(AgentSessionRow.entity_id, func.count()).where(
                    AgentSessionRow.entity_id.is_not(None)).group_by(
                        AgentSessionRow.entity_id)):
            sessions[entity_id] = int(count)
        components: dict[str, int] = defaultdict(int)
        for entity_id, count in self._session.execute(
                select(ComponentRelationRow.entity_id, func.count()).where(
                    ComponentRelationRow.valid_to.is_(None)).group_by(
                        ComponentRelationRow.entity_id)):
            components[entity_id] = int(count)
        return instances, sessions, components

    def _row(self, attr: EntityAttributeRow, entity: EntityRow | None,
             snapshot: EntitySnapshotRow | None, *, latest_generation: int | None,
             scope_runs: dict[tuple[str, str], int] | None = None,
             instance_count: int = 0,
             session_count: int = 0, component_count: int = 0,
             include_location: bool = False) -> dict:
        scope_runs = scope_runs or {}
        current = self._is_current(snapshot, latest_generation, scope_runs)
        presence = snapshot.presence if snapshot is not None else "UNKNOWN"
        verification = snapshot.verification if snapshot is not None else "STALE"
        lifecycle = snapshot.lifecycle if snapshot is not None else "ACTIVE"
        if snapshot is not None and lifecycle == "ACTIVE":
            # Pre-v3 rows have no lifecycle column: the old removal verdict
            # still carries the same meaning, so honour it.
            if snapshot.removal_verdict == "CONFIRMED":
                lifecycle = "ARCHIVED"
            elif snapshot.removal_verdict == "CANDIDATE":
                lifecycle = "WATCH"
        reason_code = (snapshot.reason_code if snapshot is not None else "") or ""
        last_known = "UNKNOWN"
        if snapshot is not None:
            last_known = snapshot.last_known_status or "UNKNOWN"
            if last_known == "UNKNOWN":
                # Pre-v3 rows have no durable column; recover it from the basis.
                last_known = _durable_from_snapshot(snapshot)
        if snapshot is not None and current:
            agent_status = snapshot.agent_status
            status_basis = _normalize_status_basis(
                _json(snapshot.status_basis_json, {}))
        elif snapshot is not None:
            # Keep the last durable status but mark it as not re-verified.
            # RUNNING is never durable: it describes one observation window.
            agent_status = (last_known if last_known in ("CONFIGURED",
                                                         "INSTALLED")
                            else "UNKNOWN")
            verification = "STALE"
            status_basis = {
                "basis_version": 3, "installed": None, "configured": None,
                "running": None, "claim_ids": {}, "conflicts": [],
                "stale": True,
                "last_generation_id": snapshot.generation_id,
                "last_known_status": last_known,
                "verification": "STALE",
                "presence": presence,
                "lifecycle": lifecycle,
                "reason_code": "stale_snapshot",
                "reason": "该资产在最近一次扫描中没有被覆盖",
                "verified": False,
            }
        else:
            agent_status = None
            status_basis = {}
        if (agent_status == "RUNNING"
                and verification not in ("VERIFIED", "PARTIAL")):
            # RUNNING never survives a run that did not verify it (old rows
            # without verification metadata land here as STALE).
            agent_status = (last_known if last_known in ("CONFIGURED",
                                                         "INSTALLED")
                            else "UNKNOWN")
        row = {
            "entity_id": attr.entity_id,
            "entity_kind": entity.entity_kind if entity else "UNKNOWN",
            "entity_alias_status": "OK",
            "agent_type": attr.agent_type,
            "name": attr.name,
            "vendor": attr.vendor,
            "version": attr.version or "UNKNOWN",
            "version_source": attr.version_source or "unknown",
            "origin": attr.origin or "host",
            "status": attr.status or "inactive",
            "first_seen_at": attr.first_seen_at,
            "last_seen_at": attr.last_seen_at,
            "agent_status": agent_status,
            "presence": presence,
            "verification": verification,
            "lifecycle": lifecycle,
            "reason_code": reason_code,
            "reason": status_basis.get("reason") or "",
            "last_known_status": last_known,
            "status_basis": status_basis,
            "verified_scopes": (_json(snapshot.verified_scopes_json, [])
                                if snapshot is not None else []),
            "owner_scope": ({"scope_type": snapshot.owner_scope_type,
                             "scope_key": snapshot.owner_scope_key}
                            if snapshot is not None
                            and snapshot.owner_scope_type else None),
            "snapshot_generation_id": (snapshot.generation_id
                                       if snapshot else None),
            "snapshot_current": current,
            "snapshot_projected_at": (snapshot.projected_at if snapshot
                                      else None),
            "capability_tags": (_json(snapshot.capability_tags_json, [])
                                if snapshot else []),
            "snapshot_hook_state": (snapshot.hook_state if snapshot
                                    else "UNKNOWN"),
            "coverage_summary": (_json(snapshot.coverage_summary_json, {})
                                 if snapshot else {}),
            "removal_verdict": (snapshot.removal_verdict if snapshot
                                else "NONE"),
            "instance_count": instance_count,
            "session_count": session_count,
            "component_count": component_count,
            "executable": attr.executable,
            "config_paths": _json(attr.config_paths_json, []),
            "mcp_servers": _json(attr.mcp_servers_json, []),
            "llm_endpoints": _json(attr.llm_endpoints_json, []),
            "notes": _json(attr.notes_json, []),
            "capabilities": _json(attr.capabilities_json, {}),
        }
        if include_location:
            location = self._session.get(EntityLocationRow, attr.entity_id)
            row["location"] = None if location is None else {
                "root_path": location.root_path,
                "environment_path": location.environment_path,
                "runtime": location.runtime,
                "entrypoint": location.entrypoint,
                "entry_kind": location.entry_kind,
                "status": location.status,
                "first_seen_at": location.first_seen_at,
                "last_seen_at": location.last_seen_at,
            }
        return row

    def list_agents(self, *, include_hidden: bool = False) -> list[dict]:
        attrs = list(self._session.scalars(
            select(EntityAttributeRow).where(
                EntityAttributeRow.inventory_kind == "agent").order_by(
                    EntityAttributeRow.name)))
        entities = {row.entity_id: row for row in self._session.scalars(
            select(EntityRow))}
        snapshots, latest_generation = self._latest_snapshots()
        scope_runs = self._latest_scope_runs()
        instances, sessions, components = self._counts()
        result: list[dict] = []
        for attr in attrs:
            row = self._row(
                attr, entities.get(attr.entity_id),
                snapshots.get(attr.entity_id),
                latest_generation=latest_generation, scope_runs=scope_runs,
                instance_count=instances.get(attr.entity_id, 0),
                session_count=sessions.get(attr.entity_id, 0),
                component_count=components.get(attr.entity_id, 0))
            # Confirmed-absent rows are archived: hidden by default, kept in
            # the database and still reachable with include_removed=true.
            # WATCH (unconfirmed absence) stays visible.
            if not include_hidden and row["lifecycle"] == "ARCHIVED":
                continue
            result.append(row)
        return result

    def get_agent(self, entity_id: str) -> dict | None:
        attr = self._session.get(EntityAttributeRow, entity_id)
        if attr is None:
            return None
        entity = self._session.get(EntityRow, entity_id)
        snapshots, latest_generation = self._latest_snapshots()
        instances, sessions, components = self._counts()
        return self._row(
            attr, entity, snapshots.get(entity_id),
            latest_generation=latest_generation,
            scope_runs=self._latest_scope_runs(),
            instance_count=instances.get(entity_id, 0),
            session_count=sessions.get(entity_id, 0),
            component_count=components.get(entity_id, 0),
            include_location=True)

    def find_by_agent_type(self, agent_type: str) -> dict | None:
        attr = self._session.scalars(
            select(EntityAttributeRow).where(
                EntityAttributeRow.agent_type == agent_type,
                EntityAttributeRow.inventory_kind == "agent").order_by(
                EntityAttributeRow.last_seen_at.desc()).limit(1)).first()
        if attr is None:
            return None
        entity = self._session.get(EntityRow, attr.entity_id)
        snapshots, latest_generation = self._latest_snapshots()
        return self._row(attr, entity, snapshots.get(attr.entity_id),
                         latest_generation=latest_generation,
                         scope_runs=self._latest_scope_runs())

    def list_instances(self, entity_id: str,
                       include_stopped: bool = True) -> list[dict]:
        statement = select(AgentInstanceRow).where(
            AgentInstanceRow.entity_id == entity_id)
        if not include_stopped:
            statement = statement.where(AgentInstanceRow.status == "running")
        rows = self._session.scalars(statement.order_by(
            AgentInstanceRow.last_seen_at.desc())).all()
        return [{
            "instance_id": row.instance_id,
            "entity_id": row.entity_id,
            "agent_type": row.agent_type,
            "pid": row.pid,
            "ppid": row.ppid,
            "process_guid": row.process_guid,
            "process_name": row.process_name,
            "executable": row.executable,
            "cmdline": row.cmdline,
            "cwd": row.cwd,
            "parent_chain": _json(row.parent_chain_json, []),
            "origin": row.origin,
            "container_id": row.container_id,
            "status": row.status,
            "evidence": _json(row.evidence_json, []),
            "started_at": row.started_at,
            "last_seen_at": row.last_seen_at,
        } for row in rows]

    def list_sessions(self, entity_id: str, *, limit: int = 200) -> list[dict]:
        rows = self._session.scalars(
            select(AgentSessionRow).where(
                AgentSessionRow.entity_id == entity_id).order_by(
                    AgentSessionRow.last_event_at.desc()).limit(limit)).all()
        return [{
            "session_id": row.session_id,
            "entity_id": row.entity_id,
            "agent_type": row.agent_type,
            "instance_id": row.instance_id,
            "source": row.source,
            "cwd": row.cwd,
            "last_tool": row.last_tool,
            "event_count": row.event_count,
            "started_at": row.started_at,
            "last_event_at": row.last_event_at,
            "ended_at": row.ended_at,
        } for row in rows]

    def count_sessions(self, entity_id: str) -> int:
        return int(self._session.scalar(
            select(func.count()).select_from(AgentSessionRow).where(
                AgentSessionRow.entity_id == entity_id)) or 0)