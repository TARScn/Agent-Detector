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
                                           ComponentRelationRow, EntityAttributeRow,
                                           EntityLocationRow, EntityRow,
                                           EntitySnapshotRow)


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


class EntityRepository:
    def __init__(self, session: Session):
        self._session = session

    def _latest_snapshots(self) -> tuple[dict[str, EntitySnapshotRow], int | None]:
        """Newest snapshot per entity, plus the generation they are judged by.

        A snapshot from an older generation describes a past run. The console
        must not present it as the current status: the caller downgrades it,
        otherwise an entity that a failing scope stopped covering (docker
        engine down) keeps showing its last RUNNING forever.
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
             instance_count: int = 0,
             session_count: int = 0, component_count: int = 0,
             include_location: bool = False) -> dict:
        current = (snapshot is not None
                   and (latest_generation is None
                        or snapshot.generation_id == latest_generation))
        if snapshot is not None and current:
            agent_status = snapshot.agent_status
            status_basis = _normalize_status_basis(
                _json(snapshot.status_basis_json, {}))
        elif snapshot is not None:
            agent_status = "UNKNOWN"
            status_basis = {
                "basis_version": 2, "installed": None, "configured": None,
                "running": None, "claim_ids": {}, "conflicts": [],
                "stale": True,
                "last_generation_id": snapshot.generation_id,
            }
        else:
            agent_status = None
            status_basis = {}
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
            "status_basis": status_basis,
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
        instances, sessions, components = self._counts()
        result: list[dict] = []
        for attr in attrs:
            snapshot = snapshots.get(attr.entity_id)
            verdict = snapshot.removal_verdict if snapshot else "NONE"
            if not include_hidden:
                if verdict == "CONFIRMED":
                    continue
                if verdict == "CANDIDATE" and not attr.container_id:
                    continue
            result.append(self._row(
                attr, entities.get(attr.entity_id), snapshot,
                latest_generation=latest_generation,
                instance_count=instances.get(attr.entity_id, 0),
                session_count=sessions.get(attr.entity_id, 0),
                component_count=components.get(attr.entity_id, 0)))
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
                         latest_generation=latest_generation)

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