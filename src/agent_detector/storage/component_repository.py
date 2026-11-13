"""Component identity and entity->component dependency edges (P1)."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_detector.identity.canonical import canonical_json, digest
from agent_detector.storage.models import (ComponentRelationRow, ComponentRow,
                                          RelationRow, utc_now_iso)


class ComponentRepository:
    def __init__(self, session: Session):
        self._session = session

    def upsert_component(self, name: str, *, kind: str = "FRAMEWORK",
                         version: str = "UNKNOWN",
                         version_source: str = "unknown") -> str:
        name = (name or "").strip() or "unknown"
        kind = kind or "FRAMEWORK"
        component_key = "cmp-" + digest(
            canonical_json({"name": name.lower(), "kind": kind}), length=20)
        row = self._session.get(ComponentRow, component_key)
        now = utc_now_iso()
        if row is None:
            self._session.add(ComponentRow(
                component_key=component_key, name=name, kind=kind,
                version=version, version_source=version_source,
                first_seen=now, last_seen=now))
            return component_key
        row.name = name
        row.version = version or row.version
        row.version_source = version_source or row.version_source
        row.last_seen = now
        return component_key

    def upsert_relation(self, entity_id: str, component_key: str, *,
                        relation_type: str = "DEPENDS_ON",
                        version: str = "UNKNOWN",
                        version_source: str = "unknown",
                        status: str = "confirmed",
                        evidence_claim_id: str | None = None) -> int:
        existing = self._session.scalars(
            select(ComponentRelationRow).where(
                ComponentRelationRow.entity_id == entity_id,
                ComponentRelationRow.component_key == component_key,
                ComponentRelationRow.relation_type == relation_type,
                ComponentRelationRow.valid_to.is_(None),
            )).first()
        if existing is not None:
            existing.version = version or existing.version
            existing.version_source = version_source or existing.version_source
            existing.status = status
            existing.evidence_claim_id = evidence_claim_id or existing.evidence_claim_id
            return existing.id
        row = ComponentRelationRow(
            entity_id=entity_id, component_key=component_key,
            relation_type=relation_type, version=version,
            version_source=version_source, status=status,
            evidence_claim_id=evidence_claim_id, valid_from=utc_now_iso())
        self._session.add(row)
        self._session.flush()
        return row.id

    def close_stale(self, entity_id: str, active_component_keys: set[str]) -> int:
        """Close open dependency edges whose component was not seen this scan.

        Callers must gate this on coverage completeness; an incomplete scan
        must not invalidate a dependency.
        """
        now = utc_now_iso()
        closed = 0
        rows = self._session.scalars(
            select(ComponentRelationRow).where(
                ComponentRelationRow.entity_id == entity_id,
                ComponentRelationRow.valid_to.is_(None)))
        for row in rows:
            if row.component_key in active_component_keys:
                continue
            row.valid_to = now
            row.status = "expired"
            closed += 1
        return closed

    def list_for_entity(self, entity_id: str) -> list[dict]:
        rows = self._session.execute(
            select(ComponentRelationRow, ComponentRow).join(
                ComponentRow,
                ComponentRow.component_key == ComponentRelationRow.component_key).where(
                    ComponentRelationRow.entity_id == entity_id,
                    ComponentRelationRow.valid_to.is_(None)).order_by(
                        ComponentRow.name))
        return [{"component_key": component.component_key,
                 "name": component.name, "kind": component.kind,
                 "version": relation.version,
                 "version_source": relation.version_source,
                 "relation_type": relation.relation_type,
                 "status": relation.status,
                 "evidence_claim_id": relation.evidence_claim_id}
                for relation, component in rows]

    def upsert_relation_edge(self, from_ref: str, to_ref: str,
                             relation_type: str, *,
                             status: str = "confirmed",
                             evidence_claim_id: str | None = None) -> int:
        existing = self._session.scalars(
            select(RelationRow).where(
                RelationRow.from_ref == from_ref,
                RelationRow.to_ref == to_ref,
                RelationRow.relation_type == relation_type,
                RelationRow.valid_to.is_(None),
            )).first()
        if existing is not None:
            existing.status = status
            existing.evidence_claim_id = evidence_claim_id or existing.evidence_claim_id
            return existing.id
        row = RelationRow(from_ref=from_ref, to_ref=to_ref,
                          relation_type=relation_type, status=status,
                          evidence_claim_id=evidence_claim_id,
                          valid_from=utc_now_iso())
        self._session.add(row)
        self._session.flush()
        return row.id