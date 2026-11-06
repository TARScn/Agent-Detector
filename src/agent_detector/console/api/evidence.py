"""Claims, coverage and relation read models keyed by canonical entity_id."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from agent_detector.console.api.deps import Services, get_services
from agent_detector.storage import (ClaimRepository, ComponentRepository,
                                    CoverageRepository, EntityRepository,
                                    ScanRepository)
from agent_detector.storage.models import (EndpointBindingRow, EndpointRow,
                                           EntityAttributeRow, RelationRow)

router = APIRouter(prefix="/api/v1", tags=["evidence"])

_COVERAGE_KEYS = ("COMPLETE", "PARTIAL", "FAILED", "NOT_RUN")


def _services() -> Services:
    return get_services()


def _entity(session: Session, entity_id: str) -> EntityAttributeRow:
    row = session.get(EntityAttributeRow, entity_id)
    if row is None:
        raise HTTPException(status_code=404, detail="未找到该 Agent 实体")
    return row


def _component_view(component: dict) -> dict:
    return {
        "component_key": component["component_key"],
        "name": component["name"],
        "kind": component["kind"],
        "version": component["version"],
        "version_source": component["version_source"],
        "relation_type": component["relation_type"],
        "status": component["status"],
        "evidence_claim_id": component.get("evidence_claim_id"),
    }


def _ref_label(session: Session, ref: str | None) -> str:
    if not ref:
        return ""
    attr = session.get(EntityAttributeRow, ref)
    return attr.name if attr else ref


@router.get("/agents/{entity_id}/claims")
def agent_claims(
        entity_id: str,
        current: bool = True,
        predicate: str | None = None,
        polarity: str | None = Query(default=None, pattern="^(support|refute)$"),
        include_observations: bool = False,
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        services: Services = Depends(_services)):
    with Session(services.engine) as session:
        _entity(session, entity_id)
        repository = ClaimRepository(session)
        items = repository.for_entity(
            entity_id, predicate=predicate, polarity=polarity, current=current,
            limit=limit, offset=offset)
        if include_observations:
            for item in items:
                item["observations"] = repository.observations_for(
                    item["claim_id"])
        summary = repository.summary(entity_id)
        return {
            "available": True,
            "entity_id": entity_id,
            "completeness": "support_only",
            "reason": None,
            "items": items,
            "claim_count": summary["claim_count"],
            "by_predicate": summary["by_predicate"],
            "conflicts": [],
            "notes": [],
        }


@router.get("/agents/{entity_id}/coverage")
def agent_coverage(entity_id: str, services: Services = Depends(_services)):
    with Session(services.engine) as session:
        _entity(session, entity_id)
        latest = ScanRepository(session).latest_id()
        if latest is None:
            return {"available": False, "reason": "NO_SCAN", "scan_id": None,
                    "generation_id": None, "scope": "scan", "entity_id": entity_id,
                    "summary": {key: 0 for key in _COVERAGE_KEYS} | {
                        "scopes": 0, "truncated": 0},
                    "scopes": [], "notes": []}
        graph = CoverageRepository(session).load_graph(latest)
        scopes = graph.scopes()
        if not scopes:
            return {"available": False, "reason": "NO_COVERAGE",
                    "scan_id": latest, "generation_id": latest,
                    "scope": "scan", "entity_id": entity_id,
                    "summary": {key: 0 for key in _COVERAGE_KEYS} | {
                        "scopes": 0, "truncated": 0},
                    "scopes": [], "notes": []}
        summary = {key: 0 for key in _COVERAGE_KEYS}
        summary.update({"scopes": len(scopes), "truncated": 0})
        items = []
        for scope in scopes:
            effective = graph.effective_status(*scope.key)
            key = effective.value if effective.value in summary else "NOT_RUN"
            summary[key] += 1
            summary["truncated"] += 1 if scope.truncated else 0
            predicates = [{"predicate": predicate,
                           "status": scope.predicate_status(predicate).value}
                          for predicate, _ in scope.predicates]
            items.append({
                "scope_type": scope.scope_type, "scope_key": scope.scope_key,
                "own_status": scope.own_status.value,
                "effective_status": effective.value,
                "truncated": scope.truncated,
                "predicates": predicates,
            })
        return {
            "available": True, "reason": None, "scan_id": latest,
            "generation_id": latest, "scope": "scan", "entity_id": entity_id,
            "summary": summary, "scopes": items, "notes": [],
        }


@router.get("/agents/{entity_id}/relations")
def agent_relations(
        entity_id: str,
        status: str | None = Query(default=None,
                                  pattern="^(confirmed|candidate|expired)$"),
        type: str | None = None,
        include_expired: bool = False,
        services: Services = Depends(_services)):
    return relations_for_entity(
        entity_id, services=services, status=status, type=type,
        include_expired=include_expired)


def relations_for_entity(
        entity_id: str, *,
        services: Services,
        status: str | None = None,
        type: str | None = None,
        include_expired: bool = False) -> dict:
    with Session(services.engine) as session:
        _entity(session, entity_id)
        components = ComponentRepository(session).list_for_entity(entity_id)
        instances = EntityRepository(session).list_instances(
            entity_id, include_stopped=True)
        endpoints = _endpoints(session, entity_id)
        items: list[dict] = []
        for component in components:
            if status and component.get("status") != status:
                continue
            if type and component.get("relation_type") != type:
                continue
            if component.get("status") == "expired" and not include_expired:
                continue
            items.append({
                "relation_type": component.get("relation_type") or "DEPENDS_ON",
                "status": component.get("status") or "confirmed",
                "from_ref": entity_id,
                "to_ref": component["component_key"],
                "label": component.get("name") or component["component_key"],
                "version": component.get("version"),
                "version_source": component.get("version_source"),
                "evidence_claim_id": component.get("evidence_claim_id"),
                "valid_from": None, "valid_to": None,
            })
        for edge in session.scalars(
                select(RelationRow).where(
                    or_(RelationRow.from_ref == entity_id,
                        RelationRow.to_ref == entity_id))).all():
            if edge.status == "expired" and not include_expired:
                continue
            if status and edge.status != status:
                continue
            if type and edge.relation_type != type:
                continue
            other = (edge.to_ref if edge.from_ref == entity_id
                     else edge.from_ref)
            items.append({
                "relation_type": edge.relation_type,
                "status": edge.status,
                "from_ref": edge.from_ref, "to_ref": edge.to_ref,
                "label": _ref_label(session, other), "version": None,
                "version_source": None,
                "evidence_claim_id": edge.evidence_claim_id,
                "valid_from": edge.valid_from, "valid_to": edge.valid_to,
            })
        return {
            "items": items,
            "groups": {"components": [_component_view(item) for item in components],
                       "instances": instances, "endpoints": endpoints},
            "notes": [],
        }


def _endpoints(session: Session, entity_id: str) -> list[dict]:
    rows = session.scalars(
        select(EndpointRow).where(EndpointRow.owner_entity_id == entity_id)).all()
    result = []
    for row in rows:
        binding = session.scalars(
            select(EndpointBindingRow).where(
                EndpointBindingRow.host_endpoint_id == row.endpoint_id,
                EndpointBindingRow.valid_to.is_(None))).first()
        result.append({
            "endpoint_id": row.endpoint_id,
            "protocol": row.protocol,
            "address": f"{row.address}:{row.port}",
            "binding_status": "confirmed" if binding else "candidate",
        })
    return result