"""Agent inventory endpoints, canonical entity_id cutover.

Every route is keyed by ``entity_id``. Legacy ``asset_id``/``app_id`` fields
are no longer part of the public response.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from agent_detector.console.api.agent_view import attach_protection
from agent_detector.console.api.deps import Services, get_services
from agent_detector.console.api.evidence import (agent_coverage,
                                                 relations_for_entity)
from agent_detector.storage import (BehaviorEventRepository, ClaimRepository,
                                    ComponentRepository, EntityRepository,
                                    McpConfigRefRepository)
from agent_detector.storage.models import EntityAttributeRow

router = APIRouter(prefix="/api/v1", tags=["agents"])


def _services() -> Services:
    return get_services()


def _parse_json(value: str | None, default):
    import json
    try:
        return json.loads(value or "")
    except (TypeError, ValueError):
        return default


@router.get("/agents")
def list_agents(
        q: str | None = None, agent_type: str | None = None,
        agent_status: str | None = Query(default=None, pattern="^(RUNNING|CONFIGURED|INSTALLED|UNKNOWN)$"),
        protection: str | None = Query(default=None, pattern="^(PROTECTED|MONITOR_ONLY|UNPROTECTED|UNKNOWN)$"),
        alias_status: str | None = Query(default=None, pattern="^(OK|AMBIGUOUS|CONFLICT|MISSING)$"),
        origin: str | None = Query(default=None, pattern="^(host|docker)$"),
        lifecycle: str | None = Query(default=None, pattern="^(ACTIVE|WATCH|ARCHIVED)$"),
        verification: str | None = Query(default=None, pattern="^(VERIFIED|PARTIAL|FAILED|NOT_CHECKED|STALE)$"),
        needs_verification: bool = False,
        include_stopped: bool = False, include_removed: bool = False,
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        services: Services = Depends(_services)):
    """Canonical Agent entity list, one row per entity_id."""
    with Session(services.engine) as session:
        items = EntityRepository(session).list_agents(
            include_hidden=include_removed)
        telemetry_running, telemetry_scope = services.telemetry_context()
        attach_protection(items, telemetry_running=telemetry_running,
                          telemetry_scope=telemetry_scope)
        items = [item for item in items if _matches(
            item, q=q, agent_type=agent_type, agent_status=agent_status,
            protection=protection, alias_status=alias_status, origin=origin,
            lifecycle=lifecycle, verification=verification,
            needs_verification=needs_verification)]
        items.sort(key=lambda item: (item.get("name") or "").casefold())
        total = len(items)
        page = items[offset:offset + limit]
    return {"items": page, "total": total, "limit": limit, "offset": offset,
            "matrix_errors": services.matrix.errors}


def _matches(item: dict, *, q: str | None, agent_type: str | None,
             agent_status: str | None, protection: str | None,
             alias_status: str | None, origin: str | None,
             lifecycle: str | None = None,
             verification: str | None = None,
             needs_verification: bool = False) -> bool:
    if q:
        needle = q.casefold()
        haystack = " ".join(str(item.get(key) or "") for key in
                            ("name", "agent_type", "vendor")).casefold()
        if needle not in haystack:
            return False
    if agent_type and item.get("agent_type") != agent_type:
        return False
    if agent_status and item.get("agent_status") != agent_status:
        return False
    if protection and (item.get("protection") or {}).get("summary") != protection:
        return False
    if alias_status and alias_status != "OK":
        return False  # canonical rows are always resolved
    if origin and item.get("origin") != origin:
        return False
    if lifecycle and item.get("lifecycle") != lifecycle:
        return False
    if verification and item.get("verification") != verification:
        return False
    if needs_verification and item.get("verification") not in (
            "FAILED", "NOT_CHECKED", "STALE"):
        return False
    return True


@router.get("/agents/{entity_id}")
def agent_detail(entity_id: str, services: Services = Depends(_services)):
    with Session(services.engine) as session:
        repository = EntityRepository(session)
        asset = repository.get_agent(entity_id)
        if asset is None:
            raise HTTPException(status_code=404, detail="未找到该 Agent 实体")
        asset["instances"] = repository.list_instances(entity_id,
                                                       include_stopped=True)
        asset["instance_count"] = sum(
            1 for instance in asset["instances"]
            if instance.get("status") == "running")
        asset["session_count"] = repository.count_sessions(entity_id)
        asset["sessions"] = repository.list_sessions(entity_id=entity_id,
                                                     limit=20)
        asset["events"] = BehaviorEventRepository(session).list_events(
            limit=20, entity_id=entity_id)
        asset["components"] = ComponentRepository(session).list_for_entity(
            entity_id)
        asset["relations"] = relations_for_entity(
            entity_id, services=services)["items"]
        asset["claims_summary"] = _claims_summary(session, entity_id)
        asset["evidence"] = []
    asset["coverage"] = agent_coverage(entity_id, services=services)
    telemetry_running, telemetry_scope = services.telemetry_context()
    attach_protection([asset], telemetry_running=telemetry_running,
                      telemetry_scope=telemetry_scope)
    return asset


def _claims_summary(session: Session, entity_id: str) -> dict:
    summary = ClaimRepository(session).summary(entity_id)
    return {"available": True, "completeness": "support_only",
            "claim_count": summary["claim_count"],
            "conflicts": [], "by_predicate": summary["by_predicate"]}


@router.get("/agents/{entity_id}/instances")
def agent_instances(entity_id: str, include_stopped: bool = True,
                    services: Services = Depends(_services)):
    with Session(services.engine) as session:
        return {"items": EntityRepository(session).list_instances(
            entity_id, include_stopped=include_stopped)}


@router.get("/agents/{entity_id}/sessions")
def agent_sessions(entity_id: str, limit: int = Query(default=100, ge=1, le=500),
                   services: Services = Depends(_services)):
    with Session(services.engine) as session:
        return {"items": EntityRepository(session).list_sessions(
            entity_id, limit=limit)}


@router.get("/agents/{entity_id}/events")
def agent_events(entity_id: str,
                 limit: int = Query(default=100, ge=1, le=500),
                 services: Services = Depends(_services)):
    with Session(services.engine) as session:
        return {"items": BehaviorEventRepository(session).list_events(
            limit=limit, entity_id=entity_id)}


@router.get("/agents/{entity_id}/evidence")
def agent_evidence(entity_id: str, services: Services = Depends(_services)):
    # Legacy scan evidence is migrated to observations; the evidence tab uses
    # claims/coverage instead. Keep the endpoint stable but empty.
    with Session(services.engine) as session:
        if session.get(EntityAttributeRow, entity_id) is None:
            raise HTTPException(status_code=404, detail="未找到该 Agent 实体")
    return {"items": []}


@router.get("/agents/{entity_id}/mcp")
def agent_mcp(entity_id: str, services: Services = Depends(_services)):
    """MCP config references for one Agent entity.

    Primary source is ``mcp_config_refs`` (scoped references with transport,
    config path and runtime/probe status); the legacy name-only attribute list
    remains the fallback for entities not yet covered by a config scan.
    Names, transports and sanitized endpoints only — never commands, args,
    env or URL query (contract C10).
    """
    with Session(services.engine) as session:
        attr = session.get(EntityAttributeRow, entity_id)
        if attr is None:
            raise HTTPException(status_code=404, detail="未找到该 Agent 实体")
        refs = McpConfigRefRepository(session).list_for_entity(entity_id)
        if refs:
            items = [{"name": row.server_name, "transport": row.transport,
                      "agent_type": row.client, "source": row.config_path,
                      "scope": row.scope, "enabled": row.enabled,
                      "run_status": row.run_status or "unknown",
                      "probe_status": row.probe_status or "unknown"}
                     for row in refs]
        else:
            names = _parse_json(attr.mcp_servers_json, [])
            items = [{"name": name, "transport": "UNKNOWN",
                      "agent_type": attr.agent_type, "source": "config",
                      "scope": "user", "enabled": "unknown",
                      "run_status": "unknown", "probe_status": "unknown"}
                     for name in names]
    return {"items": items, "notes": []}