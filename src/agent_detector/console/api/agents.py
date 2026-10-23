"""Agent inventory endpoints (design section 8: /api/v1/agents...)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from agent_detector.console.api.deps import Services, get_services
from agent_detector.storage import (AgentInventoryRepository,
                                                 ApplicationRepository,
                                                 BehaviorEventRepository, EvidenceRepository)

router = APIRouter(prefix="/api/v1", tags=["agents"])


def _services() -> Services:
    return get_services()


@router.get("/agents")
def list_agents(include_stopped: bool = False, include_removed: bool = False,
                services: Services = Depends(_services)):
    """Agent 资产清单：能力、保护状态与运行实例数。已复核移除的资产默认隐藏。"""
    with Session(services.engine) as session:
        repository = AgentInventoryRepository(session)
        instances = repository.list_instances(include_stopped=include_stopped)
        counts: dict[str, int] = {}
        for instance in instances:
            counts[instance["asset_id"]] = counts.get(instance["asset_id"], 0) + 1
        items = []
        for asset in repository.list_assets(include_removed=include_removed):
            asset["instance_count"] = counts.get(asset["asset_id"], 0)
            asset["session_count"] = repository.count_sessions(asset["asset_id"])
            items.append(asset)
    return {"items": items, "total": len(items),
            "matrix_errors": services.matrix.errors}


@router.get("/agents/{asset_id}")
def agent_detail(asset_id: str, services: Services = Depends(_services)):
    with Session(services.engine) as session:
        repository = AgentInventoryRepository(session)
        asset = repository.get_asset(asset_id)
        if asset is None:
            raise HTTPException(status_code=404, detail="未找到该 Agent 资产")
        asset["instances"] = repository.list_instances(asset_id, include_stopped=True)
        asset["sessions"] = repository.list_sessions(asset_id=asset_id, limit=20)
        asset["events"] = BehaviorEventRepository(session).list_events(
            limit=20, asset_id=asset_id)
        asset["evidence"] = EvidenceRepository(session).for_asset(asset_id)
        if asset.get("app_id"):
            asset["application"] = ApplicationRepository(session).get_application(
                asset["app_id"])
    return asset


@router.get("/agents/{asset_id}/instances")
def agent_instances(asset_id: str, include_stopped: bool = True,
                    services: Services = Depends(_services)):
    with Session(services.engine) as session:
        instances = AgentInventoryRepository(session).list_instances(
            asset_id, include_stopped=include_stopped)
    return {"items": instances}


@router.get("/agents/{asset_id}/sessions")
def agent_sessions(asset_id: str, limit: int = Query(default=50, ge=1, le=500),
                   services: Services = Depends(_services)):
    with Session(services.engine) as session:
        sessions = AgentInventoryRepository(session).list_sessions(
            asset_id=asset_id, limit=limit)
    return {"items": sessions}


@router.get("/agents/{asset_id}/events")
def agent_events(asset_id: str, limit: int = Query(default=50, ge=1, le=500),
                 source: str | None = None, services: Services = Depends(_services)):
    with Session(services.engine) as session:
        events = BehaviorEventRepository(session).list_events(
            limit=limit, asset_id=asset_id, source=source)
    return {"items": events}


@router.get("/agents/{asset_id}/evidence")
def agent_evidence(asset_id: str, scan_id: int | None = None,
                   services: Services = Depends(_services)):
    """Discovery evidence for one asset: what proved it exists (no file content)."""
    with Session(services.engine) as session:
        evidence = EvidenceRepository(session).for_asset(asset_id, scan_id=scan_id)
    if not evidence:
        raise HTTPException(status_code=404, detail="该资产暂无证据记录")
    return evidence


@router.get("/agents/{asset_id}/mcp")
def agent_mcp(asset_id: str, services: Services = Depends(_services)):
    """MCP 配置清单（仅名称与传输类型，不读取命令、参数或凭据）。"""
    from agent_detector.discovery.sources.mcp import for_agent, scan_mcp_servers

    with Session(services.engine) as session:
        asset = AgentInventoryRepository(session).get_asset(asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="未找到该 Agent 资产")
    servers = scan_mcp_servers(services.home)
    return {"items": for_agent(servers, asset["agent_type"]),
            "notes": ["仅读取 MCP 服务名称与传输类型；命令、参数与环境变量不入库。",
                      "本地 stdio MCP 不产生网络流量，无法通过网络通道确认调用。"]}