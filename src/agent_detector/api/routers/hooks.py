"""Hook management endpoints: inspect, plan, install, uninstall (§5, §9).

Every write is opt-in: ``POST /hooks/{agent}/install`` with ``apply=false``
(the default) returns the exact JSON that would be written and touches nothing.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from agent_detector.api.deps import Services, get_services
from agent_detector.api.schemas import HookInstallRequest
from agent_detector.hooks.installer import (config_snippet, events_for, inspect_all, install,
                                           plan, uninstall)
from agent_detector.hooks.registry import ADAPTERS

router = APIRouter(prefix="/api/v1/hooks", tags=["hooks"])


def _services() -> Services:
    return get_services()


@router.get("")
def list_hooks(services: Services = Depends(_services)):
    """每个 Agent 的 Hook 配置状态（已安装 / 未安装 / 部分接入 / 待验证）。"""
    items = inspect_all()
    for item in items:
        adapter = ADAPTERS.get(item["agent_type"])
        if adapter is not None:
            item["events"] = list(events_for(adapter.spec.agent_type))
            item["docs_url"] = adapter.spec.docs_url
    return {"items": items, "failure_mode": services.hooks.failure_mode,
            "notes": ["Hook 安装在当前用户配置目录内：同权限用户可修改，"
                      "开发验证阶段可接受，企业级需要托管配置与防篡改（设计文档 §11.2）。",
                      "本工具默认只做 dry-run，需显式 apply=true 才会写入配置并备份原文件。"]}


@router.post("/{agent_type}/plan")
def hook_plan(agent_type: str, body: HookInstallRequest | None = None,
              services: Services = Depends(_services)):
    request = body or HookInstallRequest()
    try:
        return plan(agent_type, timeout=request.timeout,
                    fail_closed=request.fail_closed, python=request.python)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{agent_type}/install")
def hook_install(agent_type: str, body: HookInstallRequest | None = None,
                 services: Services = Depends(_services)):
    request = body or HookInstallRequest()
    try:
        result = install(agent_type, apply=request.apply, timeout=request.timeout,
                         fail_closed=request.fail_closed, python=request.python)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result.get("written"):
        result["status"] = inspect_all()
    return result


@router.post("/{agent_type}/uninstall")
def hook_uninstall(agent_type: str, body: HookInstallRequest | None = None,
                   services: Services = Depends(_services)):
    request = body or HookInstallRequest()
    try:
        result = uninstall(agent_type, apply=request.apply)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result.get("written"):
        result["status"] = inspect_all()
    return result


@router.get("/{agent_type}/snippet")
def hook_snippet(agent_type: str, timeout: float | None = None,
                 fail_closed: bool = True, services: Services = Depends(_services)):
    try:
        return config_snippet(agent_type, timeout=timeout, fail_closed=fail_closed)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc