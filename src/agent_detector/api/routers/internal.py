"""Internal control API consumed by ``hook_bridge`` (design section 8).

Separated from the console API on purpose: it is synchronous (an Agent is
blocked waiting), token-authenticated, and never rendered in the UI. A Named
Pipe with a user-SID ACL is the planned desktop transport; until then the
endpoint binds to loopback and requires the token file written by the service.
"""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from agent_detector.api.deps import Services, get_services
from agent_detector.api.schemas import HookDecideRequest
from agent_detector.common.config import hook_token

router = APIRouter(prefix="/internal/v1", tags=["internal"])


def _services() -> Services:
    return get_services()


@router.post("/hooks/decide")
def decide(body: HookDecideRequest, request: Request,
           x_agent_detector_token: str | None = Header(default=None),
           services: Services = Depends(_services)):
    """Approve / ask / deny one tool call the Agent is about to make."""
    expected = hook_token(create=False)
    if not expected:
        raise HTTPException(status_code=503,
                            detail="决策服务尚未生成 Token（请先启动 Agent Detector 服务）")
    provided = x_agent_detector_token or ""
    if not secrets.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Token 无效")
    assert services.hooks is not None
    payload = dict(body.payload or {})
    bridge_pid = body.bridge_pid
    if bridge_pid is None:
        header_pid = request.headers.get("X-Agent-Detector-Parent-Pid")
        bridge_pid = int(header_pid) if (header_pid or "").isdigit() else None
    outcome = services.hooks.decide(body.agent_type, payload, bridge_ppid=bridge_pid)
    return outcome.to_dict()


@router.get("/health")
def internal_health(services: Services = Depends(_services)):
    assert services.hooks is not None
    return {"status": "ok", "failure_mode": services.hooks.failure_mode,
            **services.hooks.policy_status()}