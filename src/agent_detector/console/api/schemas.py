"""Request bodies for the V0.2 API (design section 8)."""
from __future__ import annotations

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    active: bool = False
    """Also probe local HTTP listeners (never remote addresses)."""
    docker: bool = True
    """Include the Docker container channel (read-only API, never docker exec)."""


class MonitorStartRequest(BaseModel):
    interval: float | None = Field(default=None, ge=0.5, le=60)
    suppress_seconds: int | None = Field(default=None, ge=0, le=86400)


class BehaviorStartRequest(BaseModel):
    mode: str | None = Field(default=None,
                             description="sysmon | auditd | tetragon | poll（replay 走 CLI）")
    log_path: str | None = None
    from_start: bool = False


class PolicyUpdateRequest(BaseModel):
    enabled: bool | None = None
    decision: str | None = Field(default=None, pattern="^(allow|ask|deny|audit)$")


class AlertUpdateRequest(BaseModel):
    status: str = Field(pattern="^(open|acknowledged|resolved)$")


class HookInstallRequest(BaseModel):
    apply: bool = False
    """False = dry run. Nothing is written unless the caller asks for it."""

    timeout: float | None = Field(default=None, ge=1, le=30)
    fail_closed: bool = True
    python: str | None = None


class HookDecideRequest(BaseModel):
    """Payload submitted by ``hook_bridge`` (already platform-specific)."""

    agent_type: str | None = None
    payload: dict = Field(default_factory=dict)
    bridge_pid: int | None = None