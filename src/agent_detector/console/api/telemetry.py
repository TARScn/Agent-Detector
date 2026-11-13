"""Telemetry endpoints: channel status and start/stop control (§4.3, §8).

Two long-running channels, one control surface:

* **netmon** — zero-cooperation observation of outbound LLM connections
  (services/monitor.py)
* **system behavior** — Sysmon (Windows) / auditd (Linux) / polling fallback,
  normalized into behavior_events (services/ingest.py)
"""
from __future__ import annotations

import platform
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from agent_detector.console.api.deps import Services, get_services
from agent_detector.console.api.schemas import BehaviorStartRequest, MonitorStartRequest
from agent_detector.monitoring.collectors.audit.rules_template import (build_rules, install_commands,
                                                           uninstall_commands)
from agent_detector.monitoring.collectors.ebpf.tetragon import tetragon_available
from agent_detector.monitoring.collectors.host.sysmon import sysmon_available
from agent_detector.core.config import SYSMON_CHANNEL, TETRA_LOG
from agent_detector.monitoring.services.ingest import BehaviorIngestError
from agent_detector.monitoring.services.monitor import MonitorError

router = APIRouter(prefix="/api/v1/telemetry", tags=["telemetry"])


def _services() -> Services:
    return get_services()


def _behavior_status(services: Services) -> dict:
    """Thin delegate: the source-aware merge lives in
    ``Services.behavior_status`` (local ingest, detached child, or a foreign
    collector's published file)."""
    return services.behavior_status()


@router.get("/status")
def telemetry_status(services: Services = Depends(_services)):
    """Which observation channels exist on this host, and are they running."""
    assert services.ingest is not None and services.monitor is not None
    behavior = _behavior_status(services)
    monitor = services.monitor.status()
    sysmon = sysmon_available(SYSMON_CHANNEL)
    tetragon = tetragon_available(TETRA_LOG)
    mode = behavior.get("mode")
    service_running = bool(behavior.get("running"))
    last_event_at = _epoch_iso(behavior.get("last_event_at"))
    # native_hook is deliberately absent: hook install state lives in
    # GET /api/v1/hooks (采集页 Hook 安装区), not in the channel list.
    channels = [
        _channel("sysmon", "Sysmon", sysmon.available,
                 service_running and mode == "sysmon", "Windows",
                 "Windows 行为事件" if sysmon.available else "未安装 Sysmon",
                 last_event_at, behavior.get("status_age_seconds"),
                 active_mode=mode, control="behavior",
                 service_running=service_running),
        _channel("tetragon", "Tetragon (eBPF)", tetragon.available,
                 service_running and mode == "tetragon", "Linux",
                 "进程/网络/文件事件" if tetragon.available else "仅 Linux",
                 last_event_at,
                 tetragon.last_write_age_seconds
                 if tetragon.last_write_age_seconds is not None
                 else behavior.get("status_age_seconds"),
                 active_mode=mode, control="behavior",
                 service_running=service_running),
        _channel("auditd", "auditd", _audit_available(),
                 service_running and mode == "auditd", "Linux",
                 "进程/文件/网络事件 · 需 root" if _audit_available()
                 else "仅 Linux · 需 root",
                 last_event_at, behavior.get("status_age_seconds"),
                 active_mode=mode, control="behavior",
                 service_running=service_running),
        _channel("poll", "进程采样", True,
                 service_running and mode == "poll", "all",
                 "进程执行级 · 免管理员", last_event_at,
                 behavior.get("status_age_seconds"), active_mode=mode,
                 control="behavior", service_running=service_running),
        _channel("netmon", "出站连接观察", True,
                 bool(monitor.get("running")), "all",
                 "零合作 · 连接级证据", None, None, control="monitor"),
    ]
    return {
        "host_platform": platform.system(),
        "monitor": monitor,
        "behavior": behavior,
        "channels": channels,
        "health": _health(behavior, monitor, channels, last_event_at),
    }


def _channel(channel_id: str, name: str, available: bool, running: bool,
             platform_name: str, detail: str,
             last_event_at: str | None,
             status_age_seconds: float | None,
             active_mode: str | None = None,
             control: str | None = None,
             service_running: bool = False) -> dict:
    if not available:
        state = "UNAVAILABLE"
    elif running:
        state = "RUNNING"
    elif control == "behavior" and channel_id in ("sysmon", "tetragon",
                                                  "auditd", "poll"):
        # Behavior channels are mutually exclusive: an available channel that
        # is not the active one is standby, and the whole group is stopped
        # while the ingest service itself is down.
        state = "STANDBY" if service_running else "STOPPED"
    else:
        state = "DOWN" if service_running and channel_id == active_mode \
            else "STOPPED"
    return {"id": channel_id, "name": name, "available": available,
            "running": running, "state": state, "detail": detail,
            "control": control,
            "platform": platform_name,
            "last_event_at": last_event_at,
            "status_age_seconds": status_age_seconds,
            "reason": None if available else detail}


def _health(behavior: dict, monitor: dict, channels: list[dict],
            last_event_at: str | None) -> dict:
    mode = behavior.get("mode")
    active = next((item for item in channels
                   if item["id"] == mode), None)
    core = [item for item in channels
            if item["id"] in ("sysmon", "tetragon", "auditd", "poll")]
    bad = [item["id"] for item in core if item["state"] == "DOWN"]
    age = behavior.get("status_age_seconds")
    stale = age is not None and age > 120
    if behavior.get("running") and not bad and not stale:
        state = "OK"
        basis = [f"行为采集（{mode or '未知'}）运行中"]
    elif behavior.get("running"):
        state = "DEGRADED"
        basis = ([f"行为采集（{mode or '未知'}）运行中"]
                 + [f"{channel} 通道异常" for channel in bad]
                 + (["状态数据过期"] if stale else []))
    elif monitor.get("running"):
        state = "DEGRADED"
        basis = ["出站网络观察运行中", "行为采集未运行"]
    else:
        state = "NOT_RUNNING"
        basis = ["行为采集未运行", "出站网络观察未运行"]
    return {"state": state, "basis": basis,
            "last_event_at": last_event_at,
            "last_event_age_seconds": age}


def _epoch_iso(value) -> str | None:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(float(value), timezone.utc).isoformat(
            timespec="seconds")
    except (TypeError, ValueError, OSError):
        return None


def _audit_available() -> bool:
    return platform.system() == "Linux"


@router.post("/monitor/start")
def monitor_start(body: MonitorStartRequest | None = None,
                  services: Services = Depends(_services)):
    assert services.monitor is not None
    try:
        return services.monitor.start(
            interval=body.interval if body else None,
            suppress_seconds=body.suppress_seconds if body else None)
    except MonitorError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/monitor/stop")
def monitor_stop(services: Services = Depends(_services)):
    assert services.monitor is not None
    return services.monitor.stop()


@router.post("/behavior/start")
def behavior_start(body: BehaviorStartRequest | None = None,
                   services: Services = Depends(_services)):
    assert services.ingest is not None
    try:
        # Returns at once; the channel's readiness surfaces via
        # /telemetry/status (the seed sweep and the child spawn must not
        # hold the request thread — they used to freeze the console).
        return services.start_behavior(mode=body.mode if body else None,
                                       log_path=body.log_path if body else None,
                                       from_start=body.from_start if body else None)
    except BehaviorIngestError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/behavior/stop")
def behavior_stop(services: Services = Depends(_services)):
    return services.stop_behavior()


@router.get("/audit-rules")
def audit_rules(watch_dir: str | None = None, uid_min: int = 1000,
                include_net: bool = True, include_kill: bool = False):
    """auditd 规则与安装命令（只打印，工具本身从不提权）。"""
    try:
        rule_set = build_rules([watch_dir] if watch_dir else [], uid_min=uid_min,
                               include_net=include_net, include_kill=include_kill)
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"detail": str(exc)})
    return {
        "rules": list(rule_set.rules),
        "install": install_commands(rule_set),
        "install_persistent": install_commands(rule_set, persistent=True),
        "uninstall": uninstall_commands(rule_set),
        "notes": [
            "规则需要 root 执行（sudo auditctl / augenrules）；本工具不会自动提权。",
            "audit.log 默认仅 root 可读：以 root 运行采集器，或在 "
            "/etc/audit/auditd.conf 设置 log_group 让采集用户可读。",
            "--watch-dir（-F dir=）为递归目录过滤，只审计这些目录内的文件行为。",
        ],
    }