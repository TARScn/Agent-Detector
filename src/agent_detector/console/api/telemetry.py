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
from agent_detector.monitoring.services.collector_status import load_collector_status
from agent_detector.monitoring.services.ingest import BehaviorIngestError
from agent_detector.monitoring.services.monitor import MonitorError
from agent_detector.interception.hooks.installer import inspect_all

router = APIRouter(prefix="/api/v1/telemetry", tags=["telemetry"])


def _services() -> Services:
    return get_services()


def _behavior_status(ingest) -> dict:
    """Local ingest status, or the running collector's published counters.

    Under the systemd deployment the console never starts its own ingest —
    showing that idle twin would report the collector as stopped with zero
    counters. When the local instance is idle, prefer the collector-status
    file the real service publishes; ``source`` says which one answered.
    """
    status = dict(ingest.status())
    if not status.get("running"):
        collector = load_collector_status(hostname=platform.node() or "localhost")
        if collector is not None:
            return {**collector["collector"], "source": "collector",
                    "status_age_seconds": collector["age_seconds"]}
    status["source"] = "local"
    return status


@router.get("/status")
def telemetry_status(services: Services = Depends(_services)):
    """Which observation channels exist on this host, and are they running."""
    ingest = services.ingest
    assert ingest is not None and services.monitor is not None
    behavior = _behavior_status(ingest)
    monitor = services.monitor.status()
    sysmon = sysmon_available(SYSMON_CHANNEL)
    tetragon = tetragon_available(TETRA_LOG)
    hooks = inspect_all()
    hook_installed = any(item["state"] in ("INSTALLED", "PARTIAL")
                         for item in hooks)
    mode = behavior.get("mode")
    last_event_at = _epoch_iso(behavior.get("last_event_at"))
    channels = [
        _channel("sysmon", "Windows Sysmon", sysmon.available,
                 behavior.get("running") and mode == "sysmon", "Windows",
                 sysmon.reason, last_event_at, behavior.get("status_age_seconds"),
                 active_mode=mode),
        _channel("tetragon", "eBPF (Tetragon)", tetragon.available,
                 behavior.get("running") and mode == "tetragon", "Linux",
                 tetragon.reason or "进程/网络/文件事件，含容器身份",
                 last_event_at,
                 tetragon.last_write_age_seconds
                 if tetragon.last_write_age_seconds is not None
                 else behavior.get("status_age_seconds"),
                 active_mode=mode),
        _channel("auditd", "Linux auditd", _audit_available(),
                 behavior.get("running") and mode == "auditd", "Linux",
                 _audit_detail(), last_event_at, behavior.get("status_age_seconds"),
                 active_mode=mode),
        _channel("poll", "采样降级模式", True,
                 behavior.get("running") and mode == "poll", "all",
                 "无需 root：仅进程执行级行为", last_event_at,
                 behavior.get("status_age_seconds"), active_mode=mode),
        _channel("netmon", "出站连接观察（零合作）", True,
                 bool(monitor.get("running")), "all",
                 "连接级证据，不读取通信内容", None, None),
        _channel("native_hook", "Agent 原生 Hook", True, hook_installed, "all",
                 "执行前拦截通道，需要为每个 Agent 安装 Hook", None, None),
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
             active_mode: str | None = None) -> dict:
    if not available:
        state = "UNAVAILABLE"
    elif running:
        state = "OK"
    elif channel_id in ("sysmon", "tetragon", "auditd", "poll"):
        # The active core channel is down; a different available core channel
        # is merely standby, not a failure.
        state = "DOWN" if channel_id == active_mode else "OK"
    elif channel_id == "native_hook":
        # Hook is per-Agent and optional; no installation is degraded, not down.
        state = "DEGRADED"
    else:
        state = "DOWN"
    return {"id": channel_id, "name": name, "available": available,
            "running": running, "state": state, "detail": detail,
            "platform": platform_name,
            "last_event_at": last_event_at,
            "status_age_seconds": status_age_seconds,
            "reason": None if available else detail}


def _health(behavior: dict, monitor: dict, channels: list[dict],
            last_event_at: str | None) -> dict:
    mode = behavior.get("mode")
    active = next((item for item in channels
                   if item["id"] == mode and item["id"] != "native_hook"), None)
    core = [item for item in channels
            if item["id"] in ("sysmon", "tetragon", "auditd", "poll")]
    bad = [item["id"] for item in core
           if item["state"] in ("DEGRADED", "DOWN")]
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


def _audit_detail() -> str:
    if platform.system() == "Linux":
        return "需要 root 安装审计规则；audit.log 默认仅 root 可读"
    return "非 Linux 主机：auditd 不可用（WSL2 因发行版运行在子 PID namespace 亦不可用）"


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
        return services.ingest.start(mode=body.mode if body else None,
                                     log_path=body.log_path if body else None,
                                     from_start=body.from_start if body else None)
    except BehaviorIngestError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/behavior/stop")
def behavior_stop(services: Services = Depends(_services)):
    assert services.ingest is not None
    return services.ingest.stop()


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