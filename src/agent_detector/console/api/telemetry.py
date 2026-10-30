"""Telemetry endpoints: channel status and start/stop control (§4.3, §8).

Two long-running channels, one control surface:

* **netmon** — zero-cooperation observation of outbound LLM connections
  (services/monitor.py)
* **system behavior** — Sysmon (Windows) / auditd (Linux) / polling fallback,
  normalized into behavior_events (services/ingest.py)
"""
from __future__ import annotations

import platform

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


@router.get("/status")
def telemetry_status(services: Services = Depends(_services)):
    """Which observation channels exist on this host, and are they running."""
    ingest = services.ingest
    assert ingest is not None and services.monitor is not None
    sysmon = sysmon_available(SYSMON_CHANNEL)
    tetragon = tetragon_available(TETRA_LOG)
    return {
        "host_platform": platform.system(),
        "monitor": services.monitor.status(),
        "behavior": ingest.status(),
        "channels": [
            {"id": "sysmon", "name": "Windows Sysmon", "available": sysmon.available,
             "detail": sysmon.reason, "platform": "Windows"},
            {"id": "tetragon", "name": "eBPF (Tetragon)", "available": tetragon.available,
             "detail": tetragon.reason or "进程/网络/文件事件，含容器身份",
             "platform": "Linux"},
            {"id": "auditd", "name": "Linux auditd", "available": _audit_available(),
             "detail": _audit_detail(), "platform": "Linux"},
            {"id": "poll", "name": "采样降级模式", "available": True,
             "detail": "无需 root：仅进程执行级行为", "platform": "all"},
            {"id": "netmon", "name": "出站连接观察（零合作）", "available": True,
             "detail": "连接级证据，不读取通信内容", "platform": "all"},
            {"id": "native_hook", "name": "Agent 原生 Hook", "available": True,
             "detail": "执行前拦截通道，需要为每个 Agent 安装 Hook", "platform": "all"},
        ],
    }


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