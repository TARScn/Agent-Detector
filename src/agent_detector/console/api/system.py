"""Dashboard + system endpoints (design sections 1.3, 8)."""
from __future__ import annotations

import platform
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from agent_detector import __version__
from agent_detector.console.api.agent_view import attach_protection
from agent_detector.console.api.deps import Services, get_services
from agent_detector.monitoring.collectors.host.sysmon import sysmon_available
from agent_detector.core.config import (ALERT_RISK_LEVEL, BEHAVIOR_PATH_POLICY,
                                          BEHAVIOR_RETENTION_DAYS, DB_PATH, HOOK_FAILURE_MODE,
                                          HOOK_URL, SYSMON_CHANNEL, WEB_HOST, WEB_PORT)
from agent_detector.discovery.sources.agents import load_agent_matrix
from agent_detector.discovery.fingerprints.loader import load_rules
from agent_detector.interception.hooks.installer import inspect_all
from agent_detector.monitoring.services.retention import (get_retention_days,
                                                           purge_behavior_events,
                                                           set_retention_days)
from agent_detector.storage import (AlertRepository, BehaviorEventRepository,
                                                 EntityRepository, ScanRepository)
from agent_detector.storage.models import ComponentRow

router = APIRouter(prefix="/api/v1", tags=["system"])


def _services() -> Services:
    return get_services()


@router.get("/overview")
def overview(services: Services = Depends(_services)):
    """仪表盘：Agent 清单摘要 + 今日行为 + 已阻断 + 通道状态 + 最近事件/告警。"""
    since = _today_iso()
    with Session(services.engine) as session:
        all_entities = EntityRepository(session).list_agents(include_hidden=True)
        entities = [agent for agent in all_entities
                    if agent.get("lifecycle") != "ARCHIVED"]
        archived_total = len(all_entities) - len(entities)
        events = BehaviorEventRepository(session)
        summary = events.summary(since)
        recent_events = events.list_events(limit=12)
        recent_alerts = AlertRepository(session).list_alerts(limit=6)
        alert_stats = AlertRepository(session).stats()
        component_rows = list(session.query(ComponentRow).all())
        components_by_type: dict[str, int] = {}
        for component in component_rows:
            key = component.kind or "UNKNOWN"
            components_by_type[key] = components_by_type.get(key, 0) + 1
        latest_scan = ScanRepository(session).latest_id()
    telemetry_running, telemetry_scope = services.telemetry_context()
    attach_protection(entities, telemetry_running=telemetry_running,
                      telemetry_scope=telemetry_scope)
    protection = {}
    for agent in entities:
        key = agent["protection"]["summary"]
        protection[key] = protection.get(key, 0) + 1
    running_legacy = sum(1 for agent in entities if agent["instance_count"] > 0)

    protection_summary = _zeroed(
        ("PROTECTED", "MONITOR_ONLY", "UNPROTECTED", "UNKNOWN"),
        [agent["protection"]["summary"] for agent in entities])
    hook_states = _counts(agent["protection"]["hook_state"] for agent in entities)
    statuses = [agent.get("agent_status") for agent in entities]
    # RUNNING counts only what this scan actually observed; stale snapshots
    # keep their last durable status and are counted as needing verification.
    running_confirmed = sum(
        1 for agent in entities
        if agent.get("agent_status") == "RUNNING"
        and agent.get("verification") in ("VERIFIED", "PARTIAL"))
    running_unconfirmed = sum(
        1 for agent in entities
        if agent.get("agent_status") is None and agent["instance_count"] > 0)
    current_detected = sum(1 for agent in entities
                           if agent.get("presence") == "PRESENT")
    confirmed_present = sum(
        1 for agent in entities if agent.get("presence") == "PRESENT"
        and agent.get("verification") in ("VERIFIED", "PARTIAL"))
    needs_verification = sum(
        1 for agent in entities
        if agent.get("verification") in ("FAILED", "NOT_CHECKED", "STALE"))
    unknown_status = sum(
        1 for status in statuses if status in (None, "UNKNOWN"))
    if not statuses or all(status is None for status in statuses):
        running_basis = "unavailable"
    elif all(status is not None for status in statuses):
        running_basis = "agent_status"
    else:
        running_basis = "mixed"
    new_24h = sum(1 for agent in entities if _within_hours(agent.get("first_seen_at"), 24))
    return {
        "agents": {"total": len(entities), "running": running_legacy,
                   "protection": protection,
                   "inventory_total": len(all_entities),
                   "current_detected": current_detected,
                   "confirmed_present": confirmed_present,
                   "running_count": running_confirmed,
                   "running_confirmed": running_confirmed,
                   "running_unconfirmed": running_unconfirmed,
                   "needs_verification": needs_verification,
                   "archived_total": archived_total,
                   "running_basis": running_basis,
                   "new_24h": new_24h,
                   "unknown_status": unknown_status,
                   "by_entity_kind": _counts(
                       agent.get("entity_kind") or "UNKNOWN" for agent in entities),
                   "by_type": _counts(
                       agent.get("agent_type") or "UNKNOWN" for agent in entities),
                   "protection_summary": protection_summary,
                   "hook_states": hook_states},
        "behavior": {"events_today": summary["events_since"],
                     "blocked_today": summary["blocked_since"],
                     "by_source": summary["by_source"],
                     "last_event_at": summary["last_event_at"]},
        "components": {"total": len(component_rows),
                       "by_type": components_by_type},
        "alerts": alert_stats,
        "recent_events": recent_events,
        "recent_alerts": recent_alerts,
        "channels": _channels(services),
        "latest_scan_id": latest_scan,
        "disclaimer": [
            "监测到的行为不等于已拦截：只有接入原生 Hook 的 Agent 才能在调用前阻断。",
            "未接入 Hook 的 Agent 会显示为“仅审计”，产品不会声称已保护。",
        ],
    }


def _count_by(items: list[dict], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(item.get(key) or "UNKNOWN")
        counts[value] = counts.get(value, 0) + 1
    return counts


def _counts(values) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "UNKNOWN")
        counts[key] = counts.get(key, 0) + 1
    return counts


def _zeroed(keys: tuple[str, ...], values: list[str]) -> dict[str, int]:
    counts = _counts(values)
    return {key: counts.get(key, 0) for key in keys}


def _within_hours(iso: str | None, hours: int) -> bool:
    if not iso:
        return False
    try:
        stamp = datetime.fromisoformat(iso)
    except ValueError:
        return False
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp >= datetime.now(timezone.utc) - timedelta(hours=hours)


def _channels(services: Services) -> list[dict]:
    assert services.ingest is not None and services.monitor is not None
    behavior = services.behavior_status()
    monitor = services.monitor.status()
    sysmon = sysmon_available(SYSMON_CHANNEL)
    hooks = inspect_all()
    installed = [item for item in hooks
                 if item["state"] in ("INSTALLED", "PARTIAL")]
    return [
        {"id": "native_hook", "name": "Agent 原生 Hook", "running": bool(installed),
         "detail": (f"{len(installed)} 个 Agent 已接入" if installed
                    else "未安装：当前没有任何 Agent 可在执行前被阻断")},
        {"id": "sysmon", "name": "Windows Sysmon", "running": behavior["running"] and
         behavior["mode"] == "sysmon",
         "detail": sysmon.reason or f"通道 {sysmon.channel}"},
        {"id": "auditd", "name": "系统行为采集", "running": behavior["running"],
         "detail": f"mode={behavior['mode']} events={behavior['events']}"},
        {"id": "netmon", "name": "出站连接观察", "running": monitor["running"],
         "detail": f"hits={monitor['hits']} iterations={monitor['iterations']}"},
    ]


def _today_iso() -> str:
    """Start of the current UTC day (the console renders local time itself)."""
    midnight = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0,
                                                  microsecond=0)
    return midnight.isoformat(timespec="seconds")


@router.get("/system")
def system_info(services: Services = Depends(_services)):
    """控制台设置页需要的全部环境信息（只读）。"""
    loaded = load_rules()
    matrix = load_agent_matrix()
    sysmon = sysmon_available(SYSMON_CHANNEL)
    assert services.hooks is not None
    return {
        "version": __version__,
        "platform": {"system": platform.system(), "release": platform.release(),
                     "python": platform.python_version(), "node": platform.node()},
        "server": {"host": WEB_HOST, "port": WEB_PORT, "listen": f"{WEB_HOST}:{WEB_PORT}"},
        "database": {"path": str(DB_PATH), "url": "sqlite"},
        "policy": services.hooks.policy_status(),
        "hooks": {"failure_mode": services.hooks.failure_mode, "url": HOOK_URL,
                  "installations": inspect_all()},
        "channels": {"sysmon": sysmon.to_dict(), "auditd_platform": platform.system()},
        "behavior": {"retention_days": get_retention_days(services.engine),
                     "path_policy": BEHAVIOR_PATH_POLICY,
                     "alert_risk_level": ALERT_RISK_LEVEL,
                     "hook_failure_mode": HOOK_FAILURE_MODE},
        "detection_rules": {
            "client_rules": [{"id": rule.id, "name": rule.name,
                              "asset_type": rule.asset_type.value,
                              "revision": rule.revision} for rule in loaded.client_rules],
            "framework_rules": len(loaded.framework_rules),
            "errors": loaded.errors,
        },
        "agent_matrix": {
            "source": matrix.source, "errors": matrix.errors,
            "agents": [{"id": entry.id, "name": entry.name, "vendor": entry.vendor,
                        "capabilities": entry.capabilities(), "hook": entry.hook,
                        "docs": entry.docs, "notes": entry.notes}
                       for entry in matrix.matrix.agents],
        },
        "scope_notes": [
            "仅监听 127.0.0.1；决策接口需 Token，勿暴露到网络。",
            "不读取对话内容、文件内容与凭据原文。",
            "Sysmon 事件 3 默认关闭，需显式启用。",
        ],
    }

class RetentionUpdate(BaseModel):
    retention_days: int = Field(ge=0, le=3650)


@router.get("/settings/retention")
def get_retention(services: Services = Depends(_services)):
    """运行时保留窗口；``default_days`` 为 env 配置的出厂默认。"""
    return {"retention_days": get_retention_days(services.engine),
            "default_days": BEHAVIOR_RETENTION_DAYS}


@router.put("/settings/retention")
def put_retention(update: RetentionUpdate, services: Services = Depends(_services)):
    """保存保留窗口并立即按新窗口清理一次（0 = 停用保留策略）。"""
    stored = set_retention_days(services.engine, update.retention_days)
    purged = purge_behavior_events(services.engine, stored) if stored > 0 else 0
    return {"retention_days": stored, "purged": purged}
