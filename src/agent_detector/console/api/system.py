"""Dashboard + system endpoints (design sections 1.3, 8)."""
from __future__ import annotations

import platform
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from agent_detector import __version__
from agent_detector.console.api.agent_view import app_name_map, merge_agent_rows
from agent_detector.console.api.deps import Services, get_services
from agent_detector.monitoring.collectors.host.sysmon import sysmon_available
from agent_detector.core.config import (ALERT_RISK_LEVEL, BEHAVIOR_PATH_POLICY,
                                          BEHAVIOR_RETENTION_DAYS, DB_PATH, HOOK_FAILURE_MODE,
                                          HOOK_URL, SYSMON_CHANNEL, WEB_HOST, WEB_PORT)
from agent_detector.discovery.sources.agents import load_agent_matrix
from agent_detector.discovery.fingerprints.loader import load_rules
from agent_detector.interception.hooks.installer import inspect_all
from agent_detector.storage import (AgentInventoryRepository, AlertRepository,
                                                 AssetRepository, BehaviorEventRepository,
                                                 ScanRepository)

router = APIRouter(prefix="/api/v1", tags=["system"])


def _services() -> Services:
    return get_services()


@router.get("/overview")
def overview(services: Services = Depends(_services)):
    """仪表盘：Agent 清单摘要 + 今日行为 + 已阻断 + 通道状态 + 最近事件/告警。"""
    since = _today_iso()
    with Session(services.engine) as session:
        agents = AgentInventoryRepository(session).list_assets()
        instances = AgentInventoryRepository(session).list_instances()
        events = BehaviorEventRepository(session)
        summary = events.summary(since)
        recent_events = events.list_events(limit=12)
        recent_alerts = AlertRepository(session).list_alerts(limit=6)
        alert_stats = AlertRepository(session).stats()
        components = AssetRepository(session).latest_snapshots()
        latest_scan = ScanRepository(session).latest_id()
        # 与资产清单同一合并口径（框架折叠进产品/应用实体），数字不打架。
        counts: dict[str, int] = {}
        for instance in instances:
            counts[instance["asset_id"]] = counts.get(instance["asset_id"], 0) + 1
        entities = merge_agent_rows(agents, app_name_map(session), counts)
        # 只数未移除实体名下的实例：removed 资产的实例行要等下一次扫描才被
        # 退役（inventory 的收尾清理），两次扫描之间不能把幽灵算成运行中。
    protection: dict[str, int] = {}
    for agent in entities:
        key = agent["protection_status"]
        protection[key] = protection.get(key, 0) + 1
    running = sum(1 for agent in entities if agent["instance_count"] > 0)
    return {
        "agents": {"total": len(entities), "running": running,
                   "protection": protection},
        "behavior": {"events_today": summary["events_since"],
                     "blocked_today": summary["blocked_since"],
                     "by_source": summary["by_source"],
                     "last_event_at": summary["last_event_at"]},
        "components": {"total": len(components),
                       "by_type": _count_by(components, "asset_type")},
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


def _channels(services: Services) -> list[dict]:
    assert services.ingest is not None and services.monitor is not None
    behavior = services.ingest.status()
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
        "behavior": {"retention_days": BEHAVIOR_RETENTION_DAYS,
                     "path_policy": BEHAVIOR_PATH_POLICY,
                     "alert_risk_level": ALERT_RISK_LEVEL,
                     "hook_failure_mode": HOOK_FAILURE_MODE},
        "detection_rules": {
            "client_rules": [{"id": rule.id, "name": rule.name,
                              "asset_type": rule.asset_type.value,
                              "revision": rule.revision} for rule in loaded.client_rules],
            "signature_rules": len(loaded.signature_rules),
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