"""Protection projection shared by the console read models."""
from __future__ import annotations

_PROTECTION_REASON = {
    "PROTECTED": "已验证工具调用被前置阻断",
    "MONITOR_ONLY": "仅监测，未验证执行前阻断",
    "UNPROTECTED": "未发现 Hook 或行为采集覆盖",
    "UNKNOWN": "保护状态无法确认",
}


def protection_view(row: dict, *, telemetry_running: bool,
                    telemetry_scope: str = "none") -> dict:
    """Derive the user-facing protection summary from the snapshot state."""
    hook_state = str(row.get("snapshot_hook_state") or "UNKNOWN")
    if hook_state == "ENFORCEMENT_VERIFIED":
        summary = "PROTECTED"
    elif hook_state in ("CONFIGURED", "HOOK_OBSERVED"):
        summary = "MONITOR_ONLY"
    elif hook_state in ("PARTIAL", "CONFLICT"):
        summary = "MONITOR_ONLY" if telemetry_running else "UNKNOWN"
    elif hook_state == "NOT_CONFIGURED":
        summary = "MONITOR_ONLY" if telemetry_running else "UNPROTECTED"
    else:
        summary = "UNKNOWN"
    reason = _PROTECTION_REASON.get(summary, "保护状态无法确认")
    if summary == "MONITOR_ONLY" and hook_state == "CONFIGURED":
        reason = "Hook 已配置，尚未观测到实际阻断"
    elif summary == "MONITOR_ONLY" and telemetry_scope == "global":
        reason = "全局采集已开启，资产级覆盖未确认"
    return {
        "summary": summary,
        "hook_state": hook_state,
        "basis": {
            "enforcement_verified": hook_state == "ENFORCEMENT_VERIFIED",
            "hook_observed_at": None,
            "telemetry_running": telemetry_running,
            "telemetry_scope": telemetry_scope,
            "reason": reason,
        },
    }


def attach_protection(rows: list[dict], *, telemetry_running: bool,
                      telemetry_scope: str = "none") -> list[dict]:
    for row in rows:
        row["protection"] = protection_view(
            row, telemetry_running=telemetry_running,
            telemetry_scope=telemetry_scope)
    return rows