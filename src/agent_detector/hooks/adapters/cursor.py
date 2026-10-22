"""Cursor hook adapter (design section 5.4).

Config: ``%USERPROFILE%\\.cursor\\hooks.json`` with ``version: 1`` and event
lists named ``beforeShellExecution`` / ``beforeMCPExecution`` /
``beforeReadFile`` / ``preToolUse``. Entries accept ``failClosed`` so a broken
or timing-out hook does not silently become "allow".

Phase 1 wires ``beforeShellExecution`` and ``beforeMCPExecution`` (design
section 5.4). Cursor answers with ``permission`` plus optional ``user_message``
and ``agent_message``.
"""
from __future__ import annotations

from pathlib import Path

from agent_detector.domain.enums import Decision, HookEvent, SupportLevel
from agent_detector.domain.models import PolicyVerdict, ToolCall
from agent_detector.hooks.base import HookSpec
from agent_detector.hooks.installer_support import MARKER

# Cursor event name -> (normalized event, tool name used when none is supplied)
_EVENT_MAP = {
    "beforeshellexecution": (HookEvent.PRE_TOOL_USE, "shell"),
    "pretooluse": (HookEvent.PRE_TOOL_USE, ""),
    "beforemcpexecution": (HookEvent.PRE_TOOL_USE, "mcp"),
    "beforereadfile": (HookEvent.PRE_TOOL_USE, "read_file"),
}

_PERMISSION_MAP = {Decision.ALLOW: "allow", Decision.AUDIT: "allow",
                   Decision.ASK: "ask", Decision.DENY: "deny",
                   Decision.ERROR: "deny"}

MCP_EVENT = "beforeMCPExecution"
SHELL_EVENT = "beforeShellExecution"


class CursorAdapter:
    spec = HookSpec(
        agent_type="cursor",
        display_name="Cursor",
        vendor="Anysphere",
        config_path="~/.cursor/hooks.json",
        config_format="cursor_hooks",
        support=SupportLevel.P0,
        schema_verified=False,
        docs_url="https://cursor.com/docs/hooks",
        notes="首期只接入 beforeShellExecution / beforeMCPExecution；"
              "Cursor 内部未经过检查点的文件操作无法被前置阻断。",
        events=(HookEvent.PRE_TOOL_USE,))

    def config_path(self, home: Path | None = None) -> Path:
        base = Path(home) if home else Path.home()
        return base / ".cursor" / "hooks.json"

    def parse(self, payload: dict) -> ToolCall | None:
        name = str(payload.get("hook_event_name") or payload.get("event") or "").lower()
        mapped = _EVENT_MAP.get(name)
        if mapped is None:
            if not payload.get("command"):
                return None
            mapped = (HookEvent.PRE_TOOL_USE, "shell")
        event, default_tool = mapped
        tool_input: dict = {}
        for key in ("tool_input", "arguments"):
            value = payload.get(key)
            if isinstance(value, dict):
                tool_input.update(value)
        if payload.get("command"):
            tool_input.setdefault("command", str(payload["command"]))
        if payload.get("url"):
            tool_input.setdefault("url", str(payload["url"]))
        tool = str(payload.get("tool_name") or payload.get("tool") or default_tool)
        if event is HookEvent.PRE_TOOL_USE and not tool:
            tool = "shell" if tool_input.get("command") else (name or "tool")
        return ToolCall(agent_type=self.spec.agent_type, event_type=event,
                        tool_name=tool, tool_input=tool_input,
                        session_id=_first(payload, "conversation_id", "session_id"),
                        cwd=_first(payload, "cwd", "working_directory"),
                        agent_label=self.spec.display_name,
                        raw_event=str(payload.get("hook_event_name", "")))

    def response(self, verdict: PolicyVerdict, call: ToolCall | None = None) -> dict:
        permission = _PERMISSION_MAP.get(verdict.decision, "deny")
        body: dict = {"permission": permission,
                      "agent_message": f"[Agent Detector] {verdict.reason}"}
        if permission in ("deny", "ask"):
            body["user_message"] = (f"Agent Detector 判定该操作风险为 "
                                    f"{verdict.risk.value}：{verdict.reason}")
        return body

    def failure_response(self, reason: str, *, fail_closed: bool) -> dict:
        return {"permission": "deny" if fail_closed else "allow",
                "user_message": f"Agent Detector 决策服务不可用：{reason}",
                "agent_message": f"[Agent Detector] {reason}"}

    def install_fragment(self, command: str, *, timeout: float,
                         fail_closed: bool) -> dict:
        return {"command": command, "timeout": int(max(1, round(timeout))),
                "failClosed": bool(fail_closed), MARKER: True}

    def owns_entry(self, entry: dict) -> bool:
        return bool(entry.get(MARKER)) or "hook_bridge" in str(entry.get("command", ""))


def _first(payload: dict, *keys: str) -> str | None:
    for key in keys:
        value = payload.get(key)
        if value:
            return str(value)
    return None