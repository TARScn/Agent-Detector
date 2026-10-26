"""Codex CLI hook adapter (design section 5.3).

Config: ``%USERPROFILE%\\.codex\\hooks.json`` with a ``command_windows`` entry
so the same hook works on Windows. Codex ships a PreToolUse lifecycle hook
covering shell, ``apply_patch``, MCP and other local tools.

**Schema status: unverified.** The OpenAI hook schema is versioned, and this
adapter has not been checked against an installed Codex build — the UI reports
it as 待验证 (``schema_verified = False``) and the installer writes a fragment
only after the operator confirms the shape. Treat the response body below as
the shape to *verify*, not as a guarantee.
"""
from __future__ import annotations

from pathlib import Path

from agent_detector.core.enums import Decision, HookEvent, SupportLevel
from agent_detector.core.models import PolicyVerdict, ToolCall
from agent_detector.interception.hooks.base import HookSpec
from agent_detector.interception.hooks.installer_support import MARKER

_DECISION_MAP = {Decision.ALLOW: "allow", Decision.AUDIT: "allow",
                 Decision.ASK: "ask", Decision.DENY: "deny",
                 Decision.ERROR: "deny"}


class CodexAdapter:
    spec = HookSpec(
        agent_type="codex_cli",
        display_name="Codex CLI",
        vendor="OpenAI",
        config_path="~/.codex/hooks.json",
        config_format="codex_hooks",
        support=SupportLevel.P0,
        schema_verified=False,
        docs_url="https://developers.openai.com/codex/hooks",
        notes="Hook Schema 随版本变化：响应字段需按已安装版本核对；"
              "Codex 官方说明部分执行路径可能绕过 Hook，不能当作完整安全边界。",
        events=(HookEvent.PRE_TOOL_USE,))

    def config_path(self, home: Path | None = None) -> Path:
        base = Path(home) if home else Path.home()
        return base / ".codex" / "hooks.json"

    def parse(self, payload: dict) -> ToolCall | None:
        event = str(payload.get("hook_event_name") or payload.get("event") or "").lower()
        if event and event not in ("pretooluse", "pre_tool_use", "tool_call"):
            return None
        tool_input = payload.get("tool_input") or payload.get("arguments") or {}
        if not isinstance(tool_input, dict):
            tool_input = {"input": tool_input}
        command = payload.get("command")
        if command and "command" not in tool_input:
            tool_input = {**tool_input, "command": str(command)}
        tool = payload.get("tool_name") or payload.get("tool") or (
            "shell" if command else "")
        if not tool:
            return None
        return ToolCall(agent_type=self.spec.agent_type,
                        event_type=HookEvent.PRE_TOOL_USE, tool_name=str(tool),
                        tool_input=tool_input,
                        session_id=_first(payload, "session_id", "conversation_id"),
                        cwd=_first(payload, "cwd", "working_directory"),
                        agent_label=self.spec.display_name,
                        raw_event=str(payload.get("hook_event_name", "PreToolUse")))

    def response(self, verdict: PolicyVerdict, call: ToolCall | None = None) -> dict:
        return {"decision": _DECISION_MAP.get(verdict.decision, "deny"),
                "reason": f"[Agent Detector] {verdict.reason}"}

    def failure_response(self, reason: str, *, fail_closed: bool) -> dict:
        return {"decision": "deny" if fail_closed else "allow",
                "reason": f"[Agent Detector] {reason}"}

    def install_fragment(self, command: str, *, timeout: float,
                         fail_closed: bool) -> dict:
        return {"type": "command", "command": command,
                "command_windows": command,
                "timeout": int(max(1, round(timeout))),
                "failClosed": bool(fail_closed), MARKER: True}

    def owns_entry(self, entry: dict) -> bool:
        if entry.get(MARKER):
            return True
        text = f"{entry.get('command', '')} {entry.get('command_windows', '')}"
        for item in entry.get("hooks", []) if isinstance(entry.get("hooks"), list) else []:
            if isinstance(item, dict):
                text += f" {item.get('command', '')} {item.get('command_windows', '')}"
        return "hook_bridge" in text


def _first(payload: dict, *keys: str) -> str | None:
    for key in keys:
        value = payload.get(key)
        if value:
            return str(value)
    return None