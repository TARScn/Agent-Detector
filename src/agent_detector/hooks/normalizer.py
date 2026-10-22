"""Normalizer: raw hook payload in, normalized tool call out (design §5.5).

The policy engine never learns which Agent produced a call; everything that is
platform-specific stops here. Payloads that do not identify their Agent are
detected from their own shape (Claude Code, Codex and Cursor differ enough to
tell apart), so the bridge can stay a dumb pipe.
"""
from __future__ import annotations

from agent_detector.domain.enums import HookEvent
from agent_detector.domain.models import ToolCall
from agent_detector.hooks.registry import get_adapter


def detect_agent_type(payload: dict) -> str | None:
    """Best-effort Agent identification from a hook payload."""
    if not isinstance(payload, dict):
        return None
    hints = " ".join(str(key) for key in payload).lower()
    event = str(payload.get("hook_event_name") or payload.get("event") or "").lower()
    if "agent_type" in payload:
        return str(payload["agent_type"])
    if event.startswith("before") or "conversation_id" in hints:
        return "cursor"
    if "command_windows" in hints or "approval_policy" in hints:
        return "codex_cli"
    if "permission_mode" in hints or "transcript_path" in hints:
        return "claude_code"
    if event in ("pretooluse", "posttooluse"):
        if payload.get("tool_name") in ("Bash", "Read", "Write", "Edit", "Glob", "Grep"):
            return "claude_code"
        return "codex_cli"
    return None


def normalize(agent_type: str, payload: dict) -> ToolCall | None:
    """Normalize one payload; returns None when the event is not a tool call."""
    adapter = get_adapter(agent_type)
    if adapter is None:
        return None
    return adapter.parse(payload)


def describe_event(call: ToolCall) -> tuple[str, str]:
    """(operation, target) summary used by the event feed and the audit record."""
    if call.event_type is HookEvent.SESSION_START:
        return "session.start", call.cwd or ""
    if call.event_type is HookEvent.SESSION_END:
        return "session.end", call.cwd or ""
    tool = (call.tool_name or "tool").strip()
    normalized = tool.lower()
    command = call.command
    if normalized in ("bash", "shell", "powershell", "cmd", "local_shell",
                      "execute_command", "run_command") and command:
        return "shell.exec", command
    if normalized in ("read", "read_file", "get_file_contents"):
        return "file.read", _first_path(call)
    if normalized in ("write", "create_file", "str_replace_editor"):
        return "file.write", _first_path(call)
    if normalized in ("edit", "multiedit", "replace_string_in_file", "apply_patch"):
        return "file.edit", _first_path(call)
    if normalized.startswith("mcp__") or normalized == "mcp":
        return "mcp.call", tool
    if normalized in ("webfetch", "web_fetch", "fetch", "browse"):
        return "network.fetch", str(call.tool_input.get("url", ""))
    return f"tool.{normalized}" if normalized else "tool.call", _first_path(call)


def _first_path(call: ToolCall) -> str:
    for key in ("file_path", "filepath", "path", "notebook_path", "url"):
        value = call.tool_input.get(key)
        if isinstance(value, str) and value:
            return value
    return ""