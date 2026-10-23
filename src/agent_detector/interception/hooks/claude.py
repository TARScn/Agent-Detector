"""Claude Code hook adapter (design section 5.2).

Config: ``%USERPROFILE%\\.claude\\settings.json`` -> ``hooks.PreToolUse``.
Request payload carries ``hook_event_name``, ``tool_name``, ``tool_input``,
``session_id`` and ``cwd``. The decision is returned inline as
``hookSpecificOutput.permissionDecision`` with ``allow`` / ``ask`` / ``deny``.
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

_EVENT_MAP = {"pretooluse": HookEvent.PRE_TOOL_USE,
              "posttooluse": HookEvent.POST_TOOL_USE,
              "sessionstart": HookEvent.SESSION_START,
              "sessionend": HookEvent.SESSION_END,
              "notification": HookEvent.NOTIFICATION}


class ClaudeCodeAdapter:
    spec = HookSpec(
        agent_type="claude_code",
        display_name="Claude Code",
        vendor="Anthropic",
        config_path="~/.claude/settings.json",
        config_format="claude_settings",
        support=SupportLevel.P0,
        # Field names follow the Claude Code hooks reference; the exact
        # `onFailure` support depends on the installed version (>= 2.1.295).
        schema_verified=True,
        docs_url="https://code.claude.com/docs/en/hooks",
        notes="onFailure=block 需要 Claude Code v2.1.295+；更早版本请按审计模式运行。",
        events=(HookEvent.PRE_TOOL_USE, HookEvent.POST_TOOL_USE,
                HookEvent.SESSION_START, HookEvent.SESSION_END))

    def config_path(self, home: Path | None = None) -> Path:
        base = Path(home) if home else Path.home()
        return base / ".claude" / "settings.json"

    # -- payload -----------------------------------------------------------

    def parse(self, payload: dict) -> ToolCall | None:
        event = _EVENT_MAP.get(str(payload.get("hook_event_name", "")).lower())
        if event is None:
            return None
        if event is HookEvent.SESSION_START or event is HookEvent.SESSION_END:
            return ToolCall(agent_type=self.spec.agent_type, event_type=event,
                            tool_name="", tool_input={},
                            session_id=_session(payload), cwd=_cwd(payload),
                            agent_label=self.spec.display_name,
                            raw_event=str(payload.get("hook_event_name", "")))
        tool_input = payload.get("tool_input")
        merged_input = tool_input if isinstance(tool_input, dict) else {}
        # PostToolUse carries the result next to the input; keep it so the
        # service can tell "allowed" apart from "actually ran" (design §7).
        if payload.get("tool_response") is not None:
            merged_input = {**merged_input, "tool_response": payload["tool_response"]}
        return ToolCall(
            agent_type=self.spec.agent_type, event_type=event,
            tool_name=str(payload.get("tool_name") or payload.get("tool") or ""),
            tool_input=merged_input,
            session_id=_session(payload), cwd=_cwd(payload),
            agent_label=self.spec.display_name,
            raw_event=str(payload.get("hook_event_name", "")))

    # -- response ----------------------------------------------------------

    def response(self, verdict: PolicyVerdict, call: ToolCall | None = None) -> dict:
        event = (call.event_type if call else HookEvent.PRE_TOOL_USE)
        if event is not HookEvent.PRE_TOOL_USE:
            return {}
        return {"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": _DECISION_MAP.get(verdict.decision, "deny"),
            "permissionDecisionReason": f"[Agent Detector] {verdict.reason}"}}

    def failure_response(self, reason: str, *, fail_closed: bool) -> dict:
        decision = "deny" if fail_closed else "allow"
        return {"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": f"[Agent Detector] {reason}"}}

    # -- installation ------------------------------------------------------

    def install_fragment(self, command: str, *, timeout: float,
                         fail_closed: bool) -> dict:
        entry: dict = {"type": "command", "command": command,
                       "timeout": int(max(1, round(timeout)))}
        if fail_closed:
            entry["onFailure"] = "block"
        return {"matcher": "*", "hooks": [entry], MARKER: True}

    def owns_entry(self, entry: dict) -> bool:
        return bool(entry.get(MARKER)) or "hook_bridge" in str(
            entry.get("command", "")) or any(
            "hook_bridge" in str(item.get("command", ""))
            for item in entry.get("hooks", []) if isinstance(item, dict))


def _session(payload: dict) -> str | None:
    value = payload.get("session_id") or payload.get("sessionId")
    return str(value) if value else None


def _cwd(payload: dict) -> str | None:
    value = payload.get("cwd") or payload.get("working_directory")
    return str(value) if value else None