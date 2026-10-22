"""Adapter registry: agent type -> hook adapter.

Also the capability matrix entry point: which Agents this build can talk to,
and which hook config file each of them uses. Agents without an adapter
(Gemini CLI, OpenCode, unknown Agents) are discovered and monitored but cannot
be intercepted — the product says so instead of pretending otherwise.
"""
from __future__ import annotations

from agent_detector.hooks.adapters import ClaudeCodeAdapter, CodexAdapter, CursorAdapter

ADAPTERS = {
    "claude_code": ClaudeCodeAdapter(),
    "codex_cli": CodexAdapter(),
    "cursor": CursorAdapter(),
}


def get_adapter(agent_type: str):
    """Adapter for an agent type; accepts the detector rule id as-is."""
    key = (agent_type or "").strip().lower().replace("-", "_")
    adapter = ADAPTERS.get(key)
    if adapter is not None:
        return adapter
    # The detection rules use ids like `codex` / `claude-code`; normalize to the
    # adapter keys so an installed Agent is never reported as "unknown" just
    # because its rule id is spelled differently.
    aliases = {"codex": "codex_cli", "claude": "claude_code",
               "claude-code": "claude_code", "cursor_agent": "cursor"}
    return ADAPTERS.get(aliases.get(key, ""))


def adapter_specs() -> list[dict]:
    return [adapter.spec.__dict__ for adapter in ADAPTERS.values()]