"""Agent hook adapters, one module per Agent (design section 5.5)."""
from agent_detector.hooks.adapters.claude import ClaudeCodeAdapter
from agent_detector.hooks.adapters.codex import CodexAdapter
from agent_detector.hooks.adapters.cursor import CursorAdapter

__all__ = ["ClaudeCodeAdapter", "CodexAdapter", "CursorAdapter"]