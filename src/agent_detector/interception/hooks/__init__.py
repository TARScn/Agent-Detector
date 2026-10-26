"""Hook adapters, installer and event normalization for supported Agent clients."""

from agent_detector.interception.hooks.claude import ClaudeCodeAdapter
from agent_detector.interception.hooks.codex import CodexAdapter
from agent_detector.interception.hooks.cursor import CursorAdapter

__all__ = ["ClaudeCodeAdapter", "CodexAdapter", "CursorAdapter"]
