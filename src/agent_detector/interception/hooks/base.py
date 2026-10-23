"""Adapter contract shared by every Agent's native hook integration (§5.5).

One normalizer, one policy engine, three (later more) response formats. An
adapter owns exactly two platform-specific things: how a raw hook payload maps
onto a :class:`ToolCall`, and how a verdict is rendered back into the JSON that
Agent understands. It never decides anything itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from agent_detector.core.enums import HookEvent, HookState, SupportLevel
from agent_detector.core.models import PolicyVerdict, ToolCall


@dataclass(frozen=True)
class HookSpec:
    """Static description of one Agent's hook interface."""

    agent_type: str
    display_name: str
    vendor: str
    config_path: str            # "~/..." relative to the target user's home
    config_format: str          # "claude_settings" | "codex_hooks" | "cursor_hooks"
    support: SupportLevel
    schema_verified: bool       # True only when checked against a real install
    docs_url: str = ""
    notes: str = ""
    events: tuple[HookEvent, ...] = (HookEvent.PRE_TOOL_USE,)


@dataclass
class HookInstallation:
    """Observed state of one Agent's hook configuration on this machine."""

    agent_type: str
    display_name: str
    config_path: Path
    state: HookState
    support: SupportLevel
    schema_verified: bool
    entries: int = 0
    notes: list[str] = field(default_factory=list)
    """What the *check* found (partial wiring, unverified schema, parse errors)."""
    spec_notes: list[str] = field(default_factory=list)
    """Documentation for the adapter itself; shown on the settings page."""

    def to_dict(self) -> dict:
        return {"agent_type": self.agent_type, "display_name": self.display_name,
                "config_path": str(self.config_path), "state": self.state.value,
                "support": self.support.value,
                "schema_verified": self.schema_verified,
                "entries": self.entries, "notes": list(self.notes),
                "spec_notes": list(self.spec_notes)}


@runtime_checkable
class HookAdapter(Protocol):
    """Platform bridge for one Agent."""

    spec: HookSpec

    @property
    def agent_type(self) -> str:
        return self.spec.agent_type

    def config_path(self, home: Path | None = None) -> Path:
        """Resolve the hook configuration file for ``home`` (default: current user)."""
        ...

    def parse(self, payload: dict) -> ToolCall | None:
        """Normalize a raw hook payload; None when the event is not a tool call."""
        ...

    def response(self, verdict: PolicyVerdict, call: ToolCall | None = None) -> dict:
        """Render the verdict in the platform's own response shape."""
        ...

    def failure_response(self, reason: str, *, fail_closed: bool) -> dict:
        """Response used when the decision service could not be reached."""
        ...

    def install_fragment(self, command: str, *, timeout: float,
                         fail_closed: bool) -> dict:
        """Config fragment to merge into this Agent's hook settings."""
        ...

    def owns_entry(self, entry: dict) -> bool:
        """True when a config entry was written by Agent Detector."""
        ...


def read_config(path: Path) -> tuple[dict | None, str | None]:
    """Load a hook config file: (data, error). Missing file -> ({}, None)."""
    import json

    if not path.exists():
        return {}, None
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"无法读取配置：{exc}"
    if not raw.strip():
        return {}, None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"配置不是合法 JSON：{exc}"
    if not isinstance(data, dict):
        return None, "配置根节点不是对象"
    return data, None