"""Agent capability matrix (design section 1.2).

The matrix is data, not code: what each Agent is planned to support, which hook
adapter serves it, and the caveats that must be shown next to it. The UI uses it
to label every Agent honestly — 已启用 / 仅审计 / 待适配 — instead of implying
that detection and protection are the same thing.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

AGENTS_FILE_ENV = "AGENT_DETECTOR_AGENTS_FILE"
DEFAULT_UNKNOWN_ID = "unknown_agent"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class AgentEntry(_Strict):
    id: str
    name: str
    vendor: str = ""
    aliases: list[str] = Field(default_factory=list)
    discovery: str = "P2"
    monitor: str = "P2"
    protect: str = "PLANNED"
    hook: str | None = None
    docs: str = ""
    notes: list[str] = Field(default_factory=list)

    def capabilities(self) -> dict[str, str]:
        return {"discovery": self.discovery, "monitor": self.monitor,
                "protect": self.protect}

    def aliases_lower(self) -> tuple[str, ...]:
        return tuple(alias.lower() for alias in [self.id, self.name, *self.aliases])


class AgentMatrix(_Strict):
    kind: Literal["agent_matrix"]
    revision: int = 1
    agents: list[AgentEntry] = Field(default_factory=list)


@dataclass
class LoadedMatrix:
    matrix: AgentMatrix = field(default_factory=lambda: AgentMatrix(
        kind="agent_matrix"))
    errors: list[dict[str, str]] = field(default_factory=list)
    source: str = ""

    def for_type(self, agent_type: str) -> AgentEntry | None:
        """Look up by rule id, display name or alias (case-insensitive)."""
        key = (agent_type or "").strip().lower()
        if not key:
            return None
        normalized = key.replace("-", "_")
        for entry in self.matrix.agents:
            if entry.id.replace("-", "_") == normalized:
                return entry
        for entry in self.matrix.agents:
            if key in entry.aliases_lower():
                return entry
        return None

    def unknown(self) -> AgentEntry | None:
        return self.for_type(DEFAULT_UNKNOWN_ID)


def packaged_matrix_file() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "agents.yaml"


def load_agent_matrix(path: Path | str | None = None) -> LoadedMatrix:
    """Load the matrix; a broken file degrades to 'unknown Agent' semantics."""
    target = Path(path) if path else (
        Path(os.environ[AGENTS_FILE_ENV]) if os.getenv(AGENTS_FILE_ENV)
        else packaged_matrix_file())
    if not target.is_file():
        return LoadedMatrix(errors=[{"file": str(target), "error": "文件不存在"}])
    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
        matrix = AgentMatrix.model_validate(raw)
    except Exception as exc:  # noqa: BLE001 - surfaced through the status API
        return LoadedMatrix(errors=[{"file": str(target), "error": str(exc)}],
                            source=str(target))
    return LoadedMatrix(matrix=matrix, source=str(target))