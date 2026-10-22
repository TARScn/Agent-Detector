"""Declarative intelligence rules for network behavior matching (plan §3.1.4).

Same philosophy as fingerprints/rules: YAML is the source of truth, pydantic
validates strictly, a broken file is skipped with a warning instead of
crashing, and AGENT_DETECTOR_BEHAVIOR_RULES_DIR can override the packaged
rules with a directory containing llm_apis.yaml.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

logger = logging.getLogger(__name__)

_RULES_FILENAME = "llm_apis.yaml"
_PACKAGED_DIR = Path(__file__).parent / "rules"


class ModelPort(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    port: int = Field(ge=1, le=65535)
    name: str


class BehaviorRules(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    revision: int = 1
    known_llm_hosts: tuple[str, ...] = ()
    known_model_ports: tuple[ModelPort, ...] = ()

    @field_validator("known_llm_hosts")
    @classmethod
    def _normalize_hosts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        # Exact lowercase host matching; rstrip one trailing dot (FQDN form).
        return tuple(sorted({h.strip().lower().rstrip(".") for h in value if h.strip()}))

    @classmethod
    def parse(cls, path: Path) -> "BehaviorRules":
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("rule file must be a mapping")
        return cls.model_validate(raw)

    def model_port_name(self, port: int) -> str | None:
        for entry in self.known_model_ports:
            if entry.port == port:
                return entry.name
        return None


class LoadedRules:
    """Validated rules plus non-fatal load errors (mirrors fingerprints loader)."""

    def __init__(self, rules: BehaviorRules, errors: list[dict[str, str]]):
        self.rules = rules
        self.errors = errors


def load_rules(extra_dir: Path | str | None = None) -> LoadedRules:
    errors: list[dict[str, str]] = []
    rules: BehaviorRules | None = None
    source = Path(extra_dir) if extra_dir else None
    if source is None:
        env_dir = os.getenv("AGENT_DETECTOR_BEHAVIOR_RULES_DIR", "").strip()
        source = Path(env_dir) if env_dir else None
    if source is not None:
        path = source / _RULES_FILENAME
        try:
            rules = BehaviorRules.parse(path)
        except Exception as exc:  # isolated: bad external file falls back below
            errors.append({"file": str(path), "error": str(exc)})
            logger.warning("behavior rules %s skipped: %s", path, exc)
    if rules is None:
        path = _PACKAGED_DIR / _RULES_FILENAME
        try:
            rules = BehaviorRules.parse(path)
        except Exception as exc:  # never crash the monitor over rules
            errors.append({"file": str(path), "error": str(exc)})
            logger.error("packaged behavior rules unreadable: %s", exc)
            rules = BehaviorRules()
    return LoadedRules(rules, errors)
