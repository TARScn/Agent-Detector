"""High-level behavior rules: declarative mapping from facts to agent behaviors.

Mirrors the llm_apis loader conventions: pydantic strict validation, external
directory override via ``AGENT_DETECTOR_BEHAVIOR_RULES_DIR``, broken files are
reported and the packaged file is used instead. Rules match in file order —
specific rules first, catch-alls last; the first match wins.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent_detector.behavior.audit.normalizer import FACT_KINDS, BehaviorFact

logger = logging.getLogger(__name__)

_RULES_FILENAME = "behaviors.yaml"
_PACKAGED_DIR = Path(__file__).parent / "rules"

_Deriver = Literal["none", "script_path", "git_subcommand", "argv_join", "exec_basename"]
_Confidence = Literal["high", "medium", "low"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class WhenSpec(_Strict):
    kind: str
    executable_names: list[str] = Field(default_factory=list)
    cmdline_tokens: list[str] = Field(default_factory=list)

    @field_validator("kind")
    @classmethod
    def _known_kind(cls, value: str) -> str:
        if value not in FACT_KINDS:
            raise ValueError(f"unknown fact kind: {value}")
        return value

    @field_validator("executable_names", "cmdline_tokens")
    @classmethod
    def _lower(cls, value: list[str]) -> list[str]:
        return [item.strip().lower() for item in value if item.strip()]


class DeriveSpec(_Strict):
    target: _Deriver = "none"
    detail: _Deriver = "none"


class BehaviorRuleSpec(_Strict):
    id: str
    when: WhenSpec
    derive: DeriveSpec = Field(default_factory=DeriveSpec)
    confidence: _Confidence = "high"


class BehaviorRuleSet(_Strict):
    revision: int = 1
    rules: list[BehaviorRuleSpec] = Field(default_factory=list)

    @classmethod
    def parse(cls, path: Path) -> "BehaviorRuleSet":
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("rule file must be a mapping")
        return cls.model_validate(raw)


class LoadedBehaviorRules:
    def __init__(self, rules: BehaviorRuleSet, errors: list[dict[str, str]]):
        self.rules = rules
        self.errors = errors


@dataclass(frozen=True)
class DerivedBehavior:
    operation: str
    confidence: str
    rule_id: str
    target: str | None = None
    detail: str | None = None


def load_behavior_rules(extra_dir: Path | str | None = None) -> LoadedBehaviorRules:
    errors: list[dict[str, str]] = []
    rules: BehaviorRuleSet | None = None
    source = Path(extra_dir) if extra_dir else None
    if source is None:
        import os

        env_dir = os.getenv("AGENT_DETECTOR_BEHAVIOR_RULES_DIR", "").strip()
        if env_dir:
            source = Path(env_dir)
    if source is not None:
        path = source / _RULES_FILENAME
        try:
            rules = BehaviorRuleSet.parse(path)
        except Exception as exc:  # noqa: BLE001 - a broken override must not break startup
            errors.append({"file": str(path), "error": str(exc)})
            logger.warning("behavior rule override unreadable: %s", exc)
            rules = None
    if rules is None:
        path = _PACKAGED_DIR / _RULES_FILENAME
        try:
            rules = BehaviorRuleSet.parse(path)
        except Exception as exc:  # noqa: BLE001
            errors.append({"file": str(path), "error": str(exc)})
            logger.error("packaged behavior rules unreadable: %s", exc)
            rules = BehaviorRuleSet()
    return LoadedBehaviorRules(rules, errors)


_WINDOWS_EXE_SUFFIXES = (".exe", ".cmd", ".bat", ".ps1", ".com")


def _basename(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1]


def _strip_windows_suffix(name: str) -> str:
    """python.exe / git.cmd match the same rules as python / git."""
    for suffix in _WINDOWS_EXE_SUFFIXES:
        if name.endswith(suffix) and len(name) > len(suffix):
            return name[: -len(suffix)]
    return name


_INLINE_FLAGS = {"-c", "--eval", "-e"}


def derive_script_path(fact: BehaviorFact) -> str | None:
    args = list(fact.argv[1:])
    if not args:
        exe = fact.exe or (fact.argv[0] if fact.argv else "")
        return _basename(exe) or None
    if args[0] in _INLINE_FLAGS:
        return "inline"  # the inline program text itself is never stored
    if args[0] == "-m" and len(args) > 1:
        return f"-m {args[1]}"
    for arg in args:
        if not arg.startswith("-"):
            return arg
    return _basename(fact.exe or "") or None


def derive_git_subcommand(fact: BehaviorFact) -> str | None:
    if len(fact.argv) > 1 and not fact.argv[1].startswith("-"):
        return fact.argv[1]
    return "git"


def derive_argv_join(fact: BehaviorFact) -> str | None:
    parts = list(fact.argv[:2]) if fact.argv else [_basename(fact.exe or "")]
    joined = " ".join(part for part in parts if part)
    return joined or None


def derive_exec_basename(fact: BehaviorFact) -> str | None:
    if fact.argv:
        return _basename(fact.argv[0]) or None
    if fact.exe:
        return _basename(fact.exe) or None
    return None


_DERIVERS: dict[str, Callable[[BehaviorFact], str | None]] = {
    "none": lambda fact: None,
    "script_path": derive_script_path,
    "git_subcommand": derive_git_subcommand,
    "argv_join": derive_argv_join,
    "exec_basename": derive_exec_basename,
}


def _executable_name(fact: BehaviorFact) -> str:
    if fact.argv:
        return _strip_windows_suffix(_basename(fact.argv[0]).lower())
    if fact.exe:
        return _strip_windows_suffix(_basename(fact.exe).lower())
    return _strip_windows_suffix((fact.process_name or "").lower())


def match_fact(fact: BehaviorFact, rules: BehaviorRuleSet) -> DerivedBehavior | None:
    for rule in rules.rules:
        spec = rule.when
        if spec.kind != fact.kind:
            continue
        if spec.executable_names and _executable_name(fact) not in set(spec.executable_names):
            continue
        if spec.cmdline_tokens:
            text = " ".join((fact.exe or "", *fact.argv)).lower()
            if not any(token in text for token in spec.cmdline_tokens):
                continue
        return DerivedBehavior(operation=rule.id, confidence=rule.confidence,
                               rule_id=rule.id,
                               target=_DERIVERS[rule.derive.target](fact),
                               detail=_DERIVERS[rule.derive.detail](fact))
    return None