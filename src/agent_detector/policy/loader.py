"""Policy file loading with the same conventions as the detection rules.

Packaged defaults live in ``policy/rules/``; ``AGENT_DETECTOR_POLICY_DIR`` (or
an explicit ``extra_dir``) can add or replace files by name. A malformed file
never aborts the whole set: it is reported in ``errors`` and the remaining
policies still apply.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import ValidationError

from agent_detector.policy.schema import PolicySet, RuleSetDefaults

POLICY_DIR_ENV = "AGENT_DETECTOR_POLICY_DIR"


@dataclass(frozen=True)
class PolicyError:
    file: str
    error: str


@dataclass
class LoadedPolicies:
    ruleset: PolicySet = field(default_factory=lambda: PolicySet(
        kind="policy_set", defaults=RuleSetDefaults()))
    errors: list[dict[str, str]] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    @property
    def rules(self):
        return self.ruleset.rules


def packaged_policy_dir() -> Path:
    return Path(__file__).resolve().parent / "rules"


def load_policies(extra_dir: Path | str | None = None) -> LoadedPolicies:
    directory = Path(extra_dir) if extra_dir else (
        Path(os.environ[POLICY_DIR_ENV]) if os.getenv(POLICY_DIR_ENV) else None)
    loaded = LoadedPolicies()
    files: list[Path] = []
    packaged = packaged_policy_dir()
    if packaged.is_dir():
        files.extend(sorted(packaged.glob("*.y*ml")))
    if directory and directory.is_dir():
        overrides = {path.name for path in directory.glob("*.y*ml")}
        files = [path for path in files if path.name not in overrides]
        files.extend(sorted(directory.glob("*.y*ml")))
    rules: list = []
    for path in files:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if not isinstance(raw, dict) or raw.get("kind") != "policy_set":
                continue  # not every YAML in the directory is a policy file
            parsed = PolicySet.model_validate(raw)
        except (OSError, yaml.YAMLError, ValidationError) as exc:
            loaded.errors.append({"file": path.name, "error": str(exc)})
            continue
        rules.extend(parsed.rules)
        loaded.sources.append(str(path))
    merged = PolicySet(kind="policy_set", rules=rules)
    if files:
        try:
            first = yaml.safe_load(files[0].read_text(encoding="utf-8")) or {}
            if isinstance(first, dict) and "defaults" in first:
                merged.defaults = PolicySet.model_validate(first).defaults
        except (OSError, yaml.YAMLError, ValidationError):
            pass
    loaded.ruleset = merged
    return loaded