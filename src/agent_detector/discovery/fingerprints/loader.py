"""Loads declarative rule files for the detection engine.

Rule sources, in order: the YAML files packaged under fingerprints/rules/,
then AGENT_DETECTOR_RULES_DIR (or an explicit extra_dir). A client rule in a
later directory with the same id replaces the packaged one; signature rules
accumulate. A broken file is recorded as an error and skipped — it never
brings the scanner down (plan section 8.1).
"""
import logging
import os
from dataclasses import dataclass, field
from importlib.resources import files as resource_files
from pathlib import Path
from typing import Any

import yaml

from agent_detector.discovery.fingerprints.schema import ClientRule, FrameworkRule, SignatureRule

logger = logging.getLogger(__name__)

RULES_DIR_ENV = "AGENT_DETECTOR_RULES_DIR"


@dataclass(frozen=True)
class RuleError:
    file: str
    error: str


@dataclass
class LoadedRules:
    client_rules: list[ClientRule] = field(default_factory=list)
    framework_rules: list[FrameworkRule] = field(default_factory=list)
    signature_rules: list[SignatureRule] = field(default_factory=list)
    errors: list[RuleError] = field(default_factory=list)


def packaged_rules_dir():
    return resource_files("agent_detector.discovery").joinpath("data/fingerprints")


def load_rules(extra_dir: Path | str | None = None) -> LoadedRules:
    sources: list[Any] = [packaged_rules_dir()]
    env_dir = os.getenv(RULES_DIR_ENV)
    if env_dir:
        sources.append(Path(env_dir))
    if extra_dir:
        sources.append(Path(extra_dir))

    client: dict[str, ClientRule] = {}
    frameworks: dict[str, FrameworkRule] = {}
    signatures: list[SignatureRule] = []
    errors: list[RuleError] = []
    for source in sources:
        for file in _yaml_files(source):
            data = _read(file)
            if isinstance(data, RuleError):
                errors.append(data)
                continue
            try:
                kind = data.get("kind")
                if kind == "client_rule":
                    rule = ClientRule.model_validate(data)
                    client[rule.id] = rule
                elif kind == "framework_rule":
                    rule = FrameworkRule.model_validate(data)
                    frameworks[rule.id] = rule
                elif kind == "signature_set":
                    from agent_detector.discovery.fingerprints.schema import SignatureSet
                    signatures.extend(SignatureSet.model_validate(data).rules)
                else:
                    errors.append(RuleError(str(file), f"unknown kind {kind!r}"))
            except Exception as exc:
                errors.append(RuleError(str(file), str(exc)))
    for error in errors:
        logger.warning("rule file skipped: %s: %s", error.file, error.error)
    return LoadedRules(client_rules=list(client.values()),
                       framework_rules=list(frameworks.values()),
                       signature_rules=signatures, errors=errors)


def _yaml_files(rules_dir) -> list:
    try:
        entries = sorted(rules_dir.iterdir(), key=lambda p: getattr(p, "name", str(p)))
    except (OSError, FileNotFoundError):
        return []
    return [entry for entry in entries
            if str(entry).lower().endswith((".yaml", ".yml"))]


def _read(file) -> Any | RuleError:
    try:
        return yaml.safe_load(file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        return RuleError(str(file), f"unreadable: {exc}")
    except yaml.YAMLError as exc:
        return RuleError(str(file), f"invalid YAML: {exc}")
