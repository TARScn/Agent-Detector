"""Deterministic policy engine (design section 6.2).

Rules are evaluated in priority order and the first enabled match decides. No
model is consulted: a tool call must never wait on an LLM decision, and an
unavailable model must never change the verdict (design section 6.2). The
engine is pure — it receives a normalized :class:`ToolCall` and returns a
:class:`PolicyVerdict`; persistence, event recording and platform-specific
response shaping happen outside it.
"""
from __future__ import annotations

import logging
import re

from agent_detector.core.config import HOOK_FAILURE_MODE
from agent_detector.core.enums import Decision, RiskLevel
from agent_detector.core.models import PolicyVerdict, ToolCall
from agent_detector.interception.policy.loader import LoadedPolicies, load_policies
from agent_detector.core.paths import (candidates_from_command, is_inside, match_path,
                                           path_related)
from agent_detector.interception.policy.schema import MatchSpec, PolicyRule, PolicySet

logger = logging.getLogger(__name__)

_RISK_ORDER = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2,
               RiskLevel.CRITICAL: 3}
_MATCH_RECORD_LIMIT = 3


def risk_at_least(risk: str, threshold: str) -> bool:
    """True when ``risk`` is at or above ``threshold`` (unknown names sort low)."""
    def rank(value: str) -> int:
        try:
            return _RISK_ORDER[RiskLevel(value)]
        except ValueError:
            return -1
    return rank(risk) >= rank(threshold) >= 0


class PolicyEngine:
    """Evaluates normalized tool calls against the loaded policy set."""

    def __init__(self, ruleset: PolicySet, *, overrides: dict[str, dict] | None = None,
                 failure_mode: str | None = None):
        self.ruleset = ruleset
        self.overrides = overrides or {}
        self.failure_mode = (failure_mode or HOOK_FAILURE_MODE).lower()
        self._compiled: dict[str, tuple[re.Pattern, ...]] = {}

    @classmethod
    def from_config(cls, *, extra_dir=None, overrides: dict[str, dict] | None = None,
                    failure_mode: str | None = None) -> "PolicyEngine":
        return cls(load_policies(extra_dir).ruleset, overrides=overrides,
                   failure_mode=failure_mode)

    # -- introspection -----------------------------------------------------

    def rules(self) -> list[PolicyRule]:
        return list(self.ruleset.rules)

    def defaults(self) -> tuple[Decision, RiskLevel, str]:
        defaults = self.ruleset.defaults
        return defaults.decision, defaults.risk, defaults.reason

    # -- evaluation --------------------------------------------------------

    def decide(self, call: ToolCall) -> PolicyVerdict:
        """First enabled matching rule wins; later matches are kept for the record."""
        matched: list[str] = []
        for rule in self.ruleset.rules:
            if len(matched) >= _MATCH_RECORD_LIMIT:
                break
            if not self._enabled(rule) or not self._matches(rule, call):
                continue
            matched.append(rule.id)
        if not matched:
            decision, risk, reason = self.defaults()
            return PolicyVerdict(decision=decision, risk=risk, reason=reason)
        rule = next(item for item in self.ruleset.rules if item.id == matched[0])
        return PolicyVerdict(
            decision=self._decision(rule), risk=rule.risk,
            reason=rule.reason or rule.name or rule.description,
            matched_rules=tuple(matched), policy_id=rule.id)

    def decide_error(self, reason: str) -> PolicyVerdict:
        """Verdict used when the engine or its caller failed.

        ``block`` (default) keeps the failure closed — a broken decision service
        must not silently hand an Agent unrestricted execution; ``allow`` is the
        audit-mode behaviour and says so in the reason.
        """
        if self.failure_mode == "allow":
            return PolicyVerdict(decision=Decision.ALLOW, risk=RiskLevel.MEDIUM,
                                 reason=f"策略引擎异常，按审计模式放行：{reason}",
                                 error=reason)
        return PolicyVerdict(decision=Decision.DENY, risk=RiskLevel.HIGH,
                             reason=f"策略引擎异常，按故障关闭策略阻断：{reason}",
                             error=reason)

    # -- per-rule introspection (console policy page, CLI `policy list`) -----

    def rule_enabled(self, rule: PolicyRule) -> bool:
        """Effective enabled state after operator overrides."""
        return self._enabled(rule)

    def rule_decision(self, rule: PolicyRule) -> Decision:
        """Effective decision after operator overrides."""
        return self._decision(rule)

    # -- internals ---------------------------------------------------------

    def _enabled(self, rule: PolicyRule) -> bool:
        override = self.overrides.get(rule.id)
        if override is None:
            return rule.enabled
        return bool(override.get("enabled", rule.enabled))

    def _decision(self, rule: PolicyRule) -> Decision:
        override = self.overrides.get(rule.id)
        if override and override.get("decision"):
            try:
                return Decision(override["decision"])
            except ValueError:
                logger.warning("ignoring unknown decision override %r for %s",
                               override["decision"], rule.id)
        return rule.decision

    def _patterns(self, rule: PolicyRule, field: str) -> tuple[re.Pattern, ...]:
        key = f"{rule.id}:{field}"
        compiled = self._compiled.get(key)
        if compiled is None:
            compiled = tuple(re.compile(pattern, re.IGNORECASE)
                             for pattern in getattr(rule.match, field))
            self._compiled[key] = compiled
        return compiled

    def _matches(self, rule: PolicyRule, call: ToolCall) -> bool:
        spec: MatchSpec = rule.match
        tool = (call.tool_name or "").lower()
        if spec.agent_types and call.agent_type.lower() not in spec.agent_types:
            return False
        if spec.tools and tool not in spec.tools:
            return False
        if spec.tool_args:
            keys = {str(key).lower() for key in call.tool_input}
            if not keys.intersection(spec.tool_args):
                return False
        command = call.command or ""
        lowered = command.lower()
        if spec.command_contains and not any(item in lowered
                                             for item in spec.command_contains):
            return False
        if spec.command_not_contains and any(item in lowered
                                             for item in spec.command_not_contains):
            return False
        if spec.command_patterns and not any(
                pattern.search(command) for pattern in self._patterns(rule, "command_patterns")):
            return False
        if spec.text_patterns:
            blob = call.text_blob()
            if not any(pattern.search(blob)
                       for pattern in self._patterns(rule, "text_patterns")):
                return False
        if spec.path_patterns and not self._path_hit(spec.path_patterns, call, command):
            return False
        if spec.outside_cwd and not _outside_cwd(call, command):
            return False
        if spec.cwd_patterns and not any(match_path(pattern, call.cwd or "")
                                         for pattern in spec.cwd_patterns):
            return False
        return True

    def _path_hit(self, patterns: list[str], call: ToolCall, command: str) -> bool:
        """Check declared paths, then path-looking tokens of the command.

        Command scanning is what makes a rule like "protected directory" work
        when the Agent passes a whole shell line instead of a file argument.
        """
        for value in _declared_paths(call):
            if any(match_path(pattern, value) for pattern in patterns):
                return True
        for token in candidates_from_command(command):
            if any(path_related(pattern, token) for pattern in patterns):
                return True
        return False


_PATH_KEYS = ("file_path", "filepath", "path", "paths", "target", "target_file",
              "directory", "dir", "cwd", "notebook_path", "pattern")


def _declared_paths(call: ToolCall) -> list[str]:
    values: list[str] = []
    for key in _PATH_KEYS:
        value = call.tool_input.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value)
        elif isinstance(value, list):
            values.extend(item for item in value if isinstance(item, str))
    return values


def _outside_cwd(call: ToolCall, command: str) -> bool:
    """True when every path the call mentions is outside the session directory.

    Requires at least one path *and* a known working directory — "we could not
    tell" must never be reported as "outside", or every unparsed command would
    match a rule that is supposed to protect the workspace boundary.
    """
    cwd = call.cwd or ""
    if not cwd:
        return False
    paths = _declared_paths(call) + candidates_from_command(command)
    if not paths:
        return False
    return not any(is_inside(path, cwd) for path in paths)


def build_engine(loaded: LoadedPolicies, *, overrides: dict[str, dict] | None = None,
                 failure_mode: str | None = None) -> PolicyEngine:
    """Engine for an already-loaded set (used by the API layer to reuse the parse)."""
    return PolicyEngine(loaded.ruleset, overrides=overrides, failure_mode=failure_mode)