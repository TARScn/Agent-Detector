"""Pydantic schema for the declarative policy file (design section 6).

Unknown keys are rejected so a typo in a hand-edited policy fails at load time
instead of silently widening what is allowed.
"""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agent_detector.core.enums import Decision, PolicyScope, RiskLevel


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class MatchSpec(_Strict):
    """Conditions of one rule.

    Field groups are AND-ed, values inside a list are OR-ed::

        tools: [Bash, shell]        # tool name must be one of these
        command_patterns: ['rm -rf']  # AND the command must match one regex
    """

    agent_types: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    tool_args: list[str] = Field(default_factory=list)
    command_patterns: list[str] = Field(default_factory=list)
    text_patterns: list[str] = Field(default_factory=list)
    path_patterns: list[str] = Field(default_factory=list)
    command_contains: list[str] = Field(default_factory=list)
    command_not_contains: list[str] = Field(default_factory=list)
    cwd_patterns: list[str] = Field(default_factory=list)
    outside_cwd: bool = False

    @field_validator("command_patterns", "text_patterns")
    @classmethod
    def _regex_compiles(cls, value: list[str]) -> list[str]:
        for pattern in value:
            re.compile(pattern)
        return value

    @field_validator("agent_types", "tools", "tool_args", "command_contains",
                     "command_not_contains")
    @classmethod
    def _lower(cls, value: list[str]) -> list[str]:
        return [item.lower() for item in value]

    def is_empty(self) -> bool:
        return not any(getattr(self, name) for name in type(self).model_fields)

    def to_conditions(self) -> dict:
        """JSON-safe conditions for storage and the policy page."""
        conditions: dict = {}
        for name, value in self.model_dump().items():
            if isinstance(value, list):
                if value:
                    conditions[name] = list(value)
            elif value:
                conditions[name] = value
        return conditions


class RuleSetDefaults(_Strict):
    """Applied when no rule matches — the honest default is "we did not judge"."""

    decision: Decision = Decision.ALLOW
    risk: RiskLevel = RiskLevel.LOW
    reason: str = "未命中任何策略规则（默认放行）"


class PolicyRule(_Strict):
    id: str
    name: str
    description: str = ""
    scope: PolicyScope = PolicyScope.TOOL_CALL
    decision: Decision
    risk: RiskLevel = RiskLevel.MEDIUM
    priority: int = 100          # lower runs first; deny rules should sit low
    enabled: bool = True
    reason: str = ""
    match: MatchSpec = Field(default_factory=MatchSpec)

    @field_validator("id")
    @classmethod
    def _id_slug(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,63}", value):
            raise ValueError("rule id must be a lowercase slug (a-z0-9._-)")
        return value

    @model_validator(mode="after")
    def _needs_a_condition(self) -> "PolicyRule":
        if self.match.is_empty():
            raise ValueError(f"rule {self.id!r} has an empty match block")
        return self

    def conditions(self) -> dict:
        return self.match.to_conditions()


class PolicySet(_Strict):
    kind: Literal["policy_set"]
    revision: int = 1
    defaults: RuleSetDefaults = Field(default_factory=RuleSetDefaults)
    rules: list[PolicyRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_ids(self) -> "PolicySet":
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"duplicate policy id {rule.id!r}")
            seen.add(rule.id)
        self.rules.sort(key=lambda rule: (rule.priority, rule.id))
        return self