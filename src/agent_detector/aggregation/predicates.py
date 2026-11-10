"""Predicate policy registry.

Every predicate declares how long its claims stay valid, which evidence
methods are authoritative, and how conflicting support/refute claims are
resolved. Projection and reconfirmation read this table instead of inventing
their own rules.
"""
from __future__ import annotations

from dataclasses import dataclass

from agent_detector.core.enums import AgentStatus  # noqa: F401 (re-exported context)


@dataclass(frozen=True)
class PredicatePolicy:
    predicate: str
    validity: str                    # static_scan | config_file | ttl | instance_life
    authority: tuple[str, ...]       # strongest first
    conflict: str = "conflict"       # prefer_positive | prefer_negative | conflict


_POLICIES: dict[str, PredicatePolicy] = {
    "installed": PredicatePolicy(
        "installed", "static_scan", ("E2", "E1"), "prefer_positive"),
    "configured": PredicatePolicy(
        "configured", "config_file", ("E2", "E1"), "prefer_positive"),
    "running": PredicatePolicy(
        "running", "ttl", ("E4", "E3"), "prefer_positive"),
    "component_installed": PredicatePolicy(
        "component_installed", "static_scan", ("E2", "E1"), "prefer_positive"),
    "component_configured": PredicatePolicy(
        "component_configured", "config_file", ("E2", "E1"), "prefer_positive"),
    "component_running": PredicatePolicy(
        "component_running", "ttl", ("E4", "E3"), "prefer_positive"),
    "product_identity": PredicatePolicy(
        "product_identity", "static_scan", ("E3", "E2"), "prefer_positive"),
    # Whether the entity still exists at all. Collected every run; an
    # absence refutation only reaches the ledger when coverage allows it.
    "entity_presence": PredicatePolicy(
        "entity_presence", "static_scan", ("E3", "E2"), "prefer_positive"),
    "service_running": PredicatePolicy(
        "service_running", "ttl", ("E4", "E3"), "prefer_positive"),
    "agent_capability": PredicatePolicy(
        "agent_capability", "static_scan", ("E5", "E2", "E1"),
        "prefer_positive"),
    "hook_configured": PredicatePolicy(
        "hook_configured", "config_file", ("E5", "E2"), "prefer_positive"),
    "framework_execution": PredicatePolicy(
        "framework_execution", "static_scan", ("E5",), "prefer_positive"),
    "protocol_tool_call": PredicatePolicy(
        "protocol_tool_call", "static_scan", ("E5",), "prefer_positive"),
}

_DEFAULT = PredicatePolicy("unknown", "static_scan", ("E2", "E1"), "conflict")


def policy(predicate: str) -> PredicatePolicy:
    return _POLICIES.get(predicate, _DEFAULT)


def authority_rank(predicate: str, evidence_class: str | None) -> int:
    """Higher is stronger; unknown methods sort last."""
    order = policy(predicate).authority
    try:
        return len(order) - order.index(evidence_class or "")
    except ValueError:
        return 0


def policies() -> dict[str, PredicatePolicy]:
    return dict(_POLICIES)