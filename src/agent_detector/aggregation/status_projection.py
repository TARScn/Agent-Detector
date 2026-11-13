"""Persist the resolved state for one entity and one scan generation.

The decision itself lives in :mod:`agent_detector.aggregation.state_resolver`;
this module only keeps the long-standing ``project_entity`` entry point and
writes the snapshot row.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from agent_detector.aggregation.evidence_ledger import EvidenceLedger
from agent_detector.aggregation.state_resolver import (ResolvedState, ScopeRef,
                                                       entity_context,
                                                       removal_for, resolve)
from agent_detector.core.enums import AgentStatus  # noqa: F401 (re-exported)


def project_entity(session: Session, entity_id: str, generation_id: int, *,
                   hook_state: str = "UNKNOWN",
                   coverage_summary: dict | None = None,
                   removal_verdict: str = "NONE",
                   unverified: dict | str | None = None,
                   coverage=None, docker_scope_key: str = "local",
                   required: tuple[ScopeRef, ...] | None = None,
                   presence_verdict: str | None = None) -> dict:
    """Resolve and persist one entity's user-facing state.

    ``unverified`` marks a generation that could not check the entity at all
    (docker engine unreachable, product rule crashed). Nothing was observed,
    so no older claim may stand in for this run: the snapshot keeps the last
    durable status, records why it could not be re-verified, and never says
    RUNNING.
    """
    state = resolve(
        session, entity_id=entity_id, generation_id=generation_id,
        context=entity_context(session, entity_id), coverage=coverage,
        coverage_summary=coverage_summary,
        docker_scope_key=docker_scope_key, required=required,
        presence_verdict=presence_verdict, unverified=unverified,
        removal_verdict=removal_verdict, hook_state=hook_state)
    return write_resolved(session, state, generation_id=generation_id,
                          coverage_summary=coverage_summary)


def write_resolved(session: Session, state: ResolvedState, *,
                   generation_id: int,
                   coverage_summary: dict | None = None) -> dict:
    """Persist an already-resolved state (scan_evidence resolves once)."""
    capability_tags = _capability_tags(session, state.entity_id)
    verdict = removal_for(state)
    EvidenceLedger(session).upsert_snapshot(
        entity_id=state.entity_id, generation_id=generation_id,
        agent_status=state.agent_status, status_basis=state.basis,
        capability_tags=capability_tags, hook_state=state.hook_state,
        removal_verdict=verdict,
        coverage_summary=coverage_summary,
        presence=state.presence, verification=state.verification,
        lifecycle=state.lifecycle, reason_code=state.reason_code,
        last_known_status=state.last_known_status,
        owner_scope_type=state.owner_scope_type,
        owner_scope_key=state.owner_scope_key,
        verified_scopes=[check.as_dict() for check in state.scope_checks])
    return {"entity_id": state.entity_id,
            "agent_status": state.agent_status,
            "presence": state.presence,
            "verification": state.verification,
            "lifecycle": state.lifecycle,
            "reason_code": state.reason_code,
            "reason": state.reason,
            "last_known_status": state.last_known_status,
            "removal_verdict": verdict,
            "capability_tags": capability_tags, "hook_state": state.hook_state,
            "conflicts": state.basis.get("conflicts", [])}


def resolve_entity(session: Session, entity_id: str, generation_id: int, *,
                   hook_state: str = "UNKNOWN",
                   coverage_summary: dict | None = None,
                   removal_verdict: str = "NONE",
                   unverified: dict | str | None = None,
                   coverage=None, docker_scope_key: str = "local",
                   required: tuple[ScopeRef, ...] | None = None,
                   presence_verdict: str | None = None) -> ResolvedState:
    """Resolve without persisting; the caller writes one consistent batch."""
    return resolve(
        session, entity_id=entity_id, generation_id=generation_id,
        context=entity_context(session, entity_id), coverage=coverage,
        coverage_summary=coverage_summary,
        docker_scope_key=docker_scope_key, required=required,
        presence_verdict=presence_verdict, unverified=unverified,
        removal_verdict=removal_verdict, hook_state=hook_state)


def _capability_tags(session: Session, entity_id: str) -> list[str]:
    claims = EvidenceLedger(session).current_claims(entity_id)
    return sorted({
        claim.object_ref for claim in claims
        if claim.predicate == "agent_capability"
        and claim.polarity == "support" and claim.object_ref})


def project_scan_entities(session: Session, generation_id: int,
                          entity_hook_states: dict[str, str],
                          coverage_summary: dict | None = None) -> list[dict]:
    return [project_entity(session, entity_id, generation_id,
                           hook_state=hook_state,
                           coverage_summary=coverage_summary)
            for entity_id, hook_state in sorted(entity_hook_states.items())]