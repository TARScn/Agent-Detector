"""Project current claims into the four-value user-facing status."""
from __future__ import annotations

from sqlalchemy.orm import Session

from agent_detector.aggregation.evidence_ledger import EvidenceLedger
from agent_detector.aggregation.predicates import policy
from agent_detector.core.enums import AgentStatus


def project_entity(session: Session, entity_id: str, generation_id: int, *,
                   hook_state: str = "UNKNOWN",
                   coverage_summary: dict | None = None,
                   removal_verdict: str = "NONE",
                   unverified: str | None = None) -> dict:
    """Derive RUNNING/CONFIGURED/INSTALLED/UNKNOWN and persist a snapshot.

    ``unverified`` marks a generation that could not check the entity at all
    (docker engine unreachable, product rule crashed). Nothing was observed,
    so no older claim may stand in for this run: the snapshot records UNKNOWN
    plus the reason instead of repeating a stale RUNNING.
    """
    ledger = EvidenceLedger(session)
    claims = [] if unverified else ledger.current_claims(entity_id)
    by_predicate: dict[str, list] = {}
    for claim in claims:
        by_predicate.setdefault(claim.predicate, []).append(claim)

    conflicts: list[str] = []

    def claim_state(predicate: str) -> bool | None:
        """Tri-state: True supported, False refuted, None no evidence/conflict.

        The projection status keeps using the policy conflict preference; the
        user-facing ``status_basis`` must not turn "no evidence" into False.
        """
        items = by_predicate.get(predicate, [])
        support = [c for c in items if c.polarity == "support"]
        refute = [c for c in items if c.polarity == "refute"]
        if support and refute:
            if predicate not in conflicts:
                conflicts.append(predicate)
            conflict = policy(predicate).conflict
            if conflict == "prefer_positive":
                return True
            if conflict == "prefer_negative":
                return False
            return None
        if support:
            return True
        if refute:
            return False
        return None

    def combine(*values: bool | None) -> bool | None:
        if any(value is True for value in values):
            return True
        if values and all(value is False for value in values):
            return False
        return None

    states = {predicate: claim_state(predicate) for predicate in by_predicate}
    running_basis = combine(states.get("running"), states.get("service_running"))
    configured_basis = states.get("configured")
    installed_basis = states.get("installed")
    running = running_basis is True
    configured = configured_basis is True
    installed = installed_basis is True
    if running:
        status = AgentStatus.RUNNING
    elif configured:
        status = AgentStatus.CONFIGURED
    elif installed:
        status = AgentStatus.INSTALLED
    else:
        status = AgentStatus.UNKNOWN

    capability_tags = sorted({
        claim.object_ref for claim in claims
        if claim.predicate == "agent_capability"
        and claim.polarity == "support" and claim.object_ref})
    claim_ids: dict[str, list[str]] = {}
    for predicate, items in by_predicate.items():
        claim_ids[predicate] = [c.claim_id for c in items
                                if c.polarity == "support"]
    basis = {
        "basis_version": 2,
        "installed": installed_basis,
        "configured": configured_basis,
        "running": running_basis,
        "claim_ids": claim_ids,
        "conflicts": conflicts,
    }
    if unverified:
        basis["verified"] = False
        basis["unverified_reason"] = unverified
    ledger.upsert_snapshot(
        entity_id=entity_id, generation_id=generation_id,
        agent_status=status.value, status_basis=basis,
        capability_tags=capability_tags, hook_state=hook_state,
        removal_verdict=removal_verdict,
        coverage_summary=coverage_summary)
    return {"entity_id": entity_id, "agent_status": status.value,
            "capability_tags": capability_tags, "hook_state": hook_state,
            "conflicts": conflicts}


def project_scan_entities(session: Session, generation_id: int,
                          entity_hook_states: dict[str, str],
                          coverage_summary: dict | None = None) -> list[dict]:
    return [project_entity(session, entity_id, generation_id,
                           hook_state=hook_state,
                           coverage_summary=coverage_summary)
            for entity_id, hook_state in sorted(entity_hook_states.items())]