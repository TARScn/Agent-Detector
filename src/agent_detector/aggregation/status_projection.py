"""Project current claims into the four-value user-facing status."""
from __future__ import annotations

from sqlalchemy.orm import Session

from agent_detector.aggregation.evidence_ledger import EvidenceLedger
from agent_detector.aggregation.predicates import policy
from agent_detector.core.enums import AgentStatus


def project_entity(session: Session, entity_id: str, generation_id: int, *,
                   hook_state: str = "UNKNOWN",
                   coverage_summary: dict | None = None,
                   removal_verdict: str = "NONE") -> dict:
    """Derive RUNNING/CONFIGURED/INSTALLED/UNKNOWN and persist a snapshot."""
    ledger = EvidenceLedger(session)
    claims = ledger.current_claims(entity_id)
    by_predicate: dict[str, list] = {}
    for claim in claims:
        by_predicate.setdefault(claim.predicate, []).append(claim)

    conflicts: list[str] = []

    def supported(predicate: str) -> bool:
        items = by_predicate.get(predicate, [])
        support = [c for c in items if c.polarity == "support"]
        refute = [c for c in items if c.polarity == "refute"]
        if support and refute:
            conflicts.append(predicate)
            conflict = policy(predicate).conflict
            if conflict == "prefer_positive":
                return True
            if conflict == "prefer_negative":
                return False
            return False
        return bool(support)

    running = supported("running") or supported("service_running")
    configured = supported("configured")
    installed = supported("installed")
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
        "installed": installed,
        "configured": configured,
        "running": running,
        "claim_ids": claim_ids,
        "conflicts": conflicts,
    }
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