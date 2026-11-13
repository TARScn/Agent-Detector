"""Single place where collected evidence becomes a display state.

Collectors (the detectors, the static re-confirmation loop) only record what
they observed. This module decides what those observations mean, along three
orthogonal axes:

* ``presence``     — is the object still there? PRESENT / ABSENT / UNKNOWN
* ``verification`` — how good is *this run's* answer? VERIFIED / PARTIAL /
  FAILED / NOT_CHECKED / STALE
* ``lifecycle``    — does it belong on the current inventory? ACTIVE / WATCH /
  ARCHIVED

``agent_status`` stays the four-value compatibility field. RUNNING is only
reported when a running claim was observed in the current generation; an
unverified entity keeps its last durable status (CONFIGURED / INSTALLED) and
is marked as not re-verified, never as running.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_detector.aggregation.evidence_ledger import EvidenceLedger
from agent_detector.aggregation.predicates import policy
from agent_detector.core.enums import AgentStatus
from agent_detector.storage.models import (EntityAttributeRow, EntityLocationRow,
                                           EntityRow, EntitySnapshotRow,
                                           utc_now_iso)

PRESENCE_PREDICATE = "entity_presence"

PRESENT = "PRESENT"
ABSENT = "ABSENT"
UNKNOWN_PRESENCE = "UNKNOWN"

VERIFIED = "VERIFIED"
PARTIAL = "PARTIAL"
FAILED = "FAILED"
NOT_CHECKED = "NOT_CHECKED"
STALE = "STALE"

ACTIVE = "ACTIVE"
WATCH = "WATCH"
ARCHIVED = "ARCHIVED"

COMPLETE = "COMPLETE"
_INCOMPLETE = (PARTIAL, FAILED, NOT_CHECKED)

_RUNNING_PREDICATES = ("running", "service_running", "component_running")
_INSTALLED_PREDICATES = ("installed", "component_installed")
_CONFIGURED_PREDICATES = ("configured", "component_configured")
# State predicates that an absence verdict retires. Identity/capability claims
# are provenance, not state: they stay in the ledger.
_INVALIDATED_ON_ABSENCE = (
    "installed", "configured", "running",
    "component_installed", "component_configured", "component_running",
    "service_running", "hook_configured",
)

_KIND_COMPOSE = "COMPOSE_DEPLOYMENT"
_KIND_CONTAINER = "CONTAINER_DEPLOYMENT"
_KIND_APPLICATION = "SELF_BUILT_APPLICATION"
_KIND_PRODUCT = "PRODUCT_INSTALL"


@dataclass(frozen=True)
class ScopeRef:
    scope_type: str
    scope_key: str
    predicate: str

    def as_dict(self) -> dict:
        return {"scope_type": self.scope_type, "scope_key": self.scope_key,
                "predicate": self.predicate}


@dataclass(frozen=True)
class ScopeCheck:
    scope_type: str
    scope_key: str
    predicate: str
    status: str

    @property
    def complete(self) -> bool:
        return self.status == COMPLETE

    def as_dict(self) -> dict:
        return {"scope_type": self.scope_type, "scope_key": self.scope_key,
                "predicate": self.predicate, "status": self.status}


@dataclass(frozen=True)
class EntityContext:
    entity_kind: str
    agent_type: str
    container_id: str | None
    project: str | None
    has_location: bool


@dataclass(frozen=True)
class ResolvedState:
    entity_id: str
    presence: str
    agent_status: str
    verification: str
    lifecycle: str
    reason_code: str
    reason: str
    last_known_status: str
    hook_state: str
    basis: dict
    coverage_summary: dict
    scope_checks: tuple[ScopeCheck, ...]
    owner_scope_type: str | None
    owner_scope_key: str | None


def entity_context(session: Session, entity_id: str) -> EntityContext:
    attr = session.get(EntityAttributeRow, entity_id)
    entity = session.get(EntityRow, entity_id)
    location = session.get(EntityLocationRow, entity_id)
    kind = (entity.entity_kind if entity is not None else "") or ""
    if not kind:
        kind = _infer_kind(attr, location)
    return EntityContext(
        entity_kind=kind,
        agent_type=(attr.agent_type if attr is not None else "") or "",
        container_id=(attr.container_id if attr is not None else None),
        project=(location.root_path if location is not None
                 and kind == _KIND_COMPOSE else None),
        has_location=location is not None,
    )


def _infer_kind(attr: EntityAttributeRow | None,
                location: EntityLocationRow | None) -> str:
    if attr is None:
        return _KIND_PRODUCT
    if attr.origin == "docker":
        return _KIND_CONTAINER if attr.container_id else _KIND_COMPOSE
    return _KIND_APPLICATION if location is not None else _KIND_PRODUCT


def product_scope_refs(coverage, agent_type: str) -> tuple[ScopeRef, ...]:
    """The product-rule scope that owns ``agent_type``.

    When the stored agent type cannot be mapped to one rule, no rule can
    prove its absence: a synthetic scope that never ran keeps the verdict
    unverified instead of letting an unrelated rule archive the entity.
    """
    host = ScopeRef("host_process_enumeration", "host", "process_inventory")
    if coverage is None:
        return (ScopeRef("product_rule", agent_type, "product_presence"), host)
    scopes = [scope for scope in coverage.scopes()
              if scope.scope_type == "product_rule"]
    by_key = {scope.scope_key.replace("-", "_"): scope for scope in scopes}
    for key in (agent_type, agent_type.replace("-", "_")):
        scope = by_key.get(key.replace("-", "_"))
        if scope is not None:
            return (ScopeRef(scope.scope_type, scope.scope_key,
                             "product_presence"), host)
    return (ScopeRef("product_rule", agent_type, "product_presence"), host)


def default_scopes(coverage, context: EntityContext, *,
                   docker_scope_key: str = "local") -> tuple[ScopeRef, ...]:
    """Scopes whose completeness makes this entity's state verifiable."""
    if context.entity_kind == _KIND_COMPOSE:
        return (ScopeRef("docker_engine_enumeration", docker_scope_key,
                         "container_presence"),)
    if context.entity_kind == _KIND_CONTAINER or context.container_id:
        refs = [ScopeRef("docker_engine_enumeration", docker_scope_key,
                         "container_presence")]
        if context.container_id:
            refs.append(ScopeRef("container_deep_scan", context.container_id,
                                 "component_presence"))
        return tuple(refs)
    if context.entity_kind == _KIND_APPLICATION or context.has_location:
        return (ScopeRef("project_candidate_universe", "scan",
                         "application_presence"),
                ScopeRef("host_process_enumeration", "host", "process_inventory"))
    return product_scope_refs(coverage, context.agent_type)


def evaluate_scopes(coverage,
                    refs: tuple[ScopeRef, ...]) -> tuple[ScopeCheck, ...]:
    checks: list[ScopeCheck] = []
    for ref in refs:
        status = "NOT_RUN"
        if coverage is not None:
            status = coverage.predicate_status(
                ref.scope_type, ref.scope_key, ref.predicate).value
        checks.append(ScopeCheck(ref.scope_type, ref.scope_key, ref.predicate,
                                 status))
    return tuple(checks)


def _verification(checks: tuple[ScopeCheck, ...], presence: str, *,
                  marker: dict | None) -> tuple[str, str, str]:
    """(verification, reason_code, reason) for a presence verdict."""
    failed = [check for check in checks if check.status == FAILED]
    not_run = [check for check in checks
               if check.status not in (COMPLETE, PARTIAL) and check.status != FAILED]
    partial = [check for check in checks if check.status == PARTIAL]
    if presence == ABSENT:
        # Absence is only ever concluded from complete scopes.
        if checks and all(check.complete for check in checks):
            return VERIFIED, "absent_confirmed", "本轮完整枚举确认对象已不存在"
        return NOT_CHECKED, "absent_unconfirmed", "部分范围未覆盖，缺席尚未确认"
    if marker is not None:
        return (marker.get("verification") or FAILED,
                marker.get("reason_code") or "scope_failed",
                marker.get("reason") or "本轮无法复核")
    if checks and all(check.complete for check in checks):
        return VERIFIED, "", ""
    if failed:
        return FAILED, "scope_failed", "关键范围失败，本轮结论不可信"
    if partial and presence == PRESENT:
        return PARTIAL, "scope_partial", "对象存在，但部分范围未完整覆盖"
    if not_run:
        return NOT_CHECKED, "scope_not_run", "关键范围本轮未运行"
    return STALE, "no_new_evidence", "本轮没有产生新的证据"


def resolve(session: Session, *, entity_id: str, generation_id: int,
            context: EntityContext | None = None,
            coverage=None, coverage_summary: dict | None = None,
            docker_scope_key: str = "local",
            required: tuple[ScopeRef, ...] | None = None,
            presence_verdict: str | None = None,
            unverified: dict | None = None,
            removal_verdict: str = "NONE",
            hook_state: str = "UNKNOWN") -> ResolvedState:
    """Resolve one entity's state from claims + coverage for this run."""
    context = context or entity_context(session, entity_id)
    ledger = EvidenceLedger(session)
    now = utc_now_iso()
    run_claims = ledger.claims_for_run(
        entity_id, PRESENCE_PREDICATE, generation_id, now=now)
    presence = presence_verdict or _presence_from_claims(run_claims)
    marker = _normalize_marker(unverified)

    checks = evaluate_scopes(
        coverage,
        required if required is not None
        else default_scopes(coverage, context,
                            docker_scope_key=docker_scope_key))
    verification, reason_code, reason = _verification(
        checks, presence, marker=marker)

    current = ledger.current_claims(entity_id, now=now)
    conflicts: list[str] = []
    states = _claim_states(current, conflicts)
    running_this_run = _running_this_run(current, generation_id, now=now)

    installed = any(states.get(p) is True for p in _INSTALLED_PREDICATES)
    configured = any(states.get(p) is True for p in _CONFIGURED_PREDICATES)
    last_known = (AgentStatus.CONFIGURED.value if configured
                  else AgentStatus.INSTALLED.value if installed
                  else _previous_durable(session, entity_id, generation_id))

    if presence == ABSENT:
        agent_status = AgentStatus.UNKNOWN.value
        last_known = AgentStatus.UNKNOWN.value
        running_state: bool | None = False
    elif running_this_run:
        agent_status = AgentStatus.RUNNING.value
        running_state = True
    elif last_known == AgentStatus.CONFIGURED.value:
        # Also covers an unverified run: the last durable status is kept.
        agent_status = AgentStatus.CONFIGURED.value
        running_state = False if presence == PRESENT else None
    elif last_known == AgentStatus.INSTALLED.value:
        agent_status = AgentStatus.INSTALLED.value
        running_state = False if presence == PRESENT else None
    else:
        agent_status = AgentStatus.UNKNOWN.value
        running_state = None

    lifecycle = _lifecycle(presence, verification, removal_verdict, last_known)
    if not reason:
        reason_code, reason = _reason(agent_status, presence, verification)

    owner = checks[0] if checks else None
    basis = {
        "basis_version": 3,
        "presence": presence,
        "verification": verification,
        "lifecycle": lifecycle,
        "reason_code": reason_code,
        "reason": reason,
        "last_known_status": last_known,
        "installed": True if installed else (False if presence == ABSENT else None),
        "configured": True if configured else (False if presence == ABSENT else None),
        "running": running_state,
        "claim_ids": _claim_ids(current),
        "conflicts": conflicts,
        "verified": verification in (VERIFIED, PARTIAL),
        "scope_checks": [check.as_dict() for check in checks],
    }
    if marker is not None:
        basis["verified"] = False
        basis["unverified_reason"] = marker.get("reason") or reason
        basis["unverified_code"] = marker.get("reason_code") or "scope_failed"
    return ResolvedState(
        entity_id=entity_id, presence=presence, agent_status=agent_status,
        verification=verification, lifecycle=lifecycle,
        reason_code=reason_code, reason=reason, last_known_status=last_known,
        hook_state=hook_state, basis=basis,
        coverage_summary=coverage_summary or {}, scope_checks=checks,
        owner_scope_type=(owner.scope_type if owner else None),
        owner_scope_key=(owner.scope_key if owner else None))


def _normalize_marker(unverified: dict | str | None) -> dict | None:
    if not unverified:
        return None
    if isinstance(unverified, str):
        lowered = unverified.lower()
        verification = NOT_CHECKED if ("禁用" in unverified or "未启用" in unverified) \
            else FAILED
        return {"reason": unverified, "verification": verification,
                "reason_code": ("scope_not_run" if verification == NOT_CHECKED
                                else "scope_failed")}
    return dict(unverified)


def _presence_from_claims(claims: list) -> str:
    support = [claim for claim in claims if claim.polarity == "support"]
    refute = [claim for claim in claims if claim.polarity == "refute"]
    if support:
        return PRESENT  # observing the object beats an absence hint
    if refute:
        return ABSENT
    return UNKNOWN_PRESENCE


def _claim_states(claims: list, conflicts: list[str]) -> dict[str, bool | None]:
    by_predicate: dict[str, list] = {}
    for claim in claims:
        by_predicate.setdefault(claim.predicate, []).append(claim)
    states: dict[str, bool | None] = {}
    for predicate, items in by_predicate.items():
        support = any(claim.polarity == "support" for claim in items)
        refute = any(claim.polarity == "refute" for claim in items)
        if support and refute:
            conflicts.append(predicate)
            preference = policy(predicate).conflict
            if preference == "prefer_positive":
                states[predicate] = True
            elif preference == "prefer_negative":
                states[predicate] = False
            else:
                states[predicate] = None
        else:
            states[predicate] = True if support else False if refute else None
    return states


def _running_this_run(claims: list, generation_id: int, *, now: str) -> bool:
    """RUNNING needs a running observation from this very generation.

    A TTL-valid claim from an earlier run describes an earlier observation;
    the console must not present it as the result of the latest scan.
    """
    for claim in claims:
        if claim.predicate not in _RUNNING_PREDICATES:
            continue
        if claim.polarity != "support":
            continue
        if claim.collection_run_id != generation_id:
            continue
        if claim.valid_to is not None and claim.valid_to <= now:
            continue
        return True
    return False


def _claim_ids(claims: list) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for claim in claims:
        if claim.polarity == "support":
            result.setdefault(claim.predicate, []).append(claim.claim_id)
    return result


def _previous_durable(session: Session, entity_id: str,
                      generation_id: int) -> str:
    # Walk back to the last run that actually knew a durable status. A chain
    # of unverified runs (docker down for days) must not erase the fact that
    # the asset was last seen CONFIGURED.
    history = session.scalars(
        select(EntitySnapshotRow).where(
            EntitySnapshotRow.entity_id == entity_id,
            EntitySnapshotRow.generation_id < generation_id).order_by(
                EntitySnapshotRow.generation_id.desc(),
                EntitySnapshotRow.id.desc()).limit(20))
    for previous in history:
        stored = getattr(previous, "last_known_status", None)
        if stored and stored != AgentStatus.UNKNOWN.value:
            return stored
        recovered = durable_from_snapshot(previous)
        if recovered != AgentStatus.UNKNOWN.value:
            return recovered
    return AgentStatus.UNKNOWN.value


def durable_from_snapshot(snapshot: EntitySnapshotRow) -> str:
    """Old snapshots predate ``last_known_status``; recover what we can."""
    import json
    try:
        basis = json.loads(snapshot.status_basis_json or "{}")
    except (TypeError, ValueError):
        basis = {}
    if basis.get("configured") is True or snapshot.agent_status == "CONFIGURED":
        return AgentStatus.CONFIGURED.value
    if basis.get("installed") is True or snapshot.agent_status == "INSTALLED":
        return AgentStatus.INSTALLED.value
    return AgentStatus.UNKNOWN.value


def _lifecycle(presence: str, verification: str,
               removal_verdict: str, last_known: str) -> str:
    if presence == ABSENT:
        return ARCHIVED if verification != NOT_CHECKED else WATCH
    if removal_verdict == "CONFIRMED":
        return ARCHIVED
    if removal_verdict == "CANDIDATE":
        return WATCH
    if presence == PRESENT and verification == FAILED:
        # Degraded round (T2): seen at enumeration level, interior unverified.
        # Visible for review — neither silently ACTIVE nor archived.
        return WATCH
    if (presence == UNKNOWN_PRESENCE and verification == NOT_CHECKED
            and last_known == AgentStatus.UNKNOWN.value):
        # Nothing is known and nothing could be checked: this is exactly the
        # row an operator must review, not a silently active asset.
        return WATCH
    return ACTIVE


def _reason(agent_status: str, presence: str, verification: str
            ) -> tuple[str, str]:
    if agent_status == AgentStatus.RUNNING.value:
        return "running_verified", "本轮观察到运行证据"
    if agent_status == AgentStatus.CONFIGURED.value:
        return "configured_evidence", "静态证据显示已配置"
    if agent_status == AgentStatus.INSTALLED.value:
        return "installed_evidence", "静态证据显示已安装"
    if presence == ABSENT:
        return "absent_confirmed", "本轮完整枚举确认对象已不存在"
    if verification in (FAILED, NOT_CHECKED, STALE):
        return "no_current_evidence", "本轮没有取得可用证据"
    return "no_evidence", "没有可判定的证据"


def removal_for(state: ResolvedState) -> str:
    """Compatibility alias written to the old snapshot column."""
    if state.lifecycle == ARCHIVED:
        return "CONFIRMED"
    if state.lifecycle == WATCH and state.presence == ABSENT:
        return "CANDIDATE"
    return "NONE"


def invalidate_on_absence(session: Session, entity_id: str, *,
                          generation_id: int) -> int:
    """Retire state claims once a complete enumeration proves absence."""
    ledger = EvidenceLedger(session)
    return ledger.invalidate_claims(
        entity_id, predicates=_INVALIDATED_ON_ABSENCE,
        reason=f"absence confirmed in run {generation_id}")