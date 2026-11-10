"""Evidence ledger: immutable observations, revisable claims and snapshots."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_detector.identity.canonical import canonical_json, digest
from agent_detector.storage.models import (ClaimEvidenceRow, ClaimRow,
                                           EntitySnapshotRow, ObservationRow,
                                           RuleRevisionRow, utc_now_iso)


class EvidenceLedger:
    def __init__(self, session: Session):
        self._session = session

    # -- observations -------------------------------------------------------

    def record_observation(self, *, source: str, source_event_uid: str,
                           scope_key: str, fact_type: str, payload: dict,
                           observed_at: str, collection_run_id: int,
                           normalizer_version: int = 1,
                           retention_class: str = "raw_short") -> str:
        observation_id = "obs-" + digest(
            canonical_json({"source": source, "uid": source_event_uid,
                            "run": collection_run_id}), length=24)
        existing = self._session.get(ObservationRow, observation_id)
        if existing is not None:
            return observation_id
        payload_json = canonical_json(payload)
        self._session.add(ObservationRow(
            observation_id=observation_id,
            source=source,
            source_event_uid=source_event_uid,
            scope_key=scope_key,
            fact_type=fact_type,
            normalized_payload_json=payload_json,
            payload_digest=digest(payload_json, length=48),
            observed_at=observed_at,
            collection_run_id=collection_run_id,
            normalizer_version=normalizer_version,
            retention_class=retention_class,
        ))
        return observation_id

    # -- claims -------------------------------------------------------------

    def add_claim(self, *, subject_ref: str, predicate: str,
                  object_ref: str = "", polarity: str = "support",
                  evidence_class: str, verification_method: str,
                  rule_id: str = "", rule_digest: str = "",
                  rule_generation: int = 0, collection_run_id: int,
                  coverage_scope_id: int | None = None,
                  observed_at: str | None = None,
                  valid_from: str | None = None,
                  valid_to: str | None = None,
                  observation_id: str | None = None) -> str:
        now = utc_now_iso()
        observed_at = observed_at or now
        valid_from = valid_from or observed_at
        existing = self._session.scalars(
            select(ClaimRow).where(
                ClaimRow.subject_ref == subject_ref,
                ClaimRow.predicate == predicate,
                ClaimRow.object_ref == object_ref,
                ClaimRow.rule_id == rule_id,
                ClaimRow.rule_digest == rule_digest,
                ClaimRow.collection_run_id == collection_run_id,
            )).first()
        if existing is not None:
            if observation_id:
                self._link(existing.claim_id, observation_id)
            return existing.claim_id

        previous = self._session.scalars(
            select(ClaimRow).where(
                ClaimRow.subject_ref == subject_ref,
                ClaimRow.predicate == predicate,
                ClaimRow.object_ref == object_ref,
                ClaimRow.rule_id == rule_id,
                ClaimRow.status == "supported",
            ).order_by(ClaimRow.observed_at.desc())).first()
        if previous is not None:
            previous.status = "superseded"
            previous.valid_to = now

        claim_id = "clm-" + digest(
            canonical_json({"subject": subject_ref, "predicate": predicate,
                            "object": object_ref, "rule": rule_id,
                            "digest": rule_digest, "run": collection_run_id,
                            "observed": observed_at}), length=24)
        self._session.add(ClaimRow(
            claim_id=claim_id,
            subject_ref=subject_ref,
            predicate=predicate,
            object_ref=object_ref,
            polarity=polarity,
            evidence_class=evidence_class,
            verification_method=verification_method,
            rule_id=rule_id,
            rule_digest=rule_digest,
            rule_generation=rule_generation or collection_run_id,
            collection_run_id=collection_run_id,
            coverage_scope_id=coverage_scope_id,
            observed_at=observed_at,
            valid_from=valid_from,
            valid_to=valid_to,
            status="supported",
            supersedes_claim_id=previous.claim_id if previous else None,
        ))
        if observation_id:
            self._link(claim_id, observation_id)
        return claim_id

    def _link(self, claim_id: str, observation_id: str,
              role: str = "supports") -> None:
        row = self._session.get(ClaimEvidenceRow,
                                (claim_id, observation_id))
        if row is None:
            self._session.add(ClaimEvidenceRow(
                claim_id=claim_id, observation_id=observation_id, role=role))

    def current_claims(self, subject_ref: str, *, now: str | None = None
                       ) -> list[ClaimRow]:
        now = now or utc_now_iso()
        rows = self._session.scalars(
            select(ClaimRow).where(
                ClaimRow.subject_ref == subject_ref,
                ClaimRow.status == "supported",
                ClaimRow.valid_from <= now,
            ).order_by(ClaimRow.observed_at.desc()))
        return [row for row in rows
                if row.valid_to is None or row.valid_to > now]

    def claims_for_run(self, subject_ref: str, predicate: str,
                       collection_run_id: int, *,
                       now: str | None = None) -> list[ClaimRow]:
        """Claims observed by exactly this run (presence is per-run evidence)."""
        now = now or utc_now_iso()
        rows = self._session.scalars(
            select(ClaimRow).where(
                ClaimRow.subject_ref == subject_ref,
                ClaimRow.predicate == predicate,
                ClaimRow.collection_run_id == collection_run_id,
                ClaimRow.status == "supported",
                ClaimRow.valid_from <= now,
            ).order_by(ClaimRow.observed_at.desc()))
        return [row for row in rows
                if row.valid_to is None or row.valid_to > now]

    def invalidate_claims(self, subject_ref: str, *,
                          predicates: tuple[str, ...] | list[str] | set[str],
                          reason: str = "") -> int:
        """Retire live claims after a negative verdict proved them wrong.

        The ledger stays append-only in spirit: claims are closed, not
        deleted; the absence observation explains why.
        """
        wanted = set(predicates)
        now = utc_now_iso()
        rows = self._session.scalars(
            select(ClaimRow).where(
                ClaimRow.subject_ref == subject_ref,
                ClaimRow.status == "supported",
                ClaimRow.predicate.in_(list(wanted)),
            ))
        closed = 0
        for row in rows:
            row.status = "invalidated"
            row.valid_to = now
            closed += 1
        return closed

    # -- rules / snapshots --------------------------------------------------

    def upsert_rule_revision(self, rule_id: str, digest_value: str,
                             source_path: str = "") -> None:
        existing = self._session.scalars(
            select(RuleRevisionRow).where(
                RuleRevisionRow.rule_id == rule_id,
                RuleRevisionRow.digest == digest_value)).first()
        if existing is None:
            self._session.add(RuleRevisionRow(
                rule_id=rule_id, digest=digest_value,
                source_path=source_path))

    def upsert_snapshot(self, *, entity_id: str, generation_id: int,
                        agent_status: str, status_basis: dict,
                        capability_tags: list[str], hook_state: str,
                        removal_verdict: str = "NONE",
                        coverage_summary: dict | None = None,
                        presence: str = "UNKNOWN",
                        verification: str = "STALE",
                        lifecycle: str = "ACTIVE",
                        reason_code: str = "",
                        last_known_status: str = "UNKNOWN",
                        owner_scope_type: str | None = None,
                        owner_scope_key: str | None = None,
                        verified_scopes: list[dict] | None = None) -> None:
        row = self._session.scalars(
            select(EntitySnapshotRow).where(
                EntitySnapshotRow.entity_id == entity_id,
                EntitySnapshotRow.generation_id == generation_id)).first()
        payload = {
            "status_basis_json": json.dumps(status_basis, ensure_ascii=False),
            "capability_tags_json": json.dumps(capability_tags,
                                               ensure_ascii=False),
            "coverage_summary_json": json.dumps(coverage_summary or {},
                                                ensure_ascii=False),
            "agent_status": agent_status,
            "hook_state": hook_state,
            "removal_verdict": removal_verdict,
            "presence": presence,
            "verification": verification,
            "lifecycle": lifecycle,
            "reason_code": reason_code,
            "last_known_status": last_known_status,
            "owner_scope_type": owner_scope_type,
            "owner_scope_key": owner_scope_key,
            "verified_scopes_json": json.dumps(verified_scopes or [],
                                               ensure_ascii=False),
            "projected_at": utc_now_iso(),
        }
        if row is None:
            self._session.add(EntitySnapshotRow(
                entity_id=entity_id, generation_id=generation_id, **payload))
            return
        for key, value in payload.items():
            setattr(row, key, value)

    def latest_snapshot(self, entity_id: str) -> EntitySnapshotRow | None:
        return self._session.scalars(
            select(EntitySnapshotRow).where(
                EntitySnapshotRow.entity_id == entity_id).order_by(
                    EntitySnapshotRow.generation_id.desc(),
                    EntitySnapshotRow.id.desc())).first()


def running_claim_valid_to(ttl_seconds: int = 900) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=max(0, ttl_seconds))
            ).isoformat(timespec="seconds")


def static_claim_valid_to(ttl_seconds: int = 7 * 86400) -> str:
    """Static metadata stays usable until the next full scan, with a hard cap."""
    return (datetime.now(timezone.utc) + timedelta(seconds=max(0, ttl_seconds))
            ).isoformat(timespec="seconds")