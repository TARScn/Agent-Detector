"""Read side of the V1.2 evidence ledger (claims, observations, rules)."""
from __future__ import annotations

import json

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agent_detector.storage.models import (ClaimEvidenceRow, ClaimRow,
                                           ObservationRow, RuleRevisionRow,
                                           utc_now_iso)


class ClaimRepository:
    def __init__(self, session: Session):
        self._session = session

    def for_entity(self, entity_id: str, *, predicate: str | None = None,
                   polarity: str | None = None, current: bool = True,
                   limit: int = 50, offset: int = 0) -> list[dict]:
        now = utc_now_iso()
        statement = select(ClaimRow).where(ClaimRow.subject_ref == entity_id)
        if predicate:
            statement = statement.where(ClaimRow.predicate == predicate)
        if polarity:
            statement = statement.where(ClaimRow.polarity == polarity)
        if current:
            statement = statement.where(
                ClaimRow.status == "supported",
                ClaimRow.valid_from <= now,
                (ClaimRow.valid_to.is_(None)) | (ClaimRow.valid_to > now))
        statement = statement.order_by(ClaimRow.observed_at.desc()).offset(
            max(0, int(offset))).limit(min(max(int(limit), 1), 200))
        return [self._claim_dict(row, now) for row in self._session.scalars(statement)]

    def summary(self, entity_id: str) -> dict:
        rows = self.for_entity(entity_id, current=True, limit=200)
        by_predicate: dict[str, int] = {}
        for row in rows:
            by_predicate[row["predicate"]] = by_predicate.get(
                row["predicate"], 0) + 1
        return {"claim_count": len(rows), "by_predicate": by_predicate}

    def observations_for(self, claim_id: str) -> list[dict]:
        statement = (select(ObservationRow)
                     .join(ClaimEvidenceRow,
                           ClaimEvidenceRow.observation_id == ObservationRow.observation_id)
                     .where(ClaimEvidenceRow.claim_id == claim_id)
                     .order_by(ObservationRow.observed_at.desc()))
        return [self._observation_dict(row) for row in self._session.scalars(statement)]

    def rule_for(self, rule_id: str, digest: str) -> dict | None:
        if not rule_id:
            return None
        row = self._session.scalars(
            select(RuleRevisionRow).where(
                RuleRevisionRow.rule_id == rule_id,
                RuleRevisionRow.digest == digest).limit(1)).first()
        if row is None:
            return None
        return {"id": row.rule_id, "digest": row.digest,
                "source_path": row.source_path or None}

    def count(self, entity_id: str) -> int:
        return int(self._session.scalar(
            select(func.count()).select_from(ClaimRow).where(
                ClaimRow.subject_ref == entity_id)) or 0)

    def _claim_dict(self, row: ClaimRow, now: str) -> dict:
        valid_to = row.valid_to
        is_current = (row.status == "supported"
                      and row.valid_from <= now
                      and (valid_to is None or valid_to > now))
        return {
            "claim_id": row.claim_id,
            "predicate": row.predicate,
            "object_ref": row.object_ref,
            "polarity": row.polarity,
            "evidence_class": row.evidence_class,
            "verification_method": row.verification_method,
            "rule": (self.rule_for(row.rule_id, row.rule_digest)
                     or {"id": row.rule_id, "digest": row.rule_digest,
                         "source_path": None}),
            "coverage_scope_id": row.coverage_scope_id,
            "observed_at": row.observed_at,
            "valid_from": row.valid_from,
            "valid_to": valid_to,
            "status": row.status,
            "is_current": is_current,
            "supersedes_claim_id": row.supersedes_claim_id,
        }

    @staticmethod
    def _observation_dict(row: ObservationRow) -> dict:
        try:
            payload = json.loads(row.normalized_payload_json or "{}")
        except ValueError:
            payload = {}
        name = payload.get("name") or payload.get("asset_id") or row.fact_type
        version = payload.get("version")
        summary = " · ".join(str(part) for part in (name, version)
                             if part not in (None, "", "UNKNOWN"))
        return {
            "observation_id": row.observation_id,
            "source": row.source,
            "source_event_uid": row.source_event_uid,
            "observed_at": row.observed_at,
            "fact_type": row.fact_type,
            "summary": summary or row.fact_type,
            "payload": payload,
            "payload_digest": row.payload_digest,
            "retention_class": row.retention_class,
        }
