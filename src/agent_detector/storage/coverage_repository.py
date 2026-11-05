"""Persistence for coverage scopes and absence candidates (P0-B)."""
from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_detector.coverage.model import CoverageGraph, CoverageScope
from agent_detector.storage.models import (CoveragePredicateStatusRow,
                                           CoverageScopeEdgeRow,
                                           CoverageScopeRow,
                                           RemovalCandidateRow, utc_now_iso)


class CoverageRepository:
    def __init__(self, session: Session):
        self._session = session

    def add_graph(self, run_id: int, graph: CoverageGraph, *,
                  started_at: str | None = None,
                  finished_at: str | None = None) -> int:
        """Persist a graph; idempotent for the same (run, scope) pair."""
        started = started_at or utc_now_iso()
        finished = finished_at or started
        ids: dict[tuple[str, str], int] = {}
        for scope in graph.scopes():
            row = self._scope_row(run_id, scope)
            if row is None:
                row = CoverageScopeRow(
                    run_id=run_id, scope_type=scope.scope_type,
                    scope_key=scope.scope_key, source=scope.source,
                    own_status=scope.own_status.value, budget=scope.budget,
                    scanned_count=scope.scanned_count,
                    truncated=1 if scope.truncated else 0,
                    error_codes_json=json.dumps(list(scope.error_codes),
                                                ensure_ascii=False),
                    started_at=started, finished_at=finished,
                )
                self._session.add(row)
            else:
                row.source = scope.source
                row.own_status = scope.own_status.value
                row.budget = scope.budget
                row.scanned_count = scope.scanned_count
                row.truncated = 1 if scope.truncated else 0
                row.error_codes_json = json.dumps(list(scope.error_codes),
                                                  ensure_ascii=False)
                row.finished_at = finished
            self._session.flush()
            ids[scope.key] = row.id

        for scope in graph.scopes():
            scope_id = ids[scope.key]
            for predicate, status in scope.predicates:
                existing = self._session.scalars(
                    select(CoveragePredicateStatusRow).where(
                        CoveragePredicateStatusRow.scope_id == scope_id,
                        CoveragePredicateStatusRow.predicate == predicate,
                    )).first()
                if existing is None:
                    self._session.add(CoveragePredicateStatusRow(
                        scope_id=scope_id, predicate=predicate,
                        own_status=status.value))
                else:
                    existing.own_status = status.value
            for parent_key in scope.parents:
                parent_id = ids.get(parent_key)
                if parent_id is None:
                    continue  # missing parent is treated as NOT_RUN at query time
                existing_edge = self._session.get(
                    CoverageScopeEdgeRow, (parent_id, scope_id))
                if existing_edge is None:
                    self._session.add(CoverageScopeEdgeRow(
                        parent_id=parent_id, child_id=scope_id))
        self._session.flush()
        return len(ids)

    def record_candidates(self, run_id: int, candidates: list[dict]) -> int:
        now = utc_now_iso()
        for candidate in candidates:
            asset_id = str(candidate.get("asset_id") or "")
            predicate = str(candidate.get("predicate") or "")
            if not asset_id or not predicate:
                continue
            row = self._session.scalars(
                select(RemovalCandidateRow).where(
                    RemovalCandidateRow.run_id == run_id,
                    RemovalCandidateRow.asset_id == asset_id,
                    RemovalCandidateRow.predicate == predicate,
                )).first()
            if row is None:
                self._session.add(RemovalCandidateRow(
                    run_id=run_id, asset_id=asset_id,
                    entity_id=candidate.get("entity_id"),
                    entity_kind=str(candidate.get("entity_kind") or "UNKNOWN"),
                    predicate=predicate,
                    status=str(candidate.get("status") or "UNVERIFIED"),
                    reason=str(candidate.get("reason") or ""),
                    coverage_refs_json=json.dumps(
                        candidate.get("coverage_refs") or [], ensure_ascii=False),
                    created_at=now, updated_at=now,
                ))
                continue
            row.entity_id = candidate.get("entity_id") or row.entity_id
            row.entity_kind = str(candidate.get("entity_kind") or row.entity_kind)
            row.status = str(candidate.get("status") or row.status)
            row.reason = str(candidate.get("reason") or row.reason)
            row.coverage_refs_json = json.dumps(
                candidate.get("coverage_refs") or [], ensure_ascii=False)
            row.updated_at = now
        self._session.flush()
        return len(candidates)

    def list_scopes(self, run_id: int) -> list[dict]:
        rows = self._session.scalars(
            select(CoverageScopeRow).where(
                CoverageScopeRow.run_id == run_id).order_by(
                    CoverageScopeRow.id))
        return [{"id": row.id, "scope_type": row.scope_type,
                 "scope_key": row.scope_key, "source": row.source,
                 "own_status": row.own_status, "budget": row.budget,
                 "scanned_count": row.scanned_count,
                 "truncated": bool(row.truncated),
                 "error_codes": json.loads(row.error_codes_json or "[]")}
                for row in rows]

    def list_candidates(self, run_id: int) -> list[dict]:
        rows = self._session.scalars(
            select(RemovalCandidateRow).where(
                RemovalCandidateRow.run_id == run_id).order_by(
                    RemovalCandidateRow.id))
        return [{"asset_id": row.asset_id, "entity_id": row.entity_id,
                 "entity_kind": row.entity_kind, "predicate": row.predicate,
                 "status": row.status, "reason": row.reason,
                 "coverage_refs": json.loads(row.coverage_refs_json or "[]")}
                for row in rows]

    def _scope_row(self, run_id: int,
                   scope: CoverageScope) -> CoverageScopeRow | None:
        return self._session.scalars(
            select(CoverageScopeRow).where(
                CoverageScopeRow.run_id == run_id,
                CoverageScopeRow.scope_type == scope.scope_type,
                CoverageScopeRow.scope_key == scope.scope_key,
            )).first()