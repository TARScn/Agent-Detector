"""Coverage DAG and effective-status evaluation."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CoverageStatus(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    NOT_RUN = "NOT_RUN"
    DISABLED = "DISABLED"


# Worst wins. COMPLETE is the only status that permits an absence verdict.
_RANK = {
    CoverageStatus.COMPLETE: 0,
    CoverageStatus.PARTIAL: 1,
    CoverageStatus.FAILED: 2,
    CoverageStatus.NOT_RUN: 3,
    CoverageStatus.DISABLED: 4,
}


def _worst(left: CoverageStatus, right: CoverageStatus) -> CoverageStatus:
    return left if _RANK[left] >= _RANK[right] else right


@dataclass(frozen=True)
class CoverageScope:
    scope_type: str
    scope_key: str
    source: str = ""
    own_status: CoverageStatus = CoverageStatus.COMPLETE
    budget: int = 0
    scanned_count: int = 0
    truncated: bool = False
    error_codes: tuple[str, ...] = ()
    # Per-predicate completeness; a scope may confirm existence but not, for
    # example, package contents because of permissions.
    predicates: tuple[tuple[str, CoverageStatus], ...] = ()
    # DAG parents as (scope_type, scope_key).
    parents: tuple[tuple[str, str], ...] = ()

    @property
    def key(self) -> tuple[str, str]:
        return (self.scope_type, self.scope_key)

    def predicate_status(self, predicate: str) -> CoverageStatus:
        values = dict(self.predicates)
        if not values:
            return self.own_status
        return values.get(predicate, CoverageStatus.NOT_RUN)


class CoverageGraph:
    def __init__(self) -> None:
        self._scopes: dict[tuple[str, str], CoverageScope] = {}

    def add(self, scope: CoverageScope) -> None:
        self._scopes[scope.key] = scope

    def get(self, scope_type: str, scope_key: str) -> CoverageScope | None:
        return self._scopes.get((scope_type, scope_key))

    def scopes(self) -> list[CoverageScope]:
        return list(self._scopes.values())

    def effective_status(self, scope_type: str, scope_key: str) -> CoverageStatus:
        memo: dict[tuple[str, str], CoverageStatus] = {}
        visiting: set[tuple[str, str]] = set()

        def walk(key: tuple[str, str]) -> CoverageStatus:
            if key in memo:
                return memo[key]
            scope = self._scopes.get(key)
            if scope is None:
                return CoverageStatus.NOT_RUN
            if key in visiting:  # malformed DAG: never treat as complete
                return CoverageStatus.FAILED
            visiting.add(key)
            status = scope.own_status
            for parent in scope.parents:
                status = _worst(status, walk(parent))
            visiting.remove(key)
            memo[key] = status
            return status

        return walk((scope_type, scope_key))

    def predicate_status(self, scope_type: str, scope_key: str,
                         predicate: str) -> CoverageStatus:
        scope = self.get(scope_type, scope_key)
        if scope is None:
            return CoverageStatus.NOT_RUN
        status = scope.predicate_status(predicate)
        # Parent propagation applies to predicate-level absence too.
        for parent in scope.parents:
            status = _worst(status, self.effective_status(*parent))
        return status

    def is_complete(self, scope_type: str, scope_key: str,
                    predicate: str | None = None) -> bool:
        if predicate is None:
            return self.effective_status(scope_type, scope_key) is CoverageStatus.COMPLETE
        return self.predicate_status(scope_type, scope_key,
                                     predicate) is CoverageStatus.COMPLETE

    def eligible_for_absence(self, required: tuple[tuple[str, str, str], ...], *,
                             positive_evidence: bool = False) -> bool:
        """All required scopes complete for their predicate and no live proof."""
        if positive_evidence:
            return False
        return all(self.is_complete(scope_type, scope_key, predicate)
                   for scope_type, scope_key, predicate in required)

    def summary(self) -> dict:
        counts = {status.value: 0 for status in CoverageStatus}
        truncated = 0
        for scope in self._scopes.values():
            counts[self.effective_status(*scope.key).value] += 1
            if scope.truncated:
                truncated += 1
        return {"scopes": len(self._scopes), "truncated": truncated, **counts}