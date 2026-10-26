"""Read/write access to ``security_policies`` (design section 8).

The YAML rule set stays the source of truth for *what a rule looks like*; this
table stores the operator's overrides — enabled/disabled and the effective
decision — so the policy page never has to rewrite packaged configuration.
"""
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_detector.storage.models import SecurityPolicyRow, utc_now_iso


class PolicyRepository:
    def __init__(self, session: Session):
        self._session = session

    def sync_from_ruleset(self, ruleset) -> int:
        """Insert one row per YAML rule; keep existing operator overrides."""
        added = 0
        for rule in ruleset.rules:
            if self._session.get(SecurityPolicyRow, rule.id) is None:
                self._session.add(SecurityPolicyRow(
                    policy_id=rule.id, name=rule.name, scope=rule.scope.value,
                    decision=rule.decision.value, risk_level=rule.risk.value,
                    enabled=1 if rule.enabled else 0, priority=rule.priority,
                    conditions_json=json.dumps(rule.conditions(), ensure_ascii=False),
                    reason=rule.reason or rule.description))
                added += 1
            else:
                row = self._session.get(SecurityPolicyRow, rule.id)
                row.name = rule.name
                row.scope = rule.scope.value
                row.risk_level = rule.risk.value
                row.priority = rule.priority
                row.conditions_json = json.dumps(rule.conditions(), ensure_ascii=False)
                row.reason = rule.reason or rule.description
        return added

    def overrides(self) -> dict[str, dict]:
        """``{policy_id: {"enabled": bool, "decision": str}}`` for the engine."""
        return {row.policy_id: {"enabled": bool(row.enabled), "decision": row.decision}
                for row in self._session.scalars(select(SecurityPolicyRow))}

    def list_policies(self) -> list[dict]:
        rows = self._session.scalars(select(SecurityPolicyRow).order_by(
            SecurityPolicyRow.priority, SecurityPolicyRow.policy_id))
        return [self._to_dict(row) for row in rows]

    def get_policy(self, policy_id: str) -> dict | None:
        row = self._session.get(SecurityPolicyRow, policy_id)
        return self._to_dict(row) if row else None

    def update_policy(self, policy_id: str, *, enabled: bool | None = None,
                      decision: str | None = None) -> dict | None:
        row = self._session.get(SecurityPolicyRow, policy_id)
        if row is None:
            return None
        if enabled is not None:
            row.enabled = 1 if enabled else 0
        if decision is not None:
            row.decision = decision
        row.updated_at = utc_now_iso()
        return self._to_dict(row)

    @staticmethod
    def _to_dict(row: SecurityPolicyRow) -> dict:
        return {"policy_id": row.policy_id, "name": row.name, "scope": row.scope,
                "decision": row.decision, "risk_level": row.risk_level,
                "enabled": bool(row.enabled), "priority": row.priority,
                "conditions": json.loads(row.conditions_json or "{}"),
                "reason": row.reason, "updated_at": row.updated_at}