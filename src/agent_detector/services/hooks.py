"""Hook decision service: the synchronous path an Agent waits on (§5.1, §8).

Order of operations for one PreToolUse call:

1. normalize the platform payload into a ToolCall (hooks/normalizer)
2. correlate it to an Agent asset/instance/session where provable (detection)
3. evaluate policy (pure, deterministic — never an LLM call)
4. record the tool call as a ``native_hook`` behavior event
5. raise an alert when the verdict denies or the risk crosses the bar
6. render the answer in the Agent's own response shape

Steps 4-5 are advisory: if recording fails, the verdict still goes back. A
broken database must not turn into "allow everything" (the fail-closed rule is
applied at the transport layer, not here).
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from sqlalchemy.orm import Session

from agent_detector.common.config import ALERT_RISK_LEVEL, HOOK_FAILURE_MODE
from agent_detector.detection.correlation import resolve_instance_for_pid
from agent_detector.domain.enums import ExecutionStatus, HookEvent
from agent_detector.domain.models import PolicyVerdict, ToolCall
from agent_detector.hooks.normalizer import describe_event, normalize
from agent_detector.hooks.registry import get_adapter
from agent_detector.policy.engine import PolicyEngine, risk_at_least
from agent_detector.policy.loader import load_policies
from agent_detector.storage.models import utc_now_iso
from agent_detector.storage.repositories import (AgentInventoryRepository, AlertRepository,
                                                BehaviorEventRepository, PolicyRepository)

logger = logging.getLogger(__name__)


@dataclass
class HookOutcome:
    verdict: PolicyVerdict
    call: ToolCall | None
    response: dict
    event_id: int | None = None
    asset_id: str | None = None
    instance_id: str | None = None
    session_id: str | None = None
    correlated_by: str = "none"
    latency_ms: int = 0

    def to_dict(self) -> dict:
        return {"decision": self.verdict.decision.value,
                "risk_level": self.verdict.risk.value,
                "reason": self.verdict.reason,
                "matched_rules": list(self.verdict.matched_rules),
                "policy_id": self.verdict.policy_id,
                "error": self.verdict.error,
                "agent_type": self.call.agent_type if self.call else None,
                "event_type": (self.call.event_type.value if self.call else None),
                "tool_name": self.call.tool_name if self.call else None,
                "session_id": self.session_id, "asset_id": self.asset_id,
                "instance_id": self.instance_id,
                "correlated_by": self.correlated_by,
                "event_id": self.event_id, "latency_ms": self.latency_ms,
                "response": self.response}


class HookDecisionService:
    """Owns the policy engine cache and the audit write path."""

    def __init__(self, engine, *, policy_dir=None, failure_mode: str | None = None,
                 alert_risk: str | None = None):
        self.engine = engine
        self.policy_dir = policy_dir
        self.failure_mode = failure_mode or HOOK_FAILURE_MODE
        self.alert_risk = alert_risk or ALERT_RISK_LEVEL
        self._policy_engine: PolicyEngine | None = None
        self._load_errors: list[dict[str, str]] = []
        self._sources: list[str] = []
        self.decisions = 0
        self.denials = 0
        self.errors = 0

    # -- policy cache ------------------------------------------------------

    def reload(self) -> PolicyEngine:
        loaded = load_policies(self.policy_dir)
        self._load_errors = loaded.errors
        self._sources = loaded.sources
        overrides: dict[str, dict] = {}
        try:
            with Session(self.engine) as session:
                repo = PolicyRepository(session)
                repo.sync_from_ruleset(loaded.ruleset)
                overrides = repo.overrides()
                session.commit()
        except Exception:  # policies still work without stored overrides
            logger.exception("policy override sync failed")
        self._policy_engine = PolicyEngine(loaded.ruleset, overrides=overrides,
                                           failure_mode=self.failure_mode)
        return self._policy_engine

    @property
    def policy(self) -> PolicyEngine:
        if self._policy_engine is None:
            self.reload()
        assert self._policy_engine is not None
        # Keep the engine's failure mode in step with this service, so switching
        # between audit mode and fail-closed takes effect without a reload.
        self._policy_engine.failure_mode = self.failure_mode
        return self._policy_engine

    def policy_status(self) -> dict:
        return {"rules": len(self.policy.rules()), "sources": list(self._sources),
                "errors": self._load_errors, "failure_mode": self.failure_mode,
                "alert_risk_level": self.alert_risk,
                "decisions": self.decisions, "denials": self.denials,
                "engine_errors": self.errors}

    # -- the decision path -------------------------------------------------

    def decide(self, agent_type: str | None, payload: dict,
               *, bridge_ppid: int | None = None) -> HookOutcome:
        started = time.perf_counter()
        call = normalize(agent_type or "", payload) if agent_type else None
        adapter = get_adapter(call.agent_type if call else (agent_type or ""))
        if call is None or adapter is None:
            self.errors += 1
            verdict = self.policy.decide_error(
                f"无法规范化 Hook 事件（agent_type={agent_type or 'unknown'}）")
            response = (adapter.failure_response(verdict.reason, fail_closed=(
                self.failure_mode != "allow")) if adapter else
                {"permission": "deny", "reason": verdict.reason})
            return HookOutcome(verdict=verdict, call=None, response=response,
                               latency_ms=_ms(started))
        try:
            verdict = self.policy.decide(call)
        except Exception as exc:  # a rule blew up: fail per configured mode
            logger.exception("policy evaluation failed")
            self.errors += 1
            verdict = self.policy.decide_error(str(exc))
        response = adapter.response(verdict, call)
        outcome = HookOutcome(verdict=verdict, call=call, response=response,
                              session_id=call.session_id,
                              latency_ms=_ms(started))
        try:
            self._record(outcome, bridge_ppid=bridge_ppid)
        except Exception:  # never let audit failures change the verdict
            logger.exception("hook event recording failed")
        outcome.latency_ms = _ms(started)
        self.decisions += 1
        if verdict.decision.value == "deny":
            self.denials += 1
        return outcome

    def _record(self, outcome: HookOutcome, *, bridge_ppid: int | None) -> None:
        call = outcome.call
        assert call is not None
        with Session(self.engine) as session:
            inventory = AgentInventoryRepository(session)
            events = BehaviorEventRepository(session)
            alerts = AlertRepository(session)

            agent = inventory.find_asset_by_type(call.agent_type)
            outcome.asset_id = agent["asset_id"] if agent else None
            instance = resolve_instance_for_pid(bridge_ppid, session)
            if instance is not None:
                outcome.instance_id = instance["instance_id"]
                outcome.correlated_by = instance.get("matched_by", "process-tree")
                if outcome.asset_id is None:
                    outcome.asset_id = instance["asset_id"]
            if call.session_id:
                inventory.touch_session(
                    call.session_id, call.agent_type, asset_id=outcome.asset_id,
                    instance_id=outcome.instance_id, cwd=call.cwd,
                    tool=call.tool_name or None,
                    closed=call.event_type is HookEvent.SESSION_END)
            if call.event_type is HookEvent.PRE_TOOL_USE:
                operation, target = describe_event(call)
                execution = (ExecutionStatus.BLOCKED_BY_HOOK
                             if outcome.verdict.blocked else ExecutionStatus.ALLOWED)
                event_id = events.record_tool_call(
                    observed_at=utc_now_iso(),
                    agent_label=call.agent_label or call.agent_type,
                    tool=call.tool_name, operation=operation, target=target[:512],
                    asset_id=outcome.asset_id, session_id=call.session_id,
                    instance_id=outcome.instance_id,
                    decision=outcome.verdict.decision.value,
                    execution_status=execution.value,
                    risk_level=outcome.verdict.risk.value,
                    policy_id=outcome.verdict.policy_id,
                    pid=bridge_ppid,
                    evidence=list(outcome.verdict.matched_rules))
                outcome.event_id = event_id
                if outcome.verdict.blocked or risk_at_least(outcome.verdict.risk.value,
                                                            self.alert_risk):
                    alerts.raise_alert(
                        title=f"{call.agent_label or call.agent_type} · {operation}",
                        reason=outcome.verdict.reason,
                        risk_level=outcome.verdict.risk.value,
                        decision=outcome.verdict.decision.value,
                        asset_id=outcome.asset_id, agent_type=call.agent_type,
                        agent_label=call.agent_label or call.agent_type,
                        session_id=call.session_id, event_id=event_id,
                        policy_id=outcome.verdict.policy_id,
                        detail={"tool_name": call.tool_name, "cwd": call.cwd,
                                "matched_rules": list(outcome.verdict.matched_rules)})
            else:
                events.record_tool_call(
                    observed_at=utc_now_iso(),
                    agent_label=call.agent_label or call.agent_type,
                    tool=call.tool_name, operation="post.tool_use",
                    target=_post_target(call.tool_input),
                    asset_id=outcome.asset_id, session_id=call.session_id,
                    instance_id=outcome.instance_id,
                    decision="allow",
                    execution_status=_post_status(call),
                    risk_level=None, event_type="tool_result")
            session.commit()

    def failure_outcome(self, reason: str, agent_type: str | None = None) -> HookOutcome:
        """Verdict used when the caller (transport) could not reach the service."""
        adapter = get_adapter(agent_type or "")
        verdict = self.policy.decide_error(reason)
        self.errors += 1
        response = (adapter.failure_response(reason, fail_closed=(
            self.failure_mode != "allow")) if adapter else
            {"permission": "deny", "reason": reason})
        return HookOutcome(verdict=verdict, call=None, response=response)


def _post_target(tool_input: dict) -> str | None:
    for key in ("file_path", "path", "command"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            return value[:512]
    return None


def _post_status(call: ToolCall) -> str:
    """PostToolUse tells us whether an allowed call actually ran (§7)."""
    for key in ("error", "tool_error"):
        if call.tool_input.get(key):
            return ExecutionStatus.FAILED.value
    response = call.tool_input.get("tool_response")
    if isinstance(response, dict) and response.get("is_error"):
        return ExecutionStatus.FAILED.value
    return ExecutionStatus.SUCCEEDED.value


def _ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)