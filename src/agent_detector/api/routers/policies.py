"""Policy endpoints: list, override, reload (design sections 6, 8)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from agent_detector.api.deps import Services, get_services
from agent_detector.api.schemas import PolicyUpdateRequest
from agent_detector.storage.repositories import PolicyRepository

router = APIRouter(prefix="/api/v1", tags=["policies"])


def _services() -> Services:
    return get_services()


@router.get("/policies")
def list_policies(services: Services = Depends(_services)):
    """策略清单：决策、风险等级、优先级与命中条件。"""
    with Session(services.engine) as session:
        repository = PolicyRepository(session)
        repository.sync_from_ruleset(services.hooks.policy.ruleset)
        items = repository.list_policies()
        session.commit()
    return {"items": items, "total": len(items),
            "decision_engine": "deterministic",
            "failure_mode": services.hooks.failure_mode,
            "status": services.hooks.policy_status()}


@router.put("/policies/{policy_id}")
def update_policy(policy_id: str, body: PolicyUpdateRequest,
                  services: Services = Depends(_services)):
    """修改一条策略的启用状态或决策，并立即重建策略引擎。

    Operator overrides live in the database; the YAML rule file stays the
    source of truth for what the rule actually matches.
    """
    with Session(services.engine) as session:
        repository = PolicyRepository(session)
        updated = repository.update_policy(policy_id, enabled=body.enabled,
                                           decision=body.decision)
        session.commit()
    if updated is None:
        raise HTTPException(status_code=404, detail="未找到该策略")
    services.hooks.reload()
    return updated


@router.post("/policies/reload")
def reload_policies(services: Services = Depends(_services)):
    services.hooks.reload()
    return {"status": services.hooks.policy_status()}