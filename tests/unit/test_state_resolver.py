"""State resolver matrix: presence × verification × lifecycle.

The resolver is the only place allowed to turn evidence into a display
status. These tests pin the four answers the console shows.
"""
from __future__ import annotations

import json

from sqlalchemy.orm import Session

from agent_detector.aggregation.evidence_ledger import EvidenceLedger
from agent_detector.aggregation.state_resolver import (ABSENT, ACTIVE,
                                                       ARCHIVED, FAILED,
                                                       NOT_CHECKED, PARTIAL,
                                                       PRESENT, UNKNOWN_PRESENCE,
                                                       VERIFIED, WATCH,
                                                       invalidate_on_absence,
                                                       resolve)
from agent_detector.core.enums import AgentStatus
from agent_detector.coverage import (CoverageGraph, CoverageScope,
                                     CoverageStatus)
from agent_detector.storage.database import make_engine
from agent_detector.storage.models import (EntityAttributeRow, EntityRow,
                                           EntitySnapshotRow, utc_now_iso)

CONFIGURED = AgentStatus.CONFIGURED.value
INSTALLED = AgentStatus.INSTALLED.value
RUNNING = AgentStatus.RUNNING.value


def _seed_entity(session, entity_id="ent-1", *, kind="PRODUCT_INSTALL",
                 agent_type="claude_code", container_id=None, origin="host",
                 previous: dict | None = None):
    stamp = utc_now_iso()
    session.add(EntityRow(entity_id=entity_id, entity_kind=kind,
                          scope_key="host"))
    session.add(EntityAttributeRow(
        entity_id=entity_id, agent_type=agent_type, name="Agent",
        origin=origin, container_id=container_id, status="active",
        first_seen_at=stamp, last_seen_at=stamp, inventory_kind="agent"))
    if previous is not None:
        session.add(EntitySnapshotRow(
            entity_id=entity_id, generation_id=previous.get("generation", 0),
            agent_status=previous.get("agent_status", "UNKNOWN"),
            status_basis_json=json.dumps(previous.get("basis", {})),
            capability_tags_json="[]", hook_state="UNKNOWN",
            removal_verdict="NONE", coverage_summary_json="{}",
            projected_at=stamp))
    session.flush()


def _coverage(*, product="claude_code", product_status=CoverageStatus.COMPLETE,
              host_status=CoverageStatus.COMPLETE,
              docker_status=None) -> CoverageGraph:
    graph = CoverageGraph()
    graph.add(CoverageScope(
        "host_process_enumeration", "host", own_status=host_status,
        predicates=(("process_inventory", host_status),)))
    graph.add(CoverageScope(
        "product_rule", product, own_status=product_status,
        predicates=(("product_presence", product_status),)))
    if docker_status is not None:
        graph.add(CoverageScope(
            "docker_engine_enumeration", "local", own_status=docker_status,
            predicates=(("container_presence", docker_status),)))
    return graph


def _claim(ledger, *, entity_id="ent-1", predicate, run, object_ref="x",
           polarity="support", valid_to="2099-01-01T00:00:00+00:00"):
    return ledger.add_claim(
        subject_ref=entity_id, predicate=predicate, object_ref=object_ref,
        polarity=polarity, evidence_class="E2",
        verification_method="test", collection_run_id=run,
        valid_from="2026-01-01T00:00:00+00:00", valid_to=valid_to)


def test_running_observed_this_run_is_verified_running(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_entity(session)
        ledger = EvidenceLedger(session)
        _claim(ledger, predicate="installed", run=5)
        _claim(ledger, predicate="configured", run=5)
        _claim(ledger, predicate="running", run=5)
        _claim(ledger, predicate="entity_presence", run=5)
        state = resolve(session, entity_id="ent-1", generation_id=5,
                        coverage=_coverage())
    assert state.presence == PRESENT
    assert state.agent_status == RUNNING
    assert state.verification == VERIFIED
    assert state.lifecycle == ACTIVE
    assert state.reason_code == "running_verified"


def test_running_claim_from_an_older_run_is_not_running(tmp_path):
    """RUNNING describes one observation window, not a durable status."""
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_entity(session)
        ledger = EvidenceLedger(session)
        _claim(ledger, predicate="configured", run=4)
        _claim(ledger, predicate="running", run=4)
        # This run re-confirmed presence but saw no running evidence.
        _claim(ledger, predicate="entity_presence", run=5)
        state = resolve(session, entity_id="ent-1", generation_id=5,
                        coverage=_coverage())
    assert state.presence == PRESENT
    assert state.agent_status == CONFIGURED
    assert state.verification == VERIFIED
    assert state.basis["running"] is False


def test_degraded_presence_is_watch_not_active(tmp_path):
    """T2 降级轮：枚举确认在（PRESENT）+ 深探测失联（marker FAILED）
    → WATCH 可见待复核；状态保持持久值，绝不 RUNNING。"""
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_entity(session, previous={"generation": 4,
                                        "agent_status": "INSTALLED",
                                        "basis": {"installed": True}})
        ledger = EvidenceLedger(session)
        _claim(ledger, predicate="installed", run=4)
        _claim(ledger, predicate="entity_presence", run=5)
        state = resolve(
            session, entity_id="ent-1", generation_id=5,
            coverage=_coverage(docker_status=CoverageStatus.FAILED),
            unverified={"reason": "容器仍在（本轮枚举确认），深探测失联未复核",
                        "verification": "FAILED",
                        "reason_code": "deep_probe_stalled"})
    assert state.presence == PRESENT
    assert state.verification == FAILED
    assert state.lifecycle == WATCH
    assert state.agent_status == INSTALLED  # last_known，绝不冒充 RUNNING
    assert state.basis["running"] is False
    assert state.reason_code == "deep_probe_stalled"
    assert "深探测失联" in state.reason


def test_unverified_run_keeps_last_durable_status(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_entity(session, previous={
            "generation": 0, "agent_status": "RUNNING",
            "basis": {"basis_version": 2, "installed": True,
                      "configured": True, "running": True}})
        state = resolve(
            session, entity_id="ent-1", generation_id=5,
            coverage=_coverage(product_status=CoverageStatus.FAILED),
            unverified={"reason": "产品规则 claude_code 本轮失败",
                        "verification": FAILED,
                        "reason_code": "scope_failed"})
    assert state.presence == UNKNOWN_PRESENCE
    assert state.agent_status == CONFIGURED  # never RUNNING
    assert state.last_known_status == CONFIGURED
    assert state.verification == FAILED
    assert state.lifecycle == ACTIVE
    assert state.basis["verified"] is False
    assert state.basis["running"] is None


def test_unverifiable_entity_without_history_is_watch(tmp_path):
    """Nothing known and nothing checkable → review item, not ACTIVE."""
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_entity(session)
        state = resolve(
            session, entity_id="ent-1", generation_id=5,
            coverage=_coverage(),
            unverified={"reason": "未记录可复核的安装路径",
                        "verification": NOT_CHECKED,
                        "reason_code": "scope_not_run"})
    assert state.presence == UNKNOWN_PRESENCE
    assert state.last_known_status == UNKNOWN_PRESENCE
    assert state.lifecycle == WATCH


def test_confirmed_absence_archives_the_entity(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_entity(session)
        ledger = EvidenceLedger(session)
        _claim(ledger, predicate="entity_presence", run=5, polarity="refute")
        state = resolve(session, entity_id="ent-1", generation_id=5,
                        coverage=_coverage())
    assert state.presence == ABSENT
    assert state.agent_status == UNKNOWN_PRESENCE
    assert state.verification == VERIFIED
    assert state.lifecycle == ARCHIVED
    assert state.reason_code == "absent_confirmed"


def test_unconfirmed_absence_is_a_visible_watch_item(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_entity(session)
        ledger = EvidenceLedger(session)
        _claim(ledger, predicate="entity_presence", run=5, polarity="refute")
        state = resolve(
            session, entity_id="ent-1", generation_id=5,
            coverage=_coverage(product_status=CoverageStatus.PARTIAL))
    assert state.presence == ABSENT
    assert state.verification == NOT_CHECKED
    assert state.lifecycle == WATCH


def test_partial_coverage_with_presence_is_partial(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_entity(session, kind="CONTAINER_DEPLOYMENT",
                     container_id="c0ffee", origin="docker")
        ledger = EvidenceLedger(session)
        _claim(ledger, predicate="entity_presence", run=5)
        _claim(ledger, predicate="running", run=5)
        graph = CoverageGraph()
        graph.add(CoverageScope(
            "docker_engine_enumeration", "local",
            own_status=CoverageStatus.COMPLETE,
            predicates=(("container_presence", CoverageStatus.COMPLETE),)))
        graph.add(CoverageScope(
            "container_deep_scan", "c0ffee",
            own_status=CoverageStatus.PARTIAL,
            predicates=(("component_presence", CoverageStatus.PARTIAL),)))
        state = resolve(session, entity_id="ent-1", generation_id=5,
                        coverage=graph)
    assert state.presence == PRESENT
    assert state.verification == PARTIAL
    # Running was still observed in this generation; partial coverage is
    # about the static scopes, not about the process evidence.
    assert state.agent_status == RUNNING


def test_absence_invalidates_live_state_claims(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_entity(session)
        ledger = EvidenceLedger(session)
        _claim(ledger, predicate="installed", run=4)
        _claim(ledger, predicate="running", run=4)
        _claim(ledger, predicate="entity_presence", run=5, polarity="refute")
        closed = invalidate_on_absence(session, "ent-1", generation_id=5)
        remaining = {claim.predicate for claim in
                     ledger.current_claims("ent-1")}
        state = resolve(session, entity_id="ent-1", generation_id=5,
                        coverage=_coverage())
    assert closed == 2  # installed + running; presence is this run's evidence
    assert remaining == {"entity_presence"}
    assert state.presence == ABSENT
    assert state.agent_status == UNKNOWN_PRESENCE


def test_installed_only_is_not_promoted_to_configured(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_entity(session)
        ledger = EvidenceLedger(session)
        _claim(ledger, predicate="installed", run=5)
        _claim(ledger, predicate="entity_presence", run=5)
        state = resolve(session, entity_id="ent-1", generation_id=5,
                        coverage=_coverage())
    assert state.agent_status == INSTALLED
    assert state.last_known_status == INSTALLED


def test_missing_product_rule_scope_blocks_absent_archive(tmp_path):
    """A rule that did not run proves nothing, even if paths are gone."""
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_entity(session, agent_type="not_in_rule_list")
        ledger = EvidenceLedger(session)
        _claim(ledger, predicate="entity_presence", run=5, polarity="refute")
        state = resolve(session, entity_id="ent-1", generation_id=5,
                        coverage=_coverage())
    assert state.presence == ABSENT
    assert state.verification == NOT_CHECKED
    assert state.lifecycle == WATCH
    assert any(check.status == "NOT_RUN" for check in state.scope_checks)