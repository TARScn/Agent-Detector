"""A run that could not check an entity must not repeat older evidence.

The bug this pins down: a docker container asset detected once stayed
RUNNING forever once the docker engine became unreachable, because neither
the scan nor the read model ever revisited its snapshot.
"""
from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_detector.aggregation.status_projection import project_entity
from agent_detector.discovery.scanner import scan as scan_service
from agent_detector.core.models import HostFacts
from agent_detector.storage import EntityRepository
from agent_detector.storage.database import make_engine
from agent_detector.storage.models import (AgentInstanceRow, EntityAttributeRow,
                                           EntityRow, EntitySnapshotRow,
                                           utc_now_iso)


def _seed_container_entity(session, entity_id="ent-dify"):
    stamp = utc_now_iso()
    session.add(EntityRow(entity_id=entity_id, entity_kind="CONTAINER_DEPLOYMENT",
                          scope_key="engine:test"))
    session.add(EntityAttributeRow(
        entity_id=entity_id, agent_type="dify", name="Dify", vendor="LangGenius",
        version="1.18.0", version_source="package-metadata", origin="docker",
        container_id="c0ffee", status="active", first_seen_at=stamp,
        last_seen_at=stamp, inventory_kind="agent"))
    session.add(AgentInstanceRow(
        instance_id="inst-1", asset_id="dify--1", entity_id=entity_id,
        agent_type="dify", pid=4242, process_name="python", status="running",
        origin="docker", container_id="c0ffee", last_seen_at=stamp))
    # The stale snapshot a container asset leaves behind.
    session.add(EntitySnapshotRow(
        entity_id=entity_id, generation_id=1, agent_status="RUNNING",
        status_basis_json=json.dumps({"basis_version": 2, "installed": True,
                                      "configured": True, "running": True,
                                      "claim_ids": {}, "conflicts": [],
                                      "source": "legacy_migration"}),
        capability_tags_json="[]", hook_state="UNKNOWN",
        removal_verdict="NONE", coverage_summary_json="{}",
        projected_at=stamp))
    session.commit()


def test_unverified_projection_reports_unknown_with_reason(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        result = project_entity(session, "ent-1", 5,
                                unverified="容器状态：docker 引擎本轮不可达")
        snapshot = session.scalars(select(EntitySnapshotRow)).one()
    assert result["agent_status"] == "UNKNOWN"
    assert snapshot.agent_status == "UNKNOWN"
    basis = json.loads(snapshot.status_basis_json)
    assert basis["running"] is None and basis["configured"] is None
    assert basis["verified"] is False
    assert "docker" in basis["unverified_reason"]


def test_unverified_projection_ignores_older_live_claims(tmp_path):
    """A live claim from an earlier run may not stand in for this one."""
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        from agent_detector.aggregation.evidence_ledger import EvidenceLedger
        EvidenceLedger(session).add_claim(
            subject_ref="ent-1", predicate="running", object_ref="pid:1",
            evidence_class="E3", verification_method="process_evidence",
            rule_id="dify", collection_run_id=1,
            valid_to="2099-01-01T00:00:00+00:00")
        result = project_entity(session, "ent-1", 6, unverified="docker 不可达")
    assert result["agent_status"] == "UNKNOWN"


def test_scan_marks_unreachable_container_entity_unverified(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (), ()))
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_container_entity(session)

    result = scan_service.run_scan(engine, detectors=[], docker_enabled=False)
    assert result["evidence"]["statuses"].get("UNKNOWN") == 1

    with Session(engine) as session:
        snapshot = session.scalars(
            select(EntitySnapshotRow).where(
                EntitySnapshotRow.generation_id == result["scan_id"])).one()
        basis = json.loads(snapshot.status_basis_json)
        instance = session.get(AgentInstanceRow, "inst-1")
        detail = EntityRepository(session).get_agent("ent-dify")
    assert snapshot.agent_status == "UNKNOWN"
    assert basis["verified"] is False
    assert "docker" in basis["unverified_reason"]
    assert instance.status == "unverified"
    assert detail["agent_status"] == "UNKNOWN"
    assert detail["snapshot_current"] is True
    assert detail["instance_count"] == 0


def test_older_generation_snapshot_is_not_presented_as_current(tmp_path):
    """Read-side guard: a pre-migration RUNNING row must not survive a newer run."""
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_container_entity(session)
        # Another entity was projected by the newest generation.
        session.add(EntityRow(entity_id="ent-new", entity_kind="PRODUCT_INSTALL",
                              scope_key="host"))
        session.add(EntityAttributeRow(
            entity_id="ent-new", agent_type="claude_code", name="Claude Code",
            status="active", inventory_kind="agent",
            first_seen_at=utc_now_iso(), last_seen_at=utc_now_iso()))
        session.add(EntitySnapshotRow(
            entity_id="ent-new", generation_id=9, agent_status="RUNNING",
            status_basis_json=json.dumps({"basis_version": 2, "running": True}),
            capability_tags_json="[]", hook_state="UNKNOWN",
            removal_verdict="NONE", coverage_summary_json="{}",
            projected_at=utc_now_iso()))
        session.commit()

        repository = EntityRepository(session)
        stale = repository.get_agent("ent-dify")
        fresh = repository.get_agent("ent-new")

    assert stale["agent_status"] == "UNKNOWN"
    assert stale["snapshot_current"] is False
    assert stale["snapshot_generation_id"] == 1
    assert stale["status_basis"]["stale"] is True
    assert stale["status_basis"]["running"] is None
    assert fresh["agent_status"] == "RUNNING"
    assert fresh["snapshot_current"] is True