"""Read-side freshness and visibility.

A snapshot is current when the scope that owns the entity has not been
evaluated again since. A global generation counter would make an unrelated
scan invalidate every entity and would hide the case where the entity's own
scope never re-ran.
"""
from __future__ import annotations

import json

from sqlalchemy.orm import Session

from agent_detector.storage import EntityRepository
from agent_detector.storage.database import make_engine
from agent_detector.storage.models import (CoverageScopeRow, EntityAttributeRow,
                                           EntityRow, EntitySnapshotRow,
                                           utc_now_iso)


def _snapshot(session, entity_id, *, generation=5,
              owner=("product_rule", "claude_code"),
              agent_status="CONFIGURED", verification="VERIFIED",
              lifecycle="ACTIVE", last_known="CONFIGURED",
              removal="NONE", basis=None, presence="PRESENT"):
    session.add(EntitySnapshotRow(
        entity_id=entity_id, generation_id=generation,
        agent_status=agent_status,
        status_basis_json=json.dumps(basis or {"basis_version": 3}),
        capability_tags_json="[]", hook_state="UNKNOWN",
        removal_verdict=removal, coverage_summary_json="{}",
        presence=presence, verification=verification, lifecycle=lifecycle,
        last_known_status=last_known,
        owner_scope_type=owner[0] if owner else None,
        owner_scope_key=owner[1] if owner else None,
        projected_at=utc_now_iso()))


def _seed_entity(session, entity_id, **snapshot):
    stamp = utc_now_iso()
    session.add(EntityRow(entity_id=entity_id, entity_kind="PRODUCT_INSTALL",
                          scope_key="host"))
    session.add(EntityAttributeRow(
        entity_id=entity_id, agent_type="claude_code", name=entity_id,
        status="active", inventory_kind="agent",
        first_seen_at=stamp, last_seen_at=stamp))
    _snapshot(session, entity_id, **snapshot)


def _scope_run(session, run_id, scope_type, scope_key):
    stamp = utc_now_iso()
    session.add(CoverageScopeRow(
        run_id=run_id, scope_type=scope_type, scope_key=scope_key,
        source="test", own_status="COMPLETE", budget=0, scanned_count=0,
        truncated=0, error_codes_json="[]", started_at=stamp,
        finished_at=stamp))


def test_entity_is_stale_only_when_its_own_scope_reran(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_entity(session, "ent-product", generation=5,
                     owner=("product_rule", "claude_code"))
        _seed_entity(session, "ent-docker", generation=5,
                     owner=("docker_engine_enumeration", "local"))
        _scope_run(session, 9, "product_rule", "claude_code")
        _scope_run(session, 5, "docker_engine_enumeration", "local")
        session.commit()

        rows = {row["entity_id"]: row
                for row in EntityRepository(session).list_agents()}

    assert rows["ent-product"]["snapshot_current"] is False
    assert rows["ent-product"]["verification"] == "STALE"
    assert rows["ent-product"]["agent_status"] == "CONFIGURED"
    assert rows["ent-docker"]["snapshot_current"] is True
    assert rows["ent-docker"]["verification"] == "VERIFIED"


def test_current_running_without_verification_is_not_shown_as_running(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_entity(session, "ent-1", generation=9,
                     owner=("product_rule", "claude_code"),
                     agent_status="RUNNING", verification="FAILED",
                     last_known="CONFIGURED")
        _scope_run(session, 9, "product_rule", "claude_code")
        session.commit()
        row = EntityRepository(session).get_agent("ent-1")
    assert row["snapshot_current"] is True
    assert row["verification"] == "FAILED"
    assert row["agent_status"] == "CONFIGURED"


def test_legacy_snapshot_without_owner_falls_back_to_global_generation(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_entity(session, "ent-old", generation=1, owner=None)
        _seed_entity(session, "ent-new", generation=9, owner=None)
        session.commit()
        rows = {row["entity_id"]: row
                for row in EntityRepository(session).list_agents()}
    assert rows["ent-old"]["snapshot_current"] is False
    assert rows["ent-old"]["verification"] == "STALE"
    assert rows["ent-new"]["snapshot_current"] is True


def test_archived_rows_are_hidden_but_kept(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_entity(session, "ent-active", generation=5,
                     lifecycle="ACTIVE", verification="VERIFIED")
        _seed_entity(session, "ent-watch", generation=5,
                     lifecycle="WATCH", verification="NOT_CHECKED")
        _seed_entity(session, "ent-archived", generation=5,
                     lifecycle="ARCHIVED", verification="VERIFIED",
                     removal="CONFIRMED")
        session.commit()
        repository = EntityRepository(session)
        visible = {row["entity_id"] for row in repository.list_agents()}
        everything = {row["entity_id"]
                      for row in repository.list_agents(include_hidden=True)}
        detail = repository.get_agent("ent-archived")
    assert visible == {"ent-active", "ent-watch"}
    assert everything == {"ent-active", "ent-watch", "ent-archived"}
    assert detail["lifecycle"] == "ARCHIVED"


def test_new_scan_clears_a_previous_archive(tmp_path):
    """A PRESENT snapshot from the newest run replaces the archive verdict."""
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_entity(session, "ent-1", generation=3, lifecycle="ARCHIVED",
                     verification="VERIFIED", removal="CONFIRMED",
                     presence="ABSENT")
        _seed_entity(session, "ent-1b", generation=4, lifecycle="ACTIVE")
        _snapshot(session, "ent-1", generation=5, lifecycle="ACTIVE",
                  verification="VERIFIED", removal="NONE",
                  presence="PRESENT")
        session.commit()
        repository = EntityRepository(session)
        row = repository.get_agent("ent-1")
        visible = {item["entity_id"] for item in repository.list_agents()}
    assert row["lifecycle"] == "ACTIVE"
    assert row["removal_verdict"] == "NONE"
    assert "ent-1" in visible