"""Evidence collection is decoupled from the status decision.

Two regressions this pins down:

* a compose aggregate lost its primary ``container_id`` when re-detected, so
  the next Docker outage re-verified a project name as a filesystem path and
  produced a false ``CONFIRMED_ABSENT``;
* a re-confirmed PRESENT entity never got a snapshot, so a previous CONFIRMED
  verdict kept it hidden even though it still existed.
"""
from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_detector.aggregation.scan_evidence import (write_scan_evidence,
                                                      _write_canonical_inventory)
from agent_detector.core.enums import AssetState, AssetType
from agent_detector.core.models import DetectedAsset, VersionInfo
from agent_detector.coverage import (CoverageGraph, CoverageScope,
                                     CoverageStatus)
from agent_detector.discovery.scanner.inventory import InventoryBuilder
from agent_detector.storage import EntityRepository
from agent_detector.storage.database import make_engine
from agent_detector.storage.models import (EntityAttributeRow, EntityLocationRow,
                                           EntityRow, EntitySnapshotRow,
                                           utc_now_iso)

COMPLETE = CoverageStatus.COMPLETE
FAILED = CoverageStatus.FAILED


def _asset(**overrides) -> DetectedAsset:
    payload = dict(
        asset_id="dify--compose", name="Dify",
        asset_type=AssetType.AGENT_PLATFORM,
        states={AssetState.INSTALLED, AssetState.RUNNING}, confidence=0.9,
        version=VersionInfo.unknown(), evidence=[], detector="dify",
        scope_kind="compose", identity_scope="docker")
    payload.update(overrides)
    return DetectedAsset(**payload)


def _docker_coverage(status=COMPLETE) -> CoverageGraph:
    graph = CoverageGraph()
    graph.add(CoverageScope(
        "docker_engine_enumeration", "local", own_status=status,
        predicates=(("container_presence", status),)))
    return graph


def _seed_compose(session, entity_id="ent-dify", *, container_id="abc123",
                  removal_verdict="NONE", generation=0):
    stamp = utc_now_iso()
    session.add(EntityRow(entity_id=entity_id,
                          entity_kind="COMPOSE_DEPLOYMENT",
                          scope_key="engine:local"))
    session.add(EntityAttributeRow(
        entity_id=entity_id, agent_type="dify", name="Dify", origin="docker",
        container_id=container_id, status="active", inventory_kind="agent",
        first_seen_at=stamp, last_seen_at=stamp))
    session.add(EntityLocationRow(entity_id=entity_id, root_path="docker",
                                  runtime="docker", status="active",
                                  first_seen_at=stamp, last_seen_at=stamp))
    session.add(EntitySnapshotRow(
        entity_id=entity_id, generation_id=generation,
        agent_status="RUNNING",
        status_basis_json=json.dumps({"basis_version": 2, "installed": True,
                                      "configured": True, "running": True}),
        capability_tags_json="[]", hook_state="UNKNOWN",
        removal_verdict=removal_verdict, coverage_summary_json="{}",
        projected_at=stamp))
    session.flush()


def _builder(coverage) -> InventoryBuilder:
    builder = InventoryBuilder(home=Path.cwd())
    builder._coverage = coverage
    return builder


def test_compose_rescan_keeps_the_primary_container_id(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_compose(session)
        item = {"asset_id": "dify--compose", "agent_type": "dify",
                "name": "Dify", "container_id": None, "origin": "docker"}
        _write_canonical_inventory(
            session, [_asset()], [item],
            {"dify--compose": "ent-dify"}, {})
        attr = session.get(EntityAttributeRow, "ent-dify")
    assert attr.container_id == "abc123"


def test_service_assets_do_not_become_inventory_rows(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        service = _asset(asset_id="ollama--port", name="Ollama",
                         asset_type=AssetType.LLM_SERVICE,
                         states={AssetState.RUNNING},
                         detector="http-probe", scope_kind="listen-port",
                         identity_scope="127.0.0.1:11434")
        _write_canonical_inventory(session, [service], [], {"ollama--port": "e2"},
                                   {})
        assert session.get(EntityAttributeRow, "e2") is None


def test_compose_docker_outage_is_unverified_not_absent(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_compose(session)
        builder = _builder(_docker_coverage(FAILED))
        builder._reconfirm_unseen(
            session, set(), set(),
            docker_context={"failed": True, "error": "daemon down",
                            "scope_key": "local"})
        observation = builder.observations[0]
        attr = session.get(EntityAttributeRow, "ent-dify")
    assert observation["presence"] == "UNVERIFIED"
    assert observation["verification"] == "FAILED"
    assert "docker" in observation["reason"]
    assert attr.status == "active"  # the run proved nothing


def test_missing_compose_project_is_a_confirmed_absence(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_compose(session)
        graph = _docker_coverage()
        builder = _builder(graph)
        builder._reconfirm_unseen(
            session, set(), set(),
            docker_context={"failed": False, "containers_seen": set(),
                            "candidates_seen": set(), "projects_seen": set(),
                            "scope_key": "local"})
        observation = builder.observations[0]
        assert observation["presence"] == "ABSENT"

        stats = write_scan_evidence(
            session, scan_id=5, assets=[], inventory=[],
            coverage_summary={}, rule_digests={}, framework_ids=set(),
            host_key="host", engine_key="local", docker_scope_key="local",
            observations=builder.observations, coverage=graph)
        snapshot = session.scalars(select(EntitySnapshotRow).where(
            EntitySnapshotRow.entity_id == "ent-dify",
            EntitySnapshotRow.generation_id == 5)).one()
        attr = session.get(EntityAttributeRow, "ent-dify")
    assert snapshot.lifecycle == "ARCHIVED"
    assert snapshot.removal_verdict == "CONFIRMED"
    assert snapshot.presence == "ABSENT"
    assert snapshot.verification == "VERIFIED"
    assert attr.status == "inactive"
    assert stats["removal_candidates"][0]["status"] == "CONFIRMED_ABSENT"


def test_present_reconfirmation_cancels_a_previous_confirmed_verdict(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_compose(session, removal_verdict="CONFIRMED")
        graph = _docker_coverage()
        builder = _builder(graph)
        builder._reconfirm_unseen(
            session, set(), set(),
            docker_context={"failed": False, "containers_seen": set(),
                            "candidates_seen": set(),
                            "projects_seen": {"docker"}, "scope_key": "local"})
        assert builder.observations[0]["presence"] == "PRESENT"

        write_scan_evidence(
            session, scan_id=6, assets=[], inventory=[],
            coverage_summary={}, rule_digests={}, framework_ids=set(),
            host_key="host", engine_key="local", docker_scope_key="local",
            observations=builder.observations, coverage=graph)
        snapshot = session.scalars(select(EntitySnapshotRow).where(
            EntitySnapshotRow.entity_id == "ent-dify",
            EntitySnapshotRow.generation_id == 6)).one()
        visible = EntityRepository(session).list_agents()
    assert snapshot.lifecycle == "ACTIVE"
    assert snapshot.removal_verdict == "NONE"
    assert snapshot.presence == "PRESENT"
    assert [row["entity_id"] for row in visible] == ["ent-dify"]


def test_degraded_round_reconfirms_compose_presence(tmp_path):
    """T2 降级轮：深探测失联但 list 层面确认 compose 项目仍在。

    出 PRESENT + FAILED（中文理由），实体 WATCH 可见待复核，绝不冒充
    RUNNING，也绝不消失或归档。
    """
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_compose(session)
        graph = _docker_coverage(FAILED)
        builder = _builder(graph)
        builder._reconfirm_unseen(
            session, set(), set(),
            docker_context={"failed": True, "error": "docker 通道出现失联",
                            "containers_seen": {"abc123"},
                            "candidates_seen": set(),
                            "projects_seen": {"docker"},
                            "degraded": 1,
                            "scope_key": "local"})
        observation = builder.observations[0]
        write_scan_evidence(
            session, scan_id=8, assets=[], inventory=[],
            coverage_summary={}, rule_digests={}, framework_ids=set(),
            host_key="host", engine_key="local", docker_scope_key="local",
            observations=builder.observations, coverage=graph)
        snapshot = session.scalars(select(EntitySnapshotRow).where(
            EntitySnapshotRow.entity_id == "ent-dify",
            EntitySnapshotRow.generation_id == 8)).one()
        attr = session.get(EntityAttributeRow, "ent-dify")
        visible = EntityRepository(session).list_agents()
    assert observation["presence"] == "PRESENT"
    assert observation["verification"] == "FAILED"
    assert "深探测失联" in observation["reason"]
    assert snapshot.presence == "PRESENT"
    assert snapshot.verification == "FAILED"
    assert snapshot.lifecycle == "WATCH"
    assert snapshot.reason_code == "deep_probe_stalled"
    # 状态保持持久值（上一代 RUNNING claim 不冒充本轮；last_known 落
    # CONFIGURED——configured 谓词优先），running 绝不为真
    assert snapshot.agent_status == "CONFIGURED"
    basis = json.loads(snapshot.status_basis_json)
    assert basis["running"] is False
    assert attr.status == "active"
    assert [row["entity_id"] for row in visible] == ["ent-dify"]


def test_degraded_round_reconfirms_container_presence(tmp_path):
    """T2 降级轮：容器实体被枚举确认仍在，深探测失联未复核 → WATCH。"""
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        stamp = utc_now_iso()
        session.add(EntityRow(entity_id="ent-n8n",
                              entity_kind="CONTAINER_DEPLOYMENT",
                              scope_key="engine:local"))
        session.add(EntityAttributeRow(
            entity_id="ent-n8n", agent_type="n8n", name="n8n", origin="docker",
            container_id="c0ffee1", status="active", inventory_kind="agent",
            first_seen_at=stamp, last_seen_at=stamp))
        session.flush()
        graph = _docker_coverage(FAILED)
        builder = _builder(graph)
        builder._reconfirm_unseen(
            session, set(), set(),
            docker_context={"failed": True, "error": "docker 通道出现失联",
                            "containers_seen": {"c0ffee1"},
                            "candidates_seen": set(),
                            "projects_seen": set(),
                            "scope_key": "local"})
        observation = builder.observations[0]
        write_scan_evidence(
            session, scan_id=9, assets=[], inventory=[],
            coverage_summary={}, rule_digests={}, framework_ids=set(),
            host_key="host", engine_key="local", docker_scope_key="local",
            observations=builder.observations, coverage=graph)
        snapshot = session.scalars(select(EntitySnapshotRow).where(
            EntitySnapshotRow.entity_id == "ent-n8n",
            EntitySnapshotRow.generation_id == 9)).one()
    assert observation["presence"] == "PRESENT"
    assert "深探测失联" in observation["reason"]
    assert snapshot.presence == "PRESENT"
    assert snapshot.verification == "FAILED"
    assert snapshot.lifecycle == "WATCH"
    assert snapshot.reason_code == "deep_probe_stalled"


def test_degraded_round_without_listing_stays_unverified(tmp_path):
    """枚举本身没跑成（容器不在 containers_seen）：维持既有 UNVERIFIED 语义。"""
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _seed_compose(session)
        builder = _builder(_docker_coverage(FAILED))
        builder._reconfirm_unseen(
            session, set(), set(),
            docker_context={"failed": True, "error": "docker 通道出现失联",
                            "containers_seen": set(),
                            "projects_seen": set(),
                            "scope_key": "local"})
        observation = builder.observations[0]
    assert observation["presence"] == "UNVERIFIED"
    assert observation["verification"] == "FAILED"


def test_failed_product_rule_keeps_the_entity_but_marks_it_unverified(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    executable = tmp_path / "claude.exe"
    executable.write_text("", encoding="utf-8")
    with Session(engine) as session:
        stamp = utc_now_iso()
        session.add(EntityRow(entity_id="ent-claude",
                              entity_kind="PRODUCT_INSTALL", scope_key="host"))
        session.add(EntityAttributeRow(
            entity_id="ent-claude", agent_type="claude_code",
            name="Claude Code", origin="host", executable=str(executable),
            status="active", inventory_kind="agent",
            first_seen_at=stamp, last_seen_at=stamp))
        session.flush()
        graph = CoverageGraph()
        graph.add(CoverageScope(
            "host_process_enumeration", "host", own_status=COMPLETE,
            predicates=(("process_inventory", COMPLETE),)))
        graph.add(CoverageScope(
            "product_rule", "claude_code", own_status=FAILED,
            predicates=(("product_presence", FAILED),)))
        builder = _builder(graph)
        builder._reconfirm_unseen(
            session, set(), {"claude_code"},
            docker_context={"failed": True, "error": "disabled",
                            "scope_key": "local"})
        observation = builder.observations[0]
    assert observation["presence"] == "UNVERIFIED"
    assert observation["verification"] == "FAILED"
    assert "失败" in observation["reason"]


def test_static_presence_without_running_evidence_is_not_running(tmp_path):
    """The file is still there; the process was not seen this scan."""
    engine = make_engine(tmp_path / "db.sqlite3")
    executable = tmp_path / "claude.exe"
    executable.write_text("", encoding="utf-8")
    with Session(engine) as session:
        stamp = utc_now_iso()
        session.add(EntityRow(entity_id="ent-claude",
                              entity_kind="PRODUCT_INSTALL", scope_key="host"))
        session.add(EntityAttributeRow(
            entity_id="ent-claude", agent_type="claude_code",
            name="Claude Code", origin="host", executable=str(executable),
            status="active", inventory_kind="agent",
            first_seen_at=stamp, last_seen_at=stamp))
        session.add(EntitySnapshotRow(
            entity_id="ent-claude", generation_id=0, agent_status="RUNNING",
            status_basis_json=json.dumps({"basis_version": 2,
                                          "installed": True,
                                          "configured": True,
                                          "running": True}),
            capability_tags_json="[]", hook_state="UNKNOWN",
            removal_verdict="NONE", coverage_summary_json="{}",
            projected_at=stamp))
        session.flush()
        graph = CoverageGraph()
        graph.add(CoverageScope(
            "host_process_enumeration", "host", own_status=COMPLETE,
            predicates=(("process_inventory", COMPLETE),)))
        graph.add(CoverageScope(
            "product_rule", "claude_code", own_status=COMPLETE,
            predicates=(("product_presence", COMPLETE),)))
        builder = _builder(graph)
        builder._reconfirm_unseen(
            session, set(), set(),
            docker_context={"failed": True, "error": "disabled",
                            "scope_key": "local"})
        write_scan_evidence(
            session, scan_id=7, assets=[], inventory=[],
            coverage_summary={}, rule_digests={}, framework_ids=set(),
            host_key="host", engine_key="local", docker_scope_key="local",
            observations=builder.observations, coverage=graph)
        snapshot = session.scalars(select(EntitySnapshotRow).where(
            EntitySnapshotRow.entity_id == "ent-claude",
            EntitySnapshotRow.generation_id == 7)).one()
    assert snapshot.presence == "PRESENT"
    assert snapshot.verification == "VERIFIED"
    assert snapshot.agent_status == "CONFIGURED"
    assert snapshot.last_known_status == "CONFIGURED"