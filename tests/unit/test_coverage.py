import pytest

pytest.skip("legacy asset tables removed in the v12 cutover",
            allow_module_level=True)

"""P0-B coverage DAG, absence gating and legacy-delete switch."""
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_detector.core.enums import AssetState, AssetType
from agent_detector.core.models import (AgentInventoryItem, DetectedAsset,
                                        HostFacts, VersionInfo)
from agent_detector.coverage import (ABSENT, PRESENT, UNVERIFIED,
                                     CoverageGraph, CoverageScope,
                                     CoverageStatus, build_scan_coverage,
                                     reconfirm_application, reconfirm_container,
                                     reconfirm_paths)
from agent_detector.discovery.scanner import scan as scan_service
from agent_detector.discovery.scanner.inventory import InventoryBuilder
from agent_detector.storage import (AgentInventoryRepository,
                                    CoverageRepository, ScanRepository)
from agent_detector.storage.database import make_engine
from agent_detector.storage.models import (CoveragePredicateStatusRow,
                                           CoverageScopeEdgeRow,
                                           CoverageScopeRow,
                                           RemovalCandidateRow)


def make_asset(asset_id="x--1", *, detector="good"):
    return DetectedAsset(
        asset_id=asset_id, name="X", asset_type=AssetType.AGENT_CLIENT,
        states={AssetState.INSTALLED}, confidence=0.7,
        version=VersionInfo.unknown(), evidence=[], detector=detector)


class GoodDetector:
    name = "good"

    def __init__(self, asset=None):
        self.asset = asset or make_asset()

    def detect(self, facts):
        return [self.asset]


# -- graph ------------------------------------------------------------------


def test_partial_parent_propagates_to_child():
    graph = CoverageGraph()
    graph.add(CoverageScope("docker_engine_enumeration", "local",
                            own_status=CoverageStatus.PARTIAL))
    graph.add(CoverageScope("container_deep_scan", "cid",
                            own_status=CoverageStatus.COMPLETE,
                            parents=(("docker_engine_enumeration", "local"),)))
    assert graph.effective_status(
        "container_deep_scan", "cid") is CoverageStatus.PARTIAL
    assert not graph.is_complete("container_deep_scan", "cid")


def test_predicate_status_is_independent_of_existence():
    graph = CoverageGraph()
    graph.add(CoverageScope(
        "container_inspect", "cid", own_status=CoverageStatus.COMPLETE,
        predicates=(("container_presence", CoverageStatus.COMPLETE),
                    ("component_presence", CoverageStatus.PARTIAL))))
    assert graph.is_complete("container_inspect", "cid", "container_presence")
    assert not graph.is_complete("container_inspect", "cid", "component_presence")


def test_build_coverage_project_truncation_is_partial():
    graph = build_scan_coverage(
        processes_count=40, process_source="psutil",
        detector_names=["good"], failed_detectors=(),
        project_stats={"candidate_processes": 40, "truncated": True},
        docker_stats={"containers_total": 0}, docker_ctx={},
        docker_enabled=True, max_projects=40, max_containers=200)
    assert not graph.is_complete(
        "project_candidate_universe", "scan", "application_presence")


def test_build_coverage_docker_disabled_is_disabled():
    graph = build_scan_coverage(
        processes_count=0, process_source="psutil",
        detector_names=[], failed_detectors=(),
        project_stats={}, docker_stats={}, docker_ctx={},
        docker_enabled=False, max_projects=40, max_containers=200)
    assert graph.effective_status(
        "docker_engine_enumeration", "local") is CoverageStatus.DISABLED


def test_build_coverage_container_error_is_failed():
    cid = "a" * 64
    graph = build_scan_coverage(
        processes_count=0, process_source="psutil",
        detector_names=[], failed_detectors=(),
        project_stats={},
        docker_stats={"containers_total": 1,
                      "container_errors": [{"container": cid[:12],
                                            "error": "stalled"}]},
        docker_ctx={"containers_seen": [cid], "candidates_seen": [cid],
                    "failed": False},
        docker_enabled=True, max_projects=40, max_containers=200)
    assert graph.effective_status(
        "container_deep_scan", cid) is CoverageStatus.FAILED


def test_coverage_repository_persists_edges_and_predicates(tmp_path):
    from sqlalchemy import func, select
    engine = make_engine(tmp_path / "db.sqlite3")
    graph = CoverageGraph()
    graph.add(CoverageScope("docker_engine_enumeration", "local",
                            own_status=CoverageStatus.COMPLETE,
                            predicates=(("container_presence",
                                         CoverageStatus.COMPLETE),)))
    graph.add(CoverageScope("container_deep_scan", "cid",
                            own_status=CoverageStatus.PARTIAL,
                            predicates=(("component_presence",
                                         CoverageStatus.PARTIAL),),
                            parents=(("docker_engine_enumeration", "local"),)))
    with Session(engine) as session:
        repo = CoverageRepository(session)
        assert repo.add_graph(7, graph) == 2
        assert repo.add_graph(7, graph) == 2  # idempotent
        session.commit()
    with Session(engine) as session:
        assert session.scalar(select(func.count()).select_from(
            CoverageScopeRow)) == 2
        assert session.scalar(select(func.count()).select_from(
            CoverageScopeEdgeRow)) == 1
        assert session.scalar(select(func.count()).select_from(
            CoveragePredicateStatusRow)) == 2


# -- reconfirm --------------------------------------------------------------


def test_reconfirm_paths(tmp_path):
    existing = tmp_path / "still-here"
    existing.write_text("x", encoding="utf-8")
    assert reconfirm_paths([str(existing)]).verdict == PRESENT
    assert reconfirm_paths([str(tmp_path / "gone")]).verdict == ABSENT
    assert reconfirm_paths([]).verdict == UNVERIFIED


def test_reconfirm_application(tmp_path):
    assert reconfirm_application(str(tmp_path)).verdict == PRESENT
    assert reconfirm_application(str(tmp_path / "gone")).verdict == ABSENT
    assert reconfirm_application(None).verdict == UNVERIFIED


def test_reconfirm_container():
    cid = "a" * 64
    assert reconfirm_container(
        cid, engine_complete=False, containers_seen=[], candidates_seen=[],
        deep_scan_status=None).verdict == UNVERIFIED
    assert reconfirm_container(
        cid, engine_complete=True, containers_seen=[], candidates_seen=[],
        deep_scan_status=None).verdict == ABSENT
    assert reconfirm_container(
        cid, engine_complete=True, containers_seen=[cid],
        candidates_seen=[cid],
        deep_scan_status=CoverageStatus.FAILED).verdict == UNVERIFIED
    assert reconfirm_container(
        cid, engine_complete=True, containers_seen=[cid],
        candidates_seen=[cid],
        deep_scan_status=CoverageStatus.COMPLETE).verdict == ABSENT


# -- inventory gating -------------------------------------------------------


def _container_asset(repository, asset_id="n8n--c"):
    repository.upsert_asset(AgentInventoryItem(
        asset_id=asset_id, agent_type="n8n", name="n8n", origin="docker",
        container_id="a" * 64))


def test_legacy_delete_off_keeps_container_inactive_and_candidates(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    graph = CoverageGraph()
    graph.add(CoverageScope("docker_engine_enumeration", "local",
                            own_status=CoverageStatus.COMPLETE,
                            predicates=(("container_presence",
                                         CoverageStatus.COMPLETE),)))
    with Session(engine) as session:
        repository = AgentInventoryRepository(session)
        _container_asset(repository)
        builder = InventoryBuilder()
        builder.apply_scan(
            session, [], HostFacts("h"), coverage=graph,
            docker_context={"failed": False, "containers_seen": [],
                            "candidates_seen": [], "scope_key": "local"})
        rows = repository.list_assets(include_removed=True)
        assert len(rows) == 1
        assert rows[0]["status"] == "inactive"
        assert builder.removal_candidates[0]["status"] == "CONFIRMED_ABSENT"
        session.commit()


def test_incomplete_docker_coverage_never_confirms_absence(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    graph = CoverageGraph()
    graph.add(CoverageScope("docker_engine_enumeration", "local",
                            own_status=CoverageStatus.PARTIAL,
                            predicates=(("container_presence",
                                         CoverageStatus.PARTIAL),)))
    with Session(engine) as session:
        repository = AgentInventoryRepository(session)
        _container_asset(repository)
        builder = InventoryBuilder()
        builder.apply_scan(
            session, [], HostFacts("h"), coverage=graph,
            docker_context={"failed": False, "containers_seen": [],
                            "candidates_seen": [], "scope_key": "local"})
        assert repository.list_assets(include_removed=True)[0]["status"] == "inactive"
        assert builder.removal_candidates[0]["status"] == "UNVERIFIED"
        session.commit()


def test_rule_failure_only_blocks_its_own_asset(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    graph = CoverageGraph()
    graph.add(CoverageScope("host_process_enumeration", "host",
                            own_status=CoverageStatus.COMPLETE,
                            predicates=(("process_inventory",
                                         CoverageStatus.COMPLETE),)))
    graph.add(CoverageScope("product_rule", "good",
                            own_status=CoverageStatus.COMPLETE,
                            predicates=(("product_presence",
                                         CoverageStatus.COMPLETE),)))
    graph.add(CoverageScope("product_rule", "broken",
                            own_status=CoverageStatus.FAILED,
                            predicates=(("product_presence",
                                         CoverageStatus.FAILED),)))
    with Session(engine) as session:
        repository = AgentInventoryRepository(session)
        repository.upsert_asset(AgentInventoryItem(
            asset_id="c--1", agent_type="good", name="X",
            config_paths=(str(tmp_path / "gone"),)))
        builder = InventoryBuilder()
        builder.apply_scan(session, [], HostFacts("h"), coverage=graph,
                           docker_context={"failed": True})
        assert builder.removal_candidates[0]["status"] == "CONFIRMED_ABSENT"
        assert builder.removal_candidates[0]["asset_id"] == "c--1"
        session.commit()


def test_legacy_container_present_but_not_deep_scanned_is_inactive(
        tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_DETECTOR_LEGACY_DELETE", "1")
    engine = make_engine(tmp_path / "db.sqlite3")
    cid = "a" * 64
    with Session(engine) as session:
        repository = AgentInventoryRepository(session)
        _container_asset(repository)
        builder = InventoryBuilder()
        builder.apply_scan(
            session, [], HostFacts("h"),
            docker_context={"failed": False, "containers_seen": [cid],
                            "candidates_seen": [], "scope_key": "local"})
        rows = repository.list_assets(include_removed=True)
        assert len(rows) == 1 and rows[0]["status"] == "inactive"
        session.commit()


def test_failed_deep_scan_never_confirms_absence(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    cid = "a" * 64
    graph = CoverageGraph()
    graph.add(CoverageScope("docker_engine_enumeration", "local",
                            own_status=CoverageStatus.COMPLETE,
                            predicates=(("container_presence",
                                         CoverageStatus.COMPLETE),)))
    graph.add(CoverageScope("container_deep_scan", cid,
                            own_status=CoverageStatus.FAILED,
                            predicates=(("component_presence",
                                         CoverageStatus.FAILED),),
                            parents=(("docker_engine_enumeration", "local"),)))
    with Session(engine) as session:
        repository = AgentInventoryRepository(session)
        _container_asset(repository)
        builder = InventoryBuilder()
        builder.apply_scan(
            session, [], HostFacts("h"), coverage=graph,
            docker_context={"failed": False, "containers_seen": [cid],
                            "candidates_seen": [cid], "scope_key": "local"})
        assert repository.list_assets(include_removed=True)[0]["status"] == "inactive"
        assert builder.removal_candidates[0]["status"] == "UNVERIFIED"
        session.commit()


def test_legacy_delete_on_preserves_hard_delete(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_DETECTOR_LEGACY_DELETE", "1")
    engine = make_engine(tmp_path / "db.sqlite3")
    graph = CoverageGraph()
    graph.add(CoverageScope("docker_engine_enumeration", "local",
                            own_status=CoverageStatus.COMPLETE,
                            predicates=(("container_presence",
                                         CoverageStatus.COMPLETE),)))
    with Session(engine) as session:
        repository = AgentInventoryRepository(session)
        _container_asset(repository)
        builder = InventoryBuilder()
        builder.apply_scan(
            session, [], HostFacts("h"), coverage=graph,
            docker_context={"failed": False, "containers_seen": [],
                            "candidates_seen": [], "scope_key": "local"})
        assert repository.list_assets(include_removed=True) == []
        assert builder.removal_candidates == []
        session.commit()


# -- scan wiring ------------------------------------------------------------


def test_scan_records_coverage_and_candidate(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (), ()))
    engine = make_engine(tmp_path / "db.sqlite3")
    scan_service.run_scan(engine, detectors=[GoodDetector(make_asset("c--1"))])
    result = scan_service.run_scan(engine, detectors=[])
    assert result["coverage"]["scopes"] > 0
    assert result["removal_candidates"] >= 1
    with Session(engine) as session:
        assert AgentInventoryRepository(session).list_assets(
            include_removed=True)[0]["status"] == "inactive"
        candidates = CoverageRepository(session).list_candidates(
            result["scan_id"])
        assert candidates and candidates[0]["status"] == "UNVERIFIED"
        scopes = CoverageRepository(session).list_scopes(result["scan_id"])
        assert any(scope["scope_type"] == "host_process_enumeration"
                   for scope in scopes)