"""P1 component identity and entity dependency edges."""
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agent_detector.aggregation.scan_evidence import write_scan_evidence
from agent_detector.coverage import CoverageGraph, CoverageScope, CoverageStatus
from agent_detector.core.enums import (AssetState, AssetType, VersionSource)
from agent_detector.core.models import DetectedAsset, VersionInfo
from agent_detector.storage.component_repository import ComponentRepository
from agent_detector.storage.database import make_engine
from agent_detector.storage.identity_repository import IdentityRepository
from agent_detector.storage.models import (ComponentRelationRow, ComponentRow)


def _assets(state):
    app = DetectedAsset(
        asset_id="app--1", name="my-app", asset_type=AssetType.AI_APPLICATION,
        states={AssetState.RUNNING}, confidence=0.7,
        version=VersionInfo.unknown(), evidence=[], detector="frameworks",
        scope_kind="project", identity_scope="/srv/app")
    framework = DetectedAsset(
        asset_id="langchain--1", name="LangChain · my-app",
        asset_type=AssetType.AGENT_RUNTIME, states={state}, confidence=0.9,
        version=VersionInfo("0.3.7", VersionSource.PACKAGE_METADATA, 0.9),
        evidence=[], detector="langchain",
        scope_kind="project", identity_scope="/srv/app")
    return [app, framework]


def _coverage(project_status=CoverageStatus.COMPLETE):
    graph = CoverageGraph()
    graph.add(CoverageScope(
        "host_process_enumeration", "host", own_status=CoverageStatus.COMPLETE,
        predicates=(("process_inventory", CoverageStatus.COMPLETE),)))
    graph.add(CoverageScope(
        "project_candidate_universe", "scan", own_status=project_status,
        predicates=(("application_presence", project_status),)))
    return graph


def _write(session, state, *, scan_id=11, assets=None, inventory=None,
           coverage=None):
    return write_scan_evidence(
        session, scan_id=scan_id, assets=assets or _assets(state),
        inventory=inventory or [], coverage_summary={},
        rule_digests={"langchain": "digest"},
        framework_ids={"langchain"}, host_key="host-1",
        engine_key="engine-1", docker_scope_key="local",
        coverage=coverage)


def test_installed_framework_becomes_depends_on_edge(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _write(session, AssetState.INSTALLED)
        entity = IdentityRepository(session).resolve_alias("app--1")
        assert IdentityRepository(session).resolve_alias("langchain--1") == entity
        components = ComponentRepository(session).list_for_entity(entity)
        assert len(components) == 1
        component = components[0]
        assert component["name"] == "LangChain"
        assert component["kind"] == "AGENT_RUNTIME"
        assert component["version"] == "0.3.7"
        assert component["version_source"] == "package-metadata"
        assert component["relation_type"] == "DEPENDS_ON"
        assert component["status"] == "confirmed"
        assert component["evidence_claim_id"]
        session.commit()


def test_configured_framework_is_a_candidate_declaration(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _write(session, AssetState.CONFIGURED)
        entity = IdentityRepository(session).resolve_alias("app--1")
        components = ComponentRepository(session).list_for_entity(entity)
        assert len(components) == 1
        assert components[0]["relation_type"] == "DECLARES"
        assert components[0]["status"] == "candidate"


def test_component_relations_are_idempotent(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _write(session, AssetState.INSTALLED)
        _write(session, AssetState.INSTALLED)
        assert session.scalar(select(func.count()).select_from(
            ComponentRow)) == 1
        assert session.scalar(select(func.count()).select_from(
            ComponentRelationRow)) == 1


def test_relation_closes_when_framework_disappears_with_complete_coverage(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _write(session, AssetState.INSTALLED, coverage=_coverage())
        entity = IdentityRepository(session).resolve_alias("app--1")
        assert len(ComponentRepository(session).list_for_entity(entity)) == 1
        # Next scan sees the app but not the framework; project coverage is complete.
        _write(session, AssetState.INSTALLED, scan_id=12,
               assets=[_assets(AssetState.INSTALLED)[0]],
               coverage=_coverage())
        assert ComponentRepository(session).list_for_entity(entity) == []
        row = session.scalars(select(ComponentRelationRow)).first()
        assert row.valid_to is not None and row.status == "expired"


def test_relation_stays_when_project_coverage_is_partial(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        _write(session, AssetState.INSTALLED, coverage=_coverage())
        entity = IdentityRepository(session).resolve_alias("app--1")
        _write(session, AssetState.INSTALLED, scan_id=12,
               assets=[_assets(AssetState.INSTALLED)[0]],
               coverage=_coverage(CoverageStatus.PARTIAL))
        assert len(ComponentRepository(session).list_for_entity(entity)) == 1


def test_mcp_config_becomes_a_declared_component(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    client = DetectedAsset(
        asset_id="claude--1", name="Claude Code",
        asset_type=AssetType.AGENT_CLIENT, states={AssetState.INSTALLED},
        confidence=0.9, version=VersionInfo.unknown(), evidence=[],
        detector="claude-code", scope_kind="user-home",
        identity_scope="/home/bob")
    inventory = [{"asset_id": "claude--1", "hook_state": "UNKNOWN",
                  "mcp_servers": ["filesystem"]}]
    with Session(engine) as session:
        _write(session, AssetState.INSTALLED, assets=[client],
               inventory=inventory)
        entity = IdentityRepository(session).resolve_alias("claude--1")
        components = ComponentRepository(session).list_for_entity(entity)
        assert len(components) == 1
        assert components[0]["name"] == "filesystem"
        assert components[0]["kind"] == "MCP_SERVER"
        assert components[0]["relation_type"] == "DECLARES"
        assert components[0]["status"] == "candidate"


def test_component_version_updates_in_place(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        repo = ComponentRepository(session)
        first = repo.upsert_component("LangChain", kind="AGENT_RUNTIME",
                                      version="0.3.7")
        second = repo.upsert_component("langchain", kind="AGENT_RUNTIME",
                                       version="0.4.0")
        assert first == second
        row = session.get(ComponentRow, first)
        assert row.version == "0.4.0"
        session.commit()