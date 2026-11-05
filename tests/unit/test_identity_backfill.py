"""P0-D canonical backfill and legacy-id read annotations."""
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agent_detector.core.enums import AssetState, AssetType
from agent_detector.core.models import (AgentInventoryItem, DetectedAsset,
                                        ProjectInfo, VersionInfo)
from agent_detector.identity.backfill import backfill_identity
from agent_detector.storage import (AgentInventoryRepository,
                                    ApplicationRepository, AssetRepository,
                                    BehaviorEventRepository, ScanRepository)
from agent_detector.storage.database import make_engine
from agent_detector.storage.identity_repository import IdentityRepository
from agent_detector.storage.models import BehaviorEventRow, EntityRow


def _seed(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        scan_id = ScanRepository(session).create("agent")
        ApplicationRepository(session).upsert(
            ProjectInfo(project_id="p1", root=str(tmp_path / "app"),
                        name="app", runtime="python", pids=(1,)),
            [], app_id="app--1")
        assets = AgentInventoryRepository(session)
        assets.upsert_asset(AgentInventoryItem(
            asset_id="client--1", agent_type="claude_code", name="Claude Code"))
        assets.upsert_asset(AgentInventoryItem(
            asset_id="framework--1", agent_type="langchain",
            name="LangChain · app", app_id="app--1"))
        AssetRepository(session).upsert(DetectedAsset(
            asset_id="component--1", name="LangChain",
            asset_type=AssetType.AGENT_RUNTIME,
            states={AssetState.INSTALLED}, confidence=0.8,
            version=VersionInfo.unknown(), evidence=[], detector="langchain"),
            scan_id)
        session.add(BehaviorEventRow(
            observed_at="2026-11-01T00:00:00+00:00", source="auditd",
            agent_label="claude", asset_id="client--1",
            target_asset_id="framework--1", flow_id="auditd-1",
            upstream_host="", protocol="SYS", event_type="proc.exec",
            operation="SCRIPT_EXEC", confidence="high", endpoint=""))
        session.commit()
    return engine


def test_backfill_is_idempotent_and_folds_framework_into_application(tmp_path):
    engine = _seed(tmp_path)
    with Session(engine) as session:
        first = backfill_identity(session, scope_key="host-1")
        session.commit()
        assert first["applications"] == 1
        assert first["agent_assets"] == 2
        assert first["assets"] == 1
        assert first["aliases"] == 4
        assert first["ambiguous"] == 0

        repo = IdentityRepository(session)
        app_entity = repo.resolve_alias("app--1")
        assert app_entity
        assert repo.resolve_alias("framework--1") == app_entity
        assert repo.resolve_alias("client--1") != app_entity
        assert repo.resolve_alias("component--1") != app_entity
        assert AgentInventoryRepository(session).get_asset(
            "framework--1")["entity_id"] == app_entity

        second = backfill_identity(session, scope_key="host-1")
        session.commit()
        assert second["aliases"] == 0
        assert second["skipped"] == 4
        assert session.scalar(select(func.count()).select_from(EntityRow)) == 3


def test_behavior_events_expose_canonical_actor_and_target(tmp_path):
    engine = _seed(tmp_path)
    with Session(engine) as session:
        backfill_identity(session, scope_key="host-1")
        session.commit()
        repo = IdentityRepository(session)
        client_entity = repo.resolve_alias("client--1")
        app_entity = repo.resolve_alias("app--1")
        event = BehaviorEventRepository(session).list_events(source="auditd")[0]
    assert event["entity_id"] == client_entity
    assert event["entity_alias_status"] == "OK"
    assert event["target_entity_id"] == app_entity
    assert event["target_alias_status"] == "OK"


def test_conflicting_aliases_are_marked_ambiguous_and_not_followed(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        repo = IdentityRepository(session)
        first = repo.ensure_entity("PRODUCT_INSTALL", "legacy_asset", "key-a",
                                   scope_key="host-1")
        second = repo.ensure_entity("SERVICE", "legacy_asset", "key-b",
                                    scope_key="host-1")
        assert repo.alias_legacy("old--1", first) == "OK"
        assert repo.alias_legacy("old--1", second) == "AMBIGUOUS"
        assert repo.resolve_alias("old--1") is None
        assert repo.alias_status("old--1") == "AMBIGUOUS"
        session.commit()