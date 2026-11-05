"""P0-A identity foundation: host, process birth, entity keys and shadow write."""
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agent_detector.core.enums import AssetState, AssetType
from agent_detector.core.models import (DetectedAsset, HostFacts, ProcessInfo,
                                        VersionInfo)
from agent_detector.discovery.scanner.identity_shadow import write_identity_shadow
from agent_detector.identity.canonical import canonical_json
from agent_detector.identity.engine import resolve_engine_identity
from agent_detector.identity.entity import (EntityKind, KeyType,
                                            build_entity_key,
                                            legacy_identity_for_asset)
from agent_detector.identity.host import HostIdentityError, HostIdentityStore
from agent_detector.identity.process import (ProcessBirth, match_process_birth)
from agent_detector.storage.database import make_engine
from agent_detector.storage.models import (DockerEngineRow,
                                           EngineHostBindingRow,
                                           EntityAliasRow, EntityKeyRow,
                                           EntityRow, HostIdentityRow,
                                           ProcessBirthRow)


def make_asset(*, asset_id="asset--1", name="Asset", asset_type=AssetType.AGENT_CLIENT,
               scope_kind="user-home", identity_scope="", detector="rule",
               running_pids=None):
    return DetectedAsset(
        asset_id=asset_id, name=name, asset_type=asset_type,
        states={AssetState.INSTALLED}, confidence=0.8,
        version=VersionInfo.unknown(), evidence=[], detector=detector,
        scope_kind=scope_kind, identity_scope=identity_scope,
        running_pids=list(running_pids or []))


def birth(*, pid=10, ticks=100, boot="boot-a", pidns="pid:[1]", scope="host-1",
          platform="linux", source="proc", clock="boot_ticks"):
    return ProcessBirth(
        platform=platform, scope_key=scope, boot_identity=boot,
        pid_namespace_key=pidns, pid=pid, native_birth_value=str(ticks),
        clock_domain=clock, resolution="proc_starttime_ticks",
        canonical_start_ticks=ticks if clock == "boot_ticks" else None,
        source=source, verification_state="verified")


# -- canonical / host -------------------------------------------------------


def test_canonical_json_is_order_independent():
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})


def test_host_identity_persists_and_reuses_uuid(tmp_path):
    path = tmp_path / "host-identity.json"
    first = HostIdentityStore(path, platform="test").resolve()
    second = HostIdentityStore(path, platform="test").resolve()
    assert first.host_key == second.host_key
    assert first.installation_id == second.installation_id
    assert first.identity_basis == "installation_uuid"
    assert path.exists()


def test_host_identity_operator_override(tmp_path):
    store = HostIdentityStore(
        tmp_path / "host-identity.json", platform="test",
        env={"AGENT_DETECTOR_HOST_ID": "operator-host"})
    identity = store.resolve()
    assert identity.host_key == "operator-host"
    assert identity.identity_basis == "operator_override"
    assert identity.trust_state == "VERIFIED"


def test_container_detector_does_not_overwrite_host_state(tmp_path, monkeypatch):
    path = tmp_path / "host-identity.json"
    host = HostIdentityStore(path, platform="test").resolve()
    container_store = HostIdentityStore(path, platform="linux")
    monkeypatch.setattr(container_store, "_in_container", lambda: True)
    local = container_store.resolve()
    assert local.detector_local is True
    assert local.identity_basis == "detector_local"
    assert local.host_key != host.host_key
    assert (tmp_path / "host-identity.json.detector-local").exists()
    # The host identity file is untouched and still resolves to the same key.
    assert HostIdentityStore(path, platform="test").resolve().host_key == host.host_key


def test_host_identity_corrupt_state_is_not_silently_replaced(tmp_path):
    path = tmp_path / "host-identity.json"
    path.write_text("{not-json", encoding="utf-8")
    with pytest.raises(HostIdentityError):
        HostIdentityStore(path, platform="test").resolve()


# -- process birth ----------------------------------------------------------


def test_instance_key_changes_with_birth_not_with_pid_alone():
    first = birth(pid=10, ticks=100)
    same = birth(pid=10, ticks=101)  # within matching tolerance, still its own key
    reused = birth(pid=10, ticks=900)  # same pid, new instance
    assert first.instance_key != same.instance_key
    assert first.instance_key != reused.instance_key
    assert first.instance_key.startswith("inst-")


def test_match_process_birth_uses_ticks_and_refuses_cross_domain():
    assert match_process_birth(birth(ticks=100), birth(ticks=101)) is True
    assert match_process_birth(birth(ticks=100), birth(ticks=110)) is False
    assert match_process_birth(birth(ticks=100), birth(pid=11, ticks=100)) is False
    assert match_process_birth(
        birth(ticks=100),
        birth(platform="win32", clock="epoch_seconds", source="psutil")) is None


def test_process_birth_from_live_process_info_is_deterministic():
    from agent_detector.identity.process import build_process_birth
    info = ProcessInfo(pid=999_999, name="python", create_time=1700000000.25)
    first = build_process_birth(999_999, "host-1", process_info=info,
                                platform="win32")
    second = build_process_birth(999_999, "host-1", process_info=info,
                                 platform="win32")
    assert first is not None and second is not None
    assert first.instance_key == second.instance_key
    assert first.clock_domain == "epoch_seconds"
    assert first.boot_identity.startswith("boot:")


# -- entity keys ------------------------------------------------------------


def test_entity_key_is_stable_and_scope_sensitive():
    first = build_entity_key(KeyType.APPLICATION, "host-1", {"root": "/srv/app"})
    same = build_entity_key(KeyType.APPLICATION, "host-1", {"root": "/srv/app"})
    other_host = build_entity_key(KeyType.APPLICATION, "host-2", {"root": "/srv/app"})
    assert first == same
    assert first != other_host


def test_project_assets_share_one_application_entity():
    app = make_asset(asset_id="app--1", asset_type=AssetType.AI_APPLICATION,
                     scope_kind="project", identity_scope="/srv/app",
                     detector="frameworks")
    framework = make_asset(asset_id="langchain--1", name="LangChain",
                           asset_type=AssetType.AGENT_RUNTIME,
                           scope_kind="project", identity_scope="/srv/app",
                           detector="langchain")
    first = legacy_identity_for_asset(app, "host-1")
    second = legacy_identity_for_asset(framework, "host-1")
    assert first.entity_kind is EntityKind.SELF_BUILT_APPLICATION
    assert first.key_type is KeyType.APPLICATION
    assert first.canonical_key == second.canonical_key


def test_user_home_identity_includes_product_but_not_home_alone():
    claude = make_asset(asset_id="claude--1", scope_kind="user-home",
                        identity_scope="/home/bob", detector="claude-code")
    codex = make_asset(asset_id="codex--1", scope_kind="user-home",
                       identity_scope="/home/bob", detector="codex-cli")
    assert (legacy_identity_for_asset(claude, "host-1").canonical_key
            != legacy_identity_for_asset(codex, "host-1").canonical_key)


def test_probe_port_is_not_a_strong_entity_key():
    probe = make_asset(asset_id="ollama--port", asset_type=AssetType.LLM_SERVICE,
                       scope_kind="listen-port", identity_scope="11434",
                       detector="http-probe")
    identity = legacy_identity_for_asset(probe, "host-1")
    assert identity.entity_kind is EntityKind.SERVICE
    assert identity.key_type is KeyType.LEGACY_ASSET


def test_remote_engine_is_not_bound_to_the_local_host(tmp_path):
    store = HostIdentityStore(tmp_path / "host.json", platform="test")
    host = store.resolve()
    local = resolve_engine_identity(host, is_local=True)
    remote = resolve_engine_identity(host, daemon_id="daemon-1", is_local=False)
    assert local.engine_host_key == host.host_key
    assert remote.engine_host_key is None
    assert remote.binding_state == "UNVERIFIED"
    assert remote.engine_key != local.engine_key


# -- shadow writer ----------------------------------------------------------


def _shadow(session, engine, assets, facts=None):
    stats = write_identity_shadow(
        session, engine, assets,
        facts or HostFacts("host", processes=(), sockets=()))
    session.commit()
    return stats


def test_identity_shadow_writes_and_is_idempotent(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    assets = [
        make_asset(asset_id="claude--1", scope_kind="user-home",
                   identity_scope="/home/bob", detector="claude-code"),
        make_asset(asset_id="app--1", asset_type=AssetType.AI_APPLICATION,
                   scope_kind="project", identity_scope="/srv/app",
                   detector="frameworks"),
    ]
    with Session(engine) as session:
        first = _shadow(session, engine, assets)
    assert first["enabled"] is True
    assert first["error"] is None
    assert first["entities"] == 2
    assert first["aliases"] == 2

    with Session(engine) as session:
        second = _shadow(session, engine, assets)
        assert second["entities"] == 2
        # All aliases still resolve to the same canonical entity.
        assert session.scalar(select(func.count()).select_from(EntityRow)) == 2
        assert session.scalar(select(func.count()).select_from(EntityKeyRow)) == 2
        assert session.scalar(select(func.count()).select_from(EntityAliasRow)) == 2
        assert session.scalar(select(func.count()).select_from(HostIdentityRow)) == 1
        assert session.scalar(select(func.count()).select_from(DockerEngineRow)) == 1
        assert session.scalar(
            select(func.count()).select_from(EngineHostBindingRow)) == 1
        claude = session.get(EntityAliasRow, "claude--1")
        app = session.get(EntityAliasRow, "app--1")
        assert claude is not None and app is not None
        assert claude.entity_id != app.entity_id
        assert all(row.scope_key for row in session.scalars(select(EntityRow)))


def test_identity_shadow_skips_container_pids(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    container = make_asset(asset_id="n8n--c", asset_type=AssetType.AGENT_PLATFORM,
                           scope_kind="container", identity_scope="c" * 64,
                           detector="n8n", running_pids=[123])
    with Session(engine) as session:
        stats = _shadow(session, engine, [container])
    assert stats["process_births"] == 0
    with Session(engine) as session:
        assert session.scalar(select(func.count()).select_from(ProcessBirthRow)) == 0
        alias = session.get(EntityAliasRow, "n8n--c")
        entity = session.get(EntityRow, alias.entity_id)
        assert entity.entity_kind == EntityKind.CONTAINER_DEPLOYMENT.value


def test_run_scan_publishes_identity_shadow(tmp_path, monkeypatch):
    from agent_detector.discovery.scanner import scan as scan_service

    class Detector:
        name = "fake"

        def detect(self, facts):
            return [make_asset(asset_id="claude--1", scope_kind="user-home",
                               identity_scope="/home/bob",
                               detector="claude-code")]

    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("host", processes=(), sockets=()))
    engine = make_engine(tmp_path / "db.sqlite3")
    result = scan_service.run_scan(engine, detectors=[Detector()],
                                   docker_enabled=False)
    assert result["status"] == "completed"
    assert result["identity_shadow"]["enabled"] is True
    assert result["identity_shadow"]["entities"] == 1
    with Session(engine) as session:
        assert session.scalar(select(func.count()).select_from(EntityRow)) == 1
        assert session.scalar(select(func.count()).select_from(EntityAliasRow)) == 1


def test_run_scan_survives_corrupt_identity_state(tmp_path, monkeypatch):
    from agent_detector.discovery.scanner import scan as scan_service

    class Detector:
        name = "fake"

        def detect(self, facts):
            return [make_asset(asset_id="claude--1", scope_kind="user-home",
                               identity_scope="/home/bob",
                               detector="claude-code")]

    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("host", processes=(), sockets=()))
    engine = make_engine(tmp_path / "db.sqlite3")
    (tmp_path / "host-identity.json").write_text("{bad-json", encoding="utf-8")
    result = scan_service.run_scan(engine, detectors=[Detector()],
                                   docker_enabled=False)
    assert result["status"] == "completed"
    assert result["identity_shadow"]["enabled"] is True
    assert result["identity_shadow"]["error"]
    assert any(error["detector"] == "identity-shadow"
               for error in result["errors"])


def test_remote_docker_host_stays_unbound(tmp_path, monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "tcp://10.0.0.5:2375")
    engine = make_engine(tmp_path / "db.sqlite3")
    asset = make_asset(asset_id="n8n--compose", asset_type=AssetType.AGENT_PLATFORM,
                       scope_kind="compose", identity_scope="prod",
                       detector="n8n")
    with Session(engine) as session:
        stats = _shadow(session, engine, [asset])
    with Session(engine) as session:
        row = session.scalars(select(DockerEngineRow)).first()
        assert row is not None
        assert row.engine_host_key is None
        assert row.binding_state == "UNVERIFIED"
        assert session.scalar(
            select(func.count()).select_from(EngineHostBindingRow)) == 0
        entity = session.get(EntityRow, session.get(
            EntityAliasRow, "n8n--compose").entity_id)
        assert entity.scope_key == stats["engine_key"]


def test_container_project_uses_engine_scope_and_skips_container_pids(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    asset = make_asset(asset_id="app--ctr", asset_type=AssetType.AI_APPLICATION,
                       scope_kind="project",
                       identity_scope="container:abc123:/app",
                       detector="frameworks", running_pids=[321])
    facts = HostFacts("host", processes=(
        ProcessInfo(pid=321, name="python", create_time=1700000000.25,
                    container_id="abc123"),), sockets=())
    with Session(engine) as session:
        stats = _shadow(session, engine, [asset], facts)
    assert stats["process_births"] == 0
    with Session(engine) as session:
        alias = session.get(EntityAliasRow, "app--ctr")
        entity = session.get(EntityRow, alias.entity_id)
        assert entity.scope_key == stats["engine_key"]
        assert entity.scope_key.startswith("engine:")


def test_identity_shadow_records_host_process_birth(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    asset = make_asset(asset_id="claude--1", scope_kind="user-home",
                       identity_scope="/home/bob", detector="claude-code",
                       running_pids=[999_999])
    facts = HostFacts("host", processes=(
        ProcessInfo(pid=999_999, name="claude", create_time=1700000000.25),), sockets=())
    with Session(engine) as session:
        stats = _shadow(session, engine, [asset], facts)
    assert stats["process_births"] == 1
    with Session(engine) as session:
        row = session.scalars(select(ProcessBirthRow)).first()
        assert row is not None
        assert row.pid == 999_999
        assert row.scope_key == stats["host_key"]