from sqlalchemy.orm import Session

from agent_detector.domain.enums import AssetState, AssetType, EvidenceKind, VersionSource
from agent_detector.domain.models import DetectedAsset, Evidence, VersionInfo
from agent_detector.persistence.database import make_engine
from agent_detector.persistence.repositories import (AssetRepository, EvidenceRepository,
                                                      ScanRepository)


def make_asset(**overrides):
    defaults = dict(
        asset_id="claude-code--abc123", name="Claude Code",
        asset_type=AssetType.AGENT_CLIENT,
        states={AssetState.INSTALLED, AssetState.CONFIGURED},
        confidence=0.9,
        version=VersionInfo("1.2.3", VersionSource.PACKAGE_METADATA, 0.9),
        evidence=[Evidence(EvidenceKind.INSTALL_METADATA, "npm pkg",
                           {"path": "x/package.json", "version": "1.2.3"}, 0.9)],
        running_pids=[], listening_ports=[], detector="claude-code")
    defaults.update(overrides)
    return DetectedAsset(**defaults)


def test_scan_roundtrip_and_asset_dedup(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        scan_repo = ScanRepository(session)
        asset_repo = AssetRepository(session)
        evidence_repo = EvidenceRepository(session)

        first = scan_repo.create("passive")
        asset_repo.upsert(make_asset(), first)
        evidence_repo.add_all(first, make_asset())
        scan_repo.finish(first, "completed", {"assets": 1})

        second = scan_repo.create("passive")
        asset_repo.upsert(make_asset(states={AssetState.INSTALLED, AssetState.RUNNING},
                                     running_pids=[42]), second)
        scan_repo.finish(second, "completed", {"assets": 1})
        session.commit()

    with Session(engine) as session:
        assert len(AssetRepository(session).list_assets()) == 1  # no duplicate identity

        first_snapshots = AssetRepository(session).list_snapshots(first)
        second_snapshots = AssetRepository(session).list_snapshots(second)
        assert first_snapshots[0]["states"] == ["CONFIGURED", "INSTALLED"]
        assert second_snapshots[0]["states"] == ["INSTALLED", "RUNNING"]
        assert second_snapshots[0]["running_pids"] == [42]
        assert first_snapshots[0]["version"] == "1.2.3"
        assert first_snapshots[0]["version_source"] == "package-metadata"

        evidence = EvidenceRepository(session).for_asset("claude-code--abc123",
                                                         scan_id=first)
        assert evidence and evidence[0]["summary"] == "npm pkg"
        assert evidence[0]["detail"]["version"] == "1.2.3"

        scans = ScanRepository(session).list()
        assert [s["id"] for s in scans] == [second, first]
        assert all(s["status"] == "completed" for s in scans)

        latest = AssetRepository(session).latest_snapshots()
        assert len(latest) == 1 and latest[0]["states"] == ["INSTALLED", "RUNNING"]


def test_assets_survive_service_restart(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        scan_repo = ScanRepository(session)
        scan_id = scan_repo.create("passive")
        AssetRepository(session).upsert(make_asset(), scan_id)
        scan_repo.finish(scan_id, "completed", {})
        session.commit()
    engine.dispose()

    reopened = make_engine(tmp_path / "db.sqlite3")
    with Session(reopened) as session:
        assert ScanRepository(session).latest_id() == scan_id
        assert len(AssetRepository(session).list_assets()) == 1
