"""Scan statistics speak the canonical entity_id vocabulary.

The stats blob is what the CLI prints and what scan history keeps; it must not
resurrect the dropped legacy ids (``asset_id`` / ``app_id``).
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from agent_detector.core.enums import AssetState, AssetType
from agent_detector.core.models import DetectedAsset, HostFacts, VersionInfo
from agent_detector.discovery.scanner import scan as scan_service
from agent_detector.storage import EntityRepository
from agent_detector.storage.database import make_engine


class _Detector:
    name = "fake"

    def detect(self, facts):
        return [DetectedAsset(
            asset_id="claude--1", name="Claude Code",
            asset_type=AssetType.AGENT_CLIENT, states={AssetState.RUNNING},
            confidence=0.9, version=VersionInfo.unknown(), evidence=[],
            detector="fake", scope_kind="user-home",
            identity_scope="/home/bob", running_pids=[4242])]


def test_scan_stats_key_agent_rows_by_entity_id(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (), ()))
    monkeypatch.setattr(scan_service, "CONTROLLED_TRACE_PATH", "")
    engine = make_engine(tmp_path / "db.sqlite3")
    result = scan_service.run_scan(engine, detectors=[_Detector()],
                                   docker_enabled=False)

    inventory = result["entity_inventory"]
    assert len(inventory) == 1
    entry = inventory[0]
    assert "asset_id" not in entry and "app_id" not in entry
    entity_id = entry["entity_id"]
    assert entity_id

    summary = result["entity_summaries"][0]
    assert summary["entity_id"] == entity_id
    assert "asset_id" not in summary

    assert result["detections"] == 1
    for legacy_key in ("assets", "agent_assets", "asset_summaries"):
        assert legacy_key not in result, legacy_key

    with Session(engine) as session:
        agent = EntityRepository(session).get_agent(entity_id)
    assert agent["name"] == "Claude Code"