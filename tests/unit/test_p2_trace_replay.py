"""P2.2/P2.3/P2.4: controlled trace, MCP association and evidence replay."""
import json

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agent_detector.aggregation.replay import replay_scan_evidence
from agent_detector.core.enums import AssetState, AssetType
from agent_detector.core.models import DetectedAsset, HostFacts, VersionInfo
from agent_detector.discovery.scanner import scan as scan_service
from agent_detector.interception.hooks.normalizer import mcp_server_name
from agent_detector.storage import (AgentInventoryRepository,
                                    BehaviorEventRepository,
                                    EntityRepository, IdentityRepository)
from agent_detector.storage.database import make_engine
from agent_detector.storage.models import (BehaviorEventRow, ClaimRow,
                                           EntitySnapshotRow)


class _Detector:
    name = "fake"

    def detect(self, facts):
        return [DetectedAsset(
            asset_id="claude--1", name="Claude Code",
            asset_type=AssetType.AGENT_CLIENT, states={AssetState.RUNNING},
            confidence=0.9, version=VersionInfo.unknown(), evidence=[],
            detector="fake", scope_kind="user-home",
            identity_scope="/home/bob", running_pids=[4242])]


def _trace(tmp_path):
    path = tmp_path / "trace.jsonl"
    records = [
        {"kind": "runtime", "ts": "2026-11-01T00:00:00+00:00", "pid": 4242,
         "framework": "langchain", "event": "invoke", "session_id": "s1"},
        {"kind": "protocol", "ts": "2026-11-01T00:00:01+00:00", "pid": 4242,
         "protocol": "mcp", "server": "filesystem", "tool": "read_file",
         "session_id": "s1"},
        {"kind": "protocol", "ts": "2026-11-01T00:00:02+00:00", "pid": 4242,
         "protocol": "a2a", "method": "message/send", "session_id": "s1"},
    ]
    path.write_text("\n".join(json.dumps(item) for item in records),
                    encoding="utf-8")
    return path


def test_controlled_trace_records_e5_evidence_and_sessions(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (), ()))
    path = _trace(tmp_path)
    monkeypatch.setattr(scan_service, "CONTROLLED_TRACE_PATH", str(path))
    monkeypatch.setattr(scan_service, "CONTROLLED_TRACE_MAX_RECORDS", 100)
    engine = make_engine(tmp_path / "db.sqlite3")
    result = scan_service.run_scan(engine, detectors=[_Detector()],
                                   docker_enabled=False)
    assert result["controlled_trace"]["runtime"] == 1
    assert result["controlled_trace"]["protocol"] == 2
    with Session(engine) as session:
        events = BehaviorEventRepository(session).list_events(source="protocol_trace")
        assert {event["protocol"] for event in events} == {"MCP", "A2A"}
        mcp = next(event for event in events if event["protocol"] == "MCP")
        assert mcp["mcp_server"] == "filesystem"
        assert mcp["session_id"] == "s1"
        assert mcp["actor"]["entity_id"] == IdentityRepository(session).resolve_alias(
            "claude--1")
        runtime = BehaviorEventRepository(session).list_events(
            source="runtime_trace")[0]
        assert runtime["event_type"] == "framework.execution"
        assert runtime["tool"] == "langchain"
        assert runtime["agent_label"] == "Claude Code"
        sessions = AgentInventoryRepository(session).list_sessions()
        assert any(item["session_id"] == "s1" for item in sessions)
        asset = EntityRepository(session).get_agent(
            IdentityRepository(session).resolve_alias("claude--1"))
        assert asset["agent_status"] == "RUNNING"
        assert "AGENT_EXECUTION_OBSERVED" in asset["capability_tags"]
        claims = {row.predicate for row in session.scalars(select(ClaimRow))}
        assert {"framework_execution", "protocol_tool_call"} <= claims


def test_mcp_hook_tool_is_classified(tmp_path):
    assert mcp_server_name("mcp__github__create_issue") == "github"
    assert mcp_server_name("Bash") is None
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        BehaviorEventRepository(session).record_tool_call(
            observed_at="2026-11-01T00:00:00+00:00", agent_label="Claude",
            tool="mcp__github__create_issue", operation="mcp.call",
            target="mcp__github__create_issue", protocol="MCP",
            mcp_server="github", session_id="s1")
        session.commit()
        row = BehaviorEventRepository(session).list_events(source="native_hook")[0]
    assert row["protocol"] == "MCP"
    assert row["mcp_server"] == "github"
    assert row["session_id"] == "s1"


def test_replay_recomputes_claims_without_recollection(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (), ()))
    monkeypatch.setattr(scan_service, "CONTROLLED_TRACE_PATH", "")
    engine = make_engine(tmp_path / "db.sqlite3")
    first = scan_service.run_scan(engine, detectors=[_Detector()],
                                  docker_enabled=False)
    source_scan = first["scan_id"]
    with Session(engine) as session:
        stats = replay_scan_evidence(session, source_scan, 999)
        session.commit()
        entity = IdentityRepository(session).resolve_alias("claude--1")
        snapshot = session.scalars(select(EntitySnapshotRow).where(
            EntitySnapshotRow.entity_id == entity,
            EntitySnapshotRow.generation_id == 999)).first()
        replay_claims = session.scalar(
            select(func.count()).select_from(ClaimRow).where(
                ClaimRow.collection_run_id == 999))
    assert stats["replayed_assets"] == 1
    assert snapshot is not None and snapshot.agent_status == "RUNNING"
    assert replay_claims and replay_claims >= 1