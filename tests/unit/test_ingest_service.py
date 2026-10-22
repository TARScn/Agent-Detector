import time
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from agent_detector.services import ingest as isvc
from agent_detector.detection.process_graph import ProcessGraph
from agent_detector.services.ingest import BehaviorIngestError, BehaviorIngestService
from agent_detector.domain.enums import AssetState, AssetType
from agent_detector.domain.models import DetectedAsset, ProcessInfo, VersionInfo
from agent_detector.storage.database import make_engine
from agent_detector.storage.repositories import (AssetRepository,
                                                     BehaviorEventRepository,
                                                     ScanRepository)

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "audit" / "scenario.log"
AGENT_PROC = ProcessInfo(pid=4100, name="claude", cmdline=("claude",),
                         create_time=1.0, ppid=1)
ASSET_ID = "claude-code--abc123def456"


def offline_graph():
    return ProcessGraph(live_lookup=lambda pid: None)


def seed_asset(engine, *, running_pids=(4100,)):
    with Session(engine) as session:
        scan_id = ScanRepository(session).create("agent")
        AssetRepository(session).upsert(DetectedAsset(
            asset_id=ASSET_ID, name="Claude Code", asset_type=AssetType.AGENT_CLIENT,
            states={AssetState.INSTALLED, AssetState.RUNNING}, confidence=0.9,
            version=VersionInfo.unknown(), running_pids=list(running_pids),
            detector="test"), scan_id)
        session.commit()


def make_service(engine, **overrides):
    options = dict(mode="replay", process_snapshot=lambda: [AGENT_PROC],
                   graph=offline_graph())
    options.update(overrides)
    return BehaviorIngestService(engine, **options)


def stored_events(engine, source="auditd"):
    with Session(engine) as session:
        return BehaviorEventRepository(session).list_events(source=source, limit=100)


def test_replay_stores_attributed_behaviour(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    seed_asset(engine)
    service = make_service(engine)
    result = service.run_replay(FIXTURE)
    assert result["facts"] == 8 and result["events"] == 8

    events = stored_events(engine)
    operations = {event["operation"] for event in events}
    assert operations == {"SCRIPT_EXEC", "FILE_MODIFY", "FILE_MOVE", "FILE_DELETE",
                          "FILE_ATTR_CHANGE", "NETWORK_CONNECT"}
    script = next(event for event in events
                  if event["operation"] == "SCRIPT_EXEC" and event["target"] == "train.py")
    assert script["agent_label"] == "claude" and script["asset_id"] == ASSET_ID
    assert script["pid"] == 4101 and script["ppid"] == 4100
    assert script["process_name"] == "python3" and script["result"] == "started"
    assert script["evidence"][0] == "auditd" and "ancestor_asset_pid" in script["evidence"]
    assert "rule:SCRIPT_EXEC" in script["evidence"]
    assert script["protocol"] == "SYS" and script["flow_id"] == "auditd-900101"
    assert script["observed_at"].startswith("2025-")

    move = next(event for event in events if event["operation"] == "FILE_MOVE")
    assert move["target"] == ("/home/agent/agent-lab/notes.md"
                              " -> /home/agent/agent-lab/docs.md")
    connect = next(event for event in events if event["operation"] == "NETWORK_CONNECT")
    assert connect["endpoint"] == "1.2.3.4:443" and connect["target"] == "1.2.3.4:443"
    denied = next(event for event in events
                  if event["operation"] == "SCRIPT_EXEC" and event["result"] == "denied")
    assert denied["target"] == "bash"


def test_unattributed_events_are_dropped_by_default(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    service = make_service(engine, process_snapshot=lambda: [])
    result = service.run_replay(FIXTURE)
    assert result["events"] == 0 and service.dropped_unattributed == 8


def test_include_unattributed_marks_process_label(tmp_path, monkeypatch):
    monkeypatch.setattr(isvc, "BEHAVIOR_INCLUDE_UNATTRIBUTED", True)
    engine = make_engine(tmp_path / "db.sqlite3")
    service = make_service(engine, process_snapshot=lambda: [])
    result = service.run_replay(FIXTURE)
    assert result["events"] == 8
    events = stored_events(engine)
    assert {event["agent_label"] for event in events} >= {"python3", "mv", "rm"}
    assert all(event["asset_id"] is None for event in events)
    assert all("unattributed" in event["evidence"] for event in events)


def test_suppression_window_dedupes_repeated_behavior(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    seed_asset(engine)
    service = make_service(engine)
    assert service.run_replay(FIXTURE)["events"] == 8
    assert service.run_replay(FIXTURE)["events"] == 0
    assert service.suppressed == 8


def test_rate_limit_caps_events_per_minute(tmp_path, monkeypatch):
    monkeypatch.setattr(isvc, "BEHAVIOR_MAX_EVENTS_PER_MINUTE", 3)
    engine = make_engine(tmp_path / "db.sqlite3")
    seed_asset(engine)
    service = make_service(engine)
    result = service.run_replay(FIXTURE)
    assert result["events"] == 3 and service.dropped_rate == 5


def test_path_policy_basename_redacts_directories(tmp_path, monkeypatch):
    monkeypatch.setattr(isvc, "BEHAVIOR_PATH_POLICY", "basename")
    engine = make_engine(tmp_path / "db.sqlite3")
    seed_asset(engine)
    service = make_service(engine)
    service.run_replay(FIXTURE)
    events = stored_events(engine)
    move = next(event for event in events if event["operation"] == "FILE_MOVE")
    assert move["target"].startswith("notes.md#") and "/" not in move["target"]
    script = next(event for event in events
                  if event["operation"] == "SCRIPT_EXEC" and event["target"] == "train.py")
    assert script["target"] == "train.py"  # derived exec targets stay as-is


def test_poll_mode_detects_new_child_of_agent(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    seed_asset(engine, running_pids=(100,))
    agent = ProcessInfo(pid=100, name="claude", cmdline=("claude",),
                        create_time=1.0, ppid=1)
    child = ProcessInfo(pid=101, name="python3", cmdline=("python3", "t.py"),
                        create_time=2.0, ppid=100)
    snapshots = [[agent], [agent], [agent], [agent, child]]
    calls = {"n": 0}

    def provider():
        snapshot = snapshots[min(calls["n"], len(snapshots) - 1)]
        calls["n"] += 1
        return snapshot

    service = BehaviorIngestService(engine, mode="poll", process_snapshot=provider,
                                    process_lookup=lambda pid: None,
                                    graph=offline_graph())
    assert service.run_once() == []  # prime + first poll: nothing new
    stored = service.run_once()
    assert len(stored) == 1
    event = stored[0]
    assert event["operation"] == "SCRIPT_EXEC" and event["target"] == "t.py"
    assert event["agent_label"] == "claude" and event["asset_id"] == ASSET_ID
    assert event["pid"] == 101 and event["process_name"] == "python3"

    rows = stored_events(engine, source="poll")
    assert len(rows) == 1 and rows[0]["flow_id"].startswith("poll-101-")
    assert "poll" in rows[0]["evidence"]


def test_poll_collector_uses_light_snapshot_and_per_pid_lookup():
    from agent_detector.collectors.poll import PollCollector

    light = [ProcessInfo(pid=7, name="python3", create_time=1.0, ppid=1)]
    details = {8: ProcessInfo(pid=8, name="node", cmdline=("node", "a.js"),
                              create_time=2.0, ppid=7)}
    snapshots = [[*light], [*light, ProcessInfo(pid=8, name="node",
                                                create_time=2.0, ppid=7)]]
    calls = {"n": 0}

    def provider():
        item = snapshots[min(calls["n"], len(snapshots) - 1)]
        calls["n"] += 1
        return item

    collector = PollCollector(snapshot=provider, lookup=details.get)
    assert collector.poll() == []  # first call primes from the same snapshot
    facts = collector.poll()
    assert len(facts) == 1
    assert facts[0].pid == 8 and facts[0].process_name == "node"
    assert facts[0].argv == ("node", "a.js") and facts[0].ppid == 7
    assert collector.poll() == []  # same pids again: nothing new


def test_unreadable_audit_log_raises_with_remediation_hint(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    service = BehaviorIngestService(engine, mode="auditd",
                                    log_path=tmp_path / "missing.log",
                                    process_snapshot=lambda: [], graph=offline_graph())
    with pytest.raises(BehaviorIngestError) as excinfo:
        service.start()
    assert "log_group" in str(excinfo.value)
    status = service.status()
    assert status["log_readable"] is False and status["running"] is False


def test_tail_reader_processes_existing_log_from_start(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    seed_asset(engine)
    service = BehaviorIngestService(engine, mode="auditd", log_path=FIXTURE,
                                    from_start=True,
                                    process_snapshot=lambda: [AGENT_PROC],
                                    graph=offline_graph())
    stored = service.run_once()
    assert len(stored) == 8 and service.records_read > 30
    status = service.status()
    assert status["mode"] == "auditd" and status["log_readable"] is True
    assert status["rule_count"] >= 10 and status["rules_errors"] == []


def test_start_stop_auditd_loop(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    seed_asset(engine)
    log = tmp_path / "audit.log"
    log.write_text("", encoding="utf-8")
    service = BehaviorIngestService(engine, mode="auditd", log_path=log,
                                    process_snapshot=lambda: [AGENT_PROC],
                                    graph=offline_graph())
    status = service.start()
    assert status["running"] is True and status["mode"] == "auditd"
    time.sleep(0.8)
    stopped = service.stop()
    assert stopped["running"] is False and stopped["batches"] >= 1