import time
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from agent_detector.monitoring.services import ingest as isvc
from agent_detector.monitoring.detection.process_graph import ProcessGraph
from agent_detector.monitoring.services.ingest import BehaviorIngestError, BehaviorIngestService
from agent_detector.core.enums import AssetState, AssetType
from agent_detector.core.models import DetectedAsset, ProcessInfo, VersionInfo
from agent_detector.storage.database import make_engine
from agent_detector.storage import (AssetRepository,
                                                     BehaviorEventRepository,
                                                     ScanRepository)

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "audit" / "scenario.log"
TETRA_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "tetragon" / "sample.jsonl"
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
    # "started" means the exec launched: execution succeeded, not failed.
    assert script["execution_status"] == "succeeded"

    move = next(event for event in events if event["operation"] == "FILE_MOVE")
    assert move["target"] == ("/home/agent/agent-lab/notes.md"
                              " -> /home/agent/agent-lab/docs.md")
    connect = next(event for event in events if event["operation"] == "NETWORK_CONNECT")
    assert connect["endpoint"] == "1.2.3.4:443" and connect["target"] == "1.2.3.4:443"
    denied = next(event for event in events
                  if event["operation"] == "SCRIPT_EXEC" and event["result"] == "denied")
    assert denied["target"] == "bash"
    assert denied["execution_status"] == "failed"


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
    tetra = make_service(engine)
    result = tetra.run_replay(TETRA_FIXTURE, format="tetragon")
    # the kprobe facts arrive after the three exec facts filled the window
    assert result["events"] == 3 and tetra.dropped_rate == 4


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
    from agent_detector.monitoring.collectors.host.poll import PollCollector

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


# ---------------------------------------------------------------- tetragon


def test_tetragon_replay_stores_attributed_events_and_skips_exits(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    seed_asset(engine)
    service = make_service(engine)
    result = service.run_replay(TETRA_FIXTURE, format="tetragon")
    assert result["facts"] == 10  # 4 exec + 2 exit + 2 connect + 2 write facts
    assert result["events"] == 7  # exits are lifecycle, container exec unattributed
    assert service.exits_seen == 2
    assert service.dropped_unattributed == 1

    events = stored_events(engine, source="tetragon")
    assert {event["operation"] for event in events} == {
        "SCRIPT_EXEC", "COMMAND_EXEC", "NETWORK_CONNECT", "FILE_MODIFY"}
    script = next(event for event in events if event["operation"] == "SCRIPT_EXEC")
    # label follows the last exec image (the seeded claude node was replaced by
    # the python3 exec fact); the asset identity is what attribution proves.
    assert script["agent_label"] == "python3" and script["asset_id"] == ASSET_ID
    assert script["pid"] == 4100 and script["target"] == "main.py"
    assert "self_asset_pid" in script["evidence"]
    assert script["evidence"][0] == "tetragon"
    assert script["flow_id"] == "tetragon-dGVzdGhvc3Q6MTAwMDA6NDEwMA=="
    assert script["observed_at"].startswith("2026-")
    connect = next(event for event in events
                   if event["operation"] == "NETWORK_CONNECT"
                   and event["endpoint"] == "93.184.216.34:80")
    assert connect["pid"] == 4101
    assert "hook:security_socket_connect" in connect["evidence"]
    modify = next(event for event in events
                  if event["operation"] == "FILE_MODIFY"
                  and event["target"] == "/opt/agent/state.json")
    assert modify["pid"] == 4100
    ls_rows = sorted((event["pid"], event["target"]) for event in events
                     if event["operation"] == "COMMAND_EXEC")
    # pid is part of the suppression key: two ls processes stay distinct rows
    assert ls_rows == [(4101, "/bin/ls -la"), (4102, "/bin/ls /opt/agent")]
    assert all("ancestor_asset_pid" in event["evidence"]
               for event in events if event["operation"] == "COMMAND_EXEC")


def test_tetragon_replay_container_event_keeps_container_id(tmp_path, monkeypatch):
    monkeypatch.setattr(isvc, "BEHAVIOR_INCLUDE_UNATTRIBUTED", True)
    engine = make_engine(tmp_path / "db.sqlite3")
    service = make_service(engine)
    result = service.run_replay(TETRA_FIXTURE, format="tetragon")
    assert result["events"] == 8  # 4 execs + 2 connects + 2 writes, all recorded
    container = next(event for event in stored_events(engine, source="tetragon")
                     if event["pid"] == 4200)
    assert container["container_id"] == "b13f15ab2a169c85976efbd3a28b57f"
    assert container["asset_id"] is None  # container attribution lands in P2
    assert "container:b13f15ab2a169c85976efbd3a28b57f" in container["evidence"]
    assert container["operation"] == "SCRIPT_EXEC" and container["target"] == "inline"


def test_tetragon_exit_fact_evicts_graph_node(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    service = make_service(engine)
    graph = service.graph
    graph.observe_exec(pid=4101, ppid=4100, name="ls")
    assert graph.node(4101) is not None
    service.run_replay(TETRA_FIXTURE, format="tetragon")
    assert graph.node(4101) is None  # exit facts keep the graph honest


def test_tetragon_replay_rejects_unknown_format(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    service = make_service(engine)
    with pytest.raises(BehaviorIngestError):
        service.run_replay(TETRA_FIXTURE, format="sysmon")


def test_tetragon_mode_defaults_to_export_log(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    service = BehaviorIngestService(engine, mode="tetragon",
                                    process_snapshot=lambda: [],
                                    graph=offline_graph())
    assert service.mode == "tetragon" and service.source == "tetragon"
    assert service.log_path.as_posix().endswith("events.json")
    assert "tetragon" in service.status()["log_path"]


def seed_container_asset(engine, *, container_id, asset_id="n8n--container01"):
    from agent_detector.storage.models import AgentAssetRow

    with Session(engine) as session:
        session.add(AgentAssetRow(
            asset_id=asset_id, agent_type="agent_platform", name="n8n",
            states_json='["RUNNING"]', confidence=0.9,
            container_id=container_id, origin="docker"))
        session.commit()


def test_tetragon_container_event_attributes_to_container_asset(tmp_path):
    # Tetragon reports a 31-hex prefix of the full Docker ID; the Docker
    # channel stores the full id on the asset row — prefix match wins over
    # pid matching (container events carry host-namespace pids).
    full_id = "b13f15ab2a169c85976efbd3a28b57f" + "a" * 33
    engine = make_engine(tmp_path / "db.sqlite3")
    seed_container_asset(engine, container_id=full_id)
    service = make_service(engine, process_snapshot=lambda: [])
    result = service.run_replay(TETRA_FIXTURE, format="tetragon")
    assert result["events"] == 1  # host execs stay unattributed; container hits
    event = stored_events(engine, source="tetragon")[0]
    assert event["pid"] == 4200
    assert event["asset_id"] == "n8n--container01"
    assert event["agent_label"] == "n8n"
    assert event["container_id"] == "b13f15ab2a169c85976efbd3a28b57f"
    assert "container_id" in event["evidence"]