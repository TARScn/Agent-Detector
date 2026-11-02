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


def test_ignore_proc_drops_healthcheck_noise(tmp_path, monkeypatch):
    from agent_detector.core.facts import BehaviorFact

    monkeypatch.setattr(isvc, "BEHAVIOR_IGNORE_PROCS", ("pg_isready",))
    engine = make_engine(tmp_path / "db.sqlite3")
    seed_asset(engine)
    service = make_service(engine)
    service.graph.seed([AGENT_PROC])  # direct _process_facts call: seed manually
    noise = BehaviorFact(kind="proc.exec", ts=1000.0, serial="n1", pid=500,
                         ppid=1, process_name="pg_isready",
                         exe="/usr/local/bin/pg_isready",
                         argv=("/usr/local/bin/pg_isready", "-h", "db"),
                         result="started")
    assert service._process_facts([noise]) == []
    assert service.ignored_proc == 1 and service.events_stored == 0
    # registry first: the ignored process is lifecycle-real, only its
    # behavior is out of scope
    assert service.graph.node(500) is not None
    assert service.graph.node(500).name == "pg_isready"
    kept = BehaviorFact(kind="proc.exec", ts=1000.0, serial="n2", pid=501,
                        ppid=4100, process_name="python3",
                        exe="/usr/bin/python3",
                        argv=("/usr/bin/python3", "train.py"), result="started")
    rows = service._process_facts([kept])
    assert service.ignored_proc == 1  # the counter only moves for ignored names
    assert [row["operation"] for row in rows] == ["SCRIPT_EXEC"]


def test_rule_missed_exec_still_updates_registry(tmp_path):
    """Lifecycle is independent of behavior matching: an exec that matches no
    behavior rule must still enter the process registry. The graph update
    used to live after match_fact() and silently lost these — attribution
    then mis-walked ancestry for everything the rules did not classify."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "behaviors.yaml").write_text(
        "revision: 1\n"
        "rules:\n"
        "  - id: FILE_MODIFY\n"
        "    when: {kind: file.write}\n"
        "    confidence: high\n", encoding="utf-8")
    engine = make_engine(tmp_path / "db.sqlite3")
    seed_asset(engine)
    service = make_service(engine, rules_dir=rules_dir)
    service.graph.seed([AGENT_PROC])
    from agent_detector.core.facts import BehaviorFact

    unseen = BehaviorFact(kind="proc.exec", ts=1000.0, serial="u1", pid=606,
                          ppid=4100, process_name="python3",
                          exe="/usr/bin/python3",
                          argv=("/usr/bin/python3", "x.py"), result="started")
    assert service._process_facts([unseen]) == []
    assert service.dropped_no_rule == 1
    node = service.graph.node(606)
    assert node is not None and node.name == "python3"
    assert node.ppid == 4100


def test_tetragon_replay_fills_registry_identity(tmp_path):
    """Tetragon facts carry the kernel-side identity: exec facts fill the
    registry node's exec_id and start instant (create_time), so later facts
    can be identity-verified against it."""
    from datetime import datetime, timezone

    engine = make_engine(tmp_path / "db.sqlite3")
    service = make_service(engine)
    service.run_replay(TETRA_FIXTURE, format="tetragon")
    node = service.graph.node(4100)  # exec without exit: instance survives
    assert node is not None
    assert node.exec_id == "dGVzdGhvc3Q6MTAwMDA6NDEwMA=="
    expected = datetime(2026, 10, 30, 7, 1, 50, 100000, tzinfo=timezone.utc).timestamp()
    assert node.create_time == pytest.approx(expected, abs=1e-5)
    # the exited 4101 stays out of the registry even though kprobe facts for
    # it arrive after its exit fact (tombstone)
    assert service.graph.node(4101) is None


def test_silent_tail_triggers_registry_recalibration(tmp_path, monkeypatch):
    """Heuristic event-loss recovery: a tail silent for PROCESS_RESEED_SECONDS
    recalibrates the registry from one live snapshot (merge semantics), then
    resets its own timer."""
    monkeypatch.setattr(isvc, "PROCESS_RESEED_SECONDS", 1)
    log = tmp_path / "events.json"
    log.write_text("", encoding="utf-8")
    calls: list[int] = []

    def snapshot():
        calls.append(1)
        return [ProcessInfo(pid=9999, name="backfill", cmdline=("backfill",),
                            create_time=1.0, ppid=1)]

    engine = make_engine(tmp_path / "db.sqlite3")
    service = BehaviorIngestService(engine, mode="tetragon", log_path=log,
                                    process_snapshot=snapshot,
                                    graph=ProcessGraph(live_lookup=lambda pid: None))
    service.run_once()
    assert calls  # seeded once at startup
    assert service.recalibrations == 0
    service._last_record_monotonic = time.monotonic() - 5  # simulate silence
    service.run_once()
    assert service.recalibrations == 1
    assert service.graph.node(9999) is not None  # recalibrated from snapshot
    service.run_once()  # the timer reset: no spin
    assert service.recalibrations == 1


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


def seed_container_instance(engine, *, asset_id, instance_id, container_id,
                            pid=4300, status="running"):
    from agent_detector.storage.models import AgentInstanceRow

    with Session(engine) as session:
        session.add(AgentInstanceRow(
            instance_id=instance_id, asset_id=asset_id, agent_type="agent_platform",
            pid=pid, process_name="python", cmdline="python",
            container_id=container_id, origin="docker", status=status))
        session.commit()


def test_tetragon_event_attributes_via_instance_container(tmp_path):
    """Compose-merged assets carry one container_id per running instance while
    the asset row stores only the primary — an eBPF event from any sibling
    container of the project must attribute to the one asset."""
    primary = "c" * 64  # asset row's own container (different project member)
    sibling = "b13f15ab2a169c85976efbd3a28b57f" + "0" * 33  # fixture container
    engine = make_engine(tmp_path / "db.sqlite3")
    seed_container_asset(engine, container_id=primary)
    seed_container_instance(engine, asset_id="n8n--container01",
                            instance_id="inst-sibling", container_id=sibling)
    service = make_service(engine, process_snapshot=lambda: [])
    result = service.run_replay(TETRA_FIXTURE, format="tetragon")
    assert result["events"] == 1
    event = stored_events(engine, source="tetragon")[0]
    assert event["asset_id"] == "n8n--container01"
    assert event["agent_label"] == "n8n"
    assert "container_id" in event["evidence"]