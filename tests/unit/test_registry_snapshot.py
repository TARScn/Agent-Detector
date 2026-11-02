"""Cross-process registry snapshot: write/read roundtrip, freshness and
hostness gates, and the collect_host_facts source preference."""
import json

import pytest

from agent_detector.core.models import ProcessInfo
from agent_detector.monitoring.collectors.host import process as host_process
from agent_detector.monitoring.collectors.host.registry_snapshot import (
    load_process_snapshot, write_process_snapshot)

PROCS = [
    ProcessInfo(pid=100, name="python3", cmdline=("python3", "main.py"),
                create_time=1700.0, ppid=1, exe="/usr/bin/python3",
                cwd="/opt/agent"),
    ProcessInfo(pid=200, name="bash", cmdline=("bash",), create_time=1701.0,
                ppid=100),
]


def test_roundtrip_preserves_fields(tmp_path):
    path = tmp_path / "process-snapshot.json"
    write_process_snapshot("host-1", PROCS, path=path)
    loaded = load_process_snapshot(path=path, max_age=120, hostname="host-1")
    assert loaded == tuple(PROCS)


def test_stale_snapshot_is_ignored(tmp_path):
    path = tmp_path / "process-snapshot.json"
    write_process_snapshot("host-1", PROCS, path=path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["written_at"] = "2000-01-01T00:00:00+00:00"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert load_process_snapshot(path=path, max_age=120, hostname="host-1") is None


def test_missing_corrupt_and_foreign_host_are_ignored(tmp_path):
    missing = tmp_path / "absent.json"
    assert load_process_snapshot(path=missing) is None

    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{not json", encoding="utf-8")
    assert load_process_snapshot(path=corrupt) is None

    path = tmp_path / "foreign.json"
    write_process_snapshot("other-host", PROCS, path=path)
    assert load_process_snapshot(path=path, hostname="host-1") is None


def test_reader_never_sees_a_partial_write(tmp_path):
    """The atomic replace contract: whatever is on disk parses as a whole
    snapshot — the .tmp side file never becomes the snapshot."""
    path = tmp_path / "process-snapshot.json"
    write_process_snapshot("host-1", PROCS, path=path)
    leftovers = list(tmp_path.glob("*.tmp"))
    assert leftovers == []
    assert load_process_snapshot(path=path, hostname="host-1") == tuple(PROCS)


def test_collect_host_facts_prefers_fresh_registry(tmp_path, monkeypatch):
    """A fresh snapshot wins over psutil; a missing one falls back — the
    standalone scan keeps working while the collector is not running."""
    monkeypatch.setattr(host_process, "load_process_snapshot",
                        lambda **kwargs: tuple(PROCS))
    monkeypatch.setattr(host_process, "collect_processes",
                        lambda **kwargs: pytest.fail(
                            "psutil must not run when the snapshot is fresh"))
    facts = host_process.collect_host_facts()
    assert facts.process_source == "registry" and len(facts.processes) == 2

    monkeypatch.setattr(host_process, "load_process_snapshot",
                        lambda **kwargs: None)
    monkeypatch.setattr(host_process, "collect_processes",
                        lambda **kwargs: [ProcessInfo(pid=1, name="x",
                                                      create_time=1.0, ppid=0)])
    facts = host_process.collect_host_facts()
    assert facts.process_source == "psutil" and facts.processes[0].pid == 1


def test_ingest_publishes_snapshot_for_scans(tmp_path, monkeypatch):
    """The collector shares its registry through the snapshot file: the first
    batch writes immediately (throttle starts empty) and the file carries the
    seeded registry for a standalone scan to load."""
    from agent_detector.monitoring.detection.process_graph import ProcessGraph
    from agent_detector.monitoring.services import ingest as isvc
    from agent_detector.monitoring.services.ingest import BehaviorIngestService
    from agent_detector.storage.database import make_engine

    proc = ProcessInfo(pid=4100, name="claude", cmdline=("claude",),
                       create_time=1.0, ppid=1)
    snap = tmp_path / "proc-snap.json"
    monkeypatch.setattr(isvc, "PROC_SNAPSHOT_PATH", snap)
    log = tmp_path / "events.json"
    log.write_text("", encoding="utf-8")
    service = BehaviorIngestService(
        make_engine(tmp_path / "db.sqlite3"), mode="tetragon", log_path=log,
        process_snapshot=lambda: [proc],
        graph=ProcessGraph(live_lookup=lambda pid: None))
    service.run_once()
    assert service._last_snapshot_monotonic is not None
    loaded = load_process_snapshot(path=snap, hostname=service_hostname())
    assert loaded is not None and loaded[0].pid == 4100


def service_hostname() -> str:
    import platform
    return platform.node() or "localhost"
