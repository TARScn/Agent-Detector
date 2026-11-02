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


def test_registry_chain_keeps_cwd_for_module_entries(tmp_path):
    """Review P0: cwd must survive the whole registry chain — graph node →
    snapshot payload → file → scan. A `-m uvicorn` process has no script path,
    only cwd anchors its project; dropping cwd made registry-sourced scans
    silently skip processes that psutil-sourced ones resolved."""
    from pathlib import Path

    from agent_detector.core.models import HostFacts
    from agent_detector.discovery.scanner.resolver import resolve_projects
    from agent_detector.monitoring.detection.process_graph import ProcessGraph

    root = tmp_path / "ai-todo"
    (root / "app").mkdir(parents=True)
    (root / "pyproject.toml").write_text('[project]\nname = "ai-todo"\n',
                                         encoding="utf-8")
    (root / ".venv" / "bin").mkdir(parents=True)
    exe = str(root / ".venv" / "bin" / "python")

    graph = ProcessGraph(live_lookup=lambda pid: None)
    graph.seed([ProcessInfo(pid=100, name="python",
                            cmdline=(exe, "-m", "uvicorn", "main:app"),
                            create_time=1700.0, ppid=1, exe=exe, cwd=str(root))])
    path = tmp_path / "process-snapshot.json"
    write_process_snapshot("h", graph.snapshot_processes(), path=path)
    loaded = load_process_snapshot(path=path, max_age=120, hostname="h")
    assert loaded is not None and loaded[0].cwd == str(root)

    projects = resolve_projects(HostFacts("h", loaded, ()))
    assert len(projects) == 1
    assert projects[0].resolver_status == "resolved"
    assert Path(projects[0].root).resolve() == root.resolve()


def test_cgroup_container_id_extraction(tmp_path):
    from agent_detector.monitoring.collectors.host.process import (
        _cgroup_container_id, _container_of)

    full = "c" * 64
    assert _cgroup_container_id(f"0::/system.slice/docker-{full}.scope\n") == full
    assert _cgroup_container_id(f"11:cpu,cpuset:/containerd/{full}") == full
    assert _cgroup_container_id("0::/user.slice/user-1000.slice/\n") is None
    assert _cgroup_container_id("") is None

    proc = tmp_path / "proc" / "1234"
    proc.mkdir(parents=True)
    (proc / "cgroup").write_text(f"0::/docker/{full}\n", encoding="utf-8")
    assert _container_of(1234, proc_root=str(tmp_path / "proc")) == full
    assert _container_of(9999, proc_root=str(tmp_path / "proc")) is None
