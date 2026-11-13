"""Detached collector child lifecycle (spawn → status file → clean stop).

Runs the real runner module in poll mode — no admin rights needed on any
platform — against a temporary database so the status file contract is
exercised end to end: the console must see the child through
``collector-status.json`` and be able to stop (or adopt) it.
"""
from __future__ import annotations

import json
import time

import pytest

from agent_detector.monitoring.services.collector_process import CollectorProcessManager
from agent_detector.monitoring.services.ingest import BehaviorIngestError


def _manager(tmp_path):
    return CollectorProcessManager(
        tmp_path / "db.sqlite3",
        status_path=tmp_path / "collector-status.json",
        snapshot_path=tmp_path / "process-snapshot.json",
        log_path=tmp_path / "collector.log")


def _file_status(manager) -> dict | None:
    try:
        raw = json.loads(manager.status_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return raw.get("collector")


def _wait_for(predicate, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.2)
    return False


def test_spawn_publishes_status_then_stops_cleanly(tmp_path):
    manager = _manager(tmp_path)
    try:
        manager.start(mode="poll")
        assert manager.status()["running"] is True
        assert _wait_for(
            lambda: (_file_status(manager) or {}).get("running") is True,
            timeout=30), "runner never published a running status file"
        published = _file_status(manager)
        assert published["mode"] == "poll"
        assert isinstance(published.get("collector_pid"), int)
    finally:
        manager.stop()
    assert manager.status()["running"] is False
    assert _wait_for(
        lambda: (_file_status(manager) or {}).get("running") is False,
        timeout=15), "stopped runner left the status file advertising itself"


def test_unknown_mode_raises_without_spawning(tmp_path):
    manager = _manager(tmp_path)
    with pytest.raises(BehaviorIngestError):
        manager.start(mode="replay")
    with pytest.raises(BehaviorIngestError):
        manager.start(mode="bogus")
    assert manager.status()["running"] is False


def test_broken_channel_raises_before_spawn(tmp_path):
    manager = _manager(tmp_path)
    with pytest.raises(BehaviorIngestError):
        manager.start(mode="auditd", log_path=tmp_path / "missing.log")
    assert manager.status()["running"] is False


def test_orphan_child_is_adopted_by_a_new_manager(tmp_path):
    """A serve restart must not lose the collector: the new manager re-attaches
    through the published pid and can stop it."""
    first = _manager(tmp_path)
    try:
        first.start(mode="poll")
        assert _wait_for(lambda: first.status()["child_pid"] is not None,
                         timeout=30)
        child_pid = first.status()["child_pid"]

        second = _manager(tmp_path)  # a fresh serve process, no Popen handle
        # Adoption reads the published pid from the status file, so allow
        # the runner's first publish to land before asserting.
        assert _wait_for(lambda: second.status()["running"] is True, timeout=30)
        assert second.status()["child_pid"] == child_pid
        second.stop()
        assert second.status()["running"] is False
        first.stop()  # reap the spawn handle (POSIX zombies linger otherwise)
        assert _wait_for(lambda: not _pid_alive(child_pid), timeout=15)
    finally:
        first.stop()


def _pid_alive(pid: int) -> bool:
    import psutil

    return psutil.pid_exists(pid)
