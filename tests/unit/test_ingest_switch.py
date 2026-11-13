"""Behavior channel switching (mutual exclusion) at the ingest service level.

The service is single-mode; on Linux the console user typically cannot read
the auditd log or the Tetragon export (root-only). Switching to a broken
channel must fail cleanly and leave the channel that is already running.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from agent_detector.monitoring.detection.process_graph import ProcessGraph
from agent_detector.monitoring.services.ingest import (BehaviorIngestError,
                                                       BehaviorIngestService)
from agent_detector.storage.database import make_engine

AUDIT_LINE = Path(__file__).resolve().parents[1] / "fixtures" / "audit" / "scenario.log"


def _service(tmp_path, mode, log):
    engine = make_engine(tmp_path / "db.sqlite3")
    return BehaviorIngestService(engine, mode=mode, log_path=log,
                                 process_snapshot=lambda: [],
                                 graph=ProcessGraph(live_lookup=lambda pid: None))


def test_start_switches_to_another_channel(tmp_path):
    log = tmp_path / "audit.log"
    log.write_text("", encoding="utf-8")
    service = _service(tmp_path, "auditd", log)
    assert service.start()["running"] is True
    try:
        switched = service.start(mode="poll")
        assert switched["running"] is True and switched["mode"] == "poll"
    finally:
        service.stop()


def test_failed_switch_keeps_the_running_channel(tmp_path):
    log = tmp_path / "audit.log"
    log.write_text("", encoding="utf-8")
    service = _service(tmp_path, "auditd", log)
    assert service.start()["running"] is True
    try:
        with pytest.raises(BehaviorIngestError) as excinfo:
            service.start(mode="tetragon", log_path=tmp_path / "missing.json")
        assert "Tetragon export" in str(excinfo.value)
        # The auditd channel never paid for the failed switch.
        status = service.status()
        assert status["running"] is True and status["mode"] == "auditd"
        assert status["log_readable"] is True
    finally:
        service.stop()


def test_stop_start_reopens_the_channel(tmp_path):
    """stop() closes and drops the reader; the next start() must subscribe
    anew and actually see new records. (Regression: the old code kept the
    closed reader object, so a restarted channel reported running while
    silently reading nothing.)"""
    log = tmp_path / "audit.log"
    log.write_text("", encoding="utf-8")
    service = _service(tmp_path, "auditd", log)
    assert service.start()["running"] is True
    try:
        service.stop()
        assert service.start()["running"] is True
        # The tail reader opens at EOF on its first poll, so the appended
        # line must land only after the RESTARTED reader has opened (count
        # batches past the restart — the counter is cumulative).
        restarted_batches = service.batches
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and service.batches <= restarted_batches:
            time.sleep(0.1)
        log.write_text(AUDIT_LINE.read_text(encoding="utf-8"), encoding="utf-8")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and service.records_read == 0:
            time.sleep(0.1)
        assert service.records_read >= 1
    finally:
        service.stop()


def test_start_returns_before_the_seed_completes(tmp_path):
    """start() pays only the cheap readiness checks; the process-registry
    seed (a multi-second psutil sweep on Windows) happens on the worker
    thread, so the call must not block on the seeded snapshot."""
    import threading

    gate = threading.Event()

    def blocked_snapshot():
        gate.wait(10)
        return []

    engine = make_engine(tmp_path / "db.sqlite3")
    log = tmp_path / "audit.log"
    log.write_text("", encoding="utf-8")
    service = BehaviorIngestService(engine, mode="auditd", log_path=log,
                                    process_snapshot=blocked_snapshot,
                                    graph=ProcessGraph(live_lookup=lambda pid: None))
    began = time.monotonic()
    status = service.start()
    elapsed = time.monotonic() - began
    try:
        assert status["running"] is True and elapsed < 2.0
        assert service._seeded is False  # seed still parked on the gate
        gate.set()
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and service.batches == 0:
            time.sleep(0.1)
        assert service.batches >= 1
    finally:
        gate.set()
        service.stop()