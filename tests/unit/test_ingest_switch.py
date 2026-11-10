"""Behavior channel switching (mutual exclusion) at the ingest service level.

The service is single-mode; on Linux the console user typically cannot read
the auditd log or the Tetragon export (root-only). Switching to a broken
channel must fail cleanly and leave the channel that is already running.
"""
from __future__ import annotations

import pytest

from agent_detector.monitoring.detection.process_graph import ProcessGraph
from agent_detector.monitoring.services.ingest import (BehaviorIngestError,
                                                       BehaviorIngestService)
from agent_detector.storage.database import make_engine


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