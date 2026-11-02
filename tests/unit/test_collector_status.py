"""Collector status file: write/read gates and the ingest service publishing
live counters for the console process (which never runs its own ingest)."""
import json
import platform

from agent_detector.monitoring.detection.process_graph import ProcessGraph
from agent_detector.monitoring.services import ingest as isvc
from agent_detector.monitoring.services.collector_status import (
    load_collector_status, write_collector_status)
from agent_detector.monitoring.services.ingest import BehaviorIngestService
from agent_detector.storage.database import make_engine


def sample_status():
    return {"running": True, "mode": "tetragon", "records_read": 42,
            "last_event_at": 1700.0, "recalibrations": 1, "graph_nodes": 7}


def test_roundtrip(tmp_path):
    path = tmp_path / "collector-status.json"
    write_collector_status(sample_status(), path=path, hostname="host-1")
    payload = load_collector_status(path=path, max_age=180, hostname="host-1")
    assert payload is not None
    assert payload["collector"]["records_read"] == 42
    assert payload["age_seconds"] >= 0
    assert payload["written_at"]


def test_stale_corrupt_and_foreign_are_ignored(tmp_path):
    path = tmp_path / "collector-status.json"
    write_collector_status(sample_status(), path=path, hostname="host-1")
    assert load_collector_status(path=path, max_age=180, hostname="other") is None

    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["written_at"] = "2000-01-01T00:00:00+00:00"
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert load_collector_status(path=path, max_age=180, hostname="host-1") is None

    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{nope", encoding="utf-8")
    assert load_collector_status(path=corrupt) is None


def test_ingest_publishes_status_for_the_console(tmp_path, monkeypatch):
    """run_once publishes live counters (records, last event time, mode) next
    to the registry snapshot — the console's idle ingest twin must never be
    the only source of truth again."""
    log = tmp_path / "events.json"
    log.write_text("", encoding="utf-8")
    status_path = tmp_path / "collector-status.json"
    monkeypatch.setattr(isvc, "COLLECTOR_STATUS_PATH", status_path)
    service = BehaviorIngestService(
        make_engine(tmp_path / "db.sqlite3"), mode="tetragon", log_path=log,
        process_snapshot=lambda: [],
        graph=ProcessGraph(live_lookup=lambda pid: None))
    service.run_once()
    payload = load_collector_status(path=status_path,
                                    hostname=platform.node() or "localhost")
    assert payload is not None
    collector = payload["collector"]
    assert collector["mode"] == "tetragon" and collector["batches"] >= 1
    # channel-open marks the event clock even before the first record arrives
    assert collector["last_event_at"] is not None
    assert 0 <= collector["last_event_age_seconds"] <= 5
