import time

from sqlalchemy.orm import Session

from agent_detector.behavior import monitor_service as ms
from agent_detector.behavior.monitor_service import MonitorError, MonitorManager
from agent_detector.behavior.netmon import ConnInfo
from agent_detector.domain.enums import AssetState, AssetType
from agent_detector.domain.models import DetectedAsset, VersionInfo
from agent_detector.persistence.database import make_engine
from agent_detector.persistence.repositories import (AssetRepository, BehaviorEventRepository,
                                                     ScanRepository)


def make_asset(**overrides):
    defaults = dict(asset_id="claude-code--abc123def456", name="Claude Code",
                    asset_type=AssetType.AGENT_CLIENT, states={AssetState.RUNNING},
                    confidence=0.9, version=VersionInfo.unknown(), evidence=[],
                    running_pids=[], listening_ports=[], detector="test")
    defaults.update(overrides)
    return DetectedAsset(**defaults)


class FakeDns:
    def __init__(self, mapping):
        self.mapping = mapping
        self.failed = False

    def snapshot(self):
        return self.mapping


def seed_events(monkeypatch, tmp_path, conns, dns_mapping):
    """Build a manager over a temp DB with collectors replaced by fixtures."""
    engine = make_engine(tmp_path / "db.sqlite3")
    monkeypatch.setattr(ms, "collect_outbound", lambda: conns)
    monkeypatch.setattr(ms, "resolve_process_names",
                        lambda pids: {c.pid: "claude.exe" for c in conns})
    manager = MonitorManager(engine)
    manager._dns = FakeDns(dns_mapping)
    return manager, engine


def test_run_once_writes_llm_api_event(monkeypatch, tmp_path):
    conns = [ConnInfo(pid=4242, process_name="", remote_ip="93.184.216.34", remote_port=443)]
    manager, engine = seed_events(monkeypatch, tmp_path, conns,
                                  {"93.184.216.34": "api.anthropic.com"})
    events = manager.run_once()
    assert len(events) == 1
    with Session(engine) as session:
        rows = BehaviorEventRepository(session).list_events(source="netmon")
    assert len(rows) == 1
    row = rows[0]
    assert (row["event_type"], row["operation"], row["upstream_host"]) == \
        ("llm.conn", "llm_api", "api.anthropic.com")
    assert row["agent_label"] == "claude.exe"
    assert row["endpoint"] == "93.184.216.34:443"
    assert row["evidence"] == ["dns_cache", "known_llm_host"]


def test_suppression_window_dedupes(monkeypatch, tmp_path):
    conns = [ConnInfo(pid=4242, process_name="", remote_ip="93.184.216.34", remote_port=443)]
    manager, engine = seed_events(monkeypatch, tmp_path, conns,
                                  {"93.184.216.34": "api.anthropic.com"})
    assert len(manager.run_once()) == 1
    assert manager.run_once() == []  # same pid+host inside the window
    manager.suppress_seconds = 0
    assert len(manager.run_once()) == 1  # window expired -> recorded again


def test_pid_attribution_to_asset(monkeypatch, tmp_path):
    conns = [ConnInfo(pid=4242, process_name="", remote_ip="93.184.216.34", remote_port=443)]
    manager, engine = seed_events(monkeypatch, tmp_path, conns,
                                  {"93.184.216.34": "api.anthropic.com"})
    with Session(engine) as session:
        scan_id = ScanRepository(session).create("agent")
        AssetRepository(session).upsert(make_asset(running_pids=[4242]), scan_id)
        session.commit()
    manager.run_once()
    with Session(engine) as session:
        row = BehaviorEventRepository(session).list_events(source="netmon")[0]
    assert row["asset_id"] == "claude-code--abc123def456"


def test_start_stop_lifecycle(monkeypatch, tmp_path):
    conns = [ConnInfo(pid=4242, process_name="", remote_ip="93.184.216.34", remote_port=443)]
    manager, engine = seed_events(monkeypatch, tmp_path, conns,
                                  {"93.184.216.34": "api.anthropic.com"})
    status = manager.start(interval=0.5, suppress_seconds=60)
    assert status["running"] is True
    try:
        time.sleep(1.3)
        assert manager.status()["iterations"] >= 1
        assert manager.status()["running"] is True
    finally:
        stopped = manager.stop()
    assert stopped["running"] is False
    with Session(engine) as session:
        assert len(BehaviorEventRepository(session).list_events(source="netmon")) >= 1


def test_double_start_rejected(monkeypatch, tmp_path):
    manager, _ = seed_events(monkeypatch, tmp_path, [], {})
    manager.start(interval=0.5)
    try:
        try:
            manager.start()
        except MonitorError as exc:
            assert "already running" in str(exc)
        else:
            raise AssertionError("expected MonitorError")
    finally:
        manager.stop()


def test_stop_without_start_is_clean(monkeypatch, tmp_path):
    manager, _ = seed_events(monkeypatch, tmp_path, [], {})
    assert manager.stop()["running"] is False
    assert manager.status()["iterations"] == 0
