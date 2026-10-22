import time

from sqlalchemy.orm import Session

from agent_detector.services import monitor as ms
from agent_detector.services.monitor import MonitorError, MonitorManager
from agent_detector.collectors.netflow import ConnInfo
from agent_detector.domain.enums import AssetState, AssetType
from agent_detector.domain.models import DetectedAsset, VersionInfo
from agent_detector.storage.database import make_engine
from agent_detector.storage.repositories import (AssetRepository, BehaviorEventRepository,
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
        self.mapping = {ip: ((host, "cache"),) for ip, host in mapping.items()}
        self.failed = False
        self.running = True
        self.proactive = {}

    def snapshot(self):
        return self.mapping

    def merge_proactive(self, mapping):
        self.proactive.update(mapping)
        for ip, host in mapping.items():
            self.mapping[ip] = ((host, "probe"),)

    def start(self):
        self.running = True

    def close(self):
        self.running = False

    @property
    def entry_count(self):
        return sum(len(hosts) for hosts in self.mapping.values())


def seed_events(monkeypatch, tmp_path, conns, dns_mapping):
    """Build a manager over a temp DB with collectors replaced by fixtures."""
    engine = make_engine(tmp_path / "db.sqlite3")
    monkeypatch.setattr(ms, "collect_outbound", lambda: conns)
    monkeypatch.setattr(ms, "resolve_process_names",
                        lambda pids: {c.pid: "claude.exe" for c in conns})
    monkeypatch.setattr(ms, "resolve_known_hosts", lambda hosts: {})
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


def test_local_model_event_uses_scan_asset_and_corroborated_port(monkeypatch, tmp_path):
    conns = [ConnInfo(pid=777, process_name="my-agent.exe",
                      remote_ip="127.0.0.1", remote_port=11434)]
    manager, engine = seed_events(monkeypatch, tmp_path, conns, {})
    with Session(engine) as session:
        scan_id = ScanRepository(session).create("agent")
        AssetRepository(session).upsert(
            make_asset(asset_id="ollama--xyz", name="Ollama",
                       asset_type=AssetType.LLM_SERVICE, listening_ports=[11434]),
            scan_id)
        session.commit()
    manager.run_once()
    with Session(engine) as session:
        row = BehaviorEventRepository(session).list_events(source="netmon")[0]
    assert (row["operation"], row["upstream_host"]) == ("local_model", "Ollama:11434")
    assert row["asset_id"] == "ollama--xyz"
    assert row["evidence"] == ["local_model_port", "scan_asset"]


def test_proactive_sweep_merges_known_hosts_and_is_throttled(monkeypatch, tmp_path):
    """Chromium/Electron apps bypass the OS DNS cache; the sweep supplies the map."""
    conns = [ConnInfo(pid=4242, process_name="", remote_ip="39.106.104.16", remote_port=443)]
    engine = make_engine(tmp_path / "db.sqlite3")
    monkeypatch.setattr(ms, "collect_outbound", lambda: conns)
    monkeypatch.setattr(ms, "resolve_process_names", lambda pids: {4242: "ZCode.exe"})
    monkeypatch.setattr(ms, "resolve_known_hosts",
                        lambda hosts: {"39.106.104.16": "token-plan.cn-beijing.maas.aliyuncs.com"})
    manager = MonitorManager(engine)
    manager._dns = FakeDns({})
    events = manager.run_once()  # first run: sweep due -> merge -> match
    assert len(events) == 1
    assert events[0].host == "token-plan.cn-beijing.maas.aliyuncs.com"
    assert events[0].evidence == ("proactive_resolve", "known_llm_host")
    assert manager._dns.proactive == {"39.106.104.16": "token-plan.cn-beijing.maas.aliyuncs.com"}
    # sweep is throttled: a second run must not resolve again
    monkeypatch.setattr(ms, "resolve_known_hosts",
                        lambda hosts: (_ for _ in ()).throw(AssertionError("reswept")))
    manager.suppress_seconds = 0
    assert len(manager.run_once()) == 1


def test_bare_port_without_scan_asset_is_not_flagged(monkeypatch, tmp_path):
    """Regression: a dev server on 8000 must not look like vLLM."""
    conns = [ConnInfo(pid=888, process_name="curl.exe",
                      remote_ip="127.0.0.1", remote_port=8000)]
    manager, engine = seed_events(monkeypatch, tmp_path, conns, {})
    assert manager.run_once() == []
    with Session(engine) as session:
        assert BehaviorEventRepository(session).list_events(source="netmon") == []


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