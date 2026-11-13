"""Telemetry API: event feed, channel control and audit-rule templates (§8)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from sqlalchemy.orm import Session

from agent_detector.monitoring.services.ingest import BehaviorIngestError
from agent_detector.storage.models import BehaviorEventRow


class FakeBehaviorService:
    """Stands in for the ingest service so no real channel has to run."""

    MODES = ("sysmon", "auditd", "poll", "tetragon", "replay")

    def __init__(self):
        self.running = False
        self.mode = "auditd"
        self.started = []

    def status(self):
        return {"running": self.running, "mode": self.mode,
                "log_path": "/var/log/audit/audit.log", "log_readable": False,
                "keys": ["agent_detector_exec"], "interval": 2.0,
                "suppress_seconds": 300, "path_policy": "full", "store_argv": False,
                "include_unattributed": False, "retention_days": 30, "started_at": None,
                "batches": 0, "records_read": 0, "facts": 0, "events": 0, "suppressed": 0,
                "dropped_no_rule": 0, "dropped_unattributed": 0, "dropped_rate": 0,
                "alerts_raised": 0, "alert_risk_level": "high",
                "sysmon_channel": None, "sysmon": {"available": False, "reason": "未安装"},
                "rule_count": 13, "rules_errors": [], "graph_nodes": 0, "last_error": None}

    def start(self, *, mode=None, log_path=None, from_start=None):
        if mode:
            mode = mode.lower()
            if mode not in self.MODES or mode == "replay":
                raise BehaviorIngestError(f"unknown behavior mode: {mode}")
            self.mode = mode
        # Mirrors BehaviorIngestService.start: channels are mutually
        # exclusive, starting one silently stops the previous one.
        self.started.append((mode, log_path, from_start))
        self.running = True
        return self.status()

    def stop(self):
        self.running = False
        return self.status()


@pytest.fixture
def telemetry_client(services, monkeypatch):
    from fastapi.testclient import TestClient

    import agent_detector.console.api.telemetry as tel

    from agent_detector.console.api.app import create_app

    services.monitor._dns = SimpleNamespace(snapshot=lambda: {}, entry_count=0,
                                            running=False, failed=False,
                                            start=lambda: None, close=lambda: None)
    monkeypatch.setattr("agent_detector.monitoring.services.monitor.collect_outbound", lambda: [])
    # Hermetic by default: no real collector-status file on this machine may
    # leak into endpoint assertions (tests that need one patch it themselves).
    monkeypatch.setattr("agent_detector.console.api.deps.load_collector_status",
                        lambda **kwargs: None)
    services.ingest = FakeBehaviorService()
    return TestClient(create_app(serve_console=False))


@pytest.fixture
def seeded(services):
    with Session(services.engine) as session:
        session.add(BehaviorEventRow(
            observed_at="2026-10-19T00:00:00+00:00", source="auditd", agent_label="claude",
            asset_id="claude--abc", actor_asset_id="claude--abc",
            actor_entity_id="claude--abc", flow_id="auditd-1",
            upstream_host="", protocol="SYS",
            event_type="proc.exec", operation="SCRIPT_EXEC", confidence="high", endpoint="",
            target="/home/u/agent-lab/train.py", pid=4242, ppid=4000, process_name="python3",
            result="success", risk_level="medium", decision="audit",
            execution_status="succeeded",
            evidence_json='["auditd", "rule:SCRIPT_EXEC"]'))
        session.add(BehaviorEventRow(
            observed_at="2026-10-19T00:01:00+00:00", source="netmon", agent_label="claude",
            flow_id="netmon-1", upstream_host="api.anthropic.com", protocol="LLM",
            event_type="llm.conn", operation="llm_api", confidence="medium",
            endpoint="1.2.3.4:443", evidence_json='["dns_cache", "known_llm_host"]'))
        session.commit()


def test_channel_status_and_behavior_lifecycle(telemetry_client):
    status = telemetry_client.get("/api/v1/telemetry/status").json()
    assert status["behavior"]["running"] is False
    assert status["behavior"]["source"] == "local"
    channels = {item["id"] for item in status["channels"]}
    assert {"sysmon", "auditd", "tetragon", "poll", "netmon"} == channels
    states = {item["id"]: item["state"] for item in status["channels"]}
    assert states["poll"] == "STOPPED" and states["netmon"] == "STOPPED"

    started = telemetry_client.post("/api/v1/telemetry/behavior/start",
                                    json={"mode": "auditd"}).json()
    assert started["running"] is True
    status = telemetry_client.get("/api/v1/telemetry/status").json()
    states = {item["id"]: item["state"] for item in status["channels"]}
    assert states["poll"] == "STANDBY"          # available but not the active one

    # Channels are mutually exclusive: starting another one switches, it does
    # not conflict.
    switched = telemetry_client.post("/api/v1/telemetry/behavior/start",
                                     json={"mode": "poll"}).json()
    assert switched["running"] is True and switched["mode"] == "poll"
    status = telemetry_client.get("/api/v1/telemetry/status").json()
    states = {item["id"]: item["state"] for item in status["channels"]}
    assert states["poll"] == "RUNNING"

    invalid = telemetry_client.post("/api/v1/telemetry/behavior/start",
                                    json={"mode": "bogus"})
    assert invalid.status_code == 409
    assert telemetry_client.post("/api/v1/telemetry/behavior/stop").json()["running"] is False


def test_linux_channels_are_mutually_exclusive(telemetry_client, monkeypatch):
    """On Linux the group is tetragon/auditd/poll: one RUNNING, the rest STANDBY."""
    import agent_detector.console.api.telemetry as tel

    monkeypatch.setattr(tel.platform, "system", lambda: "Linux")
    monkeypatch.setattr(tel, "sysmon_available",
                        lambda channel: SimpleNamespace(available=False,
                                                        reason="仅 Windows"))
    monkeypatch.setattr(tel, "tetragon_available",
                        lambda path: SimpleNamespace(available=True,
                                                     last_write_age_seconds=1.0))
    started = telemetry_client.post("/api/v1/telemetry/behavior/start",
                                    json={"mode": "tetragon"}).json()
    assert started["running"] is True and started["mode"] == "tetragon"
    channels = {item["id"]: item
                for item in telemetry_client.get(
                    "/api/v1/telemetry/status").json()["channels"]}
    assert channels["tetragon"]["state"] == "RUNNING"
    assert channels["auditd"]["state"] == "STANDBY"
    assert channels["poll"]["state"] == "STANDBY"
    assert channels["sysmon"]["state"] == "UNAVAILABLE"

    # auditd takes over from tetragon within one request (mutual exclusion).
    switched = telemetry_client.post("/api/v1/telemetry/behavior/start",
                                     json={"mode": "auditd"}).json()
    assert switched["mode"] == "auditd" and switched["running"] is True
    channels = {item["id"]: item
                for item in telemetry_client.get(
                    "/api/v1/telemetry/status").json()["channels"]}
    assert channels["auditd"]["state"] == "RUNNING"
    assert channels["tetragon"]["state"] == "STANDBY"


def test_status_prefers_collector_file_when_local_idle(telemetry_client, monkeypatch):
    """The console's own ingest stays idle under the systemd deployment: the
    endpoint must surface the real collector's published counters instead of
    the idle twin, marked source=collector."""
    import agent_detector.console.api.deps as deps

    monkeypatch.setattr(deps, "load_collector_status", lambda **kwargs: {
        "collector": {"running": True, "mode": "tetragon", "records_read": 99},
        "written_at": "2026-11-02T00:00:00+00:00", "age_seconds": 3.0})
    behavior = telemetry_client.get("/api/v1/telemetry/status").json()["behavior"]
    assert behavior["source"] == "collector"
    assert behavior["running"] is True
    assert behavior["records_read"] == 99
    assert behavior["status_age_seconds"] == 3.0


def test_status_marks_local_source_without_collector_file(telemetry_client):
    """No fresh collector file (collector down or file gone): report the local
    idle twin, but label it honestly so the UI can show a stale state."""
    behavior = telemetry_client.get("/api/v1/telemetry/status").json()["behavior"]
    assert behavior["source"] == "local" and behavior["running"] is False


def test_monitor_lifecycle(telemetry_client):
    status = telemetry_client.get("/api/v1/telemetry/status").json()
    assert status["monitor"]["running"] is False
    assert status["monitor"]["known_llm_hosts"] > 0
    assert telemetry_client.post("/api/v1/telemetry/monitor/start", json={}).json()["running"]
    assert telemetry_client.post("/api/v1/telemetry/monitor/start", json={}).status_code == 409
    assert telemetry_client.post("/api/v1/telemetry/monitor/stop").json()["running"] is False


def test_event_feed_filters_and_stats(telemetry_client, seeded):
    assert len(telemetry_client.get("/api/v1/events").json()["items"]) == 2

    auditd = telemetry_client.get("/api/v1/events?source=auditd").json()["items"]
    assert len(auditd) == 1
    assert auditd[0]["operation"] == "SCRIPT_EXEC"
    assert auditd[0]["target"] == "/home/u/agent-lab/train.py"
    assert (auditd[0]["pid"], auditd[0]["ppid"]) == (4242, 4000)
    assert auditd[0]["risk_level"] == "medium"
    assert auditd[0]["evidence"][0] == "auditd"

    by_agent = telemetry_client.get(
        "/api/v1/events?agent_label=claude&event_type=llm.conn").json()
    assert len(by_agent["items"]) == 1

    stats = telemetry_client.get("/api/v1/events/stats").json()
    assert stats["event_count"] == 2
    assert stats["by_source"] == {"auditd": 1, "netmon": 1}
    assert stats["by_risk"]["medium"] == 1


def test_event_feed_pages_backwards_with_a_cursor(telemetry_client, services):
    """The console feed walks history one page at a time (`before_id`)."""
    from agent_detector.storage.models import BehaviorEventRow

    with Session(services.engine) as session:
        for index in range(5):
            session.add(BehaviorEventRow(
                observed_at=f"2026-10-19T00:0{index}:00+00:00", source="poll",
                agent_label="pager", flow_id=f"page-{index}", upstream_host="",
                protocol="SYS", event_type="proc.exec", operation="COMMAND_EXEC",
                confidence="low", endpoint="", target=f"task_{index}.py",
                evidence_json="[]"))
        session.commit()

    first = telemetry_client.get("/api/v1/events?limit=3").json()
    assert len(first["items"]) == 3
    assert first["next_before_id"] == first["items"][-1]["id"]
    ids = [item["id"] for item in first["items"]]

    second = telemetry_client.get(
        f"/api/v1/events?limit=3&before_id={first['next_before_id']}").json()
    second_ids = [item["id"] for item in second["items"]]
    assert second_ids and max(second_ids) < min(ids)      # strictly older
    assert not set(ids) & set(second_ids)                 # no overlap between pages

    # A short page means history ends there.
    tail = telemetry_client.get("/api/v1/events?limit=500").json()
    assert tail["next_before_id"] is None


def test_agent_scoped_event_query(telemetry_client, seeded):
    payload = telemetry_client.get("/api/v1/agents/claude--abc/events").json()
    assert len(payload["items"]) == 1
    assert payload["items"][0]["entity_id"] == "claude--abc"


def test_sse_stream_sends_the_initial_tail_then_keeps_alive(telemetry_client, seeded):
    with telemetry_client.stream(
            "GET", "/api/v1/events/stream?initial=2&max_events=2&timeout=3") as stream:
        body = "".join(stream.iter_text())
    assert body.count("event: event") == 2
    assert body.index("SCRIPT_EXEC") < body.index("llm.conn")  # oldest first


def test_sse_stream_without_initial_is_a_pure_tail(telemetry_client, seeded):
    with telemetry_client.stream(
            "GET", "/api/v1/events/stream?max_events=1&timeout=2") as stream:
        body = "".join(stream.iter_text())
    assert "event: event" not in body
    assert ": keep-alive" in body


def test_audit_rules_endpoint_is_read_only_text(telemetry_client):
    payload = telemetry_client.get(
        "/api/v1/telemetry/audit-rules?watch_dir=/home/u/agent-lab").json()
    assert any("-F dir=/home/u/agent-lab -F perm=wa" in rule for rule in payload["rules"])
    assert all(command.startswith("sudo ") for command in payload["install"])
    assert payload["uninstall"][0].startswith("sudo auditctl -W ")
    assert payload["install_persistent"][-1] == "sudo augenrules --load"
    assert payload["notes"]

class StubManager:
    """Duck-typed CollectorProcessManager: no process is ever spawned."""

    def __init__(self):
        self._running = False
        self._mode = None
        self.started = []
        self.stops = 0
        self.status_path = "unused-by-stub"

    @property
    def running(self):
        return self._running

    def start(self, *, mode=None, log_path=None, from_start=None):
        if mode == "bogus":
            raise BehaviorIngestError("unknown behavior mode: bogus")
        if mode == "auditd":
            raise OSError("spawn refused")
        self.started.append((mode, log_path, from_start))
        self._mode = mode or "sysmon"
        self._running = True
        return self.status()

    def stop(self):
        self.stops += 1
        self._running = False
        return self.status()

    def status(self):
        return {"running": self._running, "mode": self._mode,
                "child_pid": 4321 if self._running else None}


def test_behavior_start_delegates_to_the_collector_manager(telemetry_client, services):
    services.collector = StubManager()
    try:
        started = telemetry_client.post("/api/v1/telemetry/behavior/start",
                                        json={"mode": "sysmon"}).json()
        assert started["running"] is True and started["source"] == "collector"
        assert services.collector.started == [("sysmon", None, False)]
        status = telemetry_client.get("/api/v1/telemetry/status").json()["behavior"]
        assert status["running"] is True and status["source"] == "collector"
        stopped = telemetry_client.post("/api/v1/telemetry/behavior/stop").json()
        assert stopped["running"] is False
        assert services.collector.stops == 1
        assert services.ingest.started == []  # the in-process path stayed idle
    finally:
        services.collector = None


def test_behavior_start_falls_back_to_ingest_when_spawn_fails(telemetry_client, services):
    services.collector = StubManager()
    try:
        started = telemetry_client.post("/api/v1/telemetry/behavior/start",
                                        json={"mode": "auditd"}).json()
        assert started["running"] is True and started["source"] == "local"
        assert services.ingest.started == [("auditd", None, False)]
    finally:
        services.collector = None
        telemetry_client.post("/api/v1/telemetry/behavior/stop")


def test_behavior_start_still_rejects_unknown_modes_with_the_manager(telemetry_client, services):
    services.collector = StubManager()
    try:
        response = telemetry_client.post("/api/v1/telemetry/behavior/start",
                                         json={"mode": "bogus"})
        assert response.status_code == 409
    finally:
        services.collector = None
