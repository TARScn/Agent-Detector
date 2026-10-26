"""Telemetry API: event feed, channel control and audit-rule templates (§8)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from sqlalchemy.orm import Session

from agent_detector.monitoring.services.ingest import BehaviorIngestError
from agent_detector.storage.models import BehaviorEventRow


class FakeBehaviorService:
    """Stands in for the ingest service so no real channel has to run."""

    def __init__(self):
        self.running = False
        self.started = []

    def status(self):
        return {"running": self.running, "mode": "auditd",
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
        if self.running:
            raise BehaviorIngestError("behavior ingest already running")
        self.running = True
        self.started.append((mode, log_path, from_start))
        return self.status()

    def stop(self):
        self.running = False
        return self.status()


@pytest.fixture
def telemetry_client(services, monkeypatch):
    from fastapi.testclient import TestClient

    from agent_detector.console.api.app import create_app

    services.monitor._dns = SimpleNamespace(snapshot=lambda: {}, entry_count=0,
                                            running=False, failed=False,
                                            start=lambda: None, close=lambda: None)
    monkeypatch.setattr("agent_detector.monitoring.services.monitor.collect_outbound", lambda: [])
    services.ingest = FakeBehaviorService()
    return TestClient(create_app(serve_console=False))


@pytest.fixture
def seeded(services):
    with Session(services.engine) as session:
        session.add(BehaviorEventRow(
            observed_at="2026-10-19T00:00:00+00:00", source="auditd", agent_label="claude",
            asset_id="claude--abc", flow_id="auditd-1", upstream_host="", protocol="SYS",
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
    channels = {item["id"] for item in status["channels"]}
    assert {"sysmon", "auditd", "poll", "netmon", "native_hook"} == channels

    started = telemetry_client.post("/api/v1/telemetry/behavior/start",
                                    json={"mode": "auditd"}).json()
    assert started["running"] is True
    conflict = telemetry_client.post("/api/v1/telemetry/behavior/start", json={})
    assert conflict.status_code == 409
    assert telemetry_client.post("/api/v1/telemetry/behavior/stop").json()["running"] is False


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
    assert payload["items"][0]["asset_id"] == "claude--abc"


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