import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from agent_detector.behavior.ingest_service import BehaviorIngestError
from agent_detector.persistence.database import make_engine
from agent_detector.persistence.models import BehaviorEventRow
from agent_detector.web import app as web_app


class FakeBehaviorService:
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
def client(tmp_path, monkeypatch):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        session.add(BehaviorEventRow(
            observed_at="2026-10-19T00:00:00+00:00", source="auditd", agent_label="claude",
            asset_id="claude--abc", flow_id="auditd-1", upstream_host="", protocol="SYS",
            event_type="proc.exec", operation="SCRIPT_EXEC", confidence="high", endpoint="",
            target="/home/u/agent-lab/train.py", pid=4242, ppid=4000, process_name="python3",
            result="started",
            evidence_json='["auditd", "rule:SCRIPT_EXEC", "ancestor_asset_pid"]'))
        session.add(BehaviorEventRow(
            observed_at="2026-10-19T00:01:00+00:00", source="netmon", agent_label="claude",
            flow_id="netmon-1", upstream_host="api.anthropic.com", protocol="LLM",
            event_type="llm.conn", operation="llm_api", confidence="medium",
            endpoint="1.2.3.4:443", evidence_json='["dns_cache", "known_llm_host"]'))
        session.commit()
    stub = FakeBehaviorService()
    monkeypatch.setattr(web_app, "engine", engine)
    monkeypatch.setattr(web_app, "behavior_service", stub)
    return TestClient(web_app.app)


def test_behavior_status_and_start_stop(client):
    status = client.get("/api/behavior/status").json()
    assert status["running"] is False and status["mode"] == "auditd"

    started = client.post("/api/behavior/start", json={"mode": "auditd"}).json()
    assert started["running"] is True

    conflict = client.post("/api/behavior/start", json={})
    assert conflict.status_code == 409
    assert "already running" in conflict.json()["detail"]

    assert client.post("/api/behavior/stop").json()["running"] is False


def test_behavior_events_filters_and_stats(client):
    assert len(client.get("/api/behavior/events").json()["items"]) == 2

    auditd = client.get("/api/behavior/events?source=auditd").json()["items"]
    assert len(auditd) == 1
    assert auditd[0]["operation"] == "SCRIPT_EXEC"
    assert auditd[0]["target"] == "/home/u/agent-lab/train.py"
    assert (auditd[0]["pid"], auditd[0]["ppid"]) == (4242, 4000)
    assert auditd[0]["evidence"][0] == "auditd"

    by_agent = client.get("/api/behavior/events?agent=claude&event_type=llm.conn").json()
    assert len(by_agent["items"]) == 1

    stats = client.get("/api/behavior/stats").json()
    assert stats["event_count"] == 2
    assert stats["by_source"] == {"auditd": 1, "netmon": 1}


def test_audit_rules_endpoint_is_read_only_text(client):
    payload = client.get("/api/behavior/audit-rules?watch_dir=/home/u/agent-lab").json()
    assert any("-F dir=/home/u/agent-lab -F perm=wa" in rule for rule in payload["rules"])
    assert all(command.startswith("sudo ") for command in payload["install"])
    assert payload["uninstall"][0].startswith("sudo auditctl -W ")
    assert payload["install_persistent"][-1] == "sudo augenrules --load"
    assert payload["notes"]


def test_asset_events_endpoint(client):
    payload = client.get("/api/assets/claude--abc/events").json()
    assert len(payload["items"]) == 1
    assert payload["items"][0]["asset_id"] == "claude--abc"