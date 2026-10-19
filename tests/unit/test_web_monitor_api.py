"""Web /api/monitor/* routes against a temp database and a stubbed manager."""
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from agent_detector.behavior import monitor_service as ms
from agent_detector.behavior.monitor_service import MonitorManager
from agent_detector.persistence.database import make_engine
from agent_detector.persistence.models import BehaviorEventRow
from agent_detector.web import app as web_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    engine = make_engine(tmp_path / "db.sqlite3")
    stub = MonitorManager(engine, interval=0.5)
    stub._dns = SimpleNamespace(snapshot=lambda: {}, entry_count=0, running=False,
                                failed=False, start=lambda: None, close=lambda: None)
    monkeypatch.setattr(ms, "collect_outbound", lambda: [])
    monkeypatch.setattr(web_app, "engine", engine)
    monkeypatch.setattr(web_app, "monitor_manager", stub)
    return TestClient(web_app.app)


def test_status_reports_stopped_with_rule_info(client):
    body = client.get("/api/monitor/status").json()
    assert body["running"] is False
    assert body["known_llm_hosts"] > 0
    assert body["iterations"] == 0 and body["hits"] == 0


def test_start_stop_lifecycle_over_api(client):
    assert client.post("/api/monitor/start", json={}).json()["running"] is True
    conflict = client.post("/api/monitor/start", json={})
    assert conflict.status_code == 409
    assert client.post("/api/monitor/stop").json()["running"] is False


def test_events_and_stats_empty_initially(client):
    assert client.get("/api/monitor/events").json()["items"] == []
    stats = client.get("/api/monitor/stats").json()
    assert stats["event_count"] == 0 and stats["by_operation"] == {}


def test_netmon_event_visible_through_api(client):
    with Session(web_app.engine) as session:
        session.add(BehaviorEventRow(
            observed_at="2026-10-19T00:00:00+00:00", source="netmon",
            agent_label="claude.exe", asset_id=None, flow_id="netmon-1",
            upstream_host="api.anthropic.com", protocol="LLM", event_type="llm.conn",
            operation="llm_api", confidence="medium", endpoint="93.184.216.34:443",
            evidence_json='["dns_cache", "known_llm_host"]'))
        session.commit()
    items = client.get("/api/monitor/events").json()["items"]
    assert len(items) == 1 and items[0]["upstream_host"] == "api.anthropic.com"
    stats = client.get("/api/monitor/stats").json()
    assert stats["by_operation"]["llm_api"] == 1
    assert stats["by_agent"]["claude.exe"] == 1
