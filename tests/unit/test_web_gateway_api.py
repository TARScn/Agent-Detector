"""Web /api/gateway/* routes against a temp database and a stubbed mitmdump."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from agent_detector.gateway.manager import GatewayManager
from agent_detector.gateway.store import BehaviorEventStore
from agent_detector.persistence.database import make_engine
from agent_detector.web import app as web_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    engine = make_engine(tmp_path / "db.sqlite3")
    stub = GatewayManager(db_path=tmp_path / "db.sqlite3",
                          state_path=tmp_path / "gateway.json",
                          log_path=tmp_path / "gateway.log")
    monkeypatch.setattr(stub, "mitmdump_path", lambda: None)
    monkeypatch.setattr(web_app, "engine", engine)
    monkeypatch.setattr(web_app, "gateway_manager", stub)
    return TestClient(web_app.app)


def test_reports_unavailable_when_mitmdump_missing(client):
    body = client.get("/api/gateway/status").json()
    assert body["available"] is False and body["running"] is False


def test_start_returns_install_hint_when_missing(client):
    response = client.post("/api/gateway/start")
    assert response.status_code == 400
    assert "mitmproxy is not installed" in response.json()["detail"]


def test_events_empty_and_protocol_validation(client):
    assert client.get("/api/gateway/events").json()["items"] == []
    assert client.get("/api/gateway/events", params={"protocol": "BOGUS"}).json()["items"] == []


def test_stats_and_events_after_store_write(client, tmp_path):
    BehaviorEventStore(tmp_path / "db.sqlite3").insert_many([{
        "observed_at": "2026-10-19T00:00:00+00:00", "agent_label": "demo",
        "flow_id": "f1", "upstream_host": "127.0.0.1", "protocol": "LLM",
        "event_type": "llm.request", "operation": "model_inference",
        "confidence": "medium", "endpoint": "/v1/chat/completions", "evidence": []}])
    stats = client.get("/api/gateway/stats").json()
    assert stats["event_count"] == 1 and stats["by_protocol"]["LLM"] == 1
    items = client.get("/api/gateway/events", params={"protocol": "LLM"}).json()["items"]
    assert len(items) == 1 and items[0]["event_type"] == "llm.request"


def test_orm_write_visible_through_api(client):
    """ORM-side writes must be visible through the same API (single-table contract)."""
    from agent_detector.persistence.models import BehaviorEventRow

    with Session(web_app.engine) as session:
        session.add(BehaviorEventRow(
            observed_at="2026-10-19T00:00:00+00:00", agent_label="web", flow_id="f9",
            upstream_host="127.0.0.1", protocol="A2A", event_type="a2a.agent_card",
            operation="agent_card_discovered", confidence="high",
            endpoint="/.well-known/agent-card.json", evidence_json="[]"))
        session.commit()
    items = client.get("/api/gateway/events", params={"protocol": "A2A"}).json()["items"]
    assert len(items) == 1 and items[0]["flow_id"] == "f9"
