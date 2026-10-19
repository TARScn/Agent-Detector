"""The raw-sqlite DDL (written by the addon) and the SQLAlchemy model (read by
web/CLI) must describe the same table — drift here would break the gateway."""
import sqlite3

from sqlalchemy.orm import Session

from agent_detector.gateway.store import BehaviorEventStore, BEHAVIOR_EVENTS_DDL
from agent_detector.persistence.database import make_engine
from agent_detector.persistence.models import BehaviorEventRow
from agent_detector.persistence.repositories import BehaviorEventRepository


def _columns(path):
    db = sqlite3.connect(str(path))
    try:
        return [(row[1], row[3]) for row in
                db.execute("PRAGMA table_info(behavior_events)") if row[1] != "id"]
    finally:
        db.close()


def test_column_layout_parity(tmp_path):
    ddl_path, model_path = tmp_path / "ddl.sqlite3", tmp_path / "model.sqlite3"
    BehaviorEventStore(ddl_path)          # creates behavior_events via raw DDL
    make_engine(model_path)               # creates all tables via SQLAlchemy
    assert _columns(ddl_path) == _columns(model_path)


def test_raw_write_then_orm_read(tmp_path):
    path = tmp_path / "shared.sqlite3"
    engine = make_engine(path)
    BehaviorEventStore(path).insert_many([{
        "observed_at": "2026-10-19T00:00:00+00:00", "agent_label": "demo",
        "flow_id": "f1", "upstream_host": "127.0.0.1", "protocol": "MCP",
        "event_type": "mcp.request", "operation": "tools/call", "confidence": "high",
        "endpoint": "/mcp", "tool": "search", "evidence": ["jsonrpc_2.0"]}])
    with Session(engine) as session:
        events = BehaviorEventRepository(session).list_events()
    assert len(events) == 1
    assert events[0]["tool"] == "search" and events[0]["source"] == "gateway"


def test_orm_write_then_raw_read(tmp_path):
    path = tmp_path / "shared.sqlite3"
    engine = make_engine(path)
    with Session(engine) as session:
        session.add(BehaviorEventRow(
            observed_at="2026-10-19T00:00:00+00:00", source="gateway",
            agent_label="web", flow_id="f2", upstream_host="127.0.0.1",
            protocol="LLM", event_type="http.response", operation="model_inference",
            confidence="medium", endpoint="/v1/messages", http_status=200,
            evidence_json='["llm_endpoint"]'))
        session.commit()
    events = BehaviorEventStore(path).list_events()
    assert len(events) == 1 and events[0]["agent_label"] == "web"
    assert events[0]["evidence"] == ["llm_endpoint"]


def test_ddl_matches_model_column_names():
    model_names = {c.name for c in BehaviorEventRow.__table__.columns}
    ddl = " ".join(BEHAVIOR_EVENTS_DDL.split())
    for name in model_names:
        assert name in ddl
