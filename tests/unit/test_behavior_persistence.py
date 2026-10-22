import sqlite3

from sqlalchemy.orm import Session

from agent_detector.services.retention import (clear_behavior_events,
                                                 purge_behavior_events)
from agent_detector.domain.models import ProcessInfo
from agent_detector.storage.database import ensure_schema, make_engine
from agent_detector.storage.models import BehaviorEventRow
from agent_detector.storage.repositories import BehaviorEventRepository

LEGACY_DDL = """
CREATE TABLE behavior_events (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    observed_at VARCHAR(48) NOT NULL,
    source VARCHAR(32) NOT NULL,
    agent_label VARCHAR(80) NOT NULL,
    asset_id VARCHAR(96),
    flow_id VARCHAR(64) NOT NULL,
    upstream_host VARCHAR(255) NOT NULL,
    protocol VARCHAR(16) NOT NULL,
    event_type VARCHAR(48) NOT NULL,
    operation VARCHAR(100) NOT NULL,
    confidence VARCHAR(16) NOT NULL,
    endpoint VARCHAR(150) NOT NULL,
    protocol_version VARCHAR(30),
    component_version VARCHAR(30),
    model VARCHAR(90),
    tool VARCHAR(90),
    http_status INTEGER,
    evidence_json TEXT NOT NULL DEFAULT '[]'
)
"""


def _seed_legacy_db(path) -> None:
    connection = sqlite3.connect(path)
    connection.execute(LEGACY_DDL)
    connection.execute(
        "INSERT INTO behavior_events (observed_at, source, agent_label, flow_id, upstream_host,"
        " protocol, event_type, operation, confidence, endpoint) VALUES"
        " ('2026-10-01T00:00:00+00:00','netmon','old.exe','f1','api.example.com','LLM',"
        " 'llm.conn','llm_api','medium','1.2.3.4:443')")
    connection.commit()
    connection.close()


def _insert_event(engine, **overrides) -> None:
    defaults = dict(observed_at="2026-10-19T00:00:00+00:00", source="auditd",
                    agent_label="claude", flow_id="auditd-1", upstream_host="",
                    protocol="SYS", event_type="proc.exec", operation="SCRIPT_EXEC",
                    confidence="high", endpoint="")
    defaults.update(overrides)
    with Session(engine) as session:
        session.add(BehaviorEventRow(**defaults))
        session.commit()


def test_ensure_schema_upgrades_legacy_table(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    _seed_legacy_db(path)
    engine = make_engine(path)  # create_all + ensure_schema
    with engine.connect() as connection:
        columns = {row[1] for row in
                   connection.exec_driver_sql("PRAGMA table_info(behavior_events)")}
    assert {"pid", "ppid", "process_name", "target", "result"} <= columns

    with Session(engine) as session:
        events = BehaviorEventRepository(session).list_events(source="netmon")
    assert events[0]["agent_label"] == "old.exe"
    assert events[0]["pid"] is None and events[0]["target"] is None
    assert ensure_schema(engine) == []  # idempotent


def test_list_events_new_filters_and_fields(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    _insert_event(engine, agent_label="claude", asset_id="claude--abc",
                  event_type="proc.exec", target="/home/u/agent-lab/train.py",
                  pid=4242, ppid=4000, process_name="python3", result="started")
    _insert_event(engine, agent_label="codex", event_type="file.move",
                  target="/home/u/agent-lab/a.py -> /home/u/agent-lab/b.py",
                  result="success")
    _insert_event(engine, source="netmon", event_type="llm.conn", agent_label="claude")

    with Session(engine) as session:
        repo = BehaviorEventRepository(session)
        assert len(repo.list_events(source="auditd")) == 2
        assert len(repo.list_events(agent_label="codex")) == 1
        assert len(repo.list_events(asset_id="claude--abc")) == 1
        assert len(repo.list_events(event_type="file.move")) == 1
        event = repo.list_events(agent_label="claude", source="auditd")[0]
        assert (event["pid"], event["ppid"], event["process_name"]) == (4242, 4000, "python3")
        assert event["result"] == "started"
        stats = repo.stats()
        assert stats["by_source"] == {"auditd": 2, "netmon": 1}


def test_purge_behavior_events_respects_window_and_source(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    _insert_event(engine, observed_at="2020-01-01T00:00:00+00:00", source="auditd")
    _insert_event(engine, observed_at="2020-01-01T00:00:00+00:00", source="netmon")
    _insert_event(engine, source="auditd")
    _insert_event(engine, source="netmon")

    assert purge_behavior_events(engine, older_than_days=0) == 0
    assert purge_behavior_events(engine, older_than_days=30, source="auditd") == 1
    assert purge_behavior_events(engine, older_than_days=30) == 1
    with Session(engine) as session:
        remaining = BehaviorEventRepository(session).list_events(limit=50)
    assert len(remaining) == 2
    assert {row["source"] for row in remaining} == {"auditd", "netmon"}


def test_process_info_carries_ppid():
    proc = ProcessInfo(pid=10, name="python3", cmdline=("python3", "x.py"), ppid=1)
    assert proc.ppid == 1
    assert ProcessInfo(pid=11, name="x").ppid is None


def test_clear_behavior_events_scopes_by_source(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    _insert_event(engine, source="auditd")
    _insert_event(engine, source="poll")
    _insert_event(engine, source="netmon")

    assert clear_behavior_events(engine, source="auditd") == 1
    assert clear_behavior_events(engine, source="poll") == 1
    with Session(engine) as session:
        remaining = BehaviorEventRepository(session).list_events(limit=50)
    assert [row["source"] for row in remaining] == ["netmon"]
    assert clear_behavior_events(engine) == 1