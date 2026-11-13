"""Events offset pagination, agent_label fuzzy search and runtime retention."""
from __future__ import annotations

from sqlalchemy.orm import Session

from agent_detector.core.config import BEHAVIOR_RETENTION_DAYS
from agent_detector.monitoring.services.retention import (
    clamp_retention_days,
    get_retention_days,
    purge_behavior_events,
    set_retention_days,
)
from agent_detector.storage import BehaviorEventRepository
from agent_detector.storage.database import make_engine
from agent_detector.storage.models import BehaviorEventRow, utc_now_iso


def _insert_event(engine, **overrides) -> None:
    defaults = dict(observed_at=utc_now_iso(), source="auditd",
                    agent_label="claude", flow_id="auditd-1", upstream_host="",
                    protocol="SYS", event_type="proc.exec", operation="SCRIPT_EXEC",
                    confidence="high", endpoint="")
    defaults.update(overrides)
    with Session(engine) as session:
        session.add(BehaviorEventRow(**defaults))
        session.commit()


def test_offset_pagination_and_total(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    for index in range(7):
        _insert_event(engine, observed_at=f"2026-11-{10 + index:02d}T00:00:00+00:00",
                      source="sysmon" if index % 2 else "auditd")

    with Session(engine) as session:
        repo = BehaviorEventRepository(session)
        all_ids = [event["id"] for event in repo.list_events(limit=50)]
        page_two = repo.list_events(limit=3, offset=3)
        assert [event["id"] for event in page_two] == all_ids[3:6]
        assert repo.list_events(limit=3, offset=99) == []  # past the end
        assert repo.count_events() == 7
        assert repo.count_events(source="sysmon") == 3


def test_agent_label_substring_search(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    _insert_event(engine, agent_label="ZCode.exe")
    _insert_event(engine, agent_label="claude")
    _insert_event(engine, agent_label="load_100%")

    with Session(engine) as session:
        repo = BehaviorEventRepository(session)
        hits = repo.list_events(agent_label="zcode")
        assert [event["agent_label"] for event in hits] == ["ZCode.exe"]
        # "%" is matched literally (autoescaped), not as a wildcard.
        assert [event["agent_label"]
                for event in repo.list_events(agent_label="%")] == ["load_100%"]


def test_offset_rejects_cursor_mix(client, engine):
    _insert_event(engine)
    assert client.get("/api/v1/events",
                      params={"offset": 1, "before_id": 5}).status_code == 422
    assert client.get("/api/v1/events",
                      params={"offset": 1, "after_id": 5}).status_code == 422

    payload = client.get("/api/v1/events", params={"limit": 10}).json()
    assert payload["total_matches"] == 1
    assert payload["offset"] == 0

    streamed = client.get("/api/v1/events",
                          params={"after_id": 1, "limit": 10}).json()
    assert streamed["total_matches"] is None  # cursor mode skips the count


def test_retention_roundtrip_and_purge(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    assert get_retention_days(engine) == BEHAVIOR_RETENTION_DAYS

    assert set_retention_days(engine, 7) == 7
    assert get_retention_days(engine) == 7
    assert set_retention_days(engine, 99_999) == 3650  # clamped high
    assert set_retention_days(engine, -5) == 0  # clamped low: retention off

    _insert_event(engine, observed_at="2020-01-01T00:00:00+00:00")
    _insert_event(engine)
    assert purge_behavior_events(engine, older_than_days=7) == 1
    with Session(engine) as session:
        assert len(BehaviorEventRepository(session).list_events()) == 1


def test_retention_api_and_system_surface(client, engine):
    _insert_event(engine, observed_at="2020-01-01T00:00:00+00:00")
    _insert_event(engine)

    initial = client.get("/api/v1/settings/retention").json()
    assert initial == {"retention_days": BEHAVIOR_RETENTION_DAYS,
                       "default_days": BEHAVIOR_RETENTION_DAYS}

    saved = client.put("/api/v1/settings/retention", json={"retention_days": 1})
    assert saved.status_code == 200
    assert saved.json() == {"retention_days": 1, "purged": 1}
    assert client.get("/api/v1/settings/retention").json()["retention_days"] == 1
    system = client.get("/api/v1/system").json()
    assert system["behavior"]["retention_days"] == 1

    assert client.put("/api/v1/settings/retention",
                      json={"retention_days": -1}).status_code == 422
    assert client.put("/api/v1/settings/retention",
                      json={"retention_days": 4000}).status_code == 422
