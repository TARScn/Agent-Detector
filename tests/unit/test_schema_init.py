"""Schema initialization tolerates the console/collector boot race."""
from __future__ import annotations

import sqlite3

import pytest
from sqlalchemy import create_engine
from sqlalchemy.engine import Connection
from sqlalchemy.exc import OperationalError

from agent_detector.storage.database import (_init_schema, ensure_schema)
from agent_detector.storage.models import Base


def _operational(statement: str, message: str) -> OperationalError:
    return OperationalError(statement, {}, sqlite3.OperationalError(message))


def test_init_schema_retries_already_exists(monkeypatch):
    engine = create_engine("sqlite://")
    real_create_all = Base.metadata.create_all
    attempts = {"count": 0}

    def flaky_create_all(*args, **kwargs):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise _operational("CREATE TABLE entities",
                               "table entities already exists")
        return real_create_all(*args, **kwargs)

    monkeypatch.setattr(Base.metadata, "create_all", flaky_create_all)
    _init_schema(engine)
    assert attempts["count"] == 2


def test_init_schema_does_not_swallow_real_errors(monkeypatch):
    engine = create_engine("sqlite://")
    attempts = {"count": 0}

    def broken_create_all(*args, **kwargs):
        attempts["count"] += 1
        raise _operational("CREATE TABLE entities", "disk I/O error")

    monkeypatch.setattr(Base.metadata, "create_all", broken_create_all)
    with pytest.raises(OperationalError):
        _init_schema(engine)
    assert attempts["count"] == 1


def test_ensure_schema_tolerates_duplicate_column_race(tmp_path, monkeypatch):
    path = tmp_path / "old.sqlite3"
    engine = create_engine(f"sqlite:///{path}")
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE behavior_events (id INTEGER PRIMARY KEY, "
            "source VARCHAR(32))")
        for table, key in (("agent_assets", "asset_id"),
                           ("applications", "app_id"),
                           ("agent_instances", "instance_id"),
                           ("entity_aliases", "old_id")):
            connection.exec_driver_sql(
                f"CREATE TABLE {table} ({key} VARCHAR(96) PRIMARY KEY)")

    real_execute = Connection.exec_driver_sql
    raised = {"done": False}

    def flaky_execute(self, statement, *args, **kwargs):
        if (statement.startswith("ALTER TABLE behavior_events ADD COLUMN pid")
                and not raised["done"]):
            raised["done"] = True
            raise _operational(statement, "duplicate column name: pid")
        return real_execute(self, statement, *args, **kwargs)

    monkeypatch.setattr(Connection, "exec_driver_sql", flaky_execute)
    added = ensure_schema(engine)

    assert raised["done"] is True
    assert "behavior_events.pid" not in added
    assert "behavior_events.source_event_uid" in added