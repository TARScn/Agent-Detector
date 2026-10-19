"""Raw sqlite3 access to the behavior_events table.

The mitmproxy addon process writes through this module (the proxy does not
import SQLAlchemy); the web/CLI side reads the same table via
BehaviorEventRepository. Both sides share one schema —
tests/test_gateway_schema_parity.py guards against drift between this DDL and
the SQLAlchemy model. No request bodies, prompts or credentials are ever
written here; only the bounded metadata produced by the classifier.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable

BEHAVIOR_EVENTS_DDL = """
CREATE TABLE IF NOT EXISTS behavior_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  observed_at TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'gateway',
  agent_label TEXT NOT NULL,
  asset_id TEXT,
  flow_id TEXT NOT NULL,
  upstream_host TEXT NOT NULL,
  protocol TEXT NOT NULL,
  event_type TEXT NOT NULL,
  operation TEXT NOT NULL,
  confidence TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  protocol_version TEXT,
  component_version TEXT,
  model TEXT,
  tool TEXT,
  http_status INTEGER,
  evidence_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_behavior_events_observed ON behavior_events(observed_at DESC);
CREATE INDEX IF NOT EXISTS ix_behavior_events_protocol ON behavior_events(protocol, id DESC);
CREATE INDEX IF NOT EXISTS ix_behavior_events_agent ON behavior_events(agent_label, id DESC);
"""

_COLUMNS = ("observed_at", "source", "agent_label", "asset_id", "flow_id", "upstream_host",
            "protocol", "event_type", "operation", "confidence", "endpoint",
            "protocol_version", "component_version", "model", "tool", "http_status")


class BehaviorEventStore:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = self._connect()
        try:
            with db:
                db.executescript(BEHAVIOR_EVENTS_DDL)
        finally:
            db.close()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(str(self.path), timeout=10)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA busy_timeout=10000")
        return db

    def insert_many(self, records: Iterable[dict]) -> None:
        rows = []
        for e in records:
            rows.append((e["observed_at"], e.get("source", "gateway"), e["agent_label"],
                         e.get("asset_id"), e["flow_id"], e["upstream_host"], e["protocol"],
                         e["event_type"], e["operation"], e["confidence"], e["endpoint"],
                         e.get("protocol_version"), e.get("component_version"), e.get("model"),
                         e.get("tool"), e.get("http_status"),
                         json.dumps(e.get("evidence", []), ensure_ascii=False)))
        if not rows:
            return
        placeholders = ",".join("?" * (len(_COLUMNS) + 1))
        db = self._connect()
        try:
            with db:
                db.executemany(
                    f"INSERT INTO behavior_events ({','.join(_COLUMNS)},evidence_json) "
                    f"VALUES ({placeholders})", rows)
        finally:
            db.close()

    def list_events(self, limit: int = 100, protocol: str | None = None) -> list[dict]:
        sql = "SELECT * FROM behavior_events"
        params: list[object] = []
        if protocol:
            sql += " WHERE protocol=?"
            params.append(protocol)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(min(max(int(limit), 1), 500))
        db = self._connect()
        try:
            db.row_factory = sqlite3.Row
            result = []
            for row in db.execute(sql, params):
                record = dict(row)
                record["evidence"] = json.loads(record.pop("evidence_json"))
                result.append(record)
            return result
        finally:
            db.close()

    def stats(self) -> dict:
        db = self._connect()
        try:
            count = db.execute("SELECT COUNT(*) FROM behavior_events").fetchone()[0]
            by_protocol = dict(db.execute(
                "SELECT protocol,COUNT(*) FROM behavior_events GROUP BY protocol"))
            by_agent = dict(db.execute(
                "SELECT agent_label,COUNT(*) FROM behavior_events GROUP BY agent_label"))
        finally:
            db.close()
        return {"event_count": count, "by_protocol": by_protocol, "by_agent": by_agent}
