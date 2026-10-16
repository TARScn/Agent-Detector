import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from agent_detector.models import Finding


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def _init(self):
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL, mode TEXT NOT NULL,
                observation_count INTEGER NOT NULL, finding_count INTEGER NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id),
                component TEXT NOT NULL, category TEXT NOT NULL,
                confidence REAL NOT NULL, state TEXT NOT NULL,
                version TEXT, version_source TEXT, pid INTEGER, port INTEGER,
                evidence_json TEXT NOT NULL)""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)")

    def save(self, active: bool, observation_count: int, findings: list[Finding]) -> int:
        with self.connect() as db:
            cursor = db.execute(
                "INSERT INTO scans(started_at, mode, observation_count, finding_count) VALUES(?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(), "active+passive" if active else "passive",
                 observation_count, len(findings)))
            scan_id = cursor.lastrowid
            for f in findings:
                db.execute("""INSERT INTO findings
                    (scan_id, component, category, confidence, state, version, version_source, pid, port, evidence_json)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (scan_id, f.component, f.category, f.confidence, f.state,
                     f.version, f.version_source, f.pid, f.port, json.dumps(f.evidence, ensure_ascii=False)))
            return scan_id

    def scans(self, limit=30):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))]

    def findings(self, scan_id=None, limit=500):
        query = "SELECT * FROM findings"
        params = []
        if scan_id is not None:
            query += " WHERE scan_id=?"
            params.append(scan_id)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self.connect() as db:
            rows = [dict(row) for row in db.execute(query, params)]
        for row in rows:
            row["evidence"] = json.loads(row.pop("evidence_json"))
        return rows
