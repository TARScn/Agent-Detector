"""Engine factory: SQLite with WAL and a busy timeout (design section 2).

New tables are created by ``Base.metadata.create_all``; columns added to an
existing table after a release are applied by ``ensure_schema`` so a running
installation upgrades in place (no Alembic yet).

The console and the collector are separate systemd units that open the same
database at boot. ``create_all`` checks for a table and then creates it, which
is not atomic across processes: both can pass the check and one then fails
with "table ... already exists". Initialization therefore retries benign
already-exists errors; the loser simply re-checks and finds the winner's DDL.
"""
import sqlite3
import time
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError

from agent_detector.storage.models import Base

_BENIGN_INIT_RACE = ("already exists", "duplicate column name")
_INIT_RETRIES = 4

# Additive columns, applied to databases created by an earlier version.
_ADDITIVE_COLUMNS: dict[str, dict[str, str]] = {
    # V0.1 -> V0.1.1 system behavior columns
    "behavior_events": {
        "pid": "INTEGER",
        "ppid": "INTEGER",
        "process_name": "VARCHAR(80)",
        "target": "VARCHAR(512)",
        "result": "VARCHAR(24)",
    },
}
# V0.2 columns for the same table (correlation + pre-execution decision).
_ADDITIVE_COLUMNS["behavior_events"].update({
    "instance_id": "VARCHAR(96)",
    "session_id": "VARCHAR(96)",
    "process_guid": "VARCHAR(96)",
    "risk_level": "VARCHAR(16)",
    "decision": "VARCHAR(16)",
    "execution_status": "VARCHAR(24)",
    "policy_id": "VARCHAR(64)",
})
# Docker channel (Docker Core): container-origin instances
_ADDITIVE_COLUMNS["agent_instances"] = {"origin": "VARCHAR(16) DEFAULT 'host'",
                                        "container_id": "VARCHAR(96)"}
# eBPF channel (Tetragon): container hex-ID prefix on behavior events
_ADDITIVE_COLUMNS["behavior_events"]["container_id"] = "VARCHAR(96)"
# P0-C: actor/target roles and endpoint identity on behavior events
_ADDITIVE_COLUMNS["behavior_events"].update({
    "scope_key": "VARCHAR(96)",
    "actor_asset_id": "VARCHAR(96)",
    "actor_instance_id": "VARCHAR(96)",
    "actor_process_key": "VARCHAR(96)",
    "target_asset_id": "VARCHAR(96)",
    "target_endpoint_id": "VARCHAR(96)",
    "target_instance_id": "VARCHAR(96)",
    "attribution_method": "VARCHAR(64)",
    "attribution_state": "VARCHAR(24)",
    "source_event_uid": "VARCHAR(96)",
    "mcp_server": "VARCHAR(96)",
})

_ADDITIVE_COLUMNS["entity_aliases"] = {"status": "VARCHAR(16) DEFAULT 'OK'"}

# V1.2 canonical cutover: entity keys on operational rows. Legacy asset_id
# columns stay for historical rows; new writers populate the entity columns.
_ADDITIVE_COLUMNS.setdefault("agent_instances", {})["entity_id"] = "VARCHAR(96)"
_ADDITIVE_COLUMNS.setdefault("agent_sessions", {})["entity_id"] = "VARCHAR(96)"
_ADDITIVE_COLUMNS["behavior_events"].update({
    "actor_entity_id": "VARCHAR(96)",
    "target_entity_id": "VARCHAR(96)",
})
_ADDITIVE_COLUMNS.setdefault("security_alerts", {})["entity_id"] = "VARCHAR(96)"
_ADDITIVE_COLUMNS.setdefault("removal_candidates", {})["entity_id"] = "VARCHAR(96)"
_ADDITIVE_COLUMNS.setdefault("entity_attributes", {})["inventory_kind"] = (
    "VARCHAR(16) DEFAULT 'agent'")
_ADDITIVE_COLUMNS.setdefault("entity_attributes", {})["listening_ports_json"] = (
    "TEXT DEFAULT '[]'")

# V1.3: orthogonal state dimensions + per-scope freshness on snapshots.
_ADDITIVE_COLUMNS.setdefault("entity_snapshots", {}).update({
    "presence": "VARCHAR(16) DEFAULT 'UNKNOWN'",
    "verification": "VARCHAR(16) DEFAULT 'STALE'",
    "lifecycle": "VARCHAR(16) DEFAULT 'ACTIVE'",
    "reason_code": "VARCHAR(48) DEFAULT ''",
    "last_known_status": "VARCHAR(16) DEFAULT 'UNKNOWN'",
    "owner_scope_type": "VARCHAR(48)",
    "owner_scope_key": "VARCHAR(256)",
    "verified_scopes_json": "TEXT DEFAULT '[]'",
})

_ADDITIVE_INDEXES = (
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_behavior_source_event "
    "ON behavior_events(source, source_event_uid)",
    "CREATE INDEX IF NOT EXISTS ix_behavior_actor_asset "
    "ON behavior_events(actor_asset_id)",
    "CREATE INDEX IF NOT EXISTS ix_behavior_target_asset "
    "ON behavior_events(target_asset_id)",
    "CREATE INDEX IF NOT EXISTS ix_behavior_actor_process "
    "ON behavior_events(actor_process_key)",
    "CREATE INDEX IF NOT EXISTS ix_behavior_actor_entity "
    "ON behavior_events(actor_entity_id)",
    "CREATE INDEX IF NOT EXISTS ix_behavior_target_entity "
    "ON behavior_events(target_entity_id)",
    "CREATE INDEX IF NOT EXISTS ix_agent_instance_entity "
    "ON agent_instances(entity_id)",
    "CREATE INDEX IF NOT EXISTS ix_agent_session_entity "
    "ON agent_sessions(entity_id)",
    "CREATE INDEX IF NOT EXISTS ix_alert_entity "
    "ON security_alerts(entity_id)",
)


def _benign_init_race(exc: BaseException) -> bool:
    text = str(exc).lower()
    return any(marker in text for marker in _BENIGN_INIT_RACE)


def _init_schema(engine: Engine) -> None:
    """create_all with retries for cross-process races (console vs collector)."""
    for attempt in range(_INIT_RETRIES):
        try:
            Base.metadata.create_all(engine)
            return
        except OperationalError as exc:
            if not _benign_init_race(exc) or attempt == _INIT_RETRIES - 1:
                raise
            time.sleep(0.2 * (attempt + 1))


def ensure_schema(engine: Engine) -> list[str]:
    """Idempotent additive migration; returns the ``table.column`` names it added."""
    added: list[str] = []
    with engine.begin() as connection:
        for table, columns in _ADDITIVE_COLUMNS.items():
            existing = {row[1] for row in
                        connection.exec_driver_sql(f"PRAGMA table_info({table})")}
            if not existing:
                continue  # table is created from scratch by create_all
            for name, ddl in columns.items():
                if name in existing:
                    continue
                try:
                    connection.exec_driver_sql(
                        f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
                except OperationalError as exc:
                    if not _benign_init_race(exc):
                        raise
                    continue  # another process added it first
                added.append(f"{table}.{name}")
        for statement in _ADDITIVE_INDEXES:
            try:
                connection.exec_driver_sql(statement)
            except OperationalError as exc:
                if "no such table" in str(exc).lower():
                    continue  # partial legacy DB: table not created yet
                raise
    return added


def make_engine(db_path) -> Engine:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{path}", connect_args={"timeout": 10})

    @event.listens_for(engine, "connect")
    def _pragmas(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        # busy_timeout must be in place first: switching a brand-new database
        # to WAL takes a brief exclusive lock and otherwise fails immediately
        # when two processes open it at the same moment.
        cursor.execute("PRAGMA busy_timeout=10000")
        for attempt in range(5):
            try:
                cursor.execute("PRAGMA journal_mode=WAL")
                break
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() or attempt == 4:
                    raise
                time.sleep(0.1 * (attempt + 1))
        cursor.close()

    _init_schema(engine)
    ensure_schema(engine)
    return engine
