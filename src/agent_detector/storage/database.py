"""Engine factory: SQLite with WAL and a busy timeout (design section 2).

New tables are created by ``Base.metadata.create_all``; columns added to an
existing table after a release are applied by ``ensure_schema`` so a running
installation upgrades in place (no Alembic yet).
"""
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine

from agent_detector.storage.models import Base

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
# V0.2.x: LLM base-model inventory per Agent asset
_ADDITIVE_COLUMNS["agent_assets"] = {"llm_endpoints_json": "TEXT"}
# Self-built agent discovery: framework assets link to their application
_ADDITIVE_COLUMNS["agent_assets"]["app_id"] = "VARCHAR(96)"
# Post-scan verification lifecycle (re-install flips back to active on upsert)
_ADDITIVE_COLUMNS["agent_assets"]["status"] = "VARCHAR(24) DEFAULT 'active'"
_ADDITIVE_COLUMNS["applications"] = {"status": "VARCHAR(24) DEFAULT 'active'"}
# Docker channel (Docker Core): container-origin assets and instances
_ADDITIVE_COLUMNS["agent_assets"]["origin"] = "VARCHAR(16) DEFAULT 'host'"
_ADDITIVE_COLUMNS["agent_assets"]["container_id"] = "VARCHAR(96)"
_ADDITIVE_COLUMNS["agent_instances"] = {"origin": "VARCHAR(16) DEFAULT 'host'",
                                        "container_id": "VARCHAR(96)"}
# eBPF channel (Tetragon): container hex-ID prefix on behavior events
_ADDITIVE_COLUMNS["behavior_events"]["container_id"] = "VARCHAR(96)"


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
                if name not in existing:
                    connection.exec_driver_sql(
                        f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
                    added.append(f"{table}.{name}")
    return added


def make_engine(db_path) -> Engine:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{path}", connect_args={"timeout": 10})

    @event.listens_for(engine, "connect")
    def _pragmas(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=10000")
        cursor.close()

    Base.metadata.create_all(engine)
    ensure_schema(engine)
    return engine
