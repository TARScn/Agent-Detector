"""Engine factory: SQLite with WAL and a busy timeout (plan section 5.1)."""
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine

from agent_detector.persistence.models import Base

# Additive columns introduced after V0.1 shipped; older databases are upgraded
# in place by ensure_schema() (no Alembic yet).
_BEHAVIOR_EVENT_COLUMNS = {
    "pid": "INTEGER",
    "ppid": "INTEGER",
    "process_name": "VARCHAR(80)",
    "target": "VARCHAR(512)",
    "result": "VARCHAR(24)",
}


def ensure_schema(engine: Engine) -> list[str]:
    """Idempotent additive migration; returns the column names it added."""
    added: list[str] = []
    with engine.begin() as connection:
        existing = {row[1] for row in
                    connection.exec_driver_sql("PRAGMA table_info(behavior_events)")}
        if not existing:
            return added
        for name, ddl in _BEHAVIOR_EVENT_COLUMNS.items():
            if name not in existing:
                connection.exec_driver_sql(
                    f"ALTER TABLE behavior_events ADD COLUMN {name} {ddl}")
                added.append(name)
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
