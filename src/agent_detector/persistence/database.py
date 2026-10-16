"""Engine factory: SQLite with WAL and a busy timeout (plan section 5.1)."""
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine

from agent_detector.persistence.models import Base


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
    return engine
