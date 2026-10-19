"""Retention upkeep for behavior_events.

Row writers live outside the read-only repository by design; retention is the
one deliberate delete path and is kept here so the repository stays read-only.
"""
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from agent_detector.persistence.models import BehaviorEventRow


def purge_behavior_events(engine: Engine, older_than_days: int,
                          source: str | None = None) -> int:
    """Delete behavior events older than the retention window; returns rows removed."""
    if older_than_days <= 0:
        return 0
    cutoff = (datetime.now(timezone.utc)
              - timedelta(days=older_than_days)).isoformat(timespec="seconds")
    statement = delete(BehaviorEventRow).where(BehaviorEventRow.observed_at < cutoff)
    if source:
        statement = statement.where(BehaviorEventRow.source == source)
    with Session(engine) as session:
        removed = session.execute(statement).rowcount or 0
        session.commit()
    return removed


def clear_behavior_events(engine: Engine, source: str | None = None) -> int:
    """Delete all behavior events (optionally limited to one source).

    Destructive and explicit: used to wipe demo/replay data; the CLI requires
    the ``--all`` flag to reach this path.
    """
    statement = delete(BehaviorEventRow)
    if source:
        statement = statement.where(BehaviorEventRow.source == source)
    with Session(engine) as session:
        removed = session.execute(statement).rowcount or 0
        session.commit()
    return removed