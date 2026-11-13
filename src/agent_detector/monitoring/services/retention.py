"""Retention upkeep for behavior_events.

Row writers live outside the read-only repository by design; retention is the
one deliberate delete path and is kept here so the repository stays read-only.
"""
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from agent_detector.storage.models import AppSettingRow, BehaviorEventRow

_RETENTION_KEY = "behavior.retention_days"
_RETENTION_MIN, _RETENTION_MAX = 0, 3650


def clamp_retention_days(days: int) -> int:
    """Same bounds as the env-config default: 0 disables retention."""
    return min(max(int(days), _RETENTION_MIN), _RETENTION_MAX)


def get_retention_days(engine: Engine) -> int:
    """Effective retention window: runtime override, else the env default.

    Never raises: a missing table or unreadable row degrades to the default
    so collectors and the console keep purging on a sane window.
    """
    from agent_detector.core.config import BEHAVIOR_RETENTION_DAYS

    try:
        with Session(engine) as session:
            row = session.get(AppSettingRow, _RETENTION_KEY)
    except Exception:
        return BEHAVIOR_RETENTION_DAYS
    if row is None or not row.value:
        return BEHAVIOR_RETENTION_DAYS
    try:
        return clamp_retention_days(int(row.value))
    except ValueError:
        return BEHAVIOR_RETENTION_DAYS


def set_retention_days(engine: Engine, days: int) -> int:
    """Persist the runtime retention window (clamped); returns the stored value."""
    stored = clamp_retention_days(days)
    with Session(engine) as session:
        row = session.get(AppSettingRow, _RETENTION_KEY)
        if row is None:
            row = AppSettingRow(key=_RETENTION_KEY, value=str(stored))
            session.add(row)
        else:
            row.value = str(stored)
            row.updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        session.commit()
    return stored


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