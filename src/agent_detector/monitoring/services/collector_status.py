"""Cross-process collector health file.

The ingest service rewrites this JSON with its live counters every minute
(same cadence as the registry snapshot); the console — a separate process
whose own ingest instance never starts under the systemd deployment — reads
it to show the real collector state instead of its idle twin. Same
shared-file contract as hook.token / sysmon.bookmark / process-snapshot:
a sibling of the DB, path overridable by env. Missing/stale/corrupt/
foreign-host files are ignored, never errors.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from agent_detector.core.config import (COLLECTOR_STATUS_MAX_AGE,
                                        COLLECTOR_STATUS_PATH)

logger = logging.getLogger(__name__)

_SCHEMA = 1


def write_collector_status(status: dict, *,
                           path: Path = COLLECTOR_STATUS_PATH,
                           hostname: str | None = None) -> None:
    """Atomically replace the status file. ``status`` is the ingest service's
    status() dict taken as-is, so new counters flow without schema churn."""
    import platform

    payload = {"schema": _SCHEMA,
               "written_at": _now_iso(),
               "hostname": hostname or platform.node() or "localhost",
               "collector": status}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass  # Windows ACLs ignore POSIX mode bits
        os.replace(tmp, path)
    except OSError:
        logger.exception("collector status write failed: %s", path)


def load_collector_status(*, path: Path = COLLECTOR_STATUS_PATH,
                          max_age: int = COLLECTOR_STATUS_MAX_AGE,
                          hostname: str | None = None) -> dict | None:
    """``{collector, written_at, age_seconds}`` from a fresh file, else None
    (the caller keeps its local view). Stale/corrupt/foreign-host snapshots
    are ignored, never errors."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return None
    if not isinstance(raw, dict) or raw.get("schema") != _SCHEMA:
        return None
    if hostname is not None and raw.get("hostname") != hostname:
        return None
    written = _parse_iso(raw.get("written_at"))
    if written is None or datetime.now(timezone.utc).timestamp() - written > max_age:
        return None
    collector = raw.get("collector")
    if not isinstance(collector, dict):
        return None
    return {"collector": collector,
            "written_at": raw.get("written_at"),
            "age_seconds": round(datetime.now(timezone.utc).timestamp() - written, 1)}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(value) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None
