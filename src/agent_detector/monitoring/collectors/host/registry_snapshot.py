"""Cross-process process-registry snapshot file.

The running collector atomically rewrites this JSON file with its process
registry (event-fed by Tetragon/Sysmon, backfilled from /proc); a standalone
`agent-detector scan` prefers it over a psutil one-shot so discovery sees the
live registry — and falls back to psutil whenever the file is missing, stale,
corrupt, or from another host. Same shared-file contract as hook.token /
sysmon.bookmark: a sibling of the DB, path overridable by env.

Sensitivity: the payload carries working directories and (redacted) command
lines — operator-local material at the same level as the DB itself. argv is
passed through ``redact()`` and length-capped at serialization time, and the
file is chmod 0600 on POSIX (best effort; Windows ACLs ignore mode bits).
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from agent_detector.core.config import PROC_SNAPSHOT_MAX_AGE, PROC_SNAPSHOT_PATH
from agent_detector.core.models import ProcessInfo
from agent_detector.core.security import redact

logger = logging.getLogger(__name__)

_SCHEMA = 1
_ARG_LEN_LIMIT = 512
_ARG_COUNT_LIMIT = 64  # the resolver needs interpreter + entry markers, not tails


def write_process_snapshot(hostname: str, processes: Iterable[ProcessInfo],
                           *, path: Path = PROC_SNAPSHOT_PATH) -> None:
    """Atomically replace the snapshot file (tmp + os.replace: readers never
    see a half-written file). The tmp file is chmod 0600 before the replace so
    the live path never wears loose permissions. Best-effort: a failed write
    must never take the collector down."""
    rows = [_process_row(proc) for proc in processes]
    payload = {"schema": _SCHEMA,
               "written_at": _now_iso(),
               "hostname": hostname,
               "processes": rows}
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
        logger.exception("process snapshot write failed: %s", path)


def load_process_snapshot(*, path: Path = PROC_SNAPSHOT_PATH,
                          max_age: int = PROC_SNAPSHOT_MAX_AGE,
                          hostname: str | None = None,
                          ) -> tuple[ProcessInfo, ...] | None:
    """Fresh snapshot processes, or None (caller falls back to psutil).
    Stale/corrupt/foreign-host snapshots are ignored, never errors."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return None
    if not isinstance(raw, dict) or raw.get("schema") != _SCHEMA:
        return None
    if hostname is not None and raw.get("hostname") != hostname:
        return None
    written = _parse_iso(raw.get("written_at"))
    if written is None or _now_iso_epoch() - written > max_age:
        return None
    rows = raw.get("processes")
    if not isinstance(rows, list):
        return None
    processes = []
    for row in rows:
        proc = _process_from_row(row)
        if proc is not None:
            processes.append(proc)
    return tuple(processes)


def _process_row(proc: ProcessInfo) -> dict:
    """Serialization with credential hygiene: command lines are the classic
    secrets-on-argv surface (the DB stores argv only behind an opt-in flag and
    redacted — this file must not be more permissive than the DB). redact()
    masks known token shapes per element; length caps keep long argument
    tails out while the interpreter and entry markers survive for the
    resolver."""
    cmdline = [redact(str(arg))[:_ARG_LEN_LIMIT]
               for arg in proc.cmdline[:_ARG_COUNT_LIMIT]]
    return {"pid": proc.pid, "name": proc.name,
            "cmdline": cmdline, "create_time": proc.create_time,
            "ppid": proc.ppid, "exe": proc.exe, "cwd": proc.cwd,
            "container_id": proc.container_id}


def _process_from_row(row) -> ProcessInfo | None:
    if not isinstance(row, dict) or not isinstance(row.get("pid"), int):
        return None
    cmdline = row.get("cmdline")
    return ProcessInfo(
        pid=row["pid"],
        name=str(row.get("name") or ""),
        cmdline=tuple(str(arg) for arg in cmdline) if isinstance(cmdline, list) else (),
        create_time=row.get("create_time") if isinstance(row.get("create_time"),
                                                         (int, float)) else None,
        ppid=row.get("ppid") if isinstance(row.get("ppid"), int) else None,
        exe=row.get("exe") if isinstance(row.get("exe"), str) else None,
        cwd=row.get("cwd") if isinstance(row.get("cwd"), str) else None,
        container_id=(row.get("container_id")
                      if isinstance(row.get("container_id"), str) else None))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(value) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None


def _now_iso_epoch() -> float:
    return datetime.now(timezone.utc).timestamp()
