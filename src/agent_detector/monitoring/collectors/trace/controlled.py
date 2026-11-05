"""Read a controlled, opt-in JSONL trace for runtime/protocol evidence.

The trace only carries metadata (ids, names, timestamps, direction). It is
never enabled by default: ``AGENT_DETECTOR_CONTROLLED_TRACE`` must point at a
file the operator explicitly allows the detector to read. Records are E5-style
evidence ("a tool/framework call was observed by an authorized source"), not
proof of autonomous intent or complete coverage.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TraceEvent:
    kind: str                       # "runtime" | "protocol"
    observed_at: str
    pid: int | None = None
    session_id: str | None = None
    framework: str | None = None
    protocol: str | None = None     # "mcp" | "a2a"
    server: str | None = None
    tool: str | None = None
    method: str | None = None
    direction: str | None = None


def read_trace(path: str | Path | None, *, max_records: int = 2000
               ) -> list[TraceEvent]:
    if not path:
        return []
    target = Path(path)
    events: list[TraceEvent] = []
    try:
        handle = target.open("r", encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.warning("controlled trace unreadable: %s", exc)
        return []
    with handle:
        for line in handle:
            if len(events) >= max_records:
                break
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            kind = str(payload.get("kind") or "").strip().lower()
            if kind not in ("runtime", "protocol"):
                if payload.get("protocol"):
                    kind = "protocol"
                elif payload.get("framework"):
                    kind = "runtime"
                else:
                    continue
            observed_at = str(payload.get("ts") or payload.get("observed_at")
                              or "").strip()
            if not observed_at:
                continue
            pid = _as_int(payload.get("pid"))
            session_id = _as_text(payload.get("session_id"))
            if kind == "runtime":
                framework = _as_text(payload.get("framework"))
                if not framework:
                    continue
                events.append(TraceEvent(
                    kind="runtime", observed_at=observed_at, pid=pid,
                    session_id=session_id, framework=framework,
                    method=_as_text(payload.get("event") or payload.get("method"))))
            else:
                protocol = _as_text(payload.get("protocol"))
                if protocol not in ("mcp", "a2a"):
                    continue
                events.append(TraceEvent(
                    kind="protocol", observed_at=observed_at, pid=pid,
                    session_id=session_id, protocol=protocol,
                    server=_as_text(payload.get("server")),
                    tool=_as_text(payload.get("tool")),
                    method=_as_text(payload.get("method")),
                    direction=_as_text(payload.get("direction"))))
    return events


def _as_text(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _as_int(value) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None