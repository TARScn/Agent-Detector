"""Parse Tetragon JSON export lines into typed events.

Tetragon writes one JSON object per line (``--export-filename``). This module
is the pure parsing half of the eBPF channel — no I/O, no state — mirroring the
audit channel's ``parser.py``. Shapes verified against Tetragon v1.7.1
standalone export on Linux (see tests/fixtures/tetragon/):

    {"process_exec": {"process": {...}, "parent": {...}},
     "node_name": "...", "time": "2026-10-30T07:01:52.256664067Z"}

``process.binary`` is a path string, ``process.arguments`` a space-joined
string *without* the program itself (the parser prepends the binary so argv
keeps the same shape as the auditd/sysmon channels), ``process.docker`` a
leading hex prefix of the full container ID (empty/absent for host
processes), and ``process.start_time`` an RFC3339 timestamp with nanosecond
precision.
"""
from __future__ import annotations

import json
import posixpath
import shlex
from dataclasses import dataclass, field
from datetime import datetime, timezone

# Payload keys this parser understands. process_kprobe/tracepoint/uprobe/lseek
# come from TracingPolicies (net/file capture, phase 3); the parser carries
# them through so the normalizer can grow mappings without parser changes.
EVENT_TYPES = ("process_exec", "process_exit", "process_kprobe",
               "process_tracepoint", "process_uprobe", "process_lseek")


@dataclass(frozen=True)
class TetragonEvent:
    """One parsed Tetragon event (host-namespace view of the process)."""

    etype: str
    ts: float                       # epoch seconds from the top-level time
    pid: int
    ppid: int | None
    process_name: str
    exe: str | None = None
    argv: tuple[str, ...] = ()
    cwd: str | None = None
    exec_id: str | None = None      # kernel-side process identity (base64)
    parent_exec_id: str | None = None
    start_time: float | None = None  # process start, epoch seconds
    container_id: str | None = None  # Tetragon "docker" field: hex ID prefix
    function_name: str | None = None  # kprobe/tracepoint policy hooks
    raw: dict = field(default_factory=dict, repr=False, compare=False)


def _rfc3339_to_epoch(value) -> float:
    """RFC3339 with nanoseconds ("...T07:01:52.256664525Z") → epoch seconds.

    ``datetime.fromisoformat`` rejects >6 fractional digits on Python 3.10, so
    the fraction is split off and re-added as a float. Returns 0.0 on garbage —
    the ingest layer falls back to now for timestamps of 0, same as auditd.
    """
    if not isinstance(value, str) or not value:
        return 0.0
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    dot = text.find(".")
    fraction = 0.0
    if dot >= 0:
        plus = text.find("+", dot)
        minus = text.find("-", dot)
        cut = min(c for c in (plus, minus) if c >= 0) if (plus >= 0 or minus >= 0) \
            else len(text)
        digits = text[dot + 1:cut]
        text = text[:dot] + text[cut:]
        if digits.isdigit():
            fraction = float("0." + digits)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return 0.0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp() + fraction


def _binary_path(process: dict) -> str | None:
    binary = process.get("binary")
    if isinstance(binary, dict):
        return binary.get("path") or None
    return binary or None


def _arguments(process: dict) -> tuple[str, ...]:
    args = process.get("arguments")
    if not isinstance(args, str) or not args:
        return ()
    try:
        return tuple(shlex.split(args))
    except ValueError:
        # Quoting is already lost in Tetragon's space-join; keep the raw text.
        return (args,)


def _container_id(process: dict) -> str | None:
    docker = process.get("docker")
    if isinstance(docker, str) and docker:
        return docker
    if isinstance(docker, dict):  # older/k8s shape
        return docker.get("container_id") or docker.get("id") or None
    return None


def parse_event_json(line: str | bytes) -> TetragonEvent | None:
    """One export line → TetragonEvent; None for blanks/garbage/foreign JSON."""
    if isinstance(line, bytes):
        line = line.decode("utf-8", "replace")
    text = line.strip()
    if not text:
        return None
    try:
        payload = json.loads(text)
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    etype = next((name for name in EVENT_TYPES if name in payload), None)
    if etype is None:
        return None
    body = payload.get(etype)
    if not isinstance(body, dict):
        return None
    process = body.get("process")
    if not isinstance(process, dict):
        return None
    pid = process.get("pid")
    if not isinstance(pid, int):
        return None
    parent = body.get("parent") if isinstance(body.get("parent"), dict) else {}
    ppid = parent.get("pid")
    ts = _rfc3339_to_epoch(payload.get("time")) or _rfc3339_to_epoch(body.get("time"))
    exe = _binary_path(process)
    # Tetragon's ``arguments`` excludes the program itself; every other channel
    # keeps argv[0] = executable, and rule matching keys off that — prepend it.
    argv = ((exe,) if exe else ()) + _arguments(process)
    return TetragonEvent(
        etype=etype,
        ts=ts,
        pid=pid,
        ppid=ppid if isinstance(ppid, int) else None,
        process_name=(posixpath.basename(exe) if exe else "") or "",
        exe=exe,
        argv=argv,
        cwd=process.get("cwd") or None,
        exec_id=process.get("exec_id") or None,
        parent_exec_id=process.get("parent_exec_id") or None,
        start_time=_rfc3339_to_epoch(process.get("start_time")) or None,
        container_id=_container_id(process),
        function_name=body.get("function_name") or None,
        raw=payload,
    )
