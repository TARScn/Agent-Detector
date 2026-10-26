"""Normalize grouped audit events into BehaviorFact records.

This layer records *facts* only (what the kernel observed), never inferences:
kind/pid/ppid/process/argv/paths/result. High-level behaviors are derived later
by the rule engine. Raw argv stays in memory; storage policy is applied by the
ingest service.
"""
from __future__ import annotations

import ipaddress
import posixpath
from typing import Iterable

from agent_detector.monitoring.collectors.audit.parser import AuditEvent
from agent_detector.core.facts import FACT_KINDS, BehaviorFact
from agent_detector.monitoring.collectors.audit.syscalls import (ATTR_SYSCALLS, DELETE_SYSCALLS,
                                                   EXEC_SYSCALLS, KILL_SYSCALLS,
                                                   MOVE_SYSCALLS, NET_SYSCALLS,
                                                   READ_SYSCALLS, WRITE_SYSCALLS,
                                                   syscall_name)

_READ_KEY = "agent_detector_read"


def _int_or_none(value: str | None) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _int_hex(value: str | None) -> int | None:
    try:
        return int(value, 16)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _resolve(name: str, cwd: str | None) -> str:
    if not name or name.startswith("/") or not cwd:
        return name
    return posixpath.join(cwd.rstrip("/"), name)


def _path_records(event: AuditEvent) -> list[tuple[str, str]]:
    cwd = event.field("cwd")
    collected: list[tuple[str, str]] = []
    for record in event.of_type("PATH"):
        collected.append(((record.fields.get("nametype") or "UNKNOWN").upper(),
                          _resolve(record.fields.get("name") or "", cwd)))
    return collected


def _paths_for(kind: str, paths: list[tuple[str, str]]) -> tuple[str | None, str | None]:
    if kind in ("proc.exec", "net.connect", "proc.kill"):
        # The exec's PATH records describe the binary, not a behavior target.
        return None, None
    if kind == "file.move":
        source = next((name for nametype, name in paths
                       if nametype in ("DELETE", "OLD", "RENAME_OLD")), None)
        target = next((name for nametype, name in paths
                       if nametype in ("CREATE", "NEW", "RENAME_NEW")), None)
        return source, target
    if kind == "file.delete":
        return next((name for nametype, name in paths if nametype == "DELETE"), None), None
    for nametype, name in paths:
        if nametype != "PARENT":
            return name, None
    return None, None


def _argv(event: AuditEvent) -> tuple[str, ...]:
    merged: dict[str, str] = {}
    argc = 0
    for record in event.of_type("EXECVE"):
        argc = argc or (_int_or_none(record.fields.get("argc")) or 0)
        for key, value in record.fields.items():
            if key.startswith("a") and key[1:].isdigit():
                merged[key] = value
    if merged:
        count = max(argc, len(merged))
        return tuple(merged.get(f"a{i}", "") for i in range(count))
    proctitle = event.field("proctitle")
    if proctitle:
        return tuple(part for part in proctitle.split("\x00") if part)
    return ()


def _endpoint(event: AuditEvent) -> str | None:
    """Decode an audit SOCKADDR hex dump; only AF_INET/AF_INET6 are recorded."""
    record = event.first("SOCKADDR")
    if record is None:
        return None
    saddr = record.fields.get("saddr") or ""
    if len(saddr) < 8 or len(saddr) % 2:
        return None
    try:
        raw = bytes.fromhex(saddr)
    except ValueError:
        return None
    family = int.from_bytes(raw[0:2], "little")  # sa_family_t is little-endian
    if family == 2 and len(raw) >= 8:  # AF_INET
        port = int.from_bytes(raw[2:4], "big")
        return f"{'.'.join(str(byte) for byte in raw[4:8])}:{port}"
    if family == 10 and len(raw) >= 24:  # AF_INET6
        port = int.from_bytes(raw[2:4], "big")
        return f"[{ipaddress.IPv6Address(raw[8:24])}]:{port}"
    return None  # AF_UNIX / AF_NETLINK: local IPC, not recorded


def _classify(name: str | None, keys: tuple[str, ...],
              paths: list[tuple[str, str]], event: AuditEvent) -> str | None:
    if name in READ_SYSCALLS and _READ_KEY in keys:
        return "file.read"
    if name in MOVE_SYSCALLS or "agent_detector_move" in keys:
        return "file.move"
    if name in DELETE_SYSCALLS:
        return "file.delete"
    if name in ATTR_SYSCALLS:
        return "file.attr"
    if name in WRITE_SYSCALLS:
        return "file.write"
    if name in NET_SYSCALLS or event.first("SOCKADDR") is not None:
        return "net.connect"
    if name in KILL_SYSCALLS:
        return "proc.kill"
    # Unknown syscall number (unsupported arch): infer from PATH nametypes.
    nametypes = {nametype for nametype, _ in paths}
    if "DELETE" in nametypes and ("CREATE" in nametypes or "NEW" in nametypes):
        return "file.move"
    if nametypes and nametypes <= {"DELETE", "PARENT"}:
        return "file.delete"
    if nametypes:
        return "file.write"
    return None


def _result_for(kind: str, success: bool, exit_code: int | None) -> str:
    if success:
        return "started" if kind == "proc.exec" else "success"
    if exit_code in (-1, -13):  # EPERM, EACCES
        return "denied"
    return "failed"


def normalize_event(event: AuditEvent, keys: set[str] | None = None) -> BehaviorFact | None:
    syscall_record = event.first("SYSCALL")
    if syscall_record is None:
        return None
    event_keys = event.audit_keys()
    if keys is not None and not (set(event_keys) & keys):
        return None
    pid = _int_or_none(syscall_record.fields.get("pid"))
    if pid is None:
        return None

    arch = syscall_record.fields.get("arch")
    number = _int_or_none(syscall_record.fields.get("syscall"))
    name = syscall_name(arch, number)
    success = (syscall_record.fields.get("success") or "yes").lower() == "yes"
    exit_code = _int_or_none(syscall_record.fields.get("exit"))
    paths = _path_records(event)

    if event.of_type("EXECVE") or name in EXEC_SYSCALLS:
        kind = "proc.exec"
    else:
        kind = _classify(name, event_keys, paths, event)
    if kind is None:
        return None

    endpoint = _endpoint(event) if kind == "net.connect" else None
    if kind == "net.connect" and endpoint is None:
        return None

    path, path_target = _paths_for(kind, paths)
    evidence: list[str] = ["auditd", f"syscall:{name or number}"]
    if event_keys:
        evidence.append(f"key:{event_keys[0]}")
    if name is None:
        evidence.append("unclassified_syscall")
    if not success:
        evidence.append(f"exit:{exit_code}")

    return BehaviorFact(
        kind=kind, ts=event.timestamp, serial=event.serial, pid=pid,
        ppid=_int_or_none(syscall_record.fields.get("ppid")),
        process_name=syscall_record.fields.get("comm") or "",
        exe=syscall_record.fields.get("exe") or None,
        argv=_argv(event) if kind == "proc.exec" else (),
        path=path, path_target=path_target,
        result=_result_for(kind, success, exit_code),
        endpoint=endpoint,
        target_pid=_int_hex(syscall_record.fields.get("a0")) if kind == "proc.kill" else None,
        syscall=name, keys=event_keys, evidence=tuple(evidence))


def normalize_lines(lines: Iterable[str],
                    keys: set[str] | None = None) -> Iterable[BehaviorFact]:
    """Convenience for replay/tests: raw log lines straight to facts."""
    from agent_detector.monitoring.collectors.audit.parser import AuditLogParser

    parser = AuditLogParser()
    for line in lines:
        for event in parser.feed(line):
            fact = normalize_event(event, keys=keys)
            if fact is not None:
                yield fact
    for event in parser.flush():
        fact = normalize_event(event, keys=keys)
        if fact is not None:
            yield fact