"""Normalize parsed Tetragon events into BehaviorFact records.

Same contract as the audit/sysmon normalizers: facts only (what the kernel
observed), never inferences. process_exec → proc.exec, process_exit →
proc.exit (lifecycle bookkeeping — the ingest service consumes it before the
rule engine, it is not a stored behavior). TracingPolicy kprobe events map to
net.connect (security_socket_connect sockaddr) and file.write
(security_file_permission, the policy filters to MAY_WRITE); anything else
returns None rather than guessing a kind.
"""
from __future__ import annotations

from typing import Iterable

from agent_detector.core.facts import BehaviorFact
from agent_detector.monitoring.collectors.ebpf.parser import TetragonEvent, parse_event_json

# TracingPolicy hooks shipped in configs/tetragon/ (phase 3); the normalizer
# only maps functions it knows the policy emits for.
_CONNECT_FUNCTIONS = {"security_socket_connect"}
_FILE_WRITE_FUNCTIONS = {"security_file_permission"}


def fact_from_event(event: TetragonEvent) -> BehaviorFact | None:
    if event.etype == "process_exec":
        kind, result = "proc.exec", "started"
    elif event.etype == "process_exit":
        kind, result = "proc.exit", "success"
    elif event.etype == "process_kprobe":
        return _kprobe_fact(event)
    else:
        return None
    return _fact(event, kind=kind, result=result)


def _kprobe_fact(event: TetragonEvent) -> BehaviorFact | None:
    if event.function_name in _CONNECT_FUNCTIONS:
        endpoint = _sockaddr_endpoint(event)
        if endpoint is None:  # AF_UNIX / AF_NETLINK: local IPC, not recorded
            return None
        return _fact(event, kind="net.connect", result="success", endpoint=endpoint)
    if event.function_name in _FILE_WRITE_FUNCTIONS:
        # The policy already filters to MAY_WRITE; checking the mask argument
        # keeps the fact honest even on unfiltered policies. Reads stay off by
        # default (MAY_READ=4), mirroring the auditd channel.
        path = _file_path(event)
        if path is None or not _write_mask(event):
            return None
        return _fact(event, kind="file.write", result="success", path=path)
    return None


def _fact(event: TetragonEvent, *, kind: str, result: str,
          endpoint: str | None = None, path: str | None = None) -> BehaviorFact:
    evidence = ["tetragon", f"event:{event.etype}"]
    if event.function_name:
        evidence.append(f"hook:{event.function_name}")
    if event.exec_id:
        evidence.append(f"exec_id:{event.exec_id}")
    if event.container_id:
        evidence.append(f"container:{event.container_id}")
    # kprobe events share the acting process's exec_id, so the serial needs
    # event-level salt (millisecond clock) to keep flow_id unique per event.
    serial = event.exec_id or f"{event.pid}-{int(event.ts * 1000)}"
    if event.etype == "process_kprobe":
        serial = f"{event.pid}-{int(event.ts * 1000)}-{event.function_name or 'kprobe'}"
    return BehaviorFact(
        kind=kind, ts=event.ts, serial=serial,
        pid=event.pid, ppid=event.ppid,
        process_name=event.process_name,
        exe=event.exe, argv=event.argv if kind == "proc.exec" else (),
        result=result, endpoint=endpoint, path=path,
        evidence=tuple(evidence),
        container_id=event.container_id, exec_id=event.exec_id)


def _iter_args(event: TetragonEvent):
    """Yield (type, value) for kprobe args in either export shape.

    The standalone JSON export flattens args into type-suffixed keys
    ({"file_arg": {...}}, {"int_arg": 2}, {"sockaddr_arg": {...}}), while the
    k8s CRD style wraps them as {"type": ..., "value": ...}.
    """
    payload = event.raw.get("process_kprobe")
    args = payload.get("args") if isinstance(payload, dict) else None
    for arg in args if isinstance(args, list) else []:
        if not isinstance(arg, dict):
            continue
        if "type" in arg:
            yield str(arg["type"]), arg.get("value")
        else:
            for key, value in arg.items():
                yield key.removesuffix("_arg"), value


def _sockaddr_endpoint(event: TetragonEvent) -> str | None:
    """Decode a sockaddr kprobe arg; only INET/INET6 become facts."""
    for atype, value in _iter_args(event):
        if atype != "sockaddr" or not isinstance(value, dict):
            continue
        sin4 = value.get("sin4") or value.get("sin")
        if isinstance(sin4, dict) and sin4.get("addr"):
            return f"{sin4['addr']}:{sin4.get('port', 0)}"
        sin6 = value.get("sin6")
        if isinstance(sin6, dict) and sin6.get("addr"):
            return f"[{sin6['addr']}]:{sin6.get('port', 0)}"
        family = str(value.get("family") or "")
        addr = str(value.get("addr") or "")
        if family == "AF_INET" and "." in addr and addr != "invalid IP":
            return f"{addr}:{value.get('port', 0)}"
        if family == "AF_INET6" and ":" in addr and addr != "invalid IP":
            return f"[{addr}]:{value.get('port', 0)}"
    return None


def _file_path(event: TetragonEvent) -> str | None:
    for atype, value in _iter_args(event):
        if atype == "file" and isinstance(value, dict) and value.get("path"):
            return str(value["path"])
    return None


def _write_mask(event: TetragonEvent) -> bool:
    for atype, value in _iter_args(event):
        if atype == "int" and value == 2:
            return True
    return False


def normalize_lines(lines: Iterable[str | bytes]) -> Iterable[BehaviorFact]:
    """Convenience for replay/tests: raw export lines straight to facts."""
    for line in lines:
        event = parse_event_json(line)
        if event is not None:
            fact = fact_from_event(event)
            if fact is not None:
                yield fact
