"""Normalize parsed Tetragon events into BehaviorFact records.

Same contract as the audit/sysmon normalizers: facts only (what the kernel
observed), never inferences. process_exec → proc.exec, process_exit →
proc.exit (lifecycle bookkeeping — the ingest service consumes it before the
rule engine, it is not a stored behavior). TracingPolicy events
(kprobe/tracepoint/...) map to net.connect / file.* as those policies land
in phase 3; unknown events return None rather than guessing a kind.
"""
from __future__ import annotations

from typing import Iterable

from agent_detector.core.facts import BehaviorFact
from agent_detector.monitoring.collectors.ebpf.parser import TetragonEvent, parse_event_json


def fact_from_event(event: TetragonEvent) -> BehaviorFact | None:
    if event.etype == "process_exec":
        kind, result = "proc.exec", "started"
    elif event.etype == "process_exit":
        kind, result = "proc.exit", "success"
    else:
        return None  # TracingPolicy events: mapped in the net/file phase

    evidence = ["tetragon", f"event:{event.etype}"]
    if event.exec_id:
        evidence.append(f"exec_id:{event.exec_id}")
    if event.container_id:
        evidence.append(f"container:{event.container_id}")
    return BehaviorFact(
        kind=kind, ts=event.ts, serial=event.exec_id or f"{event.pid}-{int(event.ts * 1000)}",
        pid=event.pid, ppid=event.ppid,
        process_name=event.process_name,
        exe=event.exe, argv=event.argv if kind == "proc.exec" else (),
        result=result, evidence=tuple(evidence),
        container_id=event.container_id, exec_id=event.exec_id)


def normalize_lines(lines: Iterable[str | bytes]) -> Iterable[BehaviorFact]:
    """Convenience for replay/tests: raw export lines straight to facts."""
    for line in lines:
        event = parse_event_json(line)
        if event is not None:
            fact = fact_from_event(event)
            if fact is not None:
                yield fact
