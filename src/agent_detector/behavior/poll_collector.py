"""Polling collector: detect newly created processes with psutil (no privileges).

Diffing uses a light pid/name/create_time/ppid snapshot and resolves the command
line per newly-seen pid only — a full snapshot including command lines takes
seconds on Windows (measured ~7s vs ~0.06s for 366 processes), which would push
the effective sampling resolution far beyond the configured interval.

Degraded channel by design: only process starts are visible (no file
operations) and very short-lived processes can slip between samples.
"""
from __future__ import annotations

import time
from typing import Callable, Iterable

from agent_detector.behavior.audit.normalizer import BehaviorFact
from agent_detector.behavior.graph import live_process
from agent_detector.collectors.process import collect_processes
from agent_detector.domain.models import ProcessInfo

Snapshot = Callable[[], Iterable[ProcessInfo]]
Lookup = Callable[[int], ProcessInfo | None]


def _light_snapshot() -> list[ProcessInfo]:
    return collect_processes(with_cmdline=False)


class PollCollector:
    def __init__(self, snapshot: Snapshot | None = None, lookup: Lookup | None = None):
        self._snapshot = snapshot or _light_snapshot
        self._lookup = lookup if lookup is not None else live_process
        self._seen: dict[int, float | None] = {}

    def prime(self) -> int:
        """Record the current process set without emitting facts."""
        self._seen = {proc.pid: proc.create_time for proc in self._snapshot()}
        return len(self._seen)

    def poll(self) -> list[BehaviorFact]:
        if not self._seen:
            self.prime()
            return []
        now = time.time()
        facts: list[BehaviorFact] = []
        current: dict[int, float | None] = {}
        for proc in self._snapshot():
            current[proc.pid] = proc.create_time
            if proc.pid in self._seen:
                known = self._seen.get(proc.pid)
                recycled = (known is not None and proc.create_time is not None
                            and abs(known - proc.create_time) > 0.5)
                if not recycled:
                    continue
            detail = self._lookup(proc.pid) or proc
            argv = tuple(detail.cmdline)
            facts.append(BehaviorFact(
                kind="proc.exec", ts=now, serial=f"{proc.pid}-{int(now * 1000)}",
                pid=proc.pid,
                ppid=detail.ppid if detail.ppid is not None else proc.ppid,
                process_name=detail.name or proc.name,
                exe=(argv[0] if argv else None), argv=argv, result="started",
                evidence=("poll", "sampled")))
        self._seen = current
        return facts