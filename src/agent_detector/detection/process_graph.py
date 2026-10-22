"""Process graph: pid ancestry lookup with PID-reuse defence.

Nodes are seeded from a psutil snapshot, updated by exec facts, and confirmed
against a live lookup for the acting process. Identity is (pid, create_time):
when the live process reports a different create_time the cached node is
discarded as a pid-reuse artefact.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Callable, Iterable

import psutil

from agent_detector.domain.models import ProcessInfo

_MAX_NODES = 4096


@dataclass(frozen=True)
class ProcNode:
    pid: int
    ppid: int | None
    name: str
    exe: str | None = None
    cmdline: tuple[str, ...] = ()
    create_time: float | None = None


def live_process(pid: int) -> ProcessInfo | None:
    """Best-effort single-pid lookup through psutil (cross-platform)."""
    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            name = proc.name()
            cmdline = tuple(proc.cmdline())
            create_time = proc.create_time()
            ppid = proc.ppid()
    except (psutil.Error, OSError):
        return None
    return ProcessInfo(pid=pid, name=name, cmdline=cmdline,
                       create_time=create_time, ppid=ppid)


def _node_from(proc: ProcessInfo) -> ProcNode:
    return ProcNode(pid=proc.pid, ppid=proc.ppid, name=proc.name,
                    exe=(proc.cmdline[0] if proc.cmdline else None),
                    cmdline=tuple(proc.cmdline), create_time=proc.create_time)


class ProcessGraph:
    def __init__(self, live_lookup: Callable[[int], ProcessInfo | None] | None = None,
                 max_nodes: int = _MAX_NODES):
        self._nodes: dict[int, ProcNode] = {}
        self._live = live_lookup or live_process
        self._max_nodes = max_nodes

    def seed(self, processes: Iterable[ProcessInfo]) -> int:
        count = 0
        for proc in processes:
            self._nodes[proc.pid] = _node_from(proc)
            count += 1
        self._prune()
        return count

    def observe_exec(self, *, pid: int, ppid: int | None, name: str,
                     exe: str | None = None, argv: tuple[str, ...] = (),
                     create_time: float | None = None) -> None:
        """Record an exec fact; exec replaces the image but keeps create_time."""
        existing = self._nodes.get(pid)
        self._nodes[pid] = ProcNode(
            pid=pid,
            ppid=ppid if ppid is not None else (existing.ppid if existing else None),
            name=name or (existing.name if existing else ""),
            exe=exe or (existing.exe if existing else None),
            cmdline=tuple(argv) or (existing.cmdline if existing else ()),
            create_time=(create_time if create_time is not None
                         else (existing.create_time if existing else None)))
        self._prune()

    def node(self, pid: int | None, *, verify: bool = False) -> ProcNode | None:
        if pid is None or pid <= 0:
            return None
        cached = self._nodes.get(pid)
        if cached is not None and not verify:
            return cached
        live = self._live(pid)
        if live is None:
            return cached
        node = _node_from(live)
        self._nodes[pid] = node
        self._prune()
        return node

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    def ancestors_of(self, pid: int, *, ppid: int | None = None,
                     max_depth: int = 12) -> list[ProcNode]:
        """``[actor, parent, ...]``; the first node is verified live, the fact's
        ppid hint (kernel-recorded) wins when it disagrees with the live value."""
        chain: list[ProcNode] = []
        current_pid: int | None = pid
        current_ppid: int | None = ppid
        seen: set[int] = set()
        while current_pid is not None and current_pid > 0 and len(chain) < max_depth:
            if current_pid in seen:
                break
            seen.add(current_pid)
            node = self.node(current_pid, verify=not chain)
            if node is None:
                if current_ppid is None:
                    break
                node = ProcNode(pid=current_pid, ppid=current_ppid, name="")
            elif current_ppid is not None and node.ppid != current_ppid:
                node = replace(node, ppid=current_ppid)
            chain.append(node)
            current_pid, current_ppid = node.ppid, None
        return chain

    def _prune(self) -> None:
        overflow = len(self._nodes) - self._max_nodes
        if overflow > 0:
            for pid in list(self._nodes)[:overflow]:
                del self._nodes[pid]