"""Process registry: event-fed process state with PID-reuse defence.

Nodes are seeded from a psutil snapshot — the /proc backfill that runs once at
startup and again whenever the event tail goes silent (staleness recalibration)
— and then maintained purely by channel events: exec facts upsert instances and
images, exit facts evict dead ones. Identity is ``(pid, create_time)``:
``create_time`` is the process-start instant in epoch seconds (psutil's name
for it; Tetragon facts carry the same quantity as ``start_time``). When a
fact's start instant disagrees with the stored node beyond tolerance the pid
was reused and the fresh instance replaces the node — never merged.
``exec_id`` is Tetragon's kernel-side image identity: one process instance can
re-exec many images on one pid, so an exec replaces the image (exec_id, name,
argv) while the instance identity (create_time) survives.

Attribution confirms the acting process against a live psutil lookup
(``node(verify=True)``); that refresh merges into the stored node — lifecycle
fields update from the live view while event-fed identity (``exec_id``,
``container_id``) survives for the same instance, and only a reused pid
replaces the node wholesale.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Callable, Iterable

import psutil

from agent_detector.core.models import ProcessInfo

_MAX_NODES = 4096
# Kernel-ns (Tetragon) vs jiffies-derived (psutil) clock skew, seconds. Two
# start instants further apart than this on the same pid mean two processes.
_START_TIME_TOL = 2.0


@dataclass(frozen=True)
class ProcNode:
    pid: int
    ppid: int | None
    name: str
    exe: str | None = None
    cmdline: tuple[str, ...] = ()
    create_time: float | None = None
    # Working directory — snapshot-fed only (exec events carry no cwd); the
    # resolver needs it to anchor `-m`/server-entry processes on a project.
    cwd: str | None = None
    exec_id: str | None = None
    container_id: str | None = None


def _same_instance(a: float | None, b: float | None) -> bool | None:
    """True/False when both start instants are known, else None (unknown)."""
    if a is None or b is None:
        return None
    return abs(a - b) <= _START_TIME_TOL


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
                    cmdline=tuple(proc.cmdline), create_time=proc.create_time,
                    cwd=proc.cwd, container_id=proc.container_id)


class ProcessGraph:
    def __init__(self, live_lookup: Callable[[int], ProcessInfo | None] | None = None,
                 max_nodes: int = _MAX_NODES):
        self._nodes: dict[int, ProcNode] = {}
        # Recently exited instances (pid -> exec_id). Kprobe facts for a
        # process can legitimately arrive after its exit fact (export
        # batching, late connect) — without this tombstone the registry-first
        # update would resurrect the dead process on every such fact.
        self._tombstones: dict[int, str] = {}
        self._live = live_lookup or live_process
        self._max_nodes = max_nodes

    def seed(self, processes: Iterable[ProcessInfo],
             *, prune_absent: bool = False) -> int:
        """Backfill from a live snapshot. Merge semantics: a pid whose stored
        start instant matches the snapshot keeps its event-fed fields
        (exec_id, container_id, argv) — recalibration must not wipe identity
        the events established. A disagreement is PID reuse: the fresh
        snapshot instance replaces the node.

        ``prune_absent`` turns the seed into a full recalibration: pids the
        live sweep no longer sees are evicted (an exit event can be lost, and
        without this the dead instance lingers in the registry — and in the
        snapshot file scans consume). Evicted nodes with an exec_id are
        tombstoned so late facts cannot resurrect them. Startup seeds keep
        the default: an empty registry has nothing to prune, and replay
        backfills events the live host no longer runs."""
        seen: set[int] = set()
        count = 0
        for proc in processes:
            existing = self._nodes.get(proc.pid)
            self._nodes[proc.pid] = self._merge_seed(existing, _node_from(proc))
            seen.add(proc.pid)
            count += 1
        if prune_absent:
            for pid in [pid for pid in self._nodes if pid not in seen]:
                gone = self._nodes.pop(pid)
                if gone.exec_id:
                    self._record_tombstone(pid, gone.exec_id)
        self._prune()
        return count

    @staticmethod
    def _merge_seed(existing: ProcNode | None, fresh: ProcNode) -> ProcNode:
        if existing is None:
            return fresh
        same = _same_instance(existing.create_time, fresh.create_time)
        if same is False:
            return fresh  # pid reused between the events and this snapshot
        if same is True:
            # Same instance: lifecycle fields refresh from the live view,
            # event-fed identity survives the recalibration.
            return replace(existing, ppid=fresh.ppid or existing.ppid,
                           name=fresh.name or existing.name,
                           exe=fresh.exe or existing.exe,
                           cmdline=fresh.cmdline or existing.cmdline,
                           create_time=fresh.create_time or existing.create_time,
                           cwd=fresh.cwd or existing.cwd,
                           container_id=fresh.container_id or existing.container_id)
        return existing  # snapshot lacks a start instant: trust the events

    def observe_exec(self, *, pid: int, ppid: int | None, name: str,
                     exe: str | None = None, argv: tuple[str, ...] = (),
                     create_time: float | None = None,
                     exec_id: str | None = None,
                     container_id: str | None = None) -> None:
        """Record a process observation (exec fact, or a kprobe fact's acting
        process). ``create_time`` is the fact's process-start instant: when it
        disagrees with the stored node the pid was reused and the fresh
        instance replaces the node; otherwise the exec replaces the image and
        the instance (create_time) survives."""
        existing = self._nodes.get(pid)
        if _same_instance(existing.create_time if existing else None,
                          create_time) is False:
            existing = None  # PID reuse: a brand-new instance, nothing survives
        self._tombstones.pop(pid, None)  # the pid demonstrably lives again
        self._nodes[pid] = ProcNode(
            pid=pid,
            ppid=ppid if ppid is not None else (existing.ppid if existing else None),
            name=name or (existing.name if existing else ""),
            exe=exe or (existing.exe if existing else None),
            cmdline=tuple(argv) or (existing.cmdline if existing else ()),
            create_time=(create_time if create_time is not None
                         else (existing.create_time if existing else None)),
            cwd=existing.cwd if existing else None,
            exec_id=exec_id or (existing.exec_id if existing else None),
            container_id=(container_id or
                          (existing.container_id if existing else None)))
        self._prune()

    def observe_exit(self, pid: int, exec_id: str | None = None) -> bool:
        """Drop a graph node on process exit; True when a node was removed.

        Exit is lifecycle bookkeeping, not a behavior: the fact never reaches
        the rule engine or behavior_events. An exit carrying a different
        exec_id than the stored node is a late exit for a recycled pid —
        ignored so the live instance survives. Successful exits tombstone the
        (pid, exec_id) so late facts for the dead instance are recognized."""
        node = self._nodes.get(pid)
        if node is None:
            return False
        if exec_id is not None and node.exec_id is not None \
                and exec_id != node.exec_id:
            return False
        removed = self._nodes.pop(pid, None) is not None
        if removed and exec_id:
            self._record_tombstone(pid, exec_id)
        return removed

    def _record_tombstone(self, pid: int, exec_id: str) -> None:
        self._tombstones[pid] = exec_id
        if len(self._tombstones) > self._max_nodes:
            for stale in list(self._tombstones)[:self._max_nodes // 2]:
                del self._tombstones[stale]

    def retired(self, pid: int, exec_id: str | None = None) -> bool:
        """True when this fact belongs to a recently exited instance — its
        registry update must be skipped or the exit would be undone. A fact
        with a different exec_id is a NEW instance on the recycled pid: the
        tombstone clears and the registry accepts it."""
        exited = self._tombstones.get(pid)
        if exited is None:
            return False
        if exec_id is None:
            return False  # unidentifiable fact: stay permissive
        if exec_id != exited:
            del self._tombstones[pid]  # the pid lives again, new image
            return False
        return True

    def verify(self, pid: int | None, *, exec_id: str | None = None,
               start_time: float | None = None) -> bool | None:
        """Fact-vs-node identity check for attribution. True = the fact's
        identity matches the stored instance; False = a known field disagrees
        (PID-reuse artefact); None = either side lacks the field."""
        if pid is None or pid <= 0:
            return None
        node = self._nodes.get(pid)
        if node is None:
            return None
        checks = []
        same_start = _same_instance(node.create_time, start_time)
        if same_start is not None:
            checks.append(same_start)
        if exec_id is not None and node.exec_id is not None:
            checks.append(exec_id == node.exec_id)
        if not checks:
            return None
        return all(checks)

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
        if cached is not None:
            # A live refresh must not drop event-fed identity: the merge keeps
            # exec_id/container_id/cwd for the same instance, a reused pid
            # (start instant disagrees) replaces the node wholesale.
            node = self._merge_seed(cached, node)
        self._nodes[pid] = node
        self._prune()
        return node

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    def snapshot_processes(self) -> list[ProcessInfo]:
        """Registry as ProcessInfo rows — the payload for the cross-process
        snapshot file that standalone scans prefer over a psutil sweep. cwd and
        the cgroup container tag ride along so registry-sourced scans resolve
        `-m`/server entries and keep the host/container dedup working."""
        return [ProcessInfo(pid=node.pid, name=node.name, cmdline=node.cmdline,
                            create_time=node.create_time, ppid=node.ppid,
                            exe=node.exe, cwd=node.cwd,
                            container_id=node.container_id)
                for node in self._nodes.values()]

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
