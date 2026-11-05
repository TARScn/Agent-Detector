"""Cross-platform process and listening-socket collection via psutil (plan section 3.1)."""
import os
import platform
import re
from dataclasses import replace
from pathlib import Path

import psutil

from agent_detector.core.models import HostFacts, ListeningSocket, ProcessInfo
from agent_detector.monitoring.collectors.host.registry_snapshot import load_process_snapshot

_CMDLINE_ARGS_LIMIT = 100
_CONTAINER_ID_RE = re.compile(r"[0-9a-f]{64}")
_CREATE_TIME_TOLERANCE = 2.0


def _clean(text: str) -> str:
    """Drop lone surrogates so results stay JSON / UTF-8 serializable."""
    return text.encode("utf-8", "replace").decode("utf-8")


def _cgroup_container_id(text: str) -> str | None:
    """First 64-hex token in a /proc/<pid>/cgroup body — docker, containerd
    and k8s all embed the full container id in the cgroup path. Host-process
    cgroups (system slices, user sessions) carry none."""
    match = _CONTAINER_ID_RE.search(text)
    return match.group(0) if match else None


def _container_of(pid: int, proc_root: str = "/proc") -> str | None:
    try:
        text = (Path(proc_root) / str(pid) / "cgroup").read_text(
            encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return None
    return _cgroup_container_id(text)


def collect_processes(*, with_cmdline: bool = True,
                      with_cwd: bool = True) -> list[ProcessInfo]:
    """Read-only snapshot; inaccessible process metadata is silently skipped.

    ``with_cmdline=False`` skips command lines *and* executable paths — a full
    snapshot can take seconds on Windows (measured ~7s vs ~0.06s for 366
    processes), for callers that only diff process identities and resolve
    details per new pid.

    ``cwd`` is fetched per process in its own try-block (not via process_iter
    attrs): an AccessDenied on one elevated process must not drop the whole
    process from the snapshot — the resolver treats a missing cwd as a hint
    it can work around via cmdline/exe.
    """
    result: list[ProcessInfo] = []
    attrs = ["pid", "name", "create_time", "ppid"]
    if with_cmdline:
        attrs.insert(2, "cmdline")
        attrs.append("exe")
    proc_root = "/proc" if os.path.isdir("/proc") else None
    for proc in psutil.process_iter(attrs=attrs):
        try:
            info = proc.info
            name = _clean(info.get("name") or "")
            raw_cmdline = (info.get("cmdline") or []) if with_cmdline else []
            cmdline = tuple(_clean(arg) for arg in raw_cmdline[:_CMDLINE_ARGS_LIMIT])
            executable = _clean(info.get("exe") or "") or None if with_cmdline else None
            if not name and not cmdline and not executable:
                continue
            cwd = None
            if with_cmdline and with_cwd:
                try:
                    cwd = _clean(proc.cwd() or "")
                except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                    cwd = None
            container_id = _container_of(info["pid"]) if proc_root else None
            result.append(ProcessInfo(pid=info["pid"], name=name, cmdline=cmdline,
                                      create_time=info.get("create_time"),
                                      ppid=info.get("ppid"), exe=executable,
                                      cwd=cwd or None, container_id=container_id))
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
    return result


def collect_sockets() -> list[ListeningSocket]:
    try:
        sockets = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, OSError):
        return []
    result: list[ListeningSocket] = []
    for sock in sockets:
        if sock.status != psutil.CONN_LISTEN or not sock.laddr:
            continue
        result.append(ListeningSocket(host=sock.laddr.ip, port=sock.laddr.port, pid=sock.pid))
    return result


def _live_cwd(proc: ProcessInfo) -> str | None:
    """cwd of the live process, but only when it is still the same instance.

    The event-fed registry has no cwd for processes that started after the
    last psutil seed (Tetragon exec events do not carry it), which made a
    fresh Node/Python project unresolvable until the 15-minute reseed.
    ``create_time`` is the reuse guard: a pid that now belongs to a different
    process must not inherit the old node's directory.
    """
    if proc.create_time is None:
        return None
    try:
        live = psutil.Process(proc.pid)
        if abs(live.create_time() - proc.create_time) > _CREATE_TIME_TOLERANCE:
            return None
        cwd = _clean(live.cwd() or "")
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess,
            OSError):
        return None
    return cwd or None


def _hydrate_missing_cwd(processes) -> tuple[ProcessInfo, ...]:
    hydrated = []
    for proc in processes:
        if proc.cwd is None:
            cwd = _live_cwd(proc)
            proc = replace(proc, cwd=cwd) if cwd else proc
        hydrated.append(proc)
    return tuple(hydrated)


def collect_host_facts() -> HostFacts:
    """Host facts preferring the collector's live registry snapshot over a
    psutil one-shot. The snapshot is the running collector's event-fed
    registry (exec identities the poller cannot see); whenever it is missing,
    stale, corrupt or from another host — e.g. a standalone scan while the
    collector service is not running — this falls back to the classic psutil
    sweep, so the command line keeps working everywhere. Sockets are always
    read live; Windows psutil and the Docker channel keep their own paths.
    ``facts.process_source`` records which sweep produced the processes.

    Registry entries missing a cwd get one hydrated from the live process
    (same-instance checked) so project resolution does not have to wait for
    the collector's periodic reseed."""
    hostname = platform.node() or "localhost"
    processes = load_process_snapshot(hostname=hostname)
    source = "registry" if processes is not None else "psutil"
    if processes is None:
        processes = tuple(collect_processes())
    else:
        processes = _hydrate_missing_cwd(processes)
    return HostFacts(hostname=hostname, processes=processes,
                     sockets=tuple(collect_sockets()), process_source=source)
