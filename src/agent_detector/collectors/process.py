"""Cross-platform process and listening-socket collection via psutil (plan section 3.1)."""
import platform

import psutil

from agent_detector.domain.models import HostFacts, ListeningSocket, ProcessInfo

_CMDLINE_ARGS_LIMIT = 100


def _clean(text: str) -> str:
    """Drop lone surrogates so results stay JSON / UTF-8 serializable."""
    return text.encode("utf-8", "replace").decode("utf-8")


def collect_processes() -> list[ProcessInfo]:
    """Read-only snapshot; inaccessible process metadata is silently skipped."""
    result: list[ProcessInfo] = []
    for proc in psutil.process_iter(attrs=["pid", "name", "cmdline", "create_time"]):
        try:
            info = proc.info
            name = _clean(info.get("name") or "")
            raw_cmdline = info.get("cmdline") or []
            cmdline = tuple(_clean(arg) for arg in raw_cmdline[:_CMDLINE_ARGS_LIMIT])
            if not name and not cmdline:
                continue
            result.append(ProcessInfo(pid=info["pid"], name=name, cmdline=cmdline,
                                      create_time=info.get("create_time")))
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


def collect_host_facts() -> HostFacts:
    return HostFacts(hostname=platform.node() or "localhost",
                     processes=tuple(collect_processes()),
                     sockets=tuple(collect_sockets()))
