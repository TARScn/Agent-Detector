import platform
import psutil
from agent_detector.models import Observation


def collect() -> list[Observation]:
    """Read-only Linux snapshot. Inaccessible process metadata is silently skipped."""
    if platform.system() != "Linux":
        raise RuntimeError("V0.1 only supports Linux hosts")
    result: list[Observation] = []
    pids: set[int] = set()
    for proc in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
        try:
            info = proc.info
            pid = info["pid"]
            pids.add(pid)
            cmd = " ".join(info.get("cmdline") or [])
            name = info.get("name") or ""
            if not name and not cmd:
                continue
            result.append(Observation("process", f"{name} {cmd}".strip(), pid=pid,
                                      details={"name": name, "cmdline": cmd[:4000]}))
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
    try:
        sockets = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, OSError):
        sockets = []
    for sock in sockets:
        if sock.status != psutil.CONN_LISTEN or not sock.laddr:
            continue
        host, port = sock.laddr.ip, sock.laddr.port
        result.append(Observation("listen", f"{host}:{port}", pid=sock.pid, port=port,
                                  host=host, details={"pid_known": sock.pid in pids}))
    return result
