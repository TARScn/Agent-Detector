"""GatewayManager: owns the mitmdump subprocess running the observing addon.

Whether the gateway runs is persisted to a small JSON state file next to the
database (pid + process create_time), so the web process and the CLI agree on
the gateway's status and either one may start or stop it. The stored
create_time guards against PID reuse. Only the fixed launch template from
build_command() may be started — no API accepts arbitrary command lines
(plan section 7 security constraint).
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

from agent_detector.common.config import (DB_PATH, GATEWAY_AGENT_LABEL,
                                          GATEWAY_OBSERVED_HOSTS, GATEWAY_PARSE_MAX_BYTES,
                                          GATEWAY_PORT)
from agent_detector.gateway import addon
from agent_detector.persistence.models import utc_now_iso

INSTALL_HINT = ('mitmproxy is not installed. Install it with: '
                'pip install "agent-detector[gateway]"')


class GatewayError(RuntimeError):
    """Raised when the gateway cannot be started or stopped."""


def build_command(mitmdump: str, listen_port: int, addon_path: Path) -> list[str]:
    return [mitmdump, "--mode", "regular", "--listen-host", "127.0.0.1",
            "--listen-port", str(listen_port), "-s", str(addon_path),
            "--set", "stream_large_bodies=64k", "--quiet"]


def build_env(db_path: Path, agent_label: str, observed_hosts: str,
              parse_max_bytes: int) -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "AGD_DB_PATH": str(db_path),
        "AGD_AGENT_ID": agent_label,
        "AGD_OBSERVED_HOSTS": observed_hosts,
        "AGD_PARSE_MAX_BYTES": str(parse_max_bytes),
    })
    return env


def _read_tail(path: Path, limit: int = 2000) -> str:
    try:
        data = path.read_bytes()[-limit:]
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace").strip()


class GatewayManager:
    def __init__(self, db_path: Path = DB_PATH, port: int = GATEWAY_PORT,
                 agent_label: str = GATEWAY_AGENT_LABEL,
                 observed_hosts: str = GATEWAY_OBSERVED_HOSTS,
                 parse_max_bytes: int = GATEWAY_PARSE_MAX_BYTES,
                 state_path: Path | None = None, log_path: Path | None = None):
        self.db_path = Path(db_path)
        self.port = port
        self.agent_label = agent_label
        self.observed_hosts = observed_hosts
        self.parse_max_bytes = parse_max_bytes
        self.state_path = Path(state_path or Path(db_path).parent / "gateway.json")
        self.log_path = Path(log_path or Path(db_path).parent / "gateway.stderr.log")
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None

    def mitmdump_path(self) -> str | None:
        return shutil.which("mitmdump")

    def start(self) -> dict:
        with self._lock:
            exe = self.mitmdump_path()
            if not exe:
                raise GatewayError(INSTALL_HINT)
            entry = self._running_entry()
            if entry:
                raise GatewayError(f"Gateway already running (pid {entry['pid']})")
            addon_path = Path(addon.__file__).resolve()
            command = build_command(exe, self.port, addon_path)
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            log = open(self.log_path, "ab")
            try:
                self._proc = subprocess.Popen(
                    command,
                    env=build_env(self.db_path, self.agent_label, self.observed_hosts,
                                  self.parse_max_bytes),
                    stdout=log, stderr=log,
                    creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP
                                   if sys.platform == "win32" else 0))
            except OSError as exc:
                log.close()
                raise GatewayError(f"Failed to launch mitmdump: {exc}") from exc
            time.sleep(0.8)
            if self._proc.poll() is not None:
                code, tail = self._proc.returncode, _read_tail(self.log_path)
                self._proc = None
                log.close()
                detail = f": {tail}" if tail else ""
                raise GatewayError(f"mitmdump exited immediately (code {code}){detail}")
            entry = {"pid": self._proc.pid,
                     "create_time": psutil.Process(self._proc.pid).create_time(),
                     "port": self.port, "agent_label": self.agent_label,
                     "started_at": utc_now_iso()}
            self.state_path.write_text(json.dumps(entry), encoding="utf-8")
            return self._status(entry)

    def stop(self, timeout: float = 8.0) -> dict:
        with self._lock:
            entry = self._running_entry()
            if not entry:
                return self._status(None)
            try:
                proc = psutil.Process(entry["pid"])
            except psutil.NoSuchProcess:
                self._clear_state()
                return self._status(None)
            if sys.platform == "win32":
                # Graceful CTRL_BREAK triggers mitmdump's shutdown hook (addon flush);
                # unavailable across consoles -> fall back to terminate.
                try:
                    proc.send_signal(signal.CTRL_BREAK_EVENT)
                except (OSError, ValueError):
                    proc.terminate()
            else:
                proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=timeout)
            except psutil.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=timeout)
            self._clear_state()
            if self._proc is not None and self._proc.poll() is not None:
                self._proc = None
            return self._status(None)

    def status(self) -> dict:
        return self._status(self._running_entry())

    # -- internal ----------------------------------------------------------

    def _running_entry(self) -> dict | None:
        try:
            entry = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        pid = entry.get("pid")
        if not isinstance(pid, int):
            return None
        try:
            proc = psutil.Process(pid)
            if abs(proc.create_time() - float(entry.get("create_time", 0))) > 1.0:
                raise psutil.NoSuchProcess(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self._clear_state()
            return None
        return entry

    def _status(self, entry: dict | None) -> dict:
        started_at = entry["started_at"] if entry else None
        uptime = None
        if started_at:
            try:
                started = datetime.fromisoformat(started_at)
                uptime = max(0, int((datetime.now(timezone.utc) - started).total_seconds()))
            except ValueError:
                uptime = None
        return {
            "available": self.mitmdump_path() is not None,
            "running": entry is not None,
            "pid": entry["pid"] if entry else None,
            "port": self.port,
            "listen": f"127.0.0.1:{self.port}",
            "agent_label": self.agent_label,
            "observed_hosts": [h.strip() for h in self.observed_hosts.split(",") if h.strip()],
            "parse_max_bytes": self.parse_max_bytes,
            "started_at": started_at,
            "uptime_s": uptime,
        }

    def _clear_state(self) -> None:
        try:
            self.state_path.unlink(missing_ok=True)
        except OSError:
            pass
