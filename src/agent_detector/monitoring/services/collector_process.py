"""Out-of-process collector management: spawn, adopt, stop the child.

The ingest pipeline is CPU-bound Python; in the console process it competes
for the GIL with the API and the console stalls under real event volume (one
burst benchmark: ``/overview`` 0.1s → 27.9s). This manager gives a
single-process host the shape the systemd deployment already has — collector
and console as separate processes sharing the WAL database and the
collector-status file:

* :meth:`start` spawns ``python -m agent_detector.monitoring.collector_runner``
  with the console's resolved paths propagated via env, and returns at once —
  readiness arrives via the status file, not this call.
* :meth:`stop` closes the child's stdin (its parent-death watchdog treats
  that as the graceful signal), then escalates to CTRL_BREAK/SIGTERM and
  finally TerminateProcess/SIGKILL.
* :meth:`status` reports the live child, including one adopted after a serve
  restart: the runner publishes its pid in the status file, and a still-live
  pid whose command line is our runner module counts as running.
"""
from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path

from agent_detector.monitoring.collectors.host.sysmon import sysmon_available
from agent_detector.core.config import (BEHAVIOR_AUDIT_LOG, COLLECTOR_STATUS_PATH,
                                        DB_PATH, PROC_SNAPSHOT_PATH,
                                        SYSMON_CHANNEL, TETRA_LOG)
from agent_detector.monitoring.services.ingest import (MODES, BehaviorIngestError,
                                                       default_mode)

logger = logging.getLogger(__name__)

RUNNER_MODULE = "agent_detector.monitoring.collector_runner"
_GRACE_SECONDS = 8.0


class CollectorProcessManager:
    def __init__(self, db_path: Path = DB_PATH, *,
                 status_path: Path = COLLECTOR_STATUS_PATH,
                 snapshot_path: Path = PROC_SNAPSHOT_PATH,
                 log_path: Path | None = None):
        self._db_path = Path(db_path)
        self.status_path = Path(status_path)
        self._snapshot_path = Path(snapshot_path)
        # Runner stdout/stderr land here: the console surfaces last_error from
        # the status file, the log keeps the traceback.
        self.log_path = log_path or (Path(db_path).parent / "collector.log")
        self._proc: subprocess.Popen | None = None
        self._mode: str | None = None
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- state
    @property
    def running(self) -> bool:
        with self._lock:
            if self._proc is not None and self._proc.poll() is None:
                return True
        return self._orphan_pid() is not None

    def status(self) -> dict:
        with self._lock:
            proc = self._proc
            mode = self._mode
        alive = proc is not None and proc.poll() is None
        pid = proc.pid if alive and proc is not None else self._orphan_pid()
        if not alive and proc is not None and proc.poll() not in (None, 0):
            # The child wrote its reason into the status file before exiting;
            # behavior_status() merges that file, this only carries the exit.
            logger.info("collector child exited with code %s", proc.returncode)
        return {"running": pid is not None, "mode": mode,
                "child_pid": pid, "status_path": str(self.status_path)}

    # ------------------------------------------------------------ lifecycle
    def start(self, *, mode: str | None = None, log_path=None,
              from_start: bool | None = None) -> dict:
        resolved = (mode or default_mode()).lower()
        if resolved not in MODES or resolved == "replay":
            raise BehaviorIngestError(f"unknown behavior mode: {mode}")
        self._preflight(resolved, log_path)
        with self._lock:
            previous = self._proc
            self._proc = None  # stop() on the old child below, outside the spawn path
        if previous is not None and previous.poll() is None:
            self._terminate(previous)
        elif previous is None:
            orphan = self._orphan_pid()
            if orphan is not None:
                self._terminate_pid(orphan)
        command = [sys.executable, "-m", RUNNER_MODULE, "--mode", resolved]
        if log_path:
            command += ["--log", str(log_path)]
        if from_start:
            command += ["--from-start"]
        env = os.environ.copy()
        env["AGENT_DETECTOR_DB"] = str(self._db_path)
        env["AGENT_DETECTOR_COLLECTOR_STATUS"] = str(self.status_path)
        env["AGENT_DETECTOR_PROC_SNAPSHOT"] = str(self._snapshot_path)
        creationflags = 0
        if sys.platform == "win32":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | \
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            log_handle = self.log_path.open("ab")
            proc = subprocess.Popen(
                command, stdin=subprocess.PIPE, stdout=log_handle,
                stderr=subprocess.STDOUT, env=env,
                creationflags=creationflags,
                start_new_session=(sys.platform != "win32"))
        except OSError:
            logger.exception("collector spawn failed")
            raise
        with self._lock:
            self._proc = proc
            self._mode = resolved
        return self.status()

    def stop(self) -> dict:
        with self._lock:
            proc = self._proc
            self._proc = None
        if proc is not None and proc.poll() is None:
            self._terminate(proc)
        else:
            orphan = self._orphan_pid()
            if orphan is not None:
                self._terminate_pid(orphan)
        return self.status()

    def close(self) -> None:
        self.stop()

    # ------------------------------------------------------------ internals
    def _preflight(self, mode: str, log_path) -> None:
        """Same contract as the in-process ingest: a broken channel is a 409
        before anything is spawned or stopped."""
        if mode in ("replay", "poll"):
            return
        if mode == "sysmon":
            probe = sysmon_available(SYSMON_CHANNEL)
            if not probe.available:
                raise BehaviorIngestError(
                    f"Sysmon 通道不可用：{probe.reason or '未安装'}")
            return
        path = Path(log_path) if log_path else (
            TETRA_LOG if mode == "tetragon" else BEHAVIOR_AUDIT_LOG)
        try:
            with path.open("r", encoding="utf-8", errors="replace"):
                pass
        except OSError as exc:
            target = "Tetragon export" if mode == "tetragon" else "audit log"
            raise BehaviorIngestError(f"cannot read {target} {path}: {exc}") from exc

    def _terminate(self, proc: subprocess.Popen) -> None:
        """Graceful first: the runner's stdin EOF triggers a clean shutdown."""
        try:
            if proc.stdin is not None:
                proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=_GRACE_SECONDS)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            if sys.platform == "win32":
                proc.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                proc.send_signal(signal.SIGTERM)
        except (OSError, ProcessLookupError):
            pass
        try:
            proc.wait(timeout=4.0)
            return
        except subprocess.TimeoutExpired:
            pass
        proc.kill()
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:  # pragma: no cover - kill is final
            logger.error("collector child %s refused to die", proc.pid)

    def _terminate_pid(self, pid: int) -> None:
        """Best-effort stop of an adopted orphan (no stdin pipe to close)."""
        import psutil

        try:
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=_GRACE_SECONDS)
        except (psutil.NoSuchProcess, psutil.TimeoutExpired):
            pass

    def _orphan_pid(self) -> int | None:
        """A collector child from a previous serve life: status file says
        running and the published pid is alive as our runner module."""
        try:
            import json

            raw = json.loads(self.status_path.read_text(encoding="utf-8"))
            pid = raw.get("collector", {}).get("collector_pid")
            if not pid or not raw.get("collector", {}).get("running"):
                return None
            import psutil

            proc = psutil.Process(int(pid))
            cmdline = " ".join(proc.cmdline())
            if RUNNER_MODULE in cmdline:
                return int(pid)
        except FileNotFoundError:
            return None
        except Exception:  # corrupt file, vanished process, permission — never raise
            logger.debug("orphan collector check failed", exc_info=True)
        return None
