"""MonitorManager: periodic outbound-connection observation (plan §3.3 Passive Monitor).

Runs inside the web process as a daemon thread; the CLI instead calls
run_once() in a synchronous loop, so there is no cross-process lifecycle
state to maintain. Every observation writes behavior_events rows with
source="netmon". Repeated (pid, host) pairs inside the suppression window are
recorded once — connection sampling cannot count individual calls, and one
event means "this call existed within the observation window", nothing more.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import replace

from sqlalchemy.orm import Session

from agent_detector.behavior.dnscache import DnsCache
from agent_detector.behavior.netmon import (NetObservation, collect_outbound, match_llm_call,
                                            resolve_process_names)
from agent_detector.behavior.rules import load_rules
from agent_detector.persistence.models import BehaviorEventRow, utc_now_iso
from agent_detector.persistence.repositories import AssetRepository

logger = logging.getLogger(__name__)


class MonitorError(RuntimeError):
    """Raised when the monitor cannot be started."""


class MonitorManager:
    def __init__(self, engine, interval: float | None = None,
                 suppress_seconds: int | None = None):
        from agent_detector.common.config import MONITOR_INTERVAL, MONITOR_SUPPRESS_SECONDS
        self.engine = engine
        self.interval = MONITOR_INTERVAL if interval is None else interval
        self.suppress_seconds = (MONITOR_SUPPRESS_SECONDS if suppress_seconds is None
                                 else suppress_seconds)
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._rules = load_rules()
        self._dns = DnsCache()
        self._last_seen: dict[tuple[int, str], float] = {}
        self.iterations = 0
        self.hits = 0
        self.started_at: str | None = None

    def start(self, interval: float | None = None,
              suppress_seconds: int | None = None) -> dict:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise MonitorError("Monitor already running")
            if interval is not None:
                self.interval = interval
            if suppress_seconds is not None:
                self.suppress_seconds = suppress_seconds
            self._stop.clear()
            self.started_at = utc_now_iso()
            self._thread = threading.Thread(target=self._run, daemon=True,
                                            name="agent-detector-monitor")
            self._thread.start()
            return self.status()

    def stop(self) -> dict:
        with self._lock:
            self._stop.set()
            if self._thread is not None:
                self._thread.join(timeout=max(5.0, self.interval * 3))
            self._thread = None
            self.started_at = None
            return self.status()

    def status(self) -> dict:
        running = self._thread is not None and self._thread.is_alive()
        return {
            "running": running,
            "interval": self.interval,
            "suppress_seconds": self.suppress_seconds,
            "started_at": self.started_at,
            "iterations": self.iterations,
            "hits": self.hits,
            "rules_errors": self._rules.errors,
            "known_llm_hosts": len(self._rules.rules.known_llm_hosts),
            "dns_cache_entries": len(self._dns.snapshot()) if self.iterations else 0,
        }

    def run_once(self) -> list[NetObservation]:
        """One observation window: collect, match, suppress, persist. Returns new events."""
        conns = collect_outbound()
        names = resolve_process_names({c.pid for c in conns})
        conns = [replace(c, process_name=names.get(c.pid, "")) for c in conns]
        dns = self._dns.snapshot()
        now = time.monotonic()
        observations: list[NetObservation] = []
        for conn in conns:
            observation = match_llm_call(conn, self._rules.rules, dns)
            if observation is None:
                continue
            key = (observation.pid, observation.host)
            last = self._last_seen.get(key)
            if last is not None and now - last < self.suppress_seconds:
                continue
            self._last_seen[key] = now
            observations.append(observation)
        if len(self._last_seen) > 2000:  # bound the suppression table
            cutoff = now - self.suppress_seconds
            self._last_seen = {k: v for k, v in self._last_seen.items() if v >= cutoff}
        if observations:
            self._write(observations)
        self.iterations += 1
        self.hits += len(observations)
        return observations

    # -- internal ----------------------------------------------------------

    def _run(self) -> None:
        while not self._stop.is_set():
            began = time.monotonic()
            try:
                self.run_once()
            except Exception:  # one bad iteration must not kill the monitor
                logger.exception("monitor iteration failed")
            elapsed = time.monotonic() - began
            self._stop.wait(max(0.2, self.interval - elapsed))

    def _write(self, observations: list[NetObservation]) -> None:
        attribution = self._asset_pids()
        rows = [self._to_row(observation, attribution.get(observation.pid))
                for observation in observations]
        with Session(self.engine) as session:
            session.add_all(rows)
            session.commit()

    @staticmethod
    def _to_row(observation: NetObservation, asset_id: str | None) -> BehaviorEventRow:
        return BehaviorEventRow(
            observed_at=utc_now_iso(),
            source="netmon",
            agent_label=observation.process_name or f"pid-{observation.pid}",
            asset_id=asset_id,
            flow_id=f"netmon-{observation.pid}-{observation.remote_ip}:{observation.remote_port}",
            upstream_host=observation.host,
            protocol="LLM",
            event_type="llm.conn",
            operation=observation.match_kind,
            confidence=observation.confidence,
            endpoint=f"{observation.remote_ip}:{observation.remote_port}",
            evidence_json=json.dumps(observation.evidence, ensure_ascii=False))

    def _asset_pids(self) -> dict[int, str]:
        """pid -> asset_id from the latest asset snapshots (empty on any failure)."""
        mapping: dict[int, str] = {}
        try:
            with Session(self.engine) as session:
                for snapshot in AssetRepository(session).latest_snapshots():
                    for pid in snapshot.get("running_pids") or []:
                        try:
                            mapping.setdefault(int(pid), snapshot["asset_id"])
                        except (TypeError, ValueError):
                            continue
        except Exception:  # attribution is best-effort; events still record
            logger.exception("asset attribution lookup failed")
        return mapping
