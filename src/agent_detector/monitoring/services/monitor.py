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
import uuid
from dataclasses import replace

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_detector.correlation import DockerPortResolver
from agent_detector.identity import (HostIdentityStore, ProcessBirth,
                                     build_process_birth)
from agent_detector.monitoring.collectors.host.dns_cache import DnsCache
from agent_detector.monitoring.collectors.host.netflow import (NetObservation, collect_outbound, match_llm_call,
                                            resolve_known_hosts, resolve_process_names)
from agent_detector.monitoring.detection.llm_intel import load_rules
from agent_detector.storage.models import (AgentInstanceRow, BehaviorEventRow,
                                           EntityAttributeRow, ProcessBirthRow,
                                           utc_now_iso)
from agent_detector.storage import EndpointRepository

logger = logging.getLogger(__name__)


class MonitorError(RuntimeError):
    """Raised when the monitor cannot be started."""


class MonitorManager:
    def __init__(self, engine, interval: float | None = None,
                 suppress_seconds: int | None = None,
                 port_resolver: DockerPortResolver | None = None):
        from agent_detector.core.config import MONITOR_INTERVAL, MONITOR_SUPPRESS_SECONDS
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
        self._sweep_interval = 300.0
        self._last_sweep = 0.0
        self.iterations = 0
        self.hits = 0
        self.started_at: str | None = None
        # P0-C: actor identity and local target endpoint resolution.
        self._scope_key = self._resolve_scope_key()
        self._birth_cache: dict[int, tuple[float, ProcessBirth | None]] = {}
        self._port_resolver = port_resolver or DockerPortResolver()

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
            self._dns.start()
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
        self._dns.close()
        return self.status()

    def close(self) -> None:
        """Release the DNS reader (CLI one-shot runs call this in finally)."""
        self._dns.close()

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
            "dns_cache_entries": self._dns.entry_count,
        }

    def run_once(self) -> list[NetObservation]:
        """One observation window: collect, match, suppress, persist. Returns new events."""
        if not self._dns.running:
            self._dns.start()  # CLI one-shot path; web start() already did this
        self._maybe_sweep(time.monotonic())
        conns = collect_outbound()
        names = resolve_process_names({c.pid for c in conns})
        conns = [replace(c, process_name=names.get(c.pid, "")) for c in conns]
        dns_hosts = self._dns.snapshot()
        pid_assets, model_ports, known_births = self._asset_lookup()
        now = time.monotonic()
        observations: list[NetObservation] = []
        for conn in conns:
            observation = match_llm_call(conn, self._rules.rules, dns_hosts,
                                         model_ports=model_ports)
            if observation is None:
                continue
            key = (observation.pid, observation.host)
            last = self._last_seen.get(key)
            if last is not None and now - last < self.suppress_seconds:
                continue
            self._last_seen[key] = now
            actor = pid_assets.get(observation.pid)
            birth = self._birth(observation.pid) if actor else None
            verified = bool(birth is not None
                            and birth.instance_key in known_births)
            if actor:
                method = "verified_instance" if verified else "pid_snapshot"
                state = "verified" if verified else "candidate"
            elif observation.target_asset_id:
                method, state = "target_scan_listen_port", "target_only"
            else:
                method, state = "unattributed", "unattributed"
            observation = replace(
                observation,
                actor_asset_id=actor,
                actor_process_key=(birth.instance_key if birth is not None
                                   else observation.actor_process_key),
                attribution_method=method,
                attribution_state=state)
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

    def _maybe_sweep(self, now: float) -> None:
        """Periodically resolve the known-LLM-host list into the retained map.

        Apps with built-in resolvers (Chromium/Electron, DoH) never populate
        the OS DNS cache, so observing only the cache would miss them.
        """
        if now - self._last_sweep < self._sweep_interval:
            return
        self._last_sweep = now
        mapping = resolve_known_hosts(self._rules.rules.known_llm_hosts)
        if mapping:
            self._dns.merge_proactive(mapping)

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
        with Session(self.engine) as session:
            endpoints = EndpointRepository(session)
            rows = [self._to_row(observation,
                                 self._target_endpoint(endpoints, observation))
                    for observation in observations]
            session.add_all(rows)
            session.commit()

    def _to_row(self, observation: NetObservation,
                target_endpoint_id: str | None) -> BehaviorEventRow:
        # UUID suffix keeps the id unique across monitor restarts; a plain
        # sequence would collide with yesterday's rows for the same 5-tuple.
        flow_id = (f"netmon-{observation.pid}-{observation.remote_ip}:"
                   f"{observation.remote_port}-{uuid.uuid4().hex[:12]}")[:64]
        evidence = list(observation.evidence)
        if target_endpoint_id:
            evidence.append("endpoint:local")
        return BehaviorEventRow(
            observed_at=utc_now_iso(),
            source="netmon",
            agent_label=observation.process_name or f"pid-{observation.pid}",
            # Legacy column keeps the actor only; a target service never goes here.
            asset_id=observation.actor_asset_id,
            actor_asset_id=observation.actor_asset_id,
            actor_entity_id=observation.actor_asset_id,
            actor_process_key=observation.actor_process_key,
            target_asset_id=observation.target_asset_id,
            target_entity_id=observation.target_asset_id,
            target_endpoint_id=target_endpoint_id,
            scope_key=self._scope_key,
            attribution_method=observation.attribution_method,
            attribution_state=observation.attribution_state,
            source_event_uid=flow_id,
            flow_id=flow_id,
            upstream_host=observation.host,
            protocol="LLM",
            event_type="llm.conn",
            operation=observation.match_kind,
            confidence=observation.confidence,
            endpoint=f"{observation.remote_ip}:{observation.remote_port}",
            evidence_json=json.dumps(evidence, ensure_ascii=False))

    def _target_endpoint(self, endpoints: EndpointRepository,
                         observation: NetObservation) -> str | None:
        """Resolve a local model destination and its published-port binding.

        Remote LLM APIs do not get a local endpoint row; the target service is
        represented by ``target_asset_id`` (scan corroboration) only.
        """
        if (observation.match_kind != "local_model"
                or not observation.target_asset_id):
            return None
        scope_key = self._scope_key or "unknown"
        host_endpoint = endpoints.upsert_endpoint(
            scope_key, "tcp", observation.remote_ip, observation.remote_port,
            namespace="host")
        binding = self._port_resolver.resolve(observation.remote_ip,
                                              observation.remote_port)
        if binding is not None:
            container_endpoint = endpoints.upsert_endpoint(
                scope_key, "tcp", "0.0.0.0", binding.container_port,
                namespace=f"container:{binding.container_id}")
            endpoints.bind(host_endpoint, container_endpoint,
                           binding.container_id,
                           source="docker_published_port")
        return host_endpoint

    def _resolve_scope_key(self) -> str | None:
        try:
            return HostIdentityStore.for_engine(self.engine).resolve().scope_key
        except Exception:  # identity failure must not kill monitoring
            logger.exception("monitor host identity lookup failed")
            return None

    def _birth(self, pid: int) -> ProcessBirth | None:
        """Cached ProcessBirth; used to verify a snapshot PID is still the same instance."""
        now = time.monotonic()
        cached = self._birth_cache.get(pid)
        if cached is not None and now - cached[0] < 30.0:
            return cached[1]
        birth = build_process_birth(pid, self._scope_key or "unknown")
        self._birth_cache[pid] = (now, birth)
        if len(self._birth_cache) > 4096:
            for stale in list(self._birth_cache)[:2048]:
                del self._birth_cache[stale]
        return birth

    def _asset_lookup(self) -> tuple[dict[int, str], dict[int, str | None],
                                     set[str]]:
        """Latest-snapshot attribution: (pid -> asset, LLM_SERVICE port -> asset,
        current process-birth keys).

        The port map corroborates loopback model-service connections; the birth
        set lets the monitor distinguish a verified process instance from a
        bare PID snapshot match.
        """
        pid_map: dict[int, str] = {}
        port_map: dict[int, str | None] = {}
        known_births: set[str] = set()
        try:
            with Session(self.engine) as session:
                for instance in session.scalars(
                        select(AgentInstanceRow).where(
                            AgentInstanceRow.status == "running")):
                    entity_id = instance.entity_id or instance.asset_id
                    if not entity_id:
                        continue
                    try:
                        pid_map.setdefault(int(instance.pid), entity_id)
                    except (TypeError, ValueError):
                        continue
                for attr in session.scalars(select(EntityAttributeRow)):
                    for port in json.loads(attr.listening_ports_json or "[]"):
                        try:
                            port_map.setdefault(int(port), attr.entity_id)
                        except (TypeError, ValueError):
                            continue
                if pid_map:
                    rows = session.scalars(
                        select(ProcessBirthRow).where(
                            ProcessBirthRow.pid.in_(list(pid_map))))
                    known_births = {row.instance_key for row in rows}
        except Exception:  # attribution is best-effort; events still record
            logger.exception("asset attribution lookup failed")
        return pid_map, port_map, known_births
