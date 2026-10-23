"""System behavior ingest: Sysmon / auditd tail / replay / psutil polling.

One pipeline, four collectors. Per batch: collect facts → grade risk → derive
the high-level behavior (rule engine) → attribute to an Agent (process graph +
fingerprints) → suppression → store into behavior_events, raising an alert when
the grade crosses the configured bar (design sections 4.1, 6.1).

Semantics: one row means "this behavior was observed within the suppression
window" — it is not an exact call count. Content is never stored; the path/argv
policy is applied at this boundary.
"""
from __future__ import annotations

import hashlib
import json
import logging
import platform
import posixpath
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from sqlalchemy.orm import Session

from agent_detector.monitoring.detection.attribution import AgentAttributor, Attribution
from agent_detector.monitoring.collectors.audit.normalizer import BehaviorFact, normalize_event
from agent_detector.monitoring.collectors.audit.parser import AuditEvent, AuditLogParser
from agent_detector.monitoring.collectors.audit.reader import ReplayReader, TailReader
from agent_detector.monitoring.detection.behavior_rules import (DerivedBehavior, load_behavior_rules,
                                                    match_fact)
from agent_detector.monitoring.detection.process_graph import ProcessGraph
from agent_detector.monitoring.services.retention import purge_behavior_events
from agent_detector.monitoring.collectors.host.poll import PollCollector
from agent_detector.monitoring.collectors.host.sysmon import (DEFAULT_CHANNEL as SYSMON_DEFAULT_CHANNEL,
                                              SysmonReader, fact_from_event,
                                              sysmon_available)
from agent_detector.monitoring.detection.risk import grade as grade_risk
from agent_detector.core.config import (ALERT_RISK_LEVEL, BEHAVIOR_AUDIT_KEYS,
                                          BEHAVIOR_AUDIT_LOG,
                                          BEHAVIOR_INCLUDE_UNATTRIBUTED,
                                          BEHAVIOR_MAX_EVENTS_PER_MINUTE,
                                          BEHAVIOR_PATH_POLICY, BEHAVIOR_POLL_INTERVAL,
                                          BEHAVIOR_RETENTION_DAYS, BEHAVIOR_STORE_ARGV,
                                          BEHAVIOR_SUPPRESS_SECONDS, SYSMON_CHANNEL)
from agent_detector.core.security import redact
from agent_detector.monitoring.collectors.host.process import collect_processes
from agent_detector.core.enums import RiskLevel
from agent_detector.core.models import ProcessInfo
from agent_detector.discovery.fingerprints.loader import load_rules
from agent_detector.storage.models import BehaviorEventRow, utc_now_iso
from agent_detector.interception.policy.engine import risk_at_least
from agent_detector.storage import AlertRepository, AssetRepository

logger = logging.getLogger(__name__)

MODES = ("sysmon", "auditd", "poll", "replay")
_SUPPRESSION_CACHE_LIMIT = 4000
_EVIDENCE_ARGV_LIMIT = 400


class BehaviorIngestError(RuntimeError):
    """Raised when the ingest service cannot be started."""


def default_mode() -> str:
    """Best channel for this host: Sysmon on Windows, auditd on Linux, else poll.

    Sysmon is only chosen when its event channel is actually readable; claiming
    the channel without it would silently produce an empty feed.
    """
    if platform.system() == "Windows":
        return "sysmon" if sysmon_available(SYSMON_CHANNEL).available else "poll"
    if platform.system() == "Linux":
        return "auditd"
    return "poll"


class BehaviorIngestService:
    def __init__(self, engine, *, mode: str | None = None, log_path=None,
                 keys: Iterable[str] | None = None, interval: float | None = None,
                 suppress_seconds: int | None = None, rules_dir=None,
                 from_start: bool = False,
                 process_snapshot: Callable[[], Iterable[ProcessInfo]] | None = None,
                 process_lookup: Callable[[int], ProcessInfo | None] | None = None,
                 graph: ProcessGraph | None = None):
        self.engine = engine
        self.mode = (mode or default_mode()).lower()
        if self.mode not in MODES:
            raise BehaviorIngestError(f"unknown behavior mode: {mode}")
        self.log_path = Path(log_path) if log_path else Path(BEHAVIOR_AUDIT_LOG)
        self.sysmon_channel = SYSMON_CHANNEL
        self.keys = tuple(keys) if keys else BEHAVIOR_AUDIT_KEYS
        self.interval = interval or BEHAVIOR_POLL_INTERVAL
        self.suppress_seconds = (BEHAVIOR_SUPPRESS_SECONDS if suppress_seconds is None
                                 else max(int(suppress_seconds), 0))
        self._from_start = from_start
        self._snapshot_provider = process_snapshot or collect_processes
        self._process_lookup = process_lookup
        self.graph = graph or ProcessGraph()
        loaded = load_behavior_rules(rules_dir)
        self.loaded_rules = loaded
        fingerprint_rules = load_rules()
        self._client_rules = fingerprint_rules.client_rules
        self._signature_rules = fingerprint_rules.signature_rules
        self._rule_errors = list(loaded.errors) + list(fingerprint_rules.errors)

        self._parser = AuditLogParser()
        self._reader: TailReader | None = None
        self._sysmon: SysmonReader | None = None
        self._poll: PollCollector | None = None
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._last_seen: dict[tuple[str, str, str], float] = {}
        self._recent: list[float] = []
        self._last_purge = 0.0

        self.started_at: str | None = None
        self.batches = 0
        self.records_read = 0
        self.facts_seen = 0
        self.events_stored = 0
        self.suppressed = 0
        self.dropped_no_rule = 0
        self.dropped_unattributed = 0
        self.dropped_rate = 0
        self.alerts_raised = 0
        self.last_error: str | None = None

    # ------------------------------------------------------------------ state
    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def source(self) -> str:
        return {"poll": "poll", "sysmon": "sysmon"}.get(self.mode, "auditd")

    def status(self) -> dict:
        return {
            "running": self.running, "mode": self.mode,
            "log_path": str(self.log_path) if self.mode in ("auditd", "replay") else None,
            "log_readable": self._log_readable(),
            "sysmon_channel": self.sysmon_channel if self.mode == "sysmon" else None,
            "sysmon": self._sysmon.status() if self._sysmon else
                      sysmon_available(self.sysmon_channel).to_dict(),
            "alert_risk_level": ALERT_RISK_LEVEL,
            "alerts_raised": self.alerts_raised,
            "keys": list(self.keys), "interval": self.interval,
            "suppress_seconds": self.suppress_seconds,
            "path_policy": BEHAVIOR_PATH_POLICY, "store_argv": BEHAVIOR_STORE_ARGV,
            "include_unattributed": BEHAVIOR_INCLUDE_UNATTRIBUTED,
            "retention_days": BEHAVIOR_RETENTION_DAYS,
            "started_at": self.started_at, "batches": self.batches,
            "records_read": self.records_read, "facts": self.facts_seen,
            "events": self.events_stored, "suppressed": self.suppressed,
            "dropped_no_rule": self.dropped_no_rule,
            "dropped_unattributed": self.dropped_unattributed,
            "dropped_rate": self.dropped_rate,
            "rule_count": len(self.loaded_rules.rules.rules),
            "rules_errors": self._rule_errors,
            "graph_nodes": self.graph.node_count,
            "last_error": self.last_error,
        }

    # -------------------------------------------------------------- lifecycle
    def start(self, *, mode: str | None = None, log_path=None,
              from_start: bool | None = None) -> dict:
        with self._lock:
            if self.running:
                raise BehaviorIngestError("behavior ingest already running")
            if mode:
                mode = mode.lower()
                if mode not in MODES or mode == "replay":
                    raise BehaviorIngestError(f"unknown behavior mode: {mode}")
                self.mode = mode
            if log_path:
                self.log_path = Path(log_path)
            if from_start is not None:
                self._from_start = from_start
            self._ensure_ready()
            self._stop.clear()
            self.started_at = utc_now_iso()
            self._maybe_purge(time.monotonic(), force=True)
            self._thread = threading.Thread(target=self._run,
                                            name="agent-detector-behavior", daemon=True)
            self._thread.start()
        return self.status()

    def stop(self) -> dict:
        with self._lock:
            self._stop.set()
            thread = self._thread
            self._thread = None
        if thread is not None:
            thread.join(timeout=max(5.0, self.interval * 3))
        if self._reader is not None:
            self._reader.close()
        if self._sysmon is not None:
            self._sysmon.close()
        self.started_at = None
        return self.status()

    def close(self) -> None:
        if self._reader is not None:
            self._reader.close()

    def _ensure_ready(self) -> None:
        if self.mode == "replay":
            return
        if self.mode == "sysmon":
            if self._sysmon is None:
                self._sysmon = SysmonReader(self.sysmon_channel,
                                            start_from_oldest=self._from_start)
                try:
                    self._sysmon.start()
                except RuntimeError as exc:
                    self._sysmon = None
                    raise BehaviorIngestError(
                        f"Sysmon 通道不可用：{exc}。请先安装 Sysmon 并按 "
                        f"configs/sysmon.xml 启用所需事件（Event ID 3 默认关闭）。") from exc
                self._seed_graph()
            return
        if self.mode == "poll":
            if self._poll is None:
                if self._process_lookup is None:
                    self._poll = PollCollector(self._snapshot_provider)
                else:
                    self._poll = PollCollector(self._snapshot_provider,
                                               lookup=self._process_lookup)
                self._seed_graph()
                self._poll.prime()
            return
        if self._reader is None:
            try:
                with self.log_path.open("r", encoding="utf-8", errors="replace"):
                    pass
            except OSError as exc:
                raise BehaviorIngestError(self._log_hint(exc)) from exc
            self._reader = TailReader(self.log_path, from_start=self._from_start)
            self._seed_graph()

    def _log_hint(self, exc: OSError) -> str:
        return (f"cannot read audit log {self.log_path}: {exc}. auditd logs are "
                "usually root-only: run the collector as root, or set log_group in "
                "/etc/audit/auditd.conf to a group this user belongs to.")

    def _seed_graph(self) -> None:
        try:
            self.graph.seed(self._snapshot_provider())
        except Exception:
            logger.exception("process snapshot seeding failed")

    def _log_readable(self) -> bool:
        try:
            with self.log_path.open("r", encoding="utf-8", errors="replace"):
                return True
        except OSError:
            return False

    # ------------------------------------------------------------------- loop
    def _run(self) -> None:
        while not self._stop.is_set():
            began = time.monotonic()
            try:
                self.run_once()
            except Exception as exc:  # isolate one bad batch
                self.last_error = f"{type(exc).__name__}: {exc}"
                logger.exception("behavior ingest batch failed")
            elapsed = time.monotonic() - began
            wait = max(0.2, self.interval - elapsed) if self.mode == "poll" else 0.5
            self._stop.wait(wait)

    def run_once(self) -> list[dict]:
        """One batch; returns the events stored in this round."""
        self._ensure_ready()
        facts = self._collect_facts()
        if facts:
            self.facts_seen += len(facts)
        stored = self._process_facts(facts)
        self.batches += 1
        self._maybe_purge(time.monotonic())
        return stored

    def run_replay(self, path) -> dict:
        """One-shot processing of a saved audit log (works on any platform)."""
        with self._lock:
            if self.running:
                raise BehaviorIngestError("stop the running ingest before replay")
            previous_mode = self.mode
            self.mode = "replay"
        try:
            # Ancestry for agents that started before the captured window comes
            # from the live process snapshot; agents that exec inside the log are
            # picked up from the facts themselves.
            self._seed_graph()
            parser = AuditLogParser()
            keys = set(self.keys)
            facts: list[BehaviorFact] = []
            for line in ReplayReader(path).lines():
                self.records_read += 1
                for event in parser.feed(line):
                    fact = normalize_event(event, keys=keys)
                    if fact is not None:
                        facts.append(fact)
            for event in parser.flush():
                fact = normalize_event(event, keys=keys)
                if fact is not None:
                    facts.append(fact)
            self.facts_seen += len(facts)
            stored = self._process_facts(facts)
            self.batches += 1
        finally:
            with self._lock:
                self.mode = previous_mode
        return {"log_path": str(path), "facts": len(facts), "events": len(stored),
                "items": stored}

    # ---------------------------------------------------------------- collect
    def _collect_facts(self) -> list[BehaviorFact]:
        if self.mode == "poll":
            return self._poll.poll() if self._poll is not None else []
        if self.mode == "sysmon":
            if self._sysmon is None:
                return []
            facts: list[BehaviorFact] = []
            for event in self._sysmon.poll():
                self.records_read += 1
                fact = fact_from_event(event)
                if fact is not None:
                    facts.append(fact)
            return facts
        if self.mode == "replay" or self._reader is None:
            return []
        facts: list[BehaviorFact] = []
        keys = set(self.keys)
        for line in self._reader.poll():
            self.records_read += 1
            for event in self._parser.feed(line):
                facts.extend(self._facts_from(event, keys))
        return facts

    @staticmethod
    def _facts_from(event: AuditEvent, keys: set[str]) -> list[BehaviorFact]:
        fact = normalize_event(event, keys=keys)
        return [fact] if fact is not None else []

    # ---------------------------------------------------------------- process
    def _process_facts(self, facts: list[BehaviorFact]) -> list[dict]:
        if not facts:
            return []
        rules = self.loaded_rules.rules
        attributor = self._attributor_context()
        rows: list[BehaviorEventRow] = []
        stored: list[dict] = []
        now = time.monotonic()
        for fact in facts:
            derived = match_fact(fact, rules)
            if derived is None:
                self.dropped_no_rule += 1
                continue
            if fact.kind == "proc.exec":
                self.graph.observe_exec(pid=fact.pid, ppid=fact.ppid,
                                        name=fact.process_name, exe=fact.exe,
                                        argv=fact.argv)
            attribution = attributor.attribute(pid=fact.pid, ppid=fact.ppid,
                                               process_name=fact.process_name)
            if (attribution.asset_id is None and not BEHAVIOR_INCLUDE_UNATTRIBUTED
                    and "unattributed" in attribution.evidence):
                self.dropped_unattributed += 1
                continue
            target = self._target_for(fact, derived)
            key = (attribution.agent_label, derived.operation, target or "")
            last = self._last_seen.get(key)
            if last is not None and now - last < self.suppress_seconds:
                self.suppressed += 1
                continue
            self._last_seen[key] = now
            if not self._rate_ok(now):
                self.dropped_rate += 1
                continue
            risk, risk_reasons = grade_risk(fact.kind, operation=derived.operation,
                                            target=target)
            rows.append(self._to_row(fact, derived, attribution, target,
                                     risk, risk_reasons))
            stored.append(self._event_dict(fact, derived, attribution, target,
                                           risk, risk_reasons, self.source))
        if rows:
            self._write(rows)
            self.events_stored += len(rows)
            self._maybe_alert(stored)
        self._prune_suppression(now)
        return stored

    def _attributor_context(self) -> AgentAttributor:
        pid_map: dict[int, str] = {}
        known: set[str] = set()
        try:
            with Session(self.engine) as session:
                for snapshot in AssetRepository(session).latest_snapshots():
                    asset_id = snapshot["asset_id"]
                    known.add(asset_id)
                    for pid in snapshot.get("running_pids") or []:
                        try:
                            pid_map.setdefault(int(pid), asset_id)
                        except (TypeError, ValueError):
                            continue
        except Exception:
            logger.exception("asset attribution lookup failed")
        return AgentAttributor(hostname=platform.node() or "localhost", graph=self.graph,
                               pid_map=pid_map, known_asset_ids=known,
                               client_rules=self._client_rules,
                               signature_rules=self._signature_rules,
                               home=Path.home())

    def _target_for(self, fact: BehaviorFact, derived: DerivedBehavior) -> str | None:
        if fact.kind == "file.move" and fact.path and fact.path_target:
            return f"{self._policy_path(fact.path)} -> {self._policy_path(fact.path_target)}"
        if fact.path:
            return self._policy_path(fact.path)
        if derived.target:
            return derived.target
        if fact.endpoint:
            return fact.endpoint
        return None

    @staticmethod
    def _policy_path(path: str) -> str:
        if BEHAVIOR_PATH_POLICY != "basename":
            return path
        base = posixpath.basename(path.rstrip("/")) or path
        digest = hashlib.sha256(
            posixpath.dirname(path).encode("utf-8", "replace")).hexdigest()
        return f"{base}#{digest[:12]}"

    def _rate_ok(self, now: float) -> bool:
        if BEHAVIOR_MAX_EVENTS_PER_MINUTE <= 0:
            return True
        while self._recent and now - self._recent[0] > 60.0:
            self._recent.pop(0)
        if len(self._recent) >= BEHAVIOR_MAX_EVENTS_PER_MINUTE:
            return False
        self._recent.append(now)
        return True

    def _prune_suppression(self, now: float) -> None:
        if len(self._last_seen) <= _SUPPRESSION_CACHE_LIMIT:
            return
        cutoff = now - max(self.suppress_seconds, 1)
        self._last_seen = {key: seen for key, seen in self._last_seen.items()
                           if seen >= cutoff}

    def _maybe_purge(self, now: float, *, force: bool = False) -> None:
        if BEHAVIOR_RETENTION_DAYS <= 0:
            return
        if not force and now - self._last_purge < 86400.0:
            return
        self._last_purge = now
        try:
            purge_behavior_events(self.engine, BEHAVIOR_RETENTION_DAYS,
                                  source=self.source)
        except Exception:
            logger.exception("behavior retention purge failed")

    # ---------------------------------------------------------------- persist
    def _to_row(self, fact: BehaviorFact, derived: DerivedBehavior,
                attribution: Attribution, target: str | None,
                risk: RiskLevel, risk_reasons: list[str]) -> BehaviorEventRow:
        source = self.source
        return BehaviorEventRow(
            observed_at=self._observed_at(fact), source=source,
            agent_label=(attribution.agent_label or f"pid-{fact.pid}")[:80],
            asset_id=attribution.asset_id,
            flow_id=f"{source}-{fact.serial}"[:64],
            upstream_host="", protocol="SYS",
            event_type=fact.kind, operation=derived.operation,
            confidence=derived.confidence,
            endpoint=(fact.endpoint or "")[:150],
            evidence_json=json.dumps(self._evidence(fact, derived, attribution,
                                                    risk_reasons),
                                     ensure_ascii=False),
            pid=fact.pid, ppid=fact.ppid,
            process_name=(fact.process_name or "")[:80] or None,
            target=(target or "")[:512] or None, result=fact.result,
            risk_level=risk.value, decision="audit",
            execution_status=("succeeded" if fact.result == "success" else "failed"))

    @staticmethod
    def _evidence(fact: BehaviorFact, derived: DerivedBehavior,
                  attribution: Attribution,
                  risk_reasons: list[str] | None = None) -> list[str]:
        evidence = list(fact.evidence)
        evidence.append(f"rule:{derived.rule_id}")
        evidence.extend(attribution.evidence)
        evidence.extend(f"risk:{reason}" for reason in (risk_reasons or []))
        if derived.detail:
            evidence.append(f"detail:{derived.detail}")
        if BEHAVIOR_STORE_ARGV and fact.argv:
            evidence.append("argv:" + redact(" ".join(fact.argv))[:_EVIDENCE_ARGV_LIMIT])
        return evidence

    @staticmethod
    def _event_dict(fact: BehaviorFact, derived: DerivedBehavior,
                    attribution: Attribution, target: str | None,
                    risk: RiskLevel, risk_reasons: list[str],
                    source: str = "auditd") -> dict:
        return {"observed_at": BehaviorIngestService._observed_at(fact),
                "source": "sysmon" if source == "sysmon" else source,
                "agent_label": attribution.agent_label or f"pid-{fact.pid}",
                "asset_id": attribution.asset_id, "pid": fact.pid,
                "process_name": fact.process_name, "event_type": fact.kind,
                "operation": derived.operation, "target": target,
                "result": fact.result, "confidence": derived.confidence,
                "risk_level": risk.value, "risk_reasons": list(risk_reasons)}

    @staticmethod
    def _observed_at(fact: BehaviorFact) -> str:
        if fact.ts > 0:
            try:
                return datetime.fromtimestamp(fact.ts, tz=timezone.utc).isoformat(
                    timespec="seconds")
            except (OverflowError, OSError, ValueError):
                pass
        return utc_now_iso()

    def _maybe_alert(self, stored: list[dict]) -> None:
        """Raise one alert per event at or above the configured risk bar.

        Reads the plain event dicts, not the ORM rows: those are detached once
        the batch commits. Only the graded risk decides this; a denied tool call
        is alerted by the hook path instead (services/hooks.py), so the two
        feeds never double-report the same call.
        """
        candidates = [item for item in stored
                      if risk_at_least(item.get("risk_level", ""), ALERT_RISK_LEVEL)]
        if not candidates:
            return
        try:
            with Session(self.engine) as session:
                repo = AlertRepository(session)
                for item in candidates:
                    repo.raise_alert(
                        title=f"{item['agent_label']} · {item['operation']}",
                        reason=f"系统行为风险分级 {item['risk_level']}",
                        risk_level=item["risk_level"], decision="audit",
                        asset_id=item.get("asset_id"),
                        agent_label=item["agent_label"], agent_type=None,
                        detail={"source": item.get("source"),
                                "event_type": item.get("event_type"),
                                "target": item.get("target"),
                                "risk_reasons": item.get("risk_reasons", [])})
                session.commit()
            self.alerts_raised += len(candidates)
        except Exception:
            logger.exception("alert raising failed")

    def _write(self, rows: list[BehaviorEventRow]) -> None:
        with Session(self.engine) as session:
            session.add_all(rows)
            session.commit()