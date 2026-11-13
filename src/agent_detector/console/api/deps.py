"""Service container: one place that owns long-lived objects (§2).

The web process holds the monitor thread, the behavior ingest service (in
process) or the detached collector manager, the hook decision service (with
its policy cache) and the scan lock. Keeping them in one container makes the
dependency graph explicit and lets tests build an app around a temporary
database with ``create_app(engine=...)``.
"""
from __future__ import annotations

import logging
import platform
import threading
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy.engine import Engine

from agent_detector.core.config import (COLLECTOR_STATUS_PATH, DB_PATH,
                                        PROC_SNAPSHOT_PATH)
from agent_detector.discovery.sources.agents import LoadedMatrix, load_agent_matrix
from agent_detector.interception.policy.loader import load_policies
from agent_detector.interception.policy.decision import HookDecisionService
from agent_detector.monitoring.services.collector_process import CollectorProcessManager
from agent_detector.monitoring.services.collector_status import load_collector_status
from agent_detector.monitoring.services.ingest import (BehaviorIngestError,
                                                       BehaviorIngestService)
from agent_detector.monitoring.services.monitor import MonitorManager
from agent_detector.storage.database import make_engine
from agent_detector.storage.models import utc_now_iso

logger = logging.getLogger(__name__)


@dataclass
class ScanRun:
    """In-process scan activity, so a page reload still sees the running scan.

    The scan itself is a blocking call inside this process; ``scan_lock`` is the
    authoritative "is a scan running" signal, these fields only carry display
    metadata for the console.
    """

    started_at: str | None = None
    mode: str = "agent"


@dataclass
class Services:
    engine: Engine
    started_at: str = field(default_factory=utc_now_iso)
    scan_lock: threading.Lock = field(default_factory=threading.Lock)
    scan_run: ScanRun = field(default_factory=ScanRun)
    matrix: LoadedMatrix = field(default_factory=load_agent_matrix)
    monitor: MonitorManager | None = None
    ingest: BehaviorIngestService | None = None
    hooks: HookDecisionService | None = None
    # Detached collector child (the anti-stall default in production); tests
    # and the systemd deployment leave it None and use the in-process ingest.
    collector: CollectorProcessManager | None = None
    collector_status_path: Path = COLLECTOR_STATUS_PATH

    def __post_init__(self) -> None:
        if self.monitor is None:
            self.monitor = MonitorManager(self.engine)
        if self.ingest is None:
            self.ingest = BehaviorIngestService(self.engine)
        if self.hooks is None:
            self.hooks = HookDecisionService(self.engine)
        self.hooks.reload()  # parse policies and publish them to the DB once

    @property
    def home(self) -> Path:
        return Path.home()

    def policy_summary(self) -> dict:
        loaded = load_policies()
        return {"rules": len(loaded.rules), "errors": loaded.errors,
                "sources": loaded.sources}

    def behavior_status(self) -> dict:
        """The one behavior status the console surfaces, whichever process
        collected it.

        Answer order: the in-process ingest when it runs ("local"), the
        detached child this process manages ("collector", counters merged
        from its published status file), a foreign collector's fresh status
        file (systemd deployment, also "collector"), else the idle local
        twin. Each branch keeps the ingest status() shape so callers need no
        per-source handling beyond ``source``.
        """
        local = self.ingest.status() if self.ingest is not None else {}
        if local.get("running"):
            return {**local, "source": "local"}
        if self.collector is not None:
            managed = self.collector.status()
            if managed.get("running"):
                published = load_collector_status(
                    hostname=platform.node() or "localhost",
                    path=Path(self.collector.status_path))
                if published is not None:
                    return {**published["collector"], "source": "collector",
                            "status_age_seconds": published["age_seconds"]}
                return {**managed, "source": "collector"}
            # No child alive. A "running" file without a collector_pid was
            # written by this host's own in-process ingest of a previous
            # serve life (killed hard, never unpublished) — trusting it
            # would show a phantom collector; only a stopped/error file is
            # worth surfacing here.
            published = load_collector_status(
                hostname=platform.node() or "localhost",
                path=Path(self.collector_status_path))
            if published is not None and not published["collector"].get("running"):
                return {**published["collector"], "source": "collector",
                        "status_age_seconds": published["age_seconds"]}
            return {**local, "source": "local"}
        published = load_collector_status(
            hostname=platform.node() or "localhost",
            path=Path(self.collector_status_path))
        if published is not None:
            return {**published["collector"], "source": "collector",
                    "status_age_seconds": published["age_seconds"]}
        return {**local, "source": "local"}

    def start_behavior(self, *, mode: str | None = None, log_path=None,
                       from_start=None) -> dict:
        """Start behavior collection, preferring the detached collector child.

        Channel validation errors (409 material) come from both paths; a
        spawn failure falls back to the in-process ingest so the console
        keeps working with a degraded isolation.
        """
        if self.collector is not None:
            try:
                self.collector.start(mode=mode, log_path=log_path,
                                     from_start=from_start)
                return self.behavior_status()
            except BehaviorIngestError:
                raise
            except OSError:
                logger.exception("collector spawn failed — falling back to the "
                                 "in-process ingest")
        self.ingest.start(mode=mode, log_path=log_path, from_start=from_start)
        return self.behavior_status()

    def stop_behavior(self) -> dict:
        if self.collector is not None and self.collector.running:
            self.collector.stop()
        elif self.ingest is not None and self.ingest.running:
            self.ingest.stop()
        return self.behavior_status()

    def telemetry_context(self) -> tuple[bool, str]:
        """Whether any behaviour channel is running, and its granularity.

        Asset-level coverage is not yet derivable for every source, so the
        honest default is "global"; the UI must not present it as per-asset
        monitoring.
        """
        behavior = self.behavior_status()
        monitor = self.monitor.status() if self.monitor is not None else {}
        running = bool(behavior.get("running") or monitor.get("running"))
        return running, ("global" if running else "none")

    def shutdown(self) -> None:
        if self.monitor is not None:
            try:
                self.monitor.close()
            except Exception:  # pragma: no cover - shutdown must not raise
                pass
        if self.collector is not None:
            try:
                self.collector.stop()
            except Exception:  # pragma: no cover
                pass
        if self.ingest is not None:
            try:
                self.ingest.close()
            except Exception:  # pragma: no cover
                pass


_services: Services | None = None
_lock = threading.Lock()


def get_services() -> Services:
    """Process-wide container (the app is a single-user local console)."""
    global _services
    with _lock:
        if _services is None:
            _services = Services(
                make_engine(DB_PATH),
                collector=CollectorProcessManager(DB_PATH),
                collector_status_path=COLLECTOR_STATUS_PATH)
        return _services


def set_services(services: Services | None) -> None:
    """Test hook: install a container built on a temporary database."""
    global _services
    with _lock:
        _services = services