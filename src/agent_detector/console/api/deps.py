"""Service container: one place that owns long-lived objects (§2).

The web process holds the monitor thread, the behavior ingest service, the hook
decision service (with its policy cache) and the scan lock. Keeping them in one
container makes the dependency graph explicit and lets tests build an app around
a temporary database with ``create_app(engine=...)``.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy.engine import Engine

from agent_detector.core.config import DB_PATH
from agent_detector.discovery.sources.agents import LoadedMatrix, load_agent_matrix
from agent_detector.interception.policy.loader import load_policies
from agent_detector.interception.policy.decision import HookDecisionService
from agent_detector.monitoring.services.ingest import BehaviorIngestService
from agent_detector.monitoring.services.monitor import MonitorManager
from agent_detector.storage.database import make_engine
from agent_detector.storage.models import utc_now_iso


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

    def telemetry_context(self) -> tuple[bool, str]:
        """Whether any behaviour channel is running, and its granularity.

        Asset-level coverage is not yet derivable for every source, so the
        honest default is "global"; the UI must not present it as per-asset
        monitoring.
        """
        behavior = self.ingest.status() if self.ingest is not None else {}
        monitor = self.monitor.status() if self.monitor is not None else {}
        running = bool(behavior.get("running") or monitor.get("running"))
        return running, ("global" if running else "none")

    def shutdown(self) -> None:
        if self.monitor is not None:
            try:
                self.monitor.close()
            except Exception:  # pragma: no cover - shutdown must not raise
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
            _services = Services(make_engine(DB_PATH))
        return _services


def set_services(services: Services | None) -> None:
    """Test hook: install a container built on a temporary database."""
    global _services
    with _lock:
        _services = services