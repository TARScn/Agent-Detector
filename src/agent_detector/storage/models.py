"""SQLAlchemy entities for scan tasks, assets, snapshots and evidence (plan section 5.2).

Timestamps are stored as ISO-8601 UTC strings: SQLite has no native timezone
handling, and an explicit format avoids naive/aware ambiguity.
"""
from datetime import datetime, timezone

from sqlalchemy import Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Base(DeclarativeBase):
    pass


class ScanTaskRow(Base):
    __tablename__ = "scan_tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mode: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="running")
    started_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)
    finished_at: Mapped[str | None] = mapped_column(String(48))
    stats_json: Mapped[str] = mapped_column(Text, default="{}")


class AssetRow(Base):
    """Stable asset identity across scans (plan section 5.3)."""

    __tablename__ = "assets"

    asset_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    asset_type: Mapped[str] = mapped_column(String(32))
    first_seen_at: Mapped[str] = mapped_column(String(48))
    last_seen_at: Mapped[str] = mapped_column(String(48))


class AssetSnapshotRow(Base):
    __tablename__ = "asset_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_tasks.id"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.asset_id"), index=True)
    states_json: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float)
    version: Mapped[str] = mapped_column(String(64))
    version_source: Mapped[str] = mapped_column(String(32))
    running_pids_json: Mapped[str] = mapped_column(Text, default="[]")
    listening_ports_json: Mapped[str] = mapped_column(Text, default="[]")
    detector: Mapped[str] = mapped_column(String(64))


class EvidenceRow(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_tasks.id"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.asset_id"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    summary: Mapped[str] = mapped_column(Text)
    detail_json: Mapped[str] = mapped_column(Text, default="{}")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    created_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)


class BehaviorEventRow(Base):
    """Unified behavior/telemetry event feed (design section 7).

    One table, many channels: ``source`` says which observer wrote the row
    (``netmon`` outbound LLM connections, ``auditd``/``poll`` Linux system
    behavior, ``sysmon`` Windows process/file/network events, ``native_hook``
    Agent tool calls). A row carries *evidence*, never conversation content or
    file bodies; ``asset_id`` stays empty when nothing could be proven.
    """

    __tablename__ = "behavior_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    observed_at: Mapped[str] = mapped_column(String(48), index=True)
    source: Mapped[str] = mapped_column(String(32), default="netmon")
    agent_label: Mapped[str] = mapped_column(String(80), index=True)
    asset_id: Mapped[str | None] = mapped_column(String(96))
    flow_id: Mapped[str] = mapped_column(String(64))
    upstream_host: Mapped[str] = mapped_column(String(255))
    protocol: Mapped[str] = mapped_column(String(16), index=True)
    event_type: Mapped[str] = mapped_column(String(48))
    operation: Mapped[str] = mapped_column(String(100))
    confidence: Mapped[str] = mapped_column(String(16))
    endpoint: Mapped[str] = mapped_column(String(150))
    protocol_version: Mapped[str | None] = mapped_column(String(30))
    component_version: Mapped[str | None] = mapped_column(String(30))
    model: Mapped[str | None] = mapped_column(String(90))
    tool: Mapped[str | None] = mapped_column(String(90))
    http_status: Mapped[int | None] = mapped_column(Integer)
    # System behavior columns (added after V0.1 shipped; see database.ensure_schema):
    pid: Mapped[int | None] = mapped_column(Integer)
    ppid: Mapped[int | None] = mapped_column(Integer)
    process_name: Mapped[str | None] = mapped_column(String(80))
    target: Mapped[str | None] = mapped_column(String(512))
    result: Mapped[str | None] = mapped_column(String(24))
    evidence_json: Mapped[str] = mapped_column(Text, default="[]")
    # V0.2 columns: correlation identity and pre-execution decision.
    instance_id: Mapped[str | None] = mapped_column(String(96))
    session_id: Mapped[str | None] = mapped_column(String(96), index=True)
    process_guid: Mapped[str | None] = mapped_column(String(96))
    risk_level: Mapped[str | None] = mapped_column(String(16), index=True)
    decision: Mapped[str | None] = mapped_column(String(16))
    execution_status: Mapped[str | None] = mapped_column(String(24))
    policy_id: Mapped[str | None] = mapped_column(String(64))


class AgentAssetRow(Base):
    """Logical Agent asset (design section 3.4): one row per discovered Agent.

    Shares ``assets.asset_id`` with the discovery snapshot tables so the
    detector stays the single source of identity; this table adds what the
    dashboard needs — capability matrix, hook state and protection status.
    """

    __tablename__ = "agent_assets"

    asset_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    agent_type: Mapped[str] = mapped_column(String(48), index=True)
    name: Mapped[str] = mapped_column(String(120))
    vendor: Mapped[str] = mapped_column(String(80), default="")
    version: Mapped[str] = mapped_column(String(64), default="UNKNOWN")
    version_source: Mapped[str] = mapped_column(String(32), default="unknown")
    states_json: Mapped[str] = mapped_column(Text, default="[]")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    executable: Mapped[str | None] = mapped_column(String(512))
    config_paths_json: Mapped[str] = mapped_column(Text, default="[]")
    mcp_servers_json: Mapped[str] = mapped_column(Text, default="[]")
    llm_endpoints_json: Mapped[str] = mapped_column(Text, default="[]")
    app_id: Mapped[str | None] = mapped_column(String(96))
    # Post-scan verification (design §6.3): active = seen in the latest scan,
    # inactive = self-built whose project dir still exists but no live process,
    # removed = re-verified gone (uninstalled / path deleted / sighting over).
    status: Mapped[str] = mapped_column(String(24), default="active")
    capabilities_json: Mapped[str] = mapped_column(Text, default="{}")
    protection_status: Mapped[str] = mapped_column(String(24), default="UNKNOWN")
    hook_state: Mapped[str] = mapped_column(String(24), default="UNKNOWN")
    hook_detail_json: Mapped[str] = mapped_column(Text, default="{}")
    notes_json: Mapped[str] = mapped_column(Text, default="[]")
    first_seen_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)
    last_seen_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)


class ApplicationRow(Base):
    """Self-built agent application (design §6.3): one resolved project directory.

    The Application sits between Host and Agent: one process runs one app, the
    app may embed several frameworks. ``app_id`` is shared with the discovery
    snapshot tables by convention (like agent_assets.asset_id), no SQL FK.
    """

    __tablename__ = "applications"

    app_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    root_path: Mapped[str] = mapped_column(String(512))
    runtime: Mapped[str] = mapped_column(String(32), default="unknown")
    environment_path: Mapped[str | None] = mapped_column(String(512))
    entrypoint: Mapped[str | None] = mapped_column(String(512))
    entry_kind: Mapped[str] = mapped_column(String(32), default="cwd")
    container_id: Mapped[str | None] = mapped_column(String(96))
    # Same lifecycle as agent_assets.status: active / inactive / removed.
    status: Mapped[str] = mapped_column(String(24), default="active")
    first_seen_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)
    last_seen_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)


class ApplicationComponentRow(Base):
    """One AI-relevant package seen in an application's dependency metadata."""

    __tablename__ = "application_components"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    app_id: Mapped[str] = mapped_column(String(96), index=True)
    name: Mapped[str] = mapped_column(String(120))
    version: Mapped[str] = mapped_column(String(64), default="UNKNOWN")
    version_source: Mapped[str] = mapped_column(String(32), default="unknown")
    source_path: Mapped[str | None] = mapped_column(String(512))
    first_seen_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)
    last_seen_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)


class AgentInstanceRow(Base):
    """One running Agent process. Windows reuses PIDs, so identity is
    ``instance_id`` = hash(asset_id, pid, process start time)."""

    __tablename__ = "agent_instances"

    instance_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    asset_id: Mapped[str] = mapped_column(String(96), index=True)
    agent_type: Mapped[str] = mapped_column(String(48), index=True)
    pid: Mapped[int] = mapped_column(Integer, index=True)
    ppid: Mapped[int | None] = mapped_column(Integer)
    process_guid: Mapped[str | None] = mapped_column(String(96))
    process_name: Mapped[str] = mapped_column(String(120), default="")
    executable: Mapped[str | None] = mapped_column(String(512))
    cmdline: Mapped[str] = mapped_column(Text, default="")
    cwd: Mapped[str | None] = mapped_column(String(512))
    parent_chain_json: Mapped[str] = mapped_column(Text, default="[]")
    status: Mapped[str] = mapped_column(String(24), default="running")
    evidence_json: Mapped[str] = mapped_column(Text, default="[]")
    started_at: Mapped[str | None] = mapped_column(String(48))
    last_seen_at: Mapped[str | None] = mapped_column(String(48))


class AgentSessionRow(Base):
    """Native Agent session (hook session_id); links tool calls to one run."""

    __tablename__ = "agent_sessions"

    session_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    asset_id: Mapped[str | None] = mapped_column(String(96), index=True)
    agent_type: Mapped[str] = mapped_column(String(48), index=True)
    instance_id: Mapped[str | None] = mapped_column(String(96))
    source: Mapped[str] = mapped_column(String(32), default="native_hook")
    cwd: Mapped[str | None] = mapped_column(String(512))
    last_tool: Mapped[str | None] = mapped_column(String(90))
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[str | None] = mapped_column(String(48))
    last_event_at: Mapped[str | None] = mapped_column(String(48))
    ended_at: Mapped[str | None] = mapped_column(String(48))


class SecurityPolicyRow(Base):
    """Declarative policy as stored (mirror of the packaged policies.yaml)."""

    __tablename__ = "security_policies"

    policy_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    scope: Mapped[str] = mapped_column(String(24), default="tool_call")
    decision: Mapped[str] = mapped_column(String(16), default="audit")
    risk_level: Mapped[str] = mapped_column(String(16), default="medium")
    enabled: Mapped[int] = mapped_column(Integer, default=1)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    conditions_json: Mapped[str] = mapped_column(Text, default="{}")
    reason: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)


class SecurityAlertRow(Base):
    """Raised when a behavior event or a hook verdict crosses the risk bar."""

    __tablename__ = "security_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[str] = mapped_column(String(48), index=True, default=utc_now_iso)
    asset_id: Mapped[str | None] = mapped_column(String(96), index=True)
    agent_type: Mapped[str | None] = mapped_column(String(48))
    agent_label: Mapped[str] = mapped_column(String(80), default="")
    session_id: Mapped[str | None] = mapped_column(String(96))
    event_id: Mapped[int | None] = mapped_column(Integer, index=True)
    policy_id: Mapped[str | None] = mapped_column(String(64))
    risk_level: Mapped[str] = mapped_column(String(16), default="medium")
    decision: Mapped[str] = mapped_column(String(16), default="audit")
    status: Mapped[str] = mapped_column(String(24), default="open")
    title: Mapped[str] = mapped_column(String(200), default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    detail_json: Mapped[str] = mapped_column(Text, default="{}")
    resolved_at: Mapped[str | None] = mapped_column(String(48))
