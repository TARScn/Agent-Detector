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
    """Behavior/protocol events (plan section 5.2 behavior_events).

    Writers append rows directly: ``source="netmon"`` for zero-cooperation LLM
    connection observations, ``source="auditd"``/``"poll"`` for the system
    behavior channels. ``source`` distinguishes event feeds; ``asset_id`` stays
    empty when no asset could be proven. Event rows carry the observer's
    declared confidence grade (high/medium/low), never raw content.
    """

    __tablename__ = "behavior_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    observed_at: Mapped[str] = mapped_column(String(48), index=True)
    source: Mapped[str] = mapped_column(String(32), default="gateway")
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
