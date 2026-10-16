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
