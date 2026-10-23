import json

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agent_detector.core.models import DetectedAsset
from agent_detector.storage.models import AssetRow, AssetSnapshotRow, utc_now_iso


class AssetRepository:
    def __init__(self, session: Session):
        self._session = session

    def upsert(self, asset: DetectedAsset, scan_id: int) -> None:
        """Create the asset on first sight, then only refresh last_seen afterwards."""
        now = utc_now_iso()
        row = self._session.get(AssetRow, asset.asset_id)
        if row is None:
            self._session.add(AssetRow(asset_id=asset.asset_id, name=asset.name,
                                       asset_type=asset.asset_type.value,
                                       first_seen_at=now, last_seen_at=now))
        else:
            row.last_seen_at = now
        self._session.add(AssetSnapshotRow(
            scan_id=scan_id, asset_id=asset.asset_id,
            states_json=json.dumps(sorted(state.value for state in asset.states)),
            confidence=asset.confidence,
            version=asset.version.value, version_source=asset.version.source.value,
            running_pids_json=json.dumps(asset.running_pids),
            listening_ports_json=json.dumps(asset.listening_ports),
            detector=asset.detector))

    def list_snapshots(self, scan_id: int) -> list[dict]:
        rows = self._session.execute(
            select(AssetSnapshotRow, AssetRow)
            .join(AssetRow, AssetRow.asset_id == AssetSnapshotRow.asset_id)
            .where(AssetSnapshotRow.scan_id == scan_id)
            .order_by(AssetRow.name)).all()
        return [self._to_dict(snapshot, asset) for snapshot, asset in rows]

    def latest_snapshots(self) -> list[dict]:
        latest = select(AssetSnapshotRow.asset_id,
                        func.max(AssetSnapshotRow.id).label("snap_id")
                        ).group_by(AssetSnapshotRow.asset_id).subquery()
        rows = self._session.execute(
            select(AssetSnapshotRow, AssetRow)
            .join(latest, latest.c.snap_id == AssetSnapshotRow.id)
            .join(AssetRow, AssetRow.asset_id == AssetSnapshotRow.asset_id)
            .order_by(AssetRow.name)).all()
        return [self._to_dict(snapshot, asset) for snapshot, asset in rows]

    def list_assets(self) -> list[dict]:
        rows = self._session.scalars(select(AssetRow).order_by(AssetRow.name))
        return [{"asset_id": row.asset_id, "name": row.name,
                 "asset_type": row.asset_type, "first_seen_at": row.first_seen_at,
                 "last_seen_at": row.last_seen_at} for row in rows]

    @staticmethod
    def _to_dict(snapshot: AssetSnapshotRow, asset: AssetRow) -> dict:
        return {"asset_id": snapshot.asset_id, "name": asset.name,
                "asset_type": asset.asset_type,
                "states": json.loads(snapshot.states_json),
                "confidence": snapshot.confidence,
                "version": snapshot.version,
                "version_source": snapshot.version_source,
                "running_pids": json.loads(snapshot.running_pids_json),
                "listening_ports": json.loads(snapshot.listening_ports_json),
                "detector": snapshot.detector, "scan_id": snapshot.scan_id,
                "first_seen_at": asset.first_seen_at, "last_seen_at": asset.last_seen_at}
