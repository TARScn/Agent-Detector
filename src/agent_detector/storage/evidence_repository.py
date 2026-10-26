import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_detector.core.models import DetectedAsset
from agent_detector.storage.models import EvidenceRow, utc_now_iso


class EvidenceRepository:
    def __init__(self, session: Session):
        self._session = session

    def add_all(self, scan_id: int, asset: DetectedAsset) -> None:
        for item in asset.evidence:
            self._session.add(EvidenceRow(
                scan_id=scan_id, asset_id=asset.asset_id, kind=item.kind.value,
                summary=item.summary,
                detail_json=json.dumps(item.detail, ensure_ascii=False),
                confidence=item.confidence, created_at=utc_now_iso()))

    def for_asset(self, asset_id: str, scan_id: int | None = None,
                  limit: int = 200) -> list[dict]:
        statement = select(EvidenceRow).where(EvidenceRow.asset_id == asset_id)
        if scan_id is not None:
            statement = statement.where(EvidenceRow.scan_id == scan_id)
        statement = statement.order_by(EvidenceRow.id.desc()).limit(limit)
        return [{"id": row.id, "scan_id": row.scan_id, "asset_id": row.asset_id,
                 "kind": row.kind, "summary": row.summary,
                 "detail": json.loads(row.detail_json or "{}"),
                 "confidence": row.confidence, "created_at": row.created_at}
                for row in self._session.scalars(statement)]
