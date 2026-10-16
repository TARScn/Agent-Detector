import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_detector.persistence.models import ScanTaskRow, utc_now_iso


class ScanRepository:
    def __init__(self, session: Session):
        self._session = session

    def create(self, mode: str) -> int:
        task = ScanTaskRow(mode=mode, status="running", started_at=utc_now_iso())
        self._session.add(task)
        self._session.flush()
        return task.id

    def finish(self, scan_id: int, status: str, stats: dict) -> None:
        task = self._session.get(ScanTaskRow, scan_id)
        if task is None:
            return
        task.status = status
        task.finished_at = utc_now_iso()
        task.stats_json = json.dumps(stats, ensure_ascii=False)

    def latest_id(self) -> int | None:
        task = self._session.scalars(
            select(ScanTaskRow).order_by(ScanTaskRow.id.desc()).limit(1)).first()
        return task.id if task else None

    def list(self, limit: int = 30) -> list[dict]:
        tasks = self._session.scalars(
            select(ScanTaskRow).order_by(ScanTaskRow.id.desc()).limit(limit))
        return [self._to_dict(task) for task in tasks]

    def get(self, scan_id: int) -> dict | None:
        task = self._session.get(ScanTaskRow, scan_id)
        return self._to_dict(task) if task else None

    @staticmethod
    def _to_dict(task: ScanTaskRow) -> dict:
        return {"id": task.id, "mode": task.mode, "status": task.status,
                "started_at": task.started_at, "finished_at": task.finished_at,
                "stats": json.loads(task.stats_json or "{}")}
