"""Repository for self-built agent applications (design §6.3).

``applications`` is the Host → Process → Application layer the CLI clients
never needed: one resolved project directory with its AI-relevant components.
Upserts refresh ``last_seen`` like every other repository — rows are history,
never deleted, so a project that stops running keeps its first/last seen.
"""
from typing import TYPE_CHECKING

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from agent_detector.core.models import ComponentInfo, ProjectInfo
from agent_detector.storage.models import (ApplicationComponentRow, ApplicationRow,
                                           utc_now_iso)

if TYPE_CHECKING:  # discovery bundle; imported lazily to keep storage decoupled
    from agent_detector.discovery.sources.frameworks import ApplicationBundle


class ApplicationRepository:
    def __init__(self, session: Session):
        self._session = session

    def upsert_all(self, bundles: list["ApplicationBundle"]) -> int:
        """Persist one scan's application bundles; returns how many."""
        for bundle in bundles:
            self.upsert(bundle.project, bundle.components, app_id=bundle.app_id)
        return len(bundles)

    def upsert(self, project: ProjectInfo, components: list[ComponentInfo],
               *, app_id: str) -> None:
        now = utc_now_iso()
        row = self._session.get(ApplicationRow, app_id)
        if row is None:
            row = ApplicationRow(app_id=app_id, first_seen_at=now, name=project.name,
                                 root_path=project.root)
            self._session.add(row)
        row.name = project.name
        row.root_path = project.root
        row.runtime = project.runtime
        row.environment_path = project.environment_path
        row.entrypoint = project.entry
        row.entry_kind = project.entry_kind
        row.container_id = project.container_id
        row.status = "active"  # seen again this scan
        row.last_seen_at = now
        for component in components:
            existing = self._session.scalar(select(ApplicationComponentRow).where(
                ApplicationComponentRow.app_id == app_id,
                ApplicationComponentRow.name == component.name))
            if existing is None:
                existing = ApplicationComponentRow(app_id=app_id, first_seen_at=now,
                                                   name=component.name)
                self._session.add(existing)
            existing.version = component.version
            existing.version_source = component.version_source.value
            existing.source_path = component.source_path
            existing.last_seen_at = now

    def list_applications(self, *, include_removed: bool = False,
                          limit: int = 200) -> list[dict]:
        statement = select(ApplicationRow).order_by(
            ApplicationRow.last_seen_at.desc())
        if not include_removed:
            statement = statement.where(ApplicationRow.status != "removed")
        statement = statement.limit(min(max(int(limit), 1), 1000))
        return [self._app_dict(row) for row in self._session.scalars(statement)]

    def get_application(self, app_id: str) -> dict | None:
        row = self._session.get(ApplicationRow, app_id)
        return self._app_dict(row) if row else None

    def all_for_verification(self) -> list[dict]:
        """(app_id, root_path, environment_path, runtime) for every application,
        any status — the inputs the post-scan dependency re-check needs."""
        rows = self._session.scalars(select(ApplicationRow))
        return [{"app_id": row.app_id, "root_path": row.root_path,
                 "environment_path": row.environment_path,
                 "runtime": row.runtime} for row in rows]

    def set_status(self, app_id: str, status: str) -> bool:
        """Post-scan verification verdict for an application not seen this scan."""
        row = self._session.get(ApplicationRow, app_id)
        if row is None:
            return False
        row.status = status
        return True

    def delete_application(self, app_id: str) -> None:
        """Hard delete of a verified-gone application (project dir deleted):
        the application, its components and, via the asset repository, the
        framework assets that pointed at it all leave the logical view."""
        self._session.execute(delete(ApplicationComponentRow).where(
            ApplicationComponentRow.app_id == app_id))
        row = self._session.get(ApplicationRow, app_id)
        if row is not None:
            self._session.delete(row)

    def count_applications(self) -> int:
        return len(self._session.scalars(select(ApplicationRow)).all())

    def _app_dict(self, row: ApplicationRow) -> dict:
        components = self._session.scalars(
            select(ApplicationComponentRow).where(
                ApplicationComponentRow.app_id == row.app_id).order_by(
                ApplicationComponentRow.name)).all()
        return {"app_id": row.app_id, "name": row.name, "root_path": row.root_path,
                "runtime": row.runtime, "environment_path": row.environment_path,
                "entrypoint": row.entrypoint, "entry_kind": row.entry_kind,
                "container_id": row.container_id,
                "status": row.status or "active",
                "components": [{"name": c.name, "version": c.version,
                                "version_source": c.version_source,
                                "source_path": c.source_path} for c in components],
                "first_seen_at": row.first_seen_at, "last_seen_at": row.last_seen_at}
