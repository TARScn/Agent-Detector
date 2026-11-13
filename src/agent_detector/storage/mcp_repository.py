"""MCP config reference persistence (one row per config-file server entry)."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_detector.storage.models import McpConfigRefRow, utc_now_iso


class McpConfigRefRepository:
    def __init__(self, session: Session):
        self._session = session

    def upsert_ref(self, *, ref_id: str, entity_id: str = "", client: str = "",
                   server_name: str = "", scope: str = "user",
                   config_path: str = "", transport: str = "unknown",
                   endpoint: str = "", enabled: str = "unknown",
                   config_digest: str = "") -> str:
        """Idempotent per scan: refresh the mutable fields, keep first_seen.

        ``entity_id`` only ever widens (empty never erases a previous match),
        because a ref can be seen before its client entity is first scanned.
        """
        row = self._session.get(McpConfigRefRow, ref_id)
        now = utc_now_iso()
        if row is None:
            self._session.add(McpConfigRefRow(
                ref_id=ref_id, entity_id=entity_id, client=client,
                server_name=server_name, scope=scope, config_path=config_path,
                transport=transport, endpoint=endpoint, enabled=enabled,
                config_digest=config_digest, first_seen=now, last_seen=now))
            return ref_id
        row.entity_id = entity_id or row.entity_id
        row.transport = transport
        row.endpoint = endpoint
        row.enabled = enabled
        row.config_digest = config_digest
        row.last_seen = now
        return ref_id

    def set_run_status(self, ref_id: str, run_status: str,
                       pids: list[int] | None = None) -> None:
        row = self._session.get(McpConfigRefRow, ref_id)
        if row is None:
            return
        row.run_status = run_status
        if pids is not None:
            import json
            row.run_pids_json = json.dumps(pids)

    def set_probe_result(self, ref_id: str, *, probe_status: str,
                         protocol_version: str = "") -> None:
        row = self._session.get(McpConfigRefRow, ref_id)
        if row is None:
            return
        row.probe_status = probe_status
        row.protocol_version = protocol_version
        row.last_probe_at = utc_now_iso()

    def list_for_entity(self, entity_id: str) -> list[McpConfigRefRow]:
        return list(self._session.scalars(
            select(McpConfigRefRow)
            .where(McpConfigRefRow.entity_id == entity_id)
            .order_by(McpConfigRefRow.client, McpConfigRefRow.server_name)))

    def list_all(self) -> list[McpConfigRefRow]:
        return list(self._session.scalars(
            select(McpConfigRefRow)
            .order_by(McpConfigRefRow.client, McpConfigRefRow.server_name)))
