"""Endpoint identity and host/container binding persistence (P0-C)."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_detector.identity.canonical import canonical_json, digest
from agent_detector.storage.models import (EndpointBindingRow, EndpointRow,
                                           utc_now_iso)


class EndpointRepository:
    def __init__(self, session: Session):
        self._session = session

    @staticmethod
    def endpoint_key(scope_key: str, protocol: str, address: str,
                     port: int, namespace: str = "host") -> str:
        payload = {
            "v": 1,
            "scope": scope_key,
            "protocol": (protocol or "tcp").lower(),
            "address": address or "",
            "port": int(port),
            "namespace": namespace or "host",
        }
        return "ep-" + digest(canonical_json(payload), length=24)

    def upsert_endpoint(self, scope_key: str, protocol: str, address: str,
                        port: int, *, namespace: str = "host",
                        owner_entity_id: str | None = None) -> str:
        endpoint_id = self.endpoint_key(scope_key, protocol, address, port,
                                        namespace)
        row = self._session.get(EndpointRow, endpoint_id)
        if row is None:
            self._session.add(EndpointRow(
                endpoint_id=endpoint_id,
                scope_key=scope_key,
                protocol=(protocol or "tcp").lower(),
                address=address or "",
                port=int(port),
                namespace=namespace or "host",
                owner_entity_id=owner_entity_id,
                valid_from=utc_now_iso(),
            ))
            return endpoint_id
        if owner_entity_id and not row.owner_entity_id:
            row.owner_entity_id = owner_entity_id
        return endpoint_id

    def bind(self, host_endpoint_id: str, container_endpoint_id: str,
             container_id: str, *, source: str = "docker_published_port") -> int:
        existing = self._session.scalars(
            select(EndpointBindingRow).where(
                EndpointBindingRow.host_endpoint_id == host_endpoint_id,
                EndpointBindingRow.valid_to.is_(None),
            )).first()
        if existing is not None:
            if (existing.container_endpoint_id == container_endpoint_id
                    and existing.container_id == container_id):
                existing.binding_source = source
                return existing.id
            existing.valid_to = utc_now_iso()  # rebind: keep the old window
        row = EndpointBindingRow(
            host_endpoint_id=host_endpoint_id,
            container_endpoint_id=container_endpoint_id,
            container_id=container_id,
            binding_source=source,
            valid_from=utc_now_iso(),
        )
        self._session.add(row)
        self._session.flush()
        return row.id

    def get_binding(self, host_endpoint_id: str) -> EndpointBindingRow | None:
        return self._session.scalars(
            select(EndpointBindingRow).where(
                EndpointBindingRow.host_endpoint_id == host_endpoint_id,
                EndpointBindingRow.valid_to.is_(None),
            )).first()

    def find_host_endpoint(self, scope_key: str, protocol: str, address: str,
                           port: int, namespace: str = "host"
                           ) -> EndpointRow | None:
        endpoint_id = self.endpoint_key(scope_key, protocol, address, port,
                                        namespace)
        return self._session.get(EndpointRow, endpoint_id)