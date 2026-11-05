"""Persistence for the P0-A identity tables.

Writes are idempotent: re-running a scan with the same assets must not create
duplicate entities, keys or birth rows. The repository never deletes; closing
a key (``valid_to``) is the only lifecycle operation P0-A needs.
"""
from __future__ import annotations

import json
import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from agent_detector.identity.engine import EngineIdentity
from agent_detector.identity.entity import EntityKind, KeyType
from agent_detector.identity.host import HostIdentity
from agent_detector.identity.process import ProcessBirth
from agent_detector.storage.models import (DockerEngineRow,
                                           EngineHostBindingRow,
                                           EntityAliasRow, EntityKeyRow,
                                           EntityRow, HostIdentityClaimRow,
                                           HostIdentityRow, ProcessBirthRow,
                                           utc_now_iso)


class IdentityRepository:
    def __init__(self, session: Session):
        self._session = session

    # -- host / engine ------------------------------------------------------

    def record_host_identity(self, identity: HostIdentity) -> None:
        now = utc_now_iso()
        row = self._session.get(HostIdentityRow, identity.host_key)
        if row is None:
            self._session.add(HostIdentityRow(
                host_key=identity.host_key,
                identity_version=identity.identity_version,
                identity_basis=identity.identity_basis,
                installation_id=identity.installation_id,
                trust_state=identity.trust_state,
                detector_local=1 if identity.detector_local else 0,
                first_seen=identity.first_seen,
                last_seen=now,
                identity_verified_at=identity.identity_verified_at,
            ))
            return
        row.identity_version = identity.identity_version
        row.identity_basis = identity.identity_basis
        row.installation_id = identity.installation_id
        row.trust_state = identity.trust_state
        row.detector_local = 1 if identity.detector_local else 0
        row.last_seen = now
        row.identity_verified_at = (identity.identity_verified_at
                                    or row.identity_verified_at)

    def record_host_claims(self, identity: HostIdentity) -> None:
        for anchor in identity.anchors:
            existing = self._session.scalars(
                select(HostIdentityClaimRow).where(
                    HostIdentityClaimRow.host_key == identity.host_key,
                    HostIdentityClaimRow.claim_type == anchor.claim_type,
                    HostIdentityClaimRow.value_hash == anchor.value_hash,
                )).first()
            if existing is not None:
                existing.observed_at = utc_now_iso()
                continue
            self._session.add(HostIdentityClaimRow(
                host_key=identity.host_key,
                claim_type=anchor.claim_type,
                value_hash=anchor.value_hash,
                source=anchor.source,
            ))

    def record_engine(self, engine: EngineIdentity) -> None:
        now = utc_now_iso()
        row = self._session.get(DockerEngineRow, engine.engine_key)
        aliases = json.dumps(list(engine.endpoint_aliases), ensure_ascii=False)
        if row is None:
            self._session.add(DockerEngineRow(
                engine_key=engine.engine_key,
                engine_id_claim=engine.engine_id_claim,
                endpoint_aliases_json=aliases,
                engine_host_key=engine.engine_host_key,
                binding_state=engine.binding_state,
                first_seen=now,
                last_seen=now,
            ))
            return
        row.engine_id_claim = engine.engine_id_claim or row.engine_id_claim
        row.endpoint_aliases_json = aliases
        row.engine_host_key = engine.engine_host_key or row.engine_host_key
        row.binding_state = engine.binding_state
        row.last_seen = now

    def record_engine_binding(self, engine: EngineIdentity) -> None:
        """Record a verified engine->host mapping; no-op for remote engines."""
        if not engine.engine_host_key:
            return
        existing = self._session.scalars(
            select(EngineHostBindingRow).where(
                EngineHostBindingRow.engine_key == engine.engine_key,
                EngineHostBindingRow.host_key == engine.engine_host_key,
            )).first()
        if existing is not None:
            existing.binding_state = engine.binding_state
            existing.evidence = ",".join(engine.endpoint_aliases)
            return
        self._session.add(EngineHostBindingRow(
            engine_key=engine.engine_key,
            host_key=engine.engine_host_key,
            binding_state=engine.binding_state,
            evidence=",".join(engine.endpoint_aliases),
        ))

    # -- entities -----------------------------------------------------------

    def ensure_entity(self, entity_kind: EntityKind | str, key_type: KeyType | str,
                      canonical_key: str, *, scope_key: str = "",
                      identity_version: int = 1,
                      confidence_basis: str = "") -> str:
        """Return the entity for an open key, creating both rows if needed."""
        kind = entity_kind.value if isinstance(entity_kind, EntityKind) else entity_kind
        key_type_value = key_type.value if isinstance(key_type, KeyType) else key_type
        existing = self._open_key(identity_version, key_type_value, canonical_key)
        if existing is not None:
            row = self._session.get(EntityRow, existing.entity_id)
            if row is not None and not row.scope_key and scope_key:
                row.scope_key = scope_key
            return existing.entity_id

        entity_id = str(uuid.uuid4())
        try:
            with self._session.begin_nested():
                self._session.add(EntityRow(
                    entity_id=entity_id,
                    entity_kind=kind,
                    scope_key=scope_key,
                    created_at=utc_now_iso(),
                ))
                self._session.add(EntityKeyRow(
                    key_type=key_type_value,
                    canonical_key=canonical_key,
                    identity_version=identity_version,
                    entity_id=entity_id,
                    valid_from=utc_now_iso(),
                    confidence_basis=confidence_basis,
                ))
                self._session.flush()
        except IntegrityError:
            # Another writer won the race (or a duplicate slipped through a
            # batch): the unique open-key index is authoritative.
            winner = self._open_key(identity_version, key_type_value, canonical_key)
            if winner is not None:
                return winner.entity_id
            raise
        return entity_id

    def _open_key(self, identity_version: int, key_type: str,
                  canonical_key: str) -> EntityKeyRow | None:
        return self._session.scalars(
            select(EntityKeyRow).where(
                EntityKeyRow.identity_version == identity_version,
                EntityKeyRow.key_type == key_type,
                EntityKeyRow.canonical_key == canonical_key,
                EntityKeyRow.valid_to.is_(None),
            )).first()

    def resolve_alias(self, old_id: str) -> str | None:
        row = self._session.get(EntityAliasRow, old_id)
        if row is None or (row.status or "OK") == "AMBIGUOUS":
            return None
        return row.entity_id

    def get_alias(self, old_id: str) -> EntityAliasRow | None:
        return self._session.get(EntityAliasRow, old_id)

    def alias_status(self, old_id: str) -> str | None:
        row = self._session.get(EntityAliasRow, old_id)
        return (row.status or "OK") if row is not None else None

    def entity_for_legacy(self, old_id: str) -> EntityRow | None:
        entity_id = self.resolve_alias(old_id)
        return self._session.get(EntityRow, entity_id) if entity_id else None

    def alias_legacy(self, old_id: str, entity_id: str, *,
                     reason: str = "") -> str:
        """Idempotently point a legacy id at one entity; conflicts are marked.

        Returns ``OK`` / ``AMBIGUOUS``. An ambiguous alias is deliberately not
        followed by readers: the old id may have represented more than one
        real asset, so silently choosing one would corrupt history.
        """
        row = self._session.get(EntityAliasRow, old_id)
        if row is None:
            self._session.add(EntityAliasRow(
                old_id=old_id, entity_id=entity_id, reason=reason,
                status="OK", created_at=utc_now_iso()))
            return "OK"
        if row.entity_id != entity_id:
            if (row.status or "OK") != "AMBIGUOUS":
                row.reason = (f"{row.reason} | conflicting: {reason}"
                              if row.reason else f"conflicting: {reason}")
            row.status = "AMBIGUOUS"
            return "AMBIGUOUS"
        row.reason = reason or row.reason
        row.status = row.status or "OK"
        return row.status

    # -- process births -----------------------------------------------------

    def record_process_birth(self, birth: ProcessBirth) -> None:
        now = utc_now_iso()
        row = self._session.get(ProcessBirthRow, birth.instance_key)
        if row is None:
            self._session.add(ProcessBirthRow(
                instance_key=birth.instance_key,
                scope_key=birth.scope_key,
                platform=birth.platform,
                boot_identity=birth.boot_identity,
                pid_namespace_key=birth.pid_namespace_key,
                pid=birth.pid,
                native_birth_value=birth.native_birth_value,
                clock_domain=birth.clock_domain,
                resolution=birth.resolution,
                canonical_start_ticks=birth.canonical_start_ticks,
                source=birth.source,
                verification_state=birth.verification_state,
                process_guid=birth.process_guid,
                first_seen=now,
                last_seen=now,
            ))
            return
        row.last_seen = now
        row.verification_state = birth.verification_state
        row.scope_key = birth.scope_key