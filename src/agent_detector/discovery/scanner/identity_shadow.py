"""P0-A shadow writer: canonical identity beside the legacy scan result.

This module is deliberately read-path-neutral. It resolves the host identity,
records the local engine binding, creates/aliases canonical entities for the
assets a scan already produced, and stores the process births referenced by
those assets. Nothing in the legacy tables changes, and a failure here must
never fail the scan.
"""
from __future__ import annotations

import logging
import os

from sqlalchemy.orm import Session

from agent_detector.core.config import IDENTITY_SHADOW_ENABLED
from agent_detector.core.models import DetectedAsset, HostFacts
from agent_detector.identity.engine import resolve_engine_identity
from agent_detector.identity.entity import legacy_identity_for_asset
from agent_detector.identity.host import HostIdentityStore
from agent_detector.identity.process import build_process_birth
from agent_detector.storage.identity_repository import IdentityRepository

logger = logging.getLogger(__name__)


def write_identity_shadow(session: Session, engine, assets: list[DetectedAsset],
                          facts: HostFacts) -> dict:
    """Write the canonical identity projection; return a stats dict.

    ``scope_key`` is the host key for host assets and the engine key for
    compose/container assets. Container PIDs are namespace-local, so they are
    not turned into host process births here; P0-C owns that mapping.
    """
    if not IDENTITY_SHADOW_ENABLED:
        return {"enabled": False}

    result = {
        "enabled": True,
        "entities": 0,
        "aliases": 0,
        "process_births": 0,
        "host_key": None,
        "engine_key": None,
        "error": None,
    }
    try:
        host = HostIdentityStore.for_engine(engine).resolve()
        # A tcp:// DOCKER_HOST is not the local engine until its host mapping
        # is independently verified; keep it unbound rather than borrowing the
        # detector host's identity.
        docker_host = os.getenv("DOCKER_HOST", "").strip()
        is_local_engine = (not docker_host
                           or docker_host.startswith(("unix://", "npipe://")))
        engine_identity = resolve_engine_identity(
            host,
            endpoint=docker_host or "local",
            is_local=is_local_engine)
        repo = IdentityRepository(session)
        process_by_pid = {process.pid: process for process in facts.processes}
        entity_ids: set[str] = set()
        birth_keys: set[str] = set()
        aliases = 0

        with session.begin_nested():
            repo.record_host_identity(host)
            repo.record_host_claims(host)
            repo.record_engine(engine_identity)
            repo.record_engine_binding(engine_identity)
            for asset in assets:
                container_scoped = (asset.scope_kind in ("compose", "container")
                                    or asset.identity_scope.startswith("container:"))
                scope_key = (engine_identity.engine_key if container_scoped
                             else host.scope_key)
                # Backfill may already have bound this legacy id to a canonical
                # entity (possibly with a LEGACY_ASSET key). Adopt that entity
                # instead of minting a strong-key twin, which would immediately
                # mark the alias AMBIGUOUS.
                existing = repo.get_alias(asset.asset_id)
                if existing is not None and (existing.status or "OK") == "OK":
                    entity_id = existing.entity_id
                else:
                    legacy = legacy_identity_for_asset(asset, scope_key)
                    entity_id = repo.ensure_entity(
                        legacy.entity_kind, legacy.key_type,
                        legacy.canonical_key,
                        scope_key=scope_key,
                        confidence_basis=legacy.confidence_basis)
                    repo.alias_legacy(
                        asset.asset_id, entity_id,
                        reason=f"shadow:{asset.scope_kind or 'unknown'}")
                entity_ids.add(entity_id)
                aliases += 1

                if container_scoped:
                    continue  # container-internal PIDs are not host PIDs
                for pid in asset.running_pids:
                    info = process_by_pid.get(pid)
                    if info is not None and info.container_id:
                        continue  # namespace-local pid: P0-C maps it, not P0-A
                    birth = build_process_birth(
                        pid, scope_key, process_info=info)
                    if birth is None:
                        continue
                    repo.record_process_birth(birth)
                    birth_keys.add(birth.instance_key)
            session.flush()

        result.update({
            "entities": len(entity_ids),
            "aliases": aliases,
            "process_births": len(birth_keys),
            "host_key": host.host_key,
            "engine_key": engine_identity.engine_key,
        })
    except Exception as exc:  # identity must never void a discovery scan
        logger.exception("identity shadow write failed")
        result["error"] = str(exc)
    return result