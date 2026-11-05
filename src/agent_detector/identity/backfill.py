"""P0-D: backfill canonical entities and aliases from the legacy tables.

The backfill is additive and idempotent. It never rewrites or deletes a legacy
row; it only ensures every old id has a canonical mapping (or an explicit
AMBIGUOUS marker when two mappings collide). Existing strong aliases written by
the P0-A shadow path are preserved.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from agent_detector.identity.entity import (EntityKind, KeyType,
                                            build_entity_key,
                                            canonical_scope_path)
from agent_detector.storage.agent_repository import AgentInventoryRepository
from agent_detector.storage.application_repository import ApplicationRepository
from agent_detector.storage.asset_repository import AssetRepository
from agent_detector.storage.identity_repository import IdentityRepository


def _kind_for_asset_type(asset_type: str) -> EntityKind:
    if asset_type in ("AGENT_CLIENT", "AGENT_RUNTIME", "AGENT_PLATFORM"):
        return EntityKind.PRODUCT_INSTALL
    if asset_type == "AI_APPLICATION":
        return EntityKind.SELF_BUILT_APPLICATION
    if asset_type in ("LLM_SERVICE", "MCP_SERVER", "AGENT_SERVICE"):
        return EntityKind.SERVICE
    return EntityKind.UNKNOWN


def backfill_identity(session: Session, *, scope_key: str) -> dict:
    """Ensure entities/aliases exist for applications, agent assets and assets."""
    repo = IdentityRepository(session)
    stats = {"applications": 0, "agent_assets": 0, "assets": 0,
             "aliases": 0, "skipped": 0, "ambiguous": 0}

    app_entities: dict[str, str] = {}
    applications = ApplicationRepository(session).list_applications(
        include_removed=True, limit=1000)
    for app in applications:
        old_id = app["app_id"]
        existing = repo.get_alias(old_id)
        if existing is not None:
            if (existing.status or "OK") == "OK":
                app_entities[old_id] = existing.entity_id
            else:
                stats["ambiguous"] += 1
            stats["skipped"] += 1
            continue
        root = app.get("root_path") or ""
        if not root:
            continue
        canonical = build_entity_key(
            KeyType.APPLICATION, scope_key,
            {"root": canonical_scope_path(root)})
        entity_id = repo.ensure_entity(
            EntityKind.SELF_BUILT_APPLICATION, KeyType.APPLICATION, canonical,
            scope_key=scope_key, confidence_basis="backfill:application")
        status = repo.alias_legacy(old_id, entity_id, reason="backfill:application")
        app_entities[old_id] = entity_id
        stats["applications"] += 1
        stats["aliases"] += 1
        if status == "AMBIGUOUS":
            stats["ambiguous"] += 1

    for asset in AgentInventoryRepository(session).list_assets(
            include_removed=True):
        old_id = asset["asset_id"]
        existing = repo.get_alias(old_id)
        if existing is not None:
            stats["skipped"] += 1
            continue
        app_id = asset.get("app_id")
        if app_id and app_id in app_entities:
            # A framework row is a component of the application entity.
            status = repo.alias_legacy(
                old_id, app_entities[app_id],
                reason="backfill:framework_to_application")
            stats["agent_assets"] += 1
            stats["aliases"] += 1
            if status == "AMBIGUOUS":
                stats["ambiguous"] += 1
            continue

        container_id = asset.get("container_id")
        if container_id:
            kind = EntityKind.CONTAINER_DEPLOYMENT
            key_type = KeyType.CONTAINER
            parts = {"container_id": container_id,
                     "product": asset.get("agent_type") or ""}
        else:
            kind = (EntityKind.PRODUCT_INSTALL
                    if (asset.get("origin") or "host") != "docker"
                    else EntityKind.UNKNOWN)
            key_type = KeyType.LEGACY_ASSET
            parts = {"asset_id": old_id}
        canonical = build_entity_key(key_type, scope_key, parts)
        entity_id = repo.ensure_entity(
            kind, key_type, canonical, scope_key=scope_key,
            confidence_basis="backfill:agent_asset")
        status = repo.alias_legacy(old_id, entity_id,
                                   reason="backfill:agent_asset")
        stats["agent_assets"] += 1
        stats["aliases"] += 1
        if status == "AMBIGUOUS":
            stats["ambiguous"] += 1

    for asset in AssetRepository(session).list_assets():
        old_id = asset["asset_id"]
        existing = repo.get_alias(old_id)
        if existing is not None:
            stats["skipped"] += 1
            continue
        kind = _kind_for_asset_type(asset.get("asset_type") or "")
        canonical = build_entity_key(
            KeyType.LEGACY_ASSET, scope_key, {"asset_id": old_id})
        entity_id = repo.ensure_entity(
            kind, KeyType.LEGACY_ASSET, canonical, scope_key=scope_key,
            confidence_basis="backfill:asset")
        status = repo.alias_legacy(old_id, entity_id, reason="backfill:asset")
        stats["assets"] += 1
        stats["aliases"] += 1
        if status == "AMBIGUOUS":
            stats["ambiguous"] += 1

    session.flush()
    return stats