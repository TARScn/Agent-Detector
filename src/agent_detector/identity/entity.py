"""Entity keys for the P0-A shadow identity layer.

P0-A does not replace the legacy read path. It derives a canonical entity per
detected asset (and aliases the legacy ``asset_id`` to it) so P0-D can switch
readers over without a big-bang migration. Keys are versioned and hashed; the
entity id itself is an opaque UUID assigned by the repository.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from agent_detector.core.enums import AssetType
from agent_detector.core.identity import normalize_path, slugify
from agent_detector.core.models import DetectedAsset
from agent_detector.identity.canonical import IDENTITY_VERSION, canonical_json, digest


class EntityKind(str, Enum):
    PRODUCT_INSTALL = "PRODUCT_INSTALL"
    SELF_BUILT_APPLICATION = "SELF_BUILT_APPLICATION"
    COMPOSE_DEPLOYMENT = "COMPOSE_DEPLOYMENT"
    CONTAINER_DEPLOYMENT = "CONTAINER_DEPLOYMENT"
    SERVICE = "SERVICE"
    ENVIRONMENT = "ENVIRONMENT"
    UNKNOWN = "UNKNOWN"


class KeyType(str, Enum):
    LEGACY_ASSET = "legacy_asset"
    PRODUCT_INSTALL = "product_install"
    APPLICATION = "application"
    COMPOSE = "compose"
    CONTAINER = "container"
    SERVICE = "service"
    ENVIRONMENT = "environment"


@dataclass(frozen=True)
class LegacyIdentity:
    entity_kind: EntityKind
    key_type: KeyType
    canonical_key: str
    confidence_basis: str


def canonical_scope_path(value: str) -> str:
    """Path normalization for identity: Windows paths are case-insensitive.

    Container project roots are opaque ``container:<id>:...`` references, not
    host filesystem paths; resolving them would make the key depend on the
    detector's cwd.
    """
    if value.startswith(("container:", "engine:", "host:")):
        return value.strip()
    path = normalize_path(value)
    if len(path) >= 2 and path[1] == ":":
        path = path.lower()
    return path


def build_entity_key(key_type: KeyType | str, scope_key: str,
                     parts: dict[str, str]) -> str:
    """Canonical, versioned key: same inputs -> same key on every run."""
    key_type_value = key_type.value if isinstance(key_type, KeyType) else key_type
    payload = {
        "v": IDENTITY_VERSION,
        "type": key_type_value,
        "scope": scope_key,
        "parts": {name: str(value) for name, value in parts.items()},
    }
    return "key-" + digest(canonical_json(payload), length=24)


def infer_entity_kind(asset: DetectedAsset) -> EntityKind:
    scope = asset.scope_kind
    if scope == "compose":
        return EntityKind.COMPOSE_DEPLOYMENT
    if scope == "container":
        return EntityKind.CONTAINER_DEPLOYMENT
    if scope == "project":
        return EntityKind.SELF_BUILT_APPLICATION
    if scope == "user-home":
        return EntityKind.PRODUCT_INSTALL
    if scope == "listen-port":
        return EntityKind.SERVICE
    if asset.asset_type is AssetType.AI_APPLICATION:
        return EntityKind.SELF_BUILT_APPLICATION
    if asset.asset_type in (AssetType.LLM_SERVICE, AssetType.MCP_SERVER,
                            AssetType.AGENT_SERVICE):
        return EntityKind.SERVICE
    if asset.asset_type in (AssetType.AGENT_CLIENT, AssetType.AGENT_RUNTIME,
                            AssetType.AGENT_PLATFORM):
        return EntityKind.PRODUCT_INSTALL
    return EntityKind.UNKNOWN


def legacy_identity_for_asset(asset: DetectedAsset,
                              scope_key: str) -> LegacyIdentity:
    """Map one legacy asset to its canonical shadow identity.

    Only scopes the detector actually proved become strong keys. A bare HTTP
    probe (``listen-port``) keeps the legacy asset id as its key: a port is
    not an entity anchor, so pretending otherwise would create false
    identities. P0-C replaces that path with endpoint ownership.
    """
    kind = infer_entity_kind(asset)
    product = asset.detector or slugify(asset.name)
    scope = asset.scope_kind
    basis = f"detector_scope:{scope or 'unknown'}"

    if asset.identity_scope:
        if scope == "user-home":
            return LegacyIdentity(
                entity_kind=EntityKind.PRODUCT_INSTALL,
                key_type=KeyType.PRODUCT_INSTALL,
                canonical_key=build_entity_key(
                    KeyType.PRODUCT_INSTALL, scope_key,
                    {"product": product,
                     "install_scope": canonical_scope_path(asset.identity_scope)}),
                confidence_basis=basis)
        if scope == "project":
            return LegacyIdentity(
                entity_kind=EntityKind.SELF_BUILT_APPLICATION,
                key_type=KeyType.APPLICATION,
                canonical_key=build_entity_key(
                    KeyType.APPLICATION, scope_key,
                    {"root": canonical_scope_path(asset.identity_scope)}),
                confidence_basis=basis)
        if scope == "compose":
            return LegacyIdentity(
                entity_kind=EntityKind.COMPOSE_DEPLOYMENT,
                key_type=KeyType.COMPOSE,
                canonical_key=build_entity_key(
                    KeyType.COMPOSE, scope_key,
                    {"project": asset.identity_scope, "product": product}),
                confidence_basis=basis)
        if scope == "container":
            return LegacyIdentity(
                entity_kind=EntityKind.CONTAINER_DEPLOYMENT,
                key_type=KeyType.CONTAINER,
                canonical_key=build_entity_key(
                    KeyType.CONTAINER, scope_key,
                    {"container_id": asset.identity_scope,
                     "product": product}),
                confidence_basis=basis)

    return LegacyIdentity(
        entity_kind=kind,
        key_type=KeyType.LEGACY_ASSET,
        canonical_key=build_entity_key(
            KeyType.LEGACY_ASSET, scope_key,
            {"asset_id": asset.asset_id}),
        confidence_basis="legacy_asset_id")