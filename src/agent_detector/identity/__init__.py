"""P0-A identity foundation: host, engine, process birth and entity keys.

The legacy ``core.identity.build_asset_id`` remains the read-path identity.
This package adds the canonical, versioned identities that the aggregation
layer will use; P0-A writes them in shadow mode only.
"""

from agent_detector.identity.canonical import (
    IDENTITY_VERSION,
    canonical_json,
    digest,
    now_iso,
)
from agent_detector.identity.engine import EngineIdentity, resolve_engine_identity
from agent_detector.identity.entity import (
    EntityKind,
    KeyType,
    LegacyIdentity,
    build_entity_key,
    canonical_scope_path,
    legacy_identity_for_asset,
)
from agent_detector.identity.host import (
    HostAnchor,
    HostIdentity,
    HostIdentityError,
    HostIdentityStore,
)
from agent_detector.identity.process import (
    ProcessBirth,
    build_process_birth,
    match_process_birth,
    read_linux_birth,
)

__all__ = [
    "IDENTITY_VERSION",
    "EngineIdentity",
    "EntityKind",
    "HostAnchor",
    "HostIdentity",
    "HostIdentityError",
    "HostIdentityStore",
    "KeyType",
    "LegacyIdentity",
    "ProcessBirth",
    "build_entity_key",
    "build_process_birth",
    "canonical_scope_path",
    "canonical_json",
    "digest",
    "legacy_identity_for_asset",
    "match_process_birth",
    "now_iso",
    "read_linux_birth",
    "resolve_engine_identity",
]