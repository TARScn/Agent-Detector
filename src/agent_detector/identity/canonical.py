"""Canonical serialization and hashing for identity keys.

Identity keys are stable strings, never bare ``"|"``-joined values: the same
payload must hash identically on every host and every implementation, so the
JSON is key-sorted with compact separators and no locale-dependent formatting.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

# Bump when the payload shape or normalization rules change. Old keys stay in
# ``entity_keys`` with their own version; new keys are written beside them.
IDENTITY_VERSION = 1


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def digest(text: str, *, length: int = 24) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:length]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")