"""Persistence for the docker deep-probe cache (T1, image-digest keyed)."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from agent_detector.storage.models import DockerProbeCacheRow, utc_now_iso


def probe_cache_key(engine_key: str, image_id: str, kind: str, spec: str) -> str:
    digest = hashlib.sha256(
        f"{engine_key}|{image_id}|{kind}|{spec}".encode("utf-8")).hexdigest()
    return f"dpb-{digest}"


def _age_seconds(stored: str, now: str) -> float:
    try:
        then = datetime.fromisoformat(stored)
        moment = datetime.fromisoformat(now)
    except (TypeError, ValueError):
        return float("inf")
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return (moment - then).total_seconds()


class DockerProbeCacheRepository:
    """Lookup/save for cached deep-probe payloads.

    Stale rows are simply ignored on lookup and refreshed by the next put;
    there is no background purge — rows are small and the key space is
    bounded by the distinct paths the read gates allow.
    """

    def __init__(self, session: Session):
        self._session = session

    def lookup(self, key: str, *, ttl_s: float,
               now: str | None = None) -> dict[str, Any] | None:
        row = self._session.get(DockerProbeCacheRow, key)
        if row is None:
            return None
        moment = now or utc_now_iso()
        if ttl_s <= 0 or _age_seconds(row.probed_at, moment) > ttl_s:
            return None
        try:
            payload = json.loads(row.payload_json or "{}")
        except ValueError:
            return None
        if not isinstance(payload, dict):
            return None
        row.last_hit_at = moment
        return payload

    def save(self, key: str, *, engine_key: str, image_id: str, kind: str,
             spec: str, payload: dict[str, Any]) -> None:
        now = utc_now_iso()
        row = self._session.get(DockerProbeCacheRow, key)
        encoded = json.dumps(payload, ensure_ascii=False)
        if row is None:
            row = DockerProbeCacheRow(
                cache_key=key, engine_key=engine_key, image_id=image_id,
                kind=kind, spec=spec, payload_json=encoded,
                probed_at=now, last_hit_at=now)
            self._session.add(row)
        else:
            row.engine_key = engine_key
            row.image_id = image_id
            row.kind = kind
            row.spec = spec
            row.payload_json = encoded
            row.probed_at = now
            row.last_hit_at = now
        self._session.flush()
