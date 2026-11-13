"""T1 deep-probe cache facade: reuse docker content reads across scans.

The cache stores *content* only — file bytes, existence booleans, dist
metadata tuples — keyed by (engine, image digest, op, spec). Same image
config digest means identical image layers, so the content cannot have
changed while the digest holds. Everything identity-shaped (container ids,
pids, StartedAt, match reasons) stays live per round: the facade is bound
to one container and its callers keep minting their own anchors.

A container without an image digest (old daemon responses, unit-test fakes)
bypasses the cache entirely, as does ``ttl_s <= 0`` — those rounds behave
exactly like the pre-cache channel.
"""

from __future__ import annotations

import base64
import hashlib
import time
from typing import Any, Protocol

from agent_detector.core.config import DOCKER_PROBE_CACHE_TTL_S
from agent_detector.discovery.sources import dockerapi

KIND_PROBE = "probe"
KIND_READ = "read"
KIND_DIST_METADATA = "dist_metadata"


class ProbeCacheStore(Protocol):
    """Minimal contract the DB repository and test fakes both satisfy."""

    def get(self, key: str, *, ttl_s: float) -> dict[str, Any] | None: ...

    def put(self, key: str, *, engine_key: str, image_id: str, kind: str,
            spec: str, payload: dict[str, Any]) -> None: ...


class RepositoryStore:
    """Adapter exposing ``DockerProbeCacheRepository`` as a ProbeCacheStore."""

    def __init__(self, repo):
        self._repo = repo

    def get(self, key: str, *, ttl_s: float) -> dict[str, Any] | None:
        return self._repo.lookup(key, ttl_s=ttl_s)

    def put(self, key: str, *, engine_key: str, image_id: str, kind: str,
            spec: str, payload: dict[str, Any]) -> None:
        self._repo.save(key, engine_key=engine_key, image_id=image_id,
                        kind=kind, spec=spec, payload=payload)


class DictProbeCacheStore:
    """In-memory store mirroring the protocol; for unit tests."""

    def __init__(self):
        self.rows: dict[str, dict[str, Any]] = {}
        self.puts: list[dict[str, Any]] = []

    def get(self, key: str, *, ttl_s: float) -> dict[str, Any] | None:
        row = self.rows.get(key)
        if row is None:
            return None
        if ttl_s <= 0 or time.time() - row["probed_at"] > ttl_s:
            return None
        return row["payload"]

    def put(self, key: str, *, engine_key: str, image_id: str, kind: str,
            spec: str, payload: dict[str, Any]) -> None:
        self.rows[key] = {"engine_key": engine_key, "image_id": image_id,
                          "kind": kind, "spec": spec, "payload": payload,
                          "probed_at": time.time()}
        self.puts.append(self.rows[key])


def build_key(engine_key: str, image_id: str, kind: str, spec: str) -> str:
    digest = hashlib.sha256(
        f"{engine_key}|{image_id}|{kind}|{spec}".encode("utf-8")).hexdigest()
    return f"dpb-{digest}"


class ProbeCache:
    """Cache facade bound to one container's image digest.

    Methods mirror the three deep dockerapi ops. Any miss falls through to
    the real call and stores the result; a disabled facade (no store, no
    digest, TTL 0) degrades to a plain passthrough with no stats.
    """

    def __init__(self, store: ProbeCacheStore | None, *, engine_key: str,
                 image_id: str, container_id: str, ttl_s: float | None = None,
                 stats: dict[str, int] | None = None,
                 now_fn=time.time):
        self._store = store
        self._engine_key = engine_key
        self._image_id = image_id
        self._container_id = container_id
        self._ttl = DOCKER_PROBE_CACHE_TTL_S if ttl_s is None else ttl_s
        self._stats = stats if stats is not None else {}
        self._now = now_fn

    @property
    def enabled(self) -> bool:
        return (self._store is not None and bool(self._image_id)
                and self._ttl > 0)

    @property
    def stats(self) -> dict[str, int]:
        """Live hit/miss/store counters (shared dict across containers)."""
        return self._stats

    @property
    def container_id(self) -> str:
        return self._container_id

    def _key(self, kind: str, spec: str) -> str:
        return build_key(self._engine_key, self._image_id, kind, spec)

    def _hit(self, kind: str, spec: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        payload = self._store.get(self._key(kind, spec), ttl_s=self._ttl)
        if payload is None:
            self._stats["misses"] = self._stats.get("misses", 0) + 1
            return None
        self._stats["hits"] = self._stats.get("hits", 0) + 1
        return payload

    def _save(self, kind: str, spec: str, payload: dict[str, Any]) -> None:
        if not self.enabled:
            return
        self._store.put(self._key(kind, spec), engine_key=self._engine_key,
                        image_id=self._image_id, kind=kind, spec=spec,
                        payload=payload)
        self._stats["stores"] = self._stats.get("stores", 0) + 1

    def probe_path(self, client, container_id: str, path: str) -> bool:
        payload = self._hit(KIND_PROBE, path)
        if payload is not None:
            return bool(payload.get("exists"))
        exists = bool(dockerapi.probe_path(client, container_id, path))
        self._save(KIND_PROBE, path, {"exists": exists})
        return exists

    def read_file(self, client, container_id: str, path: str,
                  max_bytes: int) -> bytes | None:
        spec = f"{path}|{int(max_bytes)}"
        payload = self._hit(KIND_READ, spec)
        if payload is not None:
            if not payload.get("found"):
                return None
            return base64.b64decode(payload.get("content_b64") or "")
        raw = dockerapi.read_container_file(client, container_id, path,
                                            max_bytes)
        self._save(KIND_READ, spec, {
            "found": raw is not None,
            "content_b64": (base64.b64encode(raw).decode("ascii")
                            if raw is not None else ""),
        })
        return raw

    def iter_dist_metadata(self, client, container_id: str, site_packages: str,
                           *, interest, byte_cap: int, time_cap: float,
                           stall_grace: float | None = None,
                           ) -> list[tuple[str, str, str]]:
        # The caps and the interest set decide result completeness, so they
        # are part of the key: a truncated run never serves a fuller one.
        spec = (f"{site_packages}|{int(byte_cap)}|{float(time_cap)}"
                f"|{','.join(sorted(interest))}")
        payload = self._hit(KIND_DIST_METADATA, spec)
        if payload is not None:
            return [tuple(item) for item in payload.get("items") or []]
        items = [list(item) for item in dockerapi.iter_dist_metadata(
            client, container_id, site_packages, interest=interest,
            byte_cap=byte_cap, time_cap=time_cap, stall_grace=stall_grace)]
        self._save(KIND_DIST_METADATA, spec, {"items": items})
        return [tuple(item) for item in items]
