"""Resolve a host TCP port to the container that publishes it.

A published port is not owned by the workload process on the host: depending
on the daemon's userland-proxy setting the host listener is docker-proxy, or
there is no host listener at all (iptables DNAT). The authoritative mapping is
``NetworkSettings.Ports`` / ``HostConfig.PortBindings`` from the engine, which
this resolver reads (read-only) and caches briefly.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Callable, Iterable

from agent_detector.core.config import (DOCKER_ENABLED, DOCKER_MAX_CONTAINERS,
                                        DOCKER_TIMEOUT_S)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DockerPortBinding:
    container_id: str
    container_port: int
    host_ip: str
    host_port: int
    protocol: str = "tcp"


class DockerPortResolver:
    """Lazy, TTL-cached host-port -> container binding lookup.

    ``loader`` is injectable for tests; production uses the read-only Docker
    API. A failed daemon lookup is cached like an empty result so a monitor
    loop does not hammer an unavailable engine.
    """

    def __init__(self, *, loader: Callable[[], Iterable[DockerPortBinding]] | None = None,
                 cache_seconds: float = 30.0, enabled: bool | None = None):
        self._loader = loader
        self._cache_seconds = max(1.0, cache_seconds)
        self._enabled = DOCKER_ENABLED if enabled is None else enabled
        self._bindings: list[DockerPortBinding] = []
        self._loaded_at = 0.0
        self._cache: dict[tuple[str, int, str], tuple[float, DockerPortBinding | None]] = {}

    def resolve(self, host_ip: str, host_port: int,
                protocol: str = "tcp") -> DockerPortBinding | None:
        if not self._enabled:
            return None
        now = time.monotonic()
        protocol = (protocol or "tcp").lower()
        key = (host_ip, int(host_port), protocol)
        cached = self._cache.get(key)
        if cached is not None and cached[0] > now:
            return cached[1]
        if now - self._loaded_at >= self._cache_seconds:
            self._bindings = self._load()
            self._loaded_at = now
        binding = self._match(host_ip, int(host_port), protocol)
        self._cache[key] = (now + self._cache_seconds, binding)
        return binding

    def _load(self) -> list[DockerPortBinding]:
        if self._loader is not None:
            try:
                return list(self._loader())
            except Exception:
                logger.debug("docker port loader failed", exc_info=True)
                return []
        try:
            return self._load_from_docker()
        except Exception:  # daemon/SDK unavailable: no target verdict
            logger.debug("docker port inspection failed", exc_info=True)
            return []

    @staticmethod
    def _load_from_docker() -> list[DockerPortBinding]:
        from agent_detector.discovery.sources import dockerapi
        # Monitoring must not stall a whole observation window behind a slow daemon.
        client = dockerapi.build_client(min(3.0, DOCKER_TIMEOUT_S))
        bindings: list[DockerPortBinding] = []
        for brief in dockerapi.list_all_containers(client, DOCKER_MAX_CONTAINERS):
            if (brief.state or "").lower() != "running":
                continue
            try:
                info = dockerapi.inspect_container(client, brief.container_id)
            except Exception:
                logger.debug("inspect failed for %s", brief.short_id, exc_info=True)
                continue
            ports = (info.get("NetworkSettings") or {}).get("Ports") or {}
            for container_port_proto, published in ports.items():
                try:
                    port_text, _, protocol = str(container_port_proto).partition("/")
                    container_port = int(port_text)
                except (TypeError, ValueError):
                    continue
                protocol = (protocol or "tcp").lower()
                for item in published or ():
                    try:
                        host_port = int((item or {}).get("HostPort") or 0)
                    except (TypeError, ValueError):
                        continue
                    if host_port <= 0:
                        continue
                    bindings.append(DockerPortBinding(
                        container_id=brief.container_id,
                        container_port=container_port,
                        host_ip=str((item or {}).get("HostIp") or ""),
                        host_port=host_port,
                        protocol=protocol,
                    ))
        return bindings

    def _match(self, host_ip: str, host_port: int,
               protocol: str) -> DockerPortBinding | None:
        for binding in self._bindings:
            if binding.host_port != host_port or binding.protocol != protocol:
                continue
            if _address_matches(binding.host_ip, host_ip):
                return binding
        return None


def _address_matches(binding_ip: str, observed_ip: str) -> bool:
    binding_ip = (binding_ip or "").strip()
    observed_ip = (observed_ip or "").strip()
    if not binding_ip or binding_ip in ("0.0.0.0", "::"):
        return True  # wildcard publish covers loopback and specific addresses
    if binding_ip == observed_ip:
        return True
    # Loopback probes see 127.0.0.1/::1; a binding on the other loopback
    # family still denotes the same local publish.
    return (observed_ip in ("127.0.0.1", "::1")
            and binding_ip in ("127.0.0.1", "::1"))