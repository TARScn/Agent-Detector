"""Docker engine identity, separate from the host that runs the detector.

A local engine may be bound to the host after endpoint validation. A remote
engine (``DOCKER_HOST=tcp://...``) has no verified host mapping; its entities
and process instances use ``engine_key`` as their scope and leave ``host_key``
empty rather than borrowing the detector host's identity.
"""
from __future__ import annotations

from dataclasses import dataclass

from agent_detector.identity.canonical import digest
from agent_detector.identity.host import HostIdentity


@dataclass(frozen=True)
class EngineIdentity:
    engine_key: str
    engine_id_claim: str | None
    endpoint_aliases: tuple[str, ...]
    engine_host_key: str | None
    binding_state: str

    @property
    def scope_key(self) -> str:
        return self.engine_key


def resolve_engine_identity(host_identity: HostIdentity, *,
                            daemon_id: str | None = None,
                            endpoint: str | None = None,
                            endpoint_aliases: tuple[str, ...] = (),
                            is_local: bool = True) -> EngineIdentity:
    """Derive a stable engine key from the daemon id or endpoint.

    ``is_local`` means the caller verified that this endpoint really is the
    local daemon (unix socket / named pipe). A remote endpoint keeps
    ``engine_host_key=None`` until an operator or independent evidence maps it.
    """
    endpoint = (endpoint or "local").strip()
    aliases = tuple(dict.fromkeys((endpoint, *endpoint_aliases)))
    if daemon_id:
        seed = f"daemon:{daemon_id.strip()}"
    elif is_local:
        seed = f"local:{host_identity.host_key}:{endpoint}"
    else:
        seed = f"endpoint:{endpoint}"
    engine_key = "engine:" + digest(seed, length=24)
    return EngineIdentity(
        engine_key=engine_key,
        engine_id_claim=daemon_id.strip() if daemon_id else None,
        endpoint_aliases=aliases,
        engine_host_key=host_identity.host_key if is_local else None,
        binding_state="VERIFIED" if is_local else "UNVERIFIED",
    )