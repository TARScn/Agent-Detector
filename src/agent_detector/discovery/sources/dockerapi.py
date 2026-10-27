"""Read-only Docker API transport for container discovery (Docker Core).

Exactly four call shapes are ever issued, all read-only: containers/list,
containers/{id}/inspect, containers/{id}/top and containers/{id}/archive in
the download direction only. ``docker exec`` is never used — a scanned
container must not know it is being scanned, and executing anything inside
a foreign container is out of the question (设计第四节).

Every byte read from a container filesystem passes two mandatory gates:

* an allowlist: only manifests, lockfiles and package-metadata file names
  are worth reading for agent identification;
* a denylist: path fragments that must never be read even if an allowlist
  rule would otherwise match (secrets, keys, tokens, credentials).

The Docker API has no readdir. Directory enumeration streams the
``get_archive`` tar of a directory and reads member headers as they arrive;
closing the stream early makes the daemon stop generating, so "stop once
the interest set is satisfied" genuinely saves traffic. Byte and time caps
bound the worst case (a multi-GB site-packages tree).
"""
from __future__ import annotations

import io
import logging
import re
import tarfile
import time
from dataclasses import dataclass

from requests.exceptions import Timeout as RequestsTimeout

from agent_detector.discovery.sources.deps import normalize_name

logger = logging.getLogger(__name__)


class DockerUnavailable(RuntimeError):
    """The daemon (or the docker SDK) is not reachable; callers degrade."""


@dataclass(frozen=True)
class ContainerBrief:
    """What containers/list returns; enough for candidate screening."""

    container_id: str
    name: str
    image: str
    state: str
    command: str = ""
    created: int = 0
    labels: dict[str, str] | None = None

    @property
    def short_id(self) -> str:
        return self.container_id[:12]


@dataclass(frozen=True)
class TopProcess:
    """One row of ``docker top``: the container-internal view of a process."""

    pid: int
    ppid: int
    cmdline: str


# ---------------------------------------------------------------------------
# Read gates: allowlist + denylist. Mandatory, not configurable per scan.
# ---------------------------------------------------------------------------

# Path fragments that must never be read (or probed) on any container. The
# bias is over-blocking: a package named "tokenizers" loses its package.json
# read rather than any secret risking a read.
_DENY_FRAGMENTS: tuple[str, ...] = (
    ".env", "secret", "credential", "passwd", "shadow", "token",
    "id_rsa", "id_ed25519", "id_ecdsa", ".pem", ".p12", ".pfx", ".key",
    "password", ".git/", ".ssh/",
)

# Exact base names readable anywhere inside a container.
_ALLOW_BASE_NAMES: frozenset[str] = frozenset({
    "pyproject.toml", "uv.lock", "poetry.lock",
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "openclaw.json",
})

_REQUIREMENTS_RE = re.compile(r"^requirements.*\.txt$")
_SETTINGS_RE = re.compile(r"/\.(claude|openclaw|codex|cursor)/settings\.json$")


def path_denied(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    return any(fragment in normalized for fragment in _DENY_FRAGMENTS)


def read_allowed(path: str) -> bool:
    """True when this exact path may be read from a container."""
    normalized = path.replace("\\", "/").lower()
    if path_denied(normalized):
        return False
    base = normalized.rsplit("/", 1)[-1]
    if base in _ALLOW_BASE_NAMES:
        return True
    if _REQUIREMENTS_RE.match(base):
        return True
    # Installed Python package metadata, e.g.
    # /usr/local/lib/python3.12/site-packages/langgraph-0.2.0.dist-info/METADATA
    if base == "metadata" and ".dist-info/" in normalized:
        return True
    # Known agent-client config directories.
    if base == "settings.json" and _SETTINGS_RE.search(normalized):
        return True
    return False


# ---------------------------------------------------------------------------
# Client construction
# ---------------------------------------------------------------------------

def build_client(timeout: float):
    """Low-level APIClient from the environment (npipe on Windows, socket on
    Linux). Raises DockerUnavailable when the SDK is missing or the daemon
    does not answer — callers treat that as "no docker channel", not an error.
    """
    try:
        import docker
    except ImportError as exc:
        raise DockerUnavailable("docker SDK 未安装") from exc
    try:
        return docker.from_env(timeout=timeout).api
    except Exception as exc:  # daemon down / no pipe / bad DOCKER_HOST
        raise DockerUnavailable(f"docker daemon 不可达: {exc}") from exc


# ---------------------------------------------------------------------------
# Read-only API calls
# ---------------------------------------------------------------------------

def list_all_containers(client, limit: int) -> list[ContainerBrief]:
    """Every container known to the daemon, running or stopped (all=True)."""
    raw = client.containers(all=True, limit=limit)
    containers: list[ContainerBrief] = []
    for item in raw or []:
        names = item.get("Names") or [""]
        containers.append(ContainerBrief(
            container_id=item.get("Id", ""),
            name=(names[0] or "").lstrip("/"),
            image=item.get("Image", ""),
            state=str(item.get("State", "")).lower(),
            command=str(item.get("Command") or ""),
            created=int(item.get("Created") or 0),
            labels=dict(item.get("Labels") or {}),
        ))
    return containers


def inspect_container(client, container_id: str) -> dict:
    """Full inspect payload (State.StartedAt, Config.WorkingDir, ...)."""
    return client.inspect_container(container_id)


_CMD_COLUMN_NAMES = ("command", "args", "cmd")


def container_top(client, container_id: str,
                  ps_args: str = "-eo pid,ppid,args") -> list[TopProcess]:
    """Container-internal processes via ``docker top`` (read-only).

    Busybox-based images (alpine) ship a ps without ``-eo`` support; when the
    custom format fails, retry the daemon's default (``-ef``), whose
    UID/PID/PPID/.../CMD columns the parser below accepts unchanged.
    """
    try:
        data = client.top(container_id, ps_args=ps_args)
    except Exception:
        if not ps_args:
            raise
        data = client.top(container_id)
    titles = [str(title).lower() for title in data.get("Titles") or []]
    try:
        pid_at = titles.index("pid")
        ppid_at = titles.index("ppid")
        cmd_at = next(titles.index(name) for name in _CMD_COLUMN_NAMES
                      if name in titles)
    except (ValueError, StopIteration):
        logger.warning("container %s: unexpected top titles %s",
                       container_id[:12], titles)
        return []
    processes: list[TopProcess] = []
    for row in data.get("Processes") or []:
        try:
            processes.append(TopProcess(pid=int(row[pid_at]),
                                        ppid=int(row[ppid_at]),
                                        cmdline=str(row[cmd_at])))
        except (IndexError, TypeError, ValueError):
            continue
    return processes


def _archive_stream(client, container_id: str, path: str):
    """One get_archive call, retried once on a read timeout.

    Probing a big directory makes the daemon start generating a huge tar; we
    detach after the first chunk, but the daemon notices the broken pipe with
    some delay, and the requests queued right behind it can time out once.
    A single retry clears that congestion (observed on n8n's ~500MB package
    tree); genuine 404s fail fast either way.
    """
    try:
        return client.get_archive(container_id, path)
    except RequestsTimeout:
        logger.info("container %s: archive %s timed out once, retrying",
                    str(container_id)[:12], path)
        return client.get_archive(container_id, path)


def probe_path(client, container_id: str, path: str) -> bool:
    """Cheap existence check: open the archive, read one chunk, stop.

    Used to locate ``python3.X`` site-packages without a readdir — each miss
    costs one 404 round-trip, each hit one tar header. Existence probing is
    gated by the denylist only (existence of a secret must not be testable
    either); the filename allowlist does not apply, directories would
    otherwise never pass.
    """
    if path_denied(path):
        return False
    try:
        stream, _stat = _archive_stream(client, container_id, path)
    except Exception:  # NotFound dominates; anything else counts as "no"
        return False
    try:
        for _chunk in stream:
            break
    except Exception:
        pass
    _close_stream(stream)
    return True


def read_container_file(client, container_id: str, path: str,
                        max_bytes: int) -> bytes | None:
    """One allowlisted file, capped. None when absent, denied or oversized."""
    if not read_allowed(path):
        logger.debug("container %s: read denied by policy: %s",
                     container_id[:12], path)
        return None
    try:
        stream, _stat = _archive_stream(client, container_id, path)
    except Exception as exc:
        logger.debug("container %s: get_archive %s failed: %s",
                     container_id[:12], path, exc)
        return None
    try:
        buf = bytearray()
        for chunk in stream:
            buf.extend(chunk)
            # Tar overhead for one member is ~1KB; anything beyond the content
            # cap plus margin means the file itself is oversized for our use.
            if len(buf) > max_bytes + 65536:
                logger.info("container %s: %s exceeds read cap, skipped",
                            container_id[:12], path)
                return None
        with tarfile.open(fileobj=io.BytesIO(bytes(buf))) as tar:
            for member in tar:
                if not member.isfile():
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                return handle.read(max_bytes)
    except (tarfile.TarError, OSError) as exc:
        logger.debug("container %s: archive %s unreadable: %s",
                     container_id[:12], path, exc)
    finally:
        _close_stream(stream)
    return None


_METADATA_HEADER_BYTES = 16384


def iter_dist_metadata(client, container_id: str, site_packages: str, *,
                       interest: frozenset[str] | set[str],
                       byte_cap: int, time_cap: float):
    """Yield (normalized_name, version, member_path) for every installed dist
    in a site-packages directory, streaming the directory archive.

    Stops early once every interest name has been observed, or when the byte
    or time cap trips — closing the stream, which stops the daemon's tar
    generation. Versions come from the METADATA header block only.
    """
    try:
        stream, _stat = _archive_stream(client, container_id, site_packages)
    except Exception as exc:
        logger.debug("container %s: archive %s unavailable: %s",
                     container_id[:12], site_packages, exc)
        return
    seen: set[str] = set()
    deadline = time.monotonic() + time_cap
    try:
        with tarfile.open(fileobj=_CappedStream(stream, byte_cap, deadline),
                          mode="r|") as tar:
            for member in tar:
                if not member.isfile() or not member.name.endswith("/METADATA"):
                    continue
                if not read_allowed(member.name):
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                text = handle.read(_METADATA_HEADER_BYTES).decode("utf-8", "replace")
                parsed = _name_version_from_headers(text)
                if parsed is None:
                    continue
                name, version = parsed
                normalized = normalize_name(name)
                seen.add(normalized)
                yield normalized, version, member.name
                if interest and interest <= seen:
                    return
    except _CapReached:
        logger.info("container %s: dependency scan of %s stopped by cap",
                    container_id[:12], site_packages)
    except (tarfile.TarError, OSError) as exc:
        logger.debug("container %s: archive %s ended early: %s",
                     container_id[:12], site_packages, exc)
    finally:
        _close_stream(stream)


_HEADER_NAME_RE = re.compile(r"Name:(.+)", re.IGNORECASE)
_HEADER_VERSION_RE = re.compile(r"Version:(.+)", re.IGNORECASE)


def _name_version_from_headers(text: str) -> tuple[str, str] | None:
    """(name, version) from a METADATA header block, None when nameless."""
    name = ""
    version = ""
    for line in text.splitlines():
        if not line.strip():
            break  # headers end at the first blank line
        if not name:
            match = _HEADER_NAME_RE.match(line)
            if match:
                name = match.group(1).strip()
                continue
        if not version:
            match = _HEADER_VERSION_RE.match(line)
            if match:
                version = match.group(1).strip()
    if name:
        return name, version
    return None


class _CapReached(Exception):
    """Internal: a byte or time cap tripped mid-archive."""


class _CappedStream(io.RawIOBase):
    """Bridge a docker archive stream into tarfile, enforcing caps.

    tarfile skips member bodies by reading them, so every byte the daemon
    sends passes through here — the byte cap bounds true network volume, the
    deadline bounds wall time.
    """

    def __init__(self, chunks, byte_cap: int, deadline: float):
        super().__init__()
        self._chunks = chunks
        self._remaining = byte_cap
        self._deadline = deadline
        self._buffer = b""

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if time.monotonic() > self._deadline:
            raise _CapReached
        if size is None or size < 0:
            size = len(self._buffer) + 1048576
        while len(self._buffer) < size:
            try:
                chunk = next(self._chunks)
            except StopIteration:
                break
            self._remaining -= len(chunk)
            if self._remaining < 0:
                raise _CapReached
            self._buffer += chunk
        data, self._buffer = self._buffer[:size], self._buffer[size:]
        return data

    def readinto(self, b) -> int:
        data = self.read(len(b))
        b[:len(data)] = data
        return len(data)


def _close_stream(stream) -> None:
    try:
        stream.close()
    except Exception:  # no close() on plain iterators; daemon sees the EOF anyway
        pass
