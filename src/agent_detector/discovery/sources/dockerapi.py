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
``get_archive`` tar of a directory and reads member headers as they arrive.

Windows transport reality (verified against a live daemon): abandoning a
GET archive mid-stream — reading one chunk of a probe, or stopping at a
byte/time cap — wedges the container's whole archive channel daemon-side.
The daemon keeps the tar-generation goroutine writing into a pipe nobody
drains; every later archive request for that container (any client, any
connection) then hangs until the daemon gives up on its own minutes later.
``stream.close()`` only returns the connection to the pool — the pipe stays
open, so the daemon never notices. Therefore:

* existence/size checks go through ``HEAD /containers/{id}/archive`` — the
  daemon answers from metadata alone and generates no tar at all;
* a GET archive is only issued for a stat-verified target (a file within
  the read cap, a directory within the byte budget) and is always drained
  to EOF — "stop early" is exactly the failure mode;
* the watchdog (``_call_bounded``) remains as the last resort for a daemon
  that stalls despite all this: npipe read timeouts are unreliable, so
  every operation runs in a daemon thread under a hard deadline, and a
  per-client stall budget stops a fully wedged daemon from leaking threads
  without end.
"""
from __future__ import annotations

import base64
import io
import json
import logging
import queue
import re
import tarfile
import threading
from dataclasses import dataclass

from requests.exceptions import Timeout as RequestsTimeout

from agent_detector.core.config import DOCKER_TIMEOUT_S
from agent_detector.discovery.sources.deps import normalize_name

logger = logging.getLogger(__name__)


class DockerUnavailable(RuntimeError):
    """The daemon (or the docker SDK) is not reachable; callers degrade."""


class DockerStalled(RuntimeError):
    """A Docker API operation blew its hard deadline; its result is unknown.

    Callers must treat "stalled" as "the channel said nothing": the operation
    may or may not have taken effect daemon-side, and absence of container
    assets this round proves nothing (the inventory's lifecycle verdicts are
    skipped when the channel reports a stall).
    """


# Abandoned-watchdog tolerance per client: each stall leaks one daemon thread
# and its pipe connection; past this many the channel gives up entirely.
_STALL_BUDGET = 3


class BoundedClient:
    """docker APIClient plus the watchdog contract used by ``_call_bounded``.

    The duck-typed attributes (``timeout`` / ``stall_budget`` / ``stalls``)
    are what the transport layer reads; a client without them (test fakes)
    gets the module defaults and unlimited budget.
    """

    def __init__(self, api, timeout: float, stall_budget: int = _STALL_BUDGET):
        self.api = api
        self.timeout = timeout
        self.stall_budget = stall_budget
        self.stalls = 0

    def __getattr__(self, name):
        # Delegate everything else (close, version checks, ...) to the SDK.
        return getattr(self.api, name)


def _call_bounded(client, fn, timeout: float | None = None):
    """Run ``fn()`` under a hard deadline, since npipe reads cannot time out.

    The operation runs in a daemon thread; past the deadline the thread is
    abandoned (it leaks, bounded by the stall budget) and DockerStalled is
    raised. Deadline comes from the client's ``timeout`` attribute when it
    carries one, else DOCKER_TIMEOUT_S — so plain test fakes behave exactly
    like direct calls.
    """
    wait = timeout if timeout is not None else (getattr(client, "timeout", None)
                                                or DOCKER_TIMEOUT_S)
    budget = getattr(client, "stall_budget", None)
    if budget is not None and getattr(client, "stalls", 0) >= budget:
        raise DockerStalled("docker 通道连续失联达到上限，已熔断")
    done: queue.SimpleQueue = queue.SimpleQueue()

    def runner():
        try:
            done.put((True, fn()))
        except BaseException as exc:  # re-raised on the caller's thread
            done.put((False, exc))

    threading.Thread(target=runner, daemon=True,
                     name="docker-watchdog").start()
    try:
        ok, payload = done.get(timeout=wait)
    except queue.Empty:
        if hasattr(client, "stalls"):
            client.stalls += 1
        raise DockerStalled(f"docker 调用超过 {wait:g}s 硬期限，已放弃该操作") from None
    if hasattr(client, "stalls"):
        client.stalls = 0  # 连续失联计数：一次成功即清零，个别容器楔死不连坐
    if not ok:
        raise payload
    return payload


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
        api = docker.from_env(timeout=timeout).api
    except Exception as exc:  # daemon down / no pipe / bad DOCKER_HOST
        raise DockerUnavailable(f"docker daemon 不可达: {exc}") from exc
    return BoundedClient(api, timeout)


# ---------------------------------------------------------------------------
# Read-only API calls
# ---------------------------------------------------------------------------

def list_all_containers(client, limit: int) -> list[ContainerBrief]:
    """Every container known to the daemon, running or stopped (all=True)."""
    return _call_bounded(client, lambda: _list_all_containers_raw(client, limit))


def _list_all_containers_raw(client, limit: int) -> list[ContainerBrief]:
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
    return _call_bounded(client, lambda: client.inspect_container(container_id))


_CMD_COLUMN_NAMES = ("command", "args", "cmd")


def container_top(client, container_id: str,
                  ps_args: str = "-eo pid,ppid,args") -> list[TopProcess]:
    """Container-internal processes via ``docker top`` (read-only).

    Busybox-based images (alpine) ship a ps without ``-eo`` support; when the
    custom format fails, retry the daemon's default (``-ef``), whose
    UID/PID/PPID/.../CMD columns the parser below accepts unchanged.
    """
    return _call_bounded(client, lambda: _container_top_raw(client, container_id,
                                                            ps_args))


def _container_top_raw(client, container_id: str,
                       ps_args: str = "-eo pid,ppid,args") -> list[TopProcess]:
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


def stat_path(client, container_id: str, path: str) -> dict | None:
    """HEAD archive: existence + size without generating a tar.

    The daemon answers from filesystem metadata alone, so this is safe to
    issue freely — unlike GET, there is no tar generation that could be
    abandoned mid-flight. Returns the stat dict ({size, mode, ...}) or None
    when the path does not exist (or is denied: the existence of a secret
    must not be testable either).
    """
    if path_denied(path):
        return None
    return _call_bounded(client, lambda: _stat_path_raw(client, container_id, path))


def _stat_path_raw(client, container_id: str, path: str) -> dict | None:
    timeout = getattr(client, "timeout", None) or DOCKER_TIMEOUT_S
    try:
        resp = client.head(client._url("/containers/{0}/archive", container_id),
                           params={"path": path}, timeout=timeout)
    except Exception as exc:  # NotFound dominates; anything else counts as "no"
        logger.debug("container %s: stat %s failed: %s",
                     container_id[:12], path, exc)
        return None
    if resp.status_code != 200:
        return None
    encoded = resp.headers.get("x-docker-container-path-stat") or ""
    try:
        return json.loads(base64.b64decode(encoded).decode("utf-8"))
    except (ValueError, TypeError):
        logger.debug("container %s: stat %s: unreadable stat header",
                     container_id[:12], path)
        return None


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
    """Cheap existence check via HEAD stat — no tar is ever generated.

    Used to locate ``python3.X`` site-packages and config roots without a
    readdir; each miss costs one 404 round-trip. Existence probing is gated
    by the denylist only (existence of a secret must not be testable
    either); the filename allowlist does not apply, directories would
    otherwise never pass.
    """
    if path_denied(path):
        return False
    return stat_path(client, container_id, path) is not None


def read_container_file(client, container_id: str, path: str,
                        max_bytes: int) -> bytes | None:
    """One allowlisted file, capped. None when absent, denied or oversized.

    The size is stat-verified before the GET, so the archive stream is
    always drained to EOF — abandoning it mid-tar would wedge the
    container's archive channel (see the module docstring).
    """
    return _call_bounded(client, lambda: _read_container_file_raw(
        client, container_id, path, max_bytes))


def _read_container_file_raw(client, container_id: str, path: str,
                             max_bytes: int) -> bytes | None:
    if not read_allowed(path):
        logger.debug("container %s: read denied by policy: %s",
                     container_id[:12], path)
        return None
    stat = _stat_path_raw(client, container_id, path)
    if stat is None:
        return None
    if int(stat.get("size") or 0) > max_bytes + 16384:
        logger.info("container %s: %s exceeds read cap, skipped",
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
            # 单文件的 stat 是准确的，这里只是兜底（stat 与实际不符时宁可
            # 多排干，也不能把内存读爆）。
            if len(buf) > max_bytes + 65536:
                logger.warning("container %s: %s grew past the stat size, "
                               "draining", container_id[:12], path)
                _drain_to_eof(stream, 32 * max_bytes + (1 << 20))
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
                       byte_cap: int, time_cap: float,
                       stall_grace: float | None = None,
                       ) -> list[tuple[str, str, str]]:
    """(normalized_name, version, member_path) for every installed dist in a
    site-packages directory, from the METADATA header blocks.

    The directory size is stat-verified first: when it exceeds ``byte_cap``
    the enumeration is skipped entirely (logged; declared dependencies still
    identify frameworks) because the only alternatives are draining a
    multi-hundred-MB tar or abandoning it mid-generation — which on npipe
    wedges the container's archive channel. Within budget, the archive is
    always drained to EOF; there is deliberately no "interest satisfied,
    stop early" exit any more. Versions come from the METADATA header block
    only; unknown names yield nothing.

    Returns a list: the whole drain runs inside the watchdog with a hard
    deadline of ``time_cap + stall_grace`` (the npipe failure mode is a read
    that never returns, which no in-stream cap could notice). ``stall_grace``
    defaults to ``min(30, time_cap)`` so the deadline scales with the budget.
    """
    grace = min(30.0, time_cap) if stall_grace is None else stall_grace

    def collect() -> list[tuple[str, str, str]]:
        return list(_iter_dist_metadata_raw(client, container_id, site_packages,
                                            interest=interest, byte_cap=byte_cap))
    return _call_bounded(client, collect, timeout=time_cap + grace)


def _iter_dist_metadata_raw(client, container_id: str, site_packages: str, *,
                            interest: frozenset[str] | set[str],
                            byte_cap: int):
    stat = _stat_path_raw(client, container_id, site_packages)
    if stat is None:
        return
    size = int(stat.get("size") or 0)
    if size > byte_cap:
        logger.info("container %s: %s is %d bytes (cap %d), "
                    "installed-metadata enumeration skipped",
                    container_id[:12], site_packages, size, byte_cap)
        return
    try:
        stream, _stat = _archive_stream(client, container_id, site_packages)
    except Exception as exc:
        logger.debug("container %s: archive %s unavailable: %s",
                     container_id[:12], site_packages, exc)
        return
    try:
        # Drain to EOF unconditionally: the byte cap is a backstop for a
        # stat that lied about the directory size — and tripping it must
        # NOT abandon the stream (that wedges the container's archive
        # channel on npipe); keep the daemon's writer fed to EOF instead,
        # keeping whatever metadata was parsed before the cap.
        with tarfile.open(fileobj=_CappedStream(stream, byte_cap), mode="r|") as tar:
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
                yield normalize_name(name), version, member.name
    except _CapReached:
        # 目录的 stat.size 只是 inode 大小（4096），拦不住大树 —— 解析在
        # byte_cap 处收手，但排水必须到 EOF（实测 dify 的 2.1GB venv，
        # 中途放弃会把容器归档通道楔死，排干只要几十秒且容器毫发无损）。
        logger.warning("container %s: %s parse capped, draining the rest",
                       container_id[:12], site_packages)
        _drain_to_eof(stream, 32 * byte_cap)
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
    """Bridge a docker archive stream into tarfile, enforcing a byte cap.

    tarfile skips member bodies by reading them, so every byte the daemon
    sends passes through here. The cap is a backstop against a stat that
    lied about the directory size — within-budget drains end at EOF on
    their own; tripping this means the archive was abandoned mid-stream.
    """

    def __init__(self, chunks, byte_cap: int):
        super().__init__()
        self._chunks = chunks
        self._remaining = byte_cap
        self._buffer = b""

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
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


def _drain_to_eof(stream, ceiling: int) -> None:
    """Keep the daemon's archive writer fed after giving up on parsing.

    Abandoning a GET mid-tar wedges the container's archive channel on
    npipe (the daemon never notices the detached stream) — so when a cap
    trips, read on and discard until EOF instead. ``ceiling`` bounds the
    extra volume; past it the stream is genuinely abandoned and the next
    operations on this container degrade through the watchdog.
    """
    drained = 0
    try:
        for chunk in stream:
            drained += len(chunk)
            if drained > ceiling:
                logger.warning("archive drain ceiling exceeded (%d bytes); "
                               "container archive channel may wedge", ceiling)
                break
    except Exception:
        pass


def _close_stream(stream) -> None:
    try:
        stream.close()
    except Exception:  # no close() on plain iterators; daemon sees the EOF anyway
        pass
