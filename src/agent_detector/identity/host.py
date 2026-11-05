"""Host identity: a locally assigned UUID plus verifiable platform anchors.

The UUID is the primary key because platform fields change (machine-id can be
regenerated, Windows MachineGuid can be cloned). Anchors are kept as hashes so
an operator can audit which platform fact backed the identity without storing
raw machine identifiers. Cloned images remain an explicit single-host limit:
if both the installation UUID and the anchor are cloned, offline detection
cannot tell the machines apart.
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

from agent_detector.identity.canonical import digest, now_iso

_STATE_VERSION = 1
_MACHINE_ID_PATHS = ("/etc/machine-id", "/var/lib/dbus/machine-id")


class HostIdentityError(RuntimeError):
    """The identity state file exists but cannot be trusted."""


@dataclass(frozen=True)
class HostAnchor:
    """One hashed platform fact that supports this host identity."""

    claim_type: str
    value_hash: str
    source: str


@dataclass(frozen=True)
class HostIdentity:
    host_key: str
    identity_version: int
    identity_basis: str
    installation_id: str
    trust_state: str
    detector_local: bool
    first_seen: str
    last_seen: str
    identity_verified_at: str | None
    anchors: tuple[HostAnchor, ...] = ()

    @property
    def scope_key(self) -> str:
        return self.host_key


class HostIdentityStore:
    """Read, create and persist the host identity.

    ``platform`` and ``env`` are injectable so tests can exercise the store
    without touching the real machine or process environment.
    """

    def __init__(self, state_path: Path, *, platform: str | None = None,
                 env: dict[str, str] | None = None):
        self._path = Path(state_path)
        self._platform = platform or sys.platform
        self._env = os.environ if env is None else env

    @classmethod
    def for_engine(cls, engine) -> "HostIdentityStore":
        """State lives beside the database so a test DB gets its own host."""
        database = getattr(engine.url, "database", None)
        if database and database != ":memory:":
            state_dir = Path(database).parent
        else:
            state_dir = Path(os.getenv("AGENT_DETECTOR_HOST_STATE_DIR",
                                       str(Path.cwd() / "data")))
        state_dir = Path(os.getenv("AGENT_DETECTOR_HOST_STATE_DIR", str(state_dir)))
        return cls(state_dir / "host-identity.json")

    @property
    def path(self) -> Path:
        return self._path

    def resolve(self) -> HostIdentity:
        now = now_iso()
        override = self._env.get("AGENT_DETECTOR_HOST_ID", "").strip()

        # A detector running inside a container must not read the container's
        # machine-id as the host identity. It gets a separate detector-local
        # state file so a mounted host identity is never overwritten.
        if not override and self._in_container():
            return self._resolve_detector_local(now)

        anchors = self._read_anchors()
        state = self._load_from(self._path)

        if override:
            host_key = override
            basis = "operator_override"
            trust = "VERIFIED"
            # A different operator id is a different host identity.
            first_seen = (state.get("first_seen") if state
                          and state.get("host_key") == host_key else now)
            installation_id = ((state or {}).get("installation_id")
                               or str(uuid.uuid4()))
            detector_local = False
        elif state:
            host_key = state["host_key"]
            basis = state.get("identity_basis", "installation_uuid")
            trust = state.get("trust_state", "UNVERIFIED")
            first_seen = state.get("first_seen", now)
            installation_id = state.get("installation_id") or str(uuid.uuid4())
            detector_local = bool(state.get("detector_local", False))
        else:
            host_key = str(uuid.uuid4())
            installation_id = str(uuid.uuid4())
            basis = ("platform_and_installation" if anchors
                     else "installation_uuid")
            trust = "VERIFIED" if anchors else "UNVERIFIED"
            first_seen = now
            detector_local = False

        identity = HostIdentity(
            host_key=host_key,
            identity_version=_STATE_VERSION,
            identity_basis=basis,
            installation_id=installation_id,
            trust_state=trust,
            detector_local=detector_local,
            first_seen=first_seen,
            last_seen=now,
            identity_verified_at=now if trust == "VERIFIED" else None,
            anchors=tuple(anchors),
        )
        self._save_to(self._path, identity)
        return identity

    def _resolve_detector_local(self, now: str) -> HostIdentity:
        path = self._path.with_name(self._path.name + ".detector-local")
        state = self._load_from(path)
        host_key = state.get("host_key") or str(uuid.uuid4())
        installation_id = state.get("installation_id") or str(uuid.uuid4())
        identity = HostIdentity(
            host_key=host_key,
            identity_version=_STATE_VERSION,
            identity_basis="detector_local",
            installation_id=installation_id,
            trust_state="UNVERIFIED",
            detector_local=True,
            first_seen=state.get("first_seen", now),
            last_seen=now,
            identity_verified_at=None,
            anchors=(),
        )
        self._save_to(path, identity)
        return identity

    # -- state file ---------------------------------------------------------

    def _load_from(self, path: Path) -> dict:
        try:
            raw = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise HostIdentityError(f"cannot read host identity: {exc}") from exc
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise HostIdentityError(
                f"host identity state is not valid JSON: {path}") from exc
        if payload.get("version") != _STATE_VERSION:
            raise HostIdentityError(
                f"unsupported host identity version: {payload.get('version')!r}")
        if not isinstance(payload.get("host_key"), str) or not payload["host_key"]:
            raise HostIdentityError("host identity state has no host_key")
        return payload

    def _save_to(self, path: Path, identity: HostIdentity) -> None:
        payload = {
            "version": _STATE_VERSION,
            "host_key": identity.host_key,
            "installation_id": identity.installation_id,
            "identity_basis": identity.identity_basis,
            "trust_state": identity.trust_state,
            "detector_local": identity.detector_local,
            "first_seen": identity.first_seen,
            "last_seen": identity.last_seen,
            "identity_verified_at": identity.identity_verified_at,
            "anchors": [
                {"claim_type": anchor.claim_type,
                 "value_hash": anchor.value_hash,
                 "source": anchor.source}
                for anchor in identity.anchors
            ],
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:  # Windows ACLs ignore POSIX mode bits
            pass

    # -- platform anchors ---------------------------------------------------

    def _read_anchors(self) -> list[HostAnchor]:
        anchors: list[HostAnchor] = []
        if self._platform.startswith("linux"):
            for path in _MACHINE_ID_PATHS:
                value = _read_text(path)
                if value:
                    anchors.append(HostAnchor(
                        claim_type="linux_machine_id",
                        value_hash=digest(value, length=32),
                        source=path))
                    break  # the two files normally carry the same value
        elif self._platform.startswith("win"):
            value = _windows_machine_guid()
            if value:
                anchors.append(HostAnchor(
                    claim_type="windows_machine_guid",
                    value_hash=digest(value, length=32),
                    source="HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid"))
        return anchors

    def _in_container(self) -> bool:
        if not self._platform.startswith("linux"):
            return False
        if self._env.get("KUBERNETES_SERVICE_HOST"):
            return True
        if Path("/.dockerenv").exists():
            return True
        cgroup = _read_text("/proc/1/cgroup")
        tokens = ("docker", "kubepods", "containerd", "lxc")
        return bool(cgroup) and any(token in cgroup for token in tokens)


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _windows_machine_guid() -> str:
    try:
        import winreg
        with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography") as key:
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
            return str(value).strip()
    except (ImportError, OSError):
        return ""