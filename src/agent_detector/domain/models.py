"""Domain models shared across collectors, detectors and persistence."""
from dataclasses import dataclass, field

from agent_detector.domain.enums import AssetState, AssetType, EvidenceKind, VersionSource


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    name: str
    cmdline: tuple[str, ...] = ()
    create_time: float | None = None


@dataclass(frozen=True)
class ListeningSocket:
    host: str
    port: int
    pid: int | None = None


@dataclass(frozen=True)
class HostFacts:
    hostname: str
    processes: tuple[ProcessInfo, ...] = ()
    sockets: tuple[ListeningSocket, ...] = ()


@dataclass(frozen=True)
class FileFact:
    """Filesystem metadata only; never file contents (except top-level JSON key names)."""

    path: str
    exists: bool
    is_dir: bool = False
    size: int | None = None
    mtime: float | None = None
    json_top_keys: tuple[str, ...] = ()


@dataclass(frozen=True)
class Evidence:
    kind: EvidenceKind
    summary: str
    detail: dict[str, object]
    confidence: float = 0.5


@dataclass(frozen=True)
class VersionInfo:
    value: str
    source: VersionSource = VersionSource.UNKNOWN
    confidence: float = 0.0

    @property
    def known(self) -> bool:
        return self.value != "UNKNOWN"

    @classmethod
    def unknown(cls) -> "VersionInfo":
        return cls("UNKNOWN")

    def to_dict(self) -> dict:
        return {"value": self.value, "source": self.source.value, "confidence": self.confidence}


@dataclass
class DetectedAsset:
    """Candidate asset emitted by a detector; merged and persisted by the scan service."""

    asset_id: str
    name: str
    asset_type: AssetType
    states: set[AssetState]
    confidence: float
    version: VersionInfo
    evidence: list[Evidence] = field(default_factory=list)
    running_pids: list[int] = field(default_factory=list)
    listening_ports: list[int] = field(default_factory=list)
    detector: str = ""
