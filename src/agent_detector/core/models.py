"""Domain models shared across collectors, detectors and persistence."""
from dataclasses import dataclass, field

from agent_detector.core.enums import (AssetState, AssetType, Decision, EvidenceKind,
                                          HookEvent, HookState, ProtectionStatus, RiskLevel,
                                          VersionSource)


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    name: str
    cmdline: tuple[str, ...] = ()
    create_time: float | None = None
    ppid: int | None = None
    exe: str | None = None
    cwd: str | None = None


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
    # Agent-level extras, filled by discovery/inventory.py for AGENT_CLIENT assets.
    mcp_servers: list[str] = field(default_factory=list)
    config_paths: list[str] = field(default_factory=list)
    executable: str | None = None


# ---------------------------------------------------------------------------
# Self-built agent discovery: process -> project -> dependency evidence.
# A project is a candidate application; a component is one AI-relevant package
# observed in the project's environment. Names only — never file contents.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProjectInfo:
    """One process (or several) resolved to a candidate project directory."""

    project_id: str
    root: str
    name: str
    runtime: str                      # "python" | "node" | "unknown"
    pids: tuple[int, ...] = ()
    executable: str | None = None         # primary process interpreter path
    environment_path: str | None = None   # venv root when the interpreter lives in one
    entry: str | None = None              # entrypoint claim, e.g. "module:app" or script path
    entry_kind: str = "cwd"               # module | script | server-entry | cwd
    container_id: str | None = None       # reserved; container association is out of scope
    resolver_status: str = "resolved"     # resolved | unresolved


@dataclass(frozen=True)
class ComponentInfo:
    """One AI-relevant package seen in a project's dependency metadata."""

    name: str
    version: str                       # "UNKNOWN" when no source could be read
    version_source: VersionSource = VersionSource.UNKNOWN
    source_path: str | None = None

    def to_dict(self) -> dict:
        return {"name": self.name, "version": self.version,
                "version_source": self.version_source.value, "source_path": self.source_path}


# ---------------------------------------------------------------------------
# Agent inventory: one logical asset, several running instances, several
# native sessions (design section 3.4). The asset never carries a PID.
# ---------------------------------------------------------------------------


@dataclass
class AgentInstance:
    """One running process of an Agent asset; PID alone is not an identity."""

    instance_id: str
    asset_id: str
    agent_type: str
    pid: int
    ppid: int | None = None
    process_guid: str | None = None
    process_name: str = ""
    executable: str | None = None
    cmdline: str = ""
    cwd: str | None = None
    started_at: str | None = None
    last_seen_at: str | None = None
    parent_chain: tuple[str, ...] = ()
    status: str = "running"
    evidence: tuple[str, ...] = ()


@dataclass
class AgentSession:
    """A native Agent session, normally learned from hook events."""

    session_id: str
    asset_id: str | None
    agent_type: str
    instance_id: str | None = None
    source: str = "native_hook"
    cwd: str | None = None
    started_at: str | None = None
    ended_at: str | None = None
    event_count: int = 0
    last_tool: str | None = None


@dataclass
class AgentInventoryItem:
    """What the dashboard shows per Agent: identity + capability + protection."""

    asset_id: str
    agent_type: str
    name: str
    vendor: str = ""
    version: VersionInfo = field(default_factory=VersionInfo.unknown)
    states: tuple[AssetState, ...] = ()
    confidence: float = 0.0
    protection: ProtectionStatus = ProtectionStatus.UNKNOWN
    hook_state: HookState = HookState.UNKNOWN
    capabilities: dict[str, str] = field(default_factory=dict)
    executable: str | None = None
    config_paths: tuple[str, ...] = ()
    mcp_servers: tuple[str, ...] = ()
    llm_endpoints: tuple[dict, ...] = ()
    app_id: str | None = None            # self-built: the application this framework runs in
    instance_count: int = 0
    last_seen_at: str | None = None
    notes: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Tool-call pipeline: normalize -> decide -> answer in the Agent's own format
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolCall:
    """Platform-neutral tool call, the only input the policy engine ever sees."""

    agent_type: str
    event_type: HookEvent
    tool_name: str
    tool_input: dict
    session_id: str | None = None
    cwd: str | None = None
    process_guid: str | None = None
    pid: int | None = None
    agent_label: str = ""
    raw_event: str = ""

    @property
    def command(self) -> str | None:
        """Best-effort shell command carried by this call, if any."""
        for key in ("command", "cmd", "script", "shell_command"):
            value = self.tool_input.get(key)
            if isinstance(value, str) and value.strip():
                return value
        return None

    def text_blob(self) -> str:
        """Tool name plus every string argument, for pattern matching."""
        parts = [self.tool_name]
        for value in self.tool_input.values():
            if isinstance(value, str):
                parts.append(value)
            elif isinstance(value, list):
                parts.extend(item for item in value if isinstance(item, str))
        return " ".join(parts)


@dataclass(frozen=True)
class PolicyVerdict:
    """Deterministic outcome of one policy evaluation."""

    decision: Decision
    risk: RiskLevel
    reason: str
    matched_rules: tuple[str, ...] = ()
    policy_id: str | None = None
    error: str | None = None

    @property
    def blocked(self) -> bool:
        return self.decision in (Decision.DENY, Decision.ERROR)
