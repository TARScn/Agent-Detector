"""Shared classification enums (V0.2 design: sections 1.1, 1.2, 5.1, 7).

Everything the product can *claim* about an Agent is an enum here, so the UI
and the API can never invent a state the backend has not modelled: capability
levels, protection status, decisions and risk levels all come from these
values.
"""
from enum import Enum


class AssetType(str, Enum):
    AGENT_CLIENT = "AGENT_CLIENT"
    AGENT_RUNTIME = "AGENT_RUNTIME"
    AGENT_SERVICE = "AGENT_SERVICE"
    AGENT_PLATFORM = "AGENT_PLATFORM"
    MCP_SERVER = "MCP_SERVER"
    LLM_SERVICE = "LLM_SERVICE"
    AI_APPLICATION = "AI_APPLICATION"
    UNKNOWN = "UNKNOWN"


class AssetState(str, Enum):
    """States are intentionally not mutually exclusive; one asset can carry several."""

    INSTALLED = "INSTALLED"
    CONFIGURED = "CONFIGURED"
    RUNNING = "RUNNING"
    BEHAVIOR_SUSPECTED = "BEHAVIOR_SUSPECTED"
    EXECUTION_CONFIRMED = "EXECUTION_CONFIRMED"
    UNKNOWN = "UNKNOWN"


class EvidenceKind(str, Enum):
    PROCESS = "process"
    LISTENING_SOCKET = "listening_socket"
    FILE_METADATA = "file_metadata"
    FILE_CONTENT_KEYS = "file_content_keys"
    INSTALL_METADATA = "install_metadata"
    DEPENDENCY_METADATA = "dependency_metadata"
    HTTP_PROBE = "http_probe"
    NATIVE_HOOK = "native_hook"
    SYSMON = "sysmon"
    CONTAINER_METADATA = "container_metadata"


class VersionSource(str, Enum):
    PACKAGE_METADATA = "package-metadata"
    INSTALLER_METADATA = "installer-metadata"
    LOCKED = "locked"
    DECLARED = "declared"
    IMAGE_TAG = "image-tag"
    PROCESS_CLAIM = "process-claim"
    UNKNOWN = "unknown"


class OperationalMode(str, Enum):
    """The three product modes (design section 1.1)."""

    DISCOVERY = "discovery"
    MONITOR = "monitor"
    PROTECT = "protect"


class SupportLevel(str, Enum):
    """Planned implementation priority, never a claim of shipped capability."""

    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    PLANNED = "PLANNED"        # 待适配
    UNVERIFIED = "UNVERIFIED"  # 待验证


class ProtectionStatus(str, Enum):
    """What the product is actually able to do about one Agent right now."""

    PROTECTED = "PROTECTED"        # Hook installed and observed to fire
    MONITOR_ONLY = "MONITOR_ONLY"  # observed passively, no pre-execution say
    DEGRADED = "DEGRADED"          # hook configured earlier, config now missing
    UNPROTECTED = "UNPROTECTED"    # neither hooks nor a collector covers it
    UNKNOWN = "UNKNOWN"


class HookState(str, Enum):
    """Installation state of one Agent's native pre-tool hook."""

    INSTALLED = "INSTALLED"
    NOT_INSTALLED = "NOT_INSTALLED"
    PARTIAL = "PARTIAL"        # config present but missing some event entries
    CONFLICT = "CONFLICT"      # config file unreadable / invalid JSON
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"


class HookEvent(str, Enum):
    PRE_TOOL_USE = "pre_tool_use"
    POST_TOOL_USE = "post_tool_use"
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    NOTIFICATION = "notification"


class Decision(str, Enum):
    """Policy verdict for one tool call (design section 5.1)."""

    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"
    AUDIT = "audit"
    ERROR = "error"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ExecutionStatus(str, Enum):
    """`decision=allow` never implies execution succeeded (design section 7)."""

    PENDING = "pending"
    ALLOWED = "allowed"
    BLOCKED_BY_HOOK = "blocked_by_hook"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"


class PolicyScope(str, Enum):
    TOOL_CALL = "tool_call"
    FILESYSTEM = "filesystem"
    NETWORK = "network"
    PROCESS = "process"
    CONFIG = "config"


class AlertStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class EventSource(str, Enum):
    """`behavior_events.source`: which channel observed the event."""

    NATIVE_HOOK = "native_hook"
    SYSMON = "sysmon"
    AUDITD = "auditd"
    TETRAGON = "tetragon"
    POLL = "poll"
    NETMON = "netmon"
    SCAN = "scan"