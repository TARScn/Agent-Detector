"""Shared classification enums (plan sections 2.1, 2.3, 4.3)."""
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
    HTTP_PROBE = "http_probe"


class VersionSource(str, Enum):
    PACKAGE_METADATA = "package-metadata"
    INSTALLER_METADATA = "installer-metadata"
    PROCESS_CLAIM = "process-claim"
    UNKNOWN = "unknown"
