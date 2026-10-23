"""MCP configuration discovery (design section 1.3: Agent 详情页 shows MCP 配置).

Only *server names and transport* are read from the Agent's own config files —
never commands, arguments, environment blocks or tokens, which is where MCP
credentials live. A local stdio MCP server is exactly the case where network
traffic proves nothing (design section 10), so the honest source for "which MCP
servers is this Agent configured with" is this file-level inventory.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - 3.10 fallback
    tomllib = None  # type: ignore[assignment]

# Agent type per config path segment, used to attach a server to an Agent asset.
# Both directories and the home-root files (`~/.claude.json`) appear here.
_OWNER_BY_SEGMENT = {".claude": "claude_code", ".claude.json": "claude_code",
                     ".cursor": "cursor", ".codex": "codex_cli"}

_JSON_SOURCES = (
    ("~/.claude.json", ("mcpServers",)),
    ("~/.claude/settings.json", ("mcpServers",)),
    ("~/.cursor/mcp.json", ("mcpServers",)),
)


@dataclass(frozen=True)
class McpServer:
    name: str
    transport: str
    agent_type: str
    source: str

    def to_dict(self) -> dict:
        return {"name": self.name, "transport": self.transport,
                "agent_type": self.agent_type, "source": self.source}


def scan_mcp_servers(home: Path | None = None) -> list[McpServer]:
    """Configured MCP servers for the target user's home (names only)."""
    base = Path(home) if home else Path.home()
    found: dict[tuple[str, str], McpServer] = {}
    for relative, keys in _JSON_SOURCES:
        path = base / relative.lstrip("~/")
        data = _read_json(path)
        for key in keys:
            for server in _servers_from_mapping(data.get(key), path, base):
                found.setdefault((server.agent_type, server.name), server)
    toml_path = base / ".codex" / "config.toml"
    for server in _servers_from_toml(toml_path, base):
        found.setdefault((server.agent_type, server.name), server)
    return sorted(found.values(), key=lambda item: (item.agent_type, item.name))


def for_agent(servers: list[McpServer], agent_type: str) -> list[dict]:
    return [server.to_dict() for server in servers if server.agent_type == agent_type]


def _read_json(path: Path) -> dict:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _servers_from_mapping(mapping, path: Path, home: Path) -> list[McpServer]:
    if not isinstance(mapping, dict):
        return []
    owner = _owner_for(path, home)
    result: list[McpServer] = []
    for name, spec in mapping.items():
        if not isinstance(name, str):
            continue
        transport = "unknown"
        if isinstance(spec, dict):
            if spec.get("command"):
                transport = "stdio"
            elif spec.get("url") or spec.get("serverUrl"):
                transport = "http"
        result.append(McpServer(name=name, transport=transport, agent_type=owner,
                                source=str(path)))
    return result


def _servers_from_toml(path: Path, home: Path) -> list[McpServer]:
    if tomllib is None or not path.is_file():
        return []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    table = data.get("mcp_servers") or data.get("mcpServers") or {}
    if not isinstance(table, dict):
        return []
    owner = _owner_for(path, home)
    servers: list[McpServer] = []
    for name, spec in table.items():
        if not isinstance(name, str):
            continue
        transport = "unknown"
        if isinstance(spec, dict):
            if spec.get("command"):
                transport = "stdio"
            elif spec.get("url"):
                transport = "http"
        servers.append(McpServer(name=name, transport=transport, agent_type=owner,
                                 source=str(path)))
    return servers


def _owner_for(path: Path, home: Path) -> str:
    try:
        relative = path.relative_to(home)
    except ValueError:
        return ""
    for part in relative.parts:
        owner = _OWNER_BY_SEGMENT.get(part)
        if owner:
            return owner
    return ""