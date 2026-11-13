"""MCP configuration discovery (design section 1.3: Agent 详情页 shows MCP 配置).

Two layers live here:

* :class:`McpConfigReference` — one server entry in one config file, with its
  scope (user/project), transport and a sanitized endpoint. This is the
  persisted identity (``mcp_config_refs``): the same server name declared by
  two different clients stays two references, never one merged row.
* :func:`scan_mcp_servers` / :func:`for_agent` — the legacy name-only view the
  inventory builder consumes, derived from the references.

Privacy (contract C10): only server names, transport and sanitized endpoints
are read — never commands, arguments, environment blocks or tokens, which is
where MCP credentials live. ``config_digest`` is a one-way hash over the raw
spec dict, safe to persist and stable across scans.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from agent_detector.identity.canonical import canonical_json, digest

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - 3.10 fallback
    tomllib = None  # type: ignore[assignment]

from urllib.parse import urlsplit, urlunsplit


@dataclass(frozen=True)
class McpConfigReference:
    """One MCP server entry as declared in one client config file."""

    client: str          # claude_code / cursor / codex_cli / vscode / ...
    name: str
    scope: str           # "user" | "project"
    config_path: str
    transport: str       # stdio / http / sse / streamable_http / unknown
    endpoint: str        # sanitized URL (query/fragment stripped); "" for stdio
    enabled: str         # "true" / "false" / "unknown"
    config_digest: str   # sha256 over the raw spec dict (one-way)

    def to_dict(self) -> dict:
        return {"client": self.client, "name": self.name, "scope": self.scope,
                "config_path": self.config_path, "transport": self.transport,
                "endpoint": self.endpoint, "enabled": self.enabled,
                "config_digest": self.config_digest}


@dataclass(frozen=True)
class McpServer:
    """Legacy name-only view (inventory ``mcp_servers`` lists)."""

    name: str
    transport: str
    agent_type: str
    source: str

    def to_dict(self) -> dict:
        return {"name": self.name, "transport": self.transport,
                "agent_type": self.agent_type, "source": self.source}


@dataclass(frozen=True)
class _ConfigSource:
    """One config file family: path layout + the key chain to the mapping."""

    client: str
    segments: tuple[str, ...]   # path relative to the home / project root
    keys: tuple[str, ...]       # key chain from document root to server mapping
    scope: str                  # "user" | "project"
    fmt: str                    # "json" | "jsonc" | "toml"


# User-scope sources. Platform-specific layouts (VS Code, Claude Desktop)
# register all OS candidates; missing files are skipped silently, so the same
# registry serves the Windows host and the Linux VM.
_USER_SOURCES: tuple[_ConfigSource, ...] = (
    _ConfigSource("claude_code", (".claude.json",), ("mcpServers",), "user", "json"),
    _ConfigSource("claude_code", (".claude", "settings.json"),
                  ("mcpServers",), "user", "json"),
    _ConfigSource("cursor", (".cursor", "mcp.json"), ("mcpServers",), "user", "json"),
    _ConfigSource("codex_cli", (".codex", "config.toml"),
                  ("mcp_servers",), "user", "toml"),
    _ConfigSource("windsurf", (".codeium", "windsurf", "mcp_config.json"),
                  ("mcpServers",), "user", "json"),
    # TODO(mcp): verify the ZCode settings path against a real install.
    _ConfigSource("zcode", (".zcode", "settings.json"), ("mcpServers",), "user", "json"),
    _ConfigSource("vscode", ("AppData", "Roaming", "Code", "User", "settings.json"),
                  ("mcp", "servers"), "user", "jsonc"),
    _ConfigSource("vscode", (".config", "Code", "User", "settings.json"),
                  ("mcp", "servers"), "user", "jsonc"),
    _ConfigSource("vscode", ("Library", "Application Support", "Code", "User",
                             "settings.json"), ("mcp", "servers"), "user", "jsonc"),
    _ConfigSource("claude_desktop", ("AppData", "Roaming", "Claude",
                                     "claude_desktop_config.json"),
                  ("mcpServers",), "user", "json"),
    _ConfigSource("claude_desktop", (".config", "Claude",
                                     "claude_desktop_config.json"),
                  ("mcpServers",), "user", "json"),
    _ConfigSource("claude_desktop", ("Library", "Application Support", "Claude",
                                     "claude_desktop_config.json"),
                  ("mcpServers",), "user", "json"),
)

# Project-scope sources, resolved under every project root the scan saw.
_PROJECT_SOURCES: tuple[_ConfigSource, ...] = (
    _ConfigSource("claude_code", (".mcp.json",), ("mcpServers",), "project", "json"),
    _ConfigSource("cursor", (".cursor", "mcp.json"), ("mcpServers",), "project", "json"),
    _ConfigSource("vscode", (".vscode", "mcp.json"), ("servers",), "project", "jsonc"),
)

# Clients the legacy inventory knows as Agent types; the rest keep their own
# client name (their servers surface via mcp_config_refs, not legacy lists).
_AGENT_TYPE_BY_CLIENT = {"claude_code": "claude_code", "cursor": "cursor",
                         "codex_cli": "codex_cli"}


def scan_mcp_configs(home: Path | None = None,
                     project_roots: Iterable[Path | str] = (),
                     diagnostics: dict[str, str] | None = None,
                     ) -> list[McpConfigReference]:
    """Every MCP server entry visible under ``home`` and the given roots.

    A broken config file degrades to an empty mapping for that file only —
    one unreadable file must not hide the other clients' servers. When
    ``diagnostics`` is passed, it receives ``ok`` / ``unreadable`` /
    ``missing`` per attempted config path, so coverage can keep the failed
    reads apart from the absent ones.
    """
    base = Path(home) if home else Path.home()
    found: dict[tuple[str, str, str], McpConfigReference] = {}

    def _record(source: _ConfigSource, path: Path) -> None:
        mapping = _server_mapping(path, source, diagnostics)
        _refs_from_mapping(source, str(path), mapping, found)

    for source in _USER_SOURCES:
        _record(source, base.joinpath(*source.segments))
    # Claude Code also stores local-scope MCP servers per project under
    # ``projects.<root>.mcpServers`` in ~/.claude.json (what `claude mcp add`
    # writes by default) — distinct from the shareable project-root .mcp.json.
    _record_claude_project_scopes(base.joinpath(".claude.json"), found,
                                  diagnostics)
    roots = sorted({Path(root) for root in project_roots})
    for root in roots:
        if not root.is_dir():
            continue
        for source in _PROJECT_SOURCES:
            _record(source, root.joinpath(*source.segments))
    return sorted(found.values(),
                  key=lambda ref: (ref.client, ref.config_path, ref.name))


def mcp_ref_id(host_key: str, config_path: str, server_name: str) -> str:
    """Stable persistence id: one host + config path + server entry."""
    return "mcr-" + digest(canonical_json({"host": host_key, "path": config_path,
                                           "name": server_name}), length=20)


def reload_stdio_command(ref: McpConfigReference, home: Path | None = None) -> str:
    """Re-read the declaring config and return one stdio ref's command basename.

    C10 boundary: the value exists only in memory, for process correlation —
    it is never persisted, logged or returned by any API. Returns "" for
    non-stdio refs or when the file/entry has changed since the scan.
    """
    if ref.transport != "stdio":
        return ""
    base = Path(home) if home else Path.home()
    if ref.scope == "project" and "::projects:" in ref.config_path:
        file_part, _, project_root = ref.config_path.rpartition("::projects:")
        doc = _read_document(Path(file_part), "json")
        entry = (doc.get("projects") or {}).get(project_root) \
            if isinstance(doc, dict) else None
        mapping = entry.get("mcpServers") if isinstance(entry, dict) else {}
        if not isinstance(mapping, dict):
            mapping = {}
    else:
        source = _source_for(ref)
        if source is None:
            return ""
        mapping = _server_mapping(base.joinpath(*source.segments), source) \
            if ref.scope == "user" else _server_mapping(Path(ref.config_path),
                                                        source)
    spec = mapping.get(ref.name)
    command = spec.get("command") if isinstance(spec, dict) else None
    if not isinstance(command, str) or not command:
        return ""
    return command.replace("\\", "/").rsplit("/", 1)[-1]


def _source_for(ref: McpConfigReference) -> _ConfigSource | None:
    """Registry source whose path layout matches the ref's config path."""
    for source in (*_USER_SOURCES, *_PROJECT_SOURCES):
        if source.client != ref.client or source.scope != ref.scope:
            continue
        layout = str(Path(*source.segments))
        if ref.config_path.replace("\\", "/").endswith(layout.replace("\\", "/")):
            return source
    return None


def legacy_servers(refs: Iterable[McpConfigReference]) -> list[McpServer]:
    """Derive the legacy name-only view from references."""
    found: dict[tuple[str, str], McpServer] = {}
    for ref in refs:
        agent_type = _AGENT_TYPE_BY_CLIENT.get(ref.client, ref.client)
        found.setdefault((agent_type, ref.name),
                         McpServer(name=ref.name, transport=ref.transport,
                                   agent_type=agent_type, source=ref.config_path))
    return sorted(found.values(), key=lambda item: (item.agent_type, item.name))


def scan_mcp_servers(home: Path | None = None) -> list[McpServer]:
    """Configured MCP servers for the target user's home (names only)."""
    return legacy_servers(scan_mcp_configs(home))


def for_agent(servers: list[McpServer], agent_type: str) -> list[dict]:
    return [server.to_dict() for server in servers if server.agent_type == agent_type]


# ---------------------------------------------------------------------------
# Parsing helpers. Everything below reads names/transport only; command,
# args and env values are never copied out of the spec dict.
# ---------------------------------------------------------------------------


def _refs_from_mapping(source: _ConfigSource, config_path: str, mapping: dict,
                       found: dict) -> None:
    """Materialize references for one resolved server mapping."""
    for name, spec in mapping.items():
        if not isinstance(name, str) or not name:
            continue
        transport, endpoint = _transport_and_endpoint(spec)
        ref = McpConfigReference(
            client=source.client, name=name, scope=source.scope,
            config_path=config_path, transport=transport, endpoint=endpoint,
            enabled=_enabled_of(spec), config_digest=_spec_digest(spec))
        found.setdefault((ref.client, ref.config_path, ref.name), ref)


def _record_claude_project_scopes(path: Path, found: dict,
                                  diagnostics: dict[str, str] | None) -> None:
    """Local-scope entries under ``projects.<root>.mcpServers`` in the Claude
    Code config. Each project gets a virtual config path
    ``<file>::projects:<root>`` so the ref identity stays stable and distinct
    from the shareable project-root .mcp.json. File-level diagnostics are the
    main loop's business — this only reads what it already classified."""
    doc = _read_document(path, "json")
    if not isinstance(doc, dict):
        return
    projects = doc.get("projects")
    if not isinstance(projects, dict):
        return
    for project_root, config in projects.items():
        servers = config.get("mcpServers") if isinstance(config, dict) else None
        if not isinstance(servers, dict) or not servers:
            continue
        source = _ConfigSource("claude_code", (".claude.json",),
                               ("projects", str(project_root), "mcpServers"),
                               "project", "json")
        _refs_from_mapping(source, f"{path}::projects:{project_root}",
                           servers, found)


def _server_mapping(path: Path, source: _ConfigSource,
                    diagnostics: dict[str, str] | None = None) -> dict:
    raw = _read_document(path, source.fmt)
    if not isinstance(raw, dict):
        if diagnostics is not None:
            diagnostics[str(path)] = "unreadable" if path.is_file() else "missing"
        return {}
    if diagnostics is not None:
        diagnostics[str(path)] = "ok"
    node: object = raw
    for key in source.keys:
        if not isinstance(node, dict):
            return {}
        node = node.get(key)
    return node if isinstance(node, dict) else {}


def _read_document(path: Path, fmt: str):
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        if fmt == "toml":
            if tomllib is None:
                return None
            return tomllib.loads(text)
        if fmt == "jsonc":
            return json.loads(_remove_trailing_commas(_strip_jsonc(text)))
        return json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return None


def _strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments, honoring string literals (URLs contain //)."""
    out: list[str] = []
    in_string = False
    escaped = False
    index = 0
    length = len(text)
    while index < length:
        ch = text[index]
        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            index += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            index += 1
            continue
        if ch == "/" and index + 1 < length and text[index + 1] == "/":
            while index < length and text[index] != "\n":
                index += 1
            continue
        if ch == "/" and index + 1 < length and text[index + 1] == "*":
            index += 2
            while index + 1 < length and not (text[index] == "*"
                                              and text[index + 1] == "/"):
                index += 1
            index += 2
            continue
        out.append(ch)
        index += 1
    return "".join(out)


def _remove_trailing_commas(text: str) -> str:
    """Drop commas directly before } / ] (JSONC tolerance), string-aware."""
    out: list[str] = []
    in_string = False
    escaped = False
    index = 0
    length = len(text)
    while index < length:
        ch = text[index]
        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            index += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            index += 1
            continue
        if ch == ",":
            probe = index + 1
            while probe < length and text[probe] in " \t\r\n":
                probe += 1
            while probe + 1 < length and text[probe] == "/" and text[probe + 1] == "/":
                while probe < length and text[probe] != "\n":
                    probe += 1
                while probe < length and text[probe] in " \t\r\n":
                    probe += 1
            if probe < length and text[probe] in "}]":
                index += 1  # drop the comma
                continue
        out.append(ch)
        index += 1
    return "".join(out)


def _transport_and_endpoint(spec: object) -> tuple[str, str]:
    """Transport from the spec's own fields; the endpoint is sanitized here so
    no query string (credential carrier) ever leaves this module."""
    if not isinstance(spec, dict):
        return "unknown", ""
    if spec.get("command"):
        return "stdio", ""
    raw_url = spec.get("url") or spec.get("serverUrl") or ""
    if not raw_url:
        return "unknown", ""
    endpoint = _sanitize_url(str(raw_url))
    declared = str(spec.get("type") or "").strip().lower()
    if declared == "sse":
        return "sse", endpoint
    if declared in ("streamable-http", "streamable_http"):
        return "streamable_http", endpoint
    return "http", endpoint


def _sanitize_url(url: str) -> str:
    parts = urlsplit(url)
    if not parts.scheme:
        return url.split("?", 1)[0].split("#", 1)[0]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _enabled_of(spec: object) -> str:
    if not isinstance(spec, dict):
        return "unknown"
    if isinstance(spec.get("disabled"), bool):
        return "false" if spec["disabled"] else "true"
    if isinstance(spec.get("enabled"), bool):
        return "true" if spec["enabled"] else "false"
    return "unknown"


def _spec_digest(spec: object) -> str:
    payload = spec if isinstance(spec, dict) else {}
    return digest(canonical_json(payload), length=32)
