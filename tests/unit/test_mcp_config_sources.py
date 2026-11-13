"""Multi-client MCP config discovery: sources, scopes, sanitization, digests."""
from __future__ import annotations

import json

from agent_detector.discovery.sources.mcp import (legacy_servers, mcp_ref_id,
                                                  scan_mcp_configs,
                                                  scan_mcp_servers)


def _write(path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _refs_by_key(refs) -> dict:
    return {(ref.client, ref.scope, ref.name): ref for ref in refs}


def test_user_configs_across_clients(tmp_path):
    _write(tmp_path / ".claude.json", {"mcpServers": {
        "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]},
        "remote": {"type": "http", "url": "https://mcp.example.com/sse?token=secret"}}})
    _write(tmp_path / ".cursor" / "mcp.json", {"mcpServers": {
        "filesystem": {"command": "npx"},       # same name, different client
        "off": {"command": "node", "disabled": True}}})
    (tmp_path / ".codex" / "config.toml").parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / ".codex" / "config.toml").write_text(
        '[mcp_servers.search]\ncommand = "uvx"\n',
        encoding="utf-8")
    _write(tmp_path / ".codeium" / "windsurf" / "mcp_config.json",
           {"mcpServers": {"windsurf-fs": {"command": "node"}}})
    _write(tmp_path / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
           {"mcpServers": {"desktop-fs": {"command": "node"}}})

    refs = scan_mcp_configs(tmp_path)
    by_key = _refs_by_key(refs)

    claude_fs = by_key[("claude_code", "user", "filesystem")]
    assert claude_fs.transport == "stdio"
    assert claude_fs.endpoint == ""
    assert claude_fs.config_digest  # spec hashed, command content not carried

    remote = by_key[("claude_code", "user", "remote")]
    assert remote.transport == "http"
    assert remote.endpoint == "https://mcp.example.com/sse"  # query stripped
    assert "secret" not in json.dumps([ref.to_dict() for ref in refs])

    cursor_fs = by_key[("cursor", "user", "filesystem")]
    assert cursor_fs.client == "cursor"  # same name, separate reference
    assert by_key[("cursor", "user", "off")].enabled == "false"

    assert by_key[("codex_cli", "user", "search")].transport == "stdio"
    assert by_key[("windsurf", "user", "windsurf-fs")].client == "windsurf"
    assert by_key[("claude_desktop", "user", "desktop-fs")].client == "claude_desktop"


def test_project_scope_configs(tmp_path):
    home = tmp_path / "home"
    project = tmp_path / "proj"
    _write(project / ".mcp.json", {"mcpServers": {"proj-fs": {"command": "npx"}}})
    (project / ".vscode" / "mcp.json").parent.mkdir(parents=True, exist_ok=True)
    # JSONC: comments and a trailing comma — must parse, not silently drop.
    (project / ".vscode" / "mcp.json").write_text(
        '{\n  // workspace MCP\n  "servers": {\n    "vscode-fs":'
        ' {"command": "node",},\n  },\n}\n', encoding="utf-8")

    refs = scan_mcp_configs(home, project_roots=[project])
    by_key = _refs_by_key(refs)
    assert by_key[("claude_code", "project", "proj-fs")].scope == "project"
    assert by_key[("claude_code", "project", "proj-fs")].config_path.endswith(".mcp.json")
    assert by_key[("vscode", "project", "vscode-fs")].transport == "stdio"
    missing_roots = scan_mcp_configs(home, project_roots=[tmp_path / "nope"])
    assert all(ref.scope == "user" for ref in missing_roots)


def test_broken_config_hides_only_itself(tmp_path):
    _write(tmp_path / ".claude.json", {"mcpServers": {"good": {"command": "npx"}}})
    (tmp_path / ".cursor").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".cursor" / "mcp.json").write_text("{not json", encoding="utf-8")
    refs = scan_mcp_configs(tmp_path)
    assert {(ref.client, ref.name) for ref in refs} == {("claude_code", "good")}


def test_vscode_user_settings_jsonc(tmp_path):
    settings = tmp_path / ".config" / "Code" / "User" / "settings.json"
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(
        '{\n  "editor.fontSize": 14, // keep this\n'
        '  "mcp": {"servers": {"ref": {"type": "sse", "url": "http://127.0.0.1:9000/sse?t=1"}}}\n}\n',
        encoding="utf-8")
    refs = scan_mcp_configs(tmp_path)
    ref = _refs_by_key(refs)[("vscode", "user", "ref")]
    assert ref.transport == "sse"
    assert ref.endpoint == "http://127.0.0.1:9000/sse"


def test_claude_local_scope_projects(tmp_path):
    """`claude mcp add` default (local scope) lives under
    projects.<root>.mcpServers in ~/.claude.json — scanned as project refs
    with a virtual config path, and reloadable for stdio correlation."""
    from agent_detector.discovery.sources.mcp import reload_stdio_command
    project = tmp_path / "work" / "demo"
    _write(tmp_path / ".claude.json", {
        "projects": {str(project): {"mcpServers": {
            "local-fs": {"command": "npx"}}}}})
    refs = scan_mcp_configs(tmp_path)
    assert len(refs) == 1
    ref = refs[0]
    assert (ref.client, ref.scope, ref.name) == ("claude_code", "project",
                                                 "local-fs")
    assert "::projects:" in ref.config_path
    assert ".claude.json::projects:" in ref.config_path
    assert reload_stdio_command(ref, home=tmp_path) == "npx"


def test_legacy_view_and_ref_id(tmp_path):
    _write(tmp_path / ".claude.json", {"mcpServers": {"fs": {"command": "npx"}}})
    _write(tmp_path / ".cursor" / "mcp.json",
           {"mcpServers": {"fs": {"command": "npx"}}})
    servers = scan_mcp_servers(tmp_path)
    by_type = {server.agent_type: server.name for server in servers}
    assert by_type == {"claude_code": "fs", "cursor": "fs"}

    derived = legacy_servers(scan_mcp_configs(tmp_path))
    assert [(s.agent_type, s.name) for s in derived] == [
        (s.agent_type, s.name) for s in servers]

    refs = scan_mcp_configs(tmp_path)
    ids = {mcp_ref_id("host-a", ref.config_path, ref.name) for ref in refs}
    assert len(ids) == len(refs)  # same name, different clients: distinct ids
    assert mcp_ref_id("host-a", "p", "n") != mcp_ref_id("host-b", "p", "n")
