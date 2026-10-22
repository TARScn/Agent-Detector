"""Hook installer: merge/remove semantics and dry-run guarantees (§5.2, §9).

These tests must never touch the real user configuration, so every call passes
an explicit fake home.
"""
from __future__ import annotations

import json

from agent_detector.domain.enums import HookState
from agent_detector.hooks.installer import (bridge_command, events_for, inspect, install,
                                            plan, uninstall)
from agent_detector.hooks.registry import get_adapter

USER_SETTINGS = {
    "permissions": {"allow": ["Bash(git status)"]},
    "hooks": {"PreToolUse": [{"matcher": "Bash",
                              "hooks": [{"type": "command", "command": "echo user-hook"}]}]},
}


def _user_entry(entry: dict) -> bool:
    """True for the hand-written entry in USER_SETTINGS (Claude's nested shape)."""
    return any(item.get("command") == "echo user-hook"
               for item in entry.get("hooks", []) if isinstance(item, dict))


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_inspect_reports_not_installed_for_an_empty_home(home):
    state = inspect(get_adapter("claude_code"), home)
    assert state.state is HookState.NOT_INSTALLED
    assert state.entries == 0
    assert state.config_path == home / ".claude" / "settings.json"


def test_install_is_a_dry_run_until_apply_is_set(home):
    path = home / ".claude" / "settings.json"
    _write(path, USER_SETTINGS)
    before = path.read_text(encoding="utf-8")

    result = install("claude_code", home=home)
    assert result["written"] is False
    assert result["changed"] is True
    assert path.read_text(encoding="utf-8") == before  # untouched

    merged = result["merged"]
    assert merged["permissions"] == USER_SETTINGS["permissions"]  # user keys kept
    entries = merged["hooks"]["PreToolUse"]
    assert any(_user_entry(entry) for entry in entries)
    assert sum(1 for entry in entries if entry.get("__agentDetector")) == 1


def test_apply_writes_an_entry_for_every_event_and_backs_up(home):
    path = home / ".claude" / "settings.json"
    _write(path, USER_SETTINGS)

    result = install("claude_code", home=home, apply=True)
    assert result["written"] is True
    assert result["backup"] and (home / ".claude").glob("*.bak")

    written = json.loads(path.read_text(encoding="utf-8"))
    for event in events_for("claude_code"):
        entries = written["hooks"][event]
        assert any(entry.get("__agentDetector") for entry in entries)
    assert inspect(get_adapter("claude_code"), home).state is HookState.INSTALLED


def test_installing_twice_does_not_duplicate_entries(home):
    install("claude_code", home=home, apply=True)
    install("claude_code", home=home, apply=True)
    written = json.loads((home / ".claude" / "settings.json").read_text(encoding="utf-8"))
    for event in events_for("claude_code"):
        owned = [entry for entry in written["hooks"][event] if entry.get("__agentDetector")]
        assert len(owned) == 1


def test_partial_state_is_reported_when_only_one_event_is_wired(home):
    path = home / ".claude" / "settings.json"
    merged = plan("claude_code", home=home)["merged"]
    merged["hooks"]["PostToolUse"] = []
    _write(path, merged)
    assert inspect(get_adapter("claude_code"), home).state is HookState.PARTIAL


def test_uninstall_removes_only_our_entries(home):
    path = home / ".claude" / "settings.json"
    _write(path, USER_SETTINGS)
    install("claude_code", home=home, apply=True)

    result = uninstall("claude_code", home=home, apply=True)
    assert result["removed"] >= 1 and result["written"] is True
    remaining = json.loads(path.read_text(encoding="utf-8"))
    assert remaining["permissions"] == USER_SETTINGS["permissions"]
    assert any(_user_entry(entry) for entry in remaining["hooks"]["PreToolUse"])
    assert not any(entry.get("__agentDetector")
                   for entry in remaining["hooks"]["PreToolUse"])


def test_broken_json_is_reported_not_overwritten(home):
    path = home / ".codex" / "hooks.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{ not json", encoding="utf-8")
    state = inspect(get_adapter("codex_cli"), home)
    assert state.state is HookState.CONFLICT
    assert "无法解析" in " ".join(state.notes) or "不是合法 JSON" in " ".join(state.notes)


def test_cursor_config_gets_a_version_field(home):
    result = install("cursor", home=home, apply=True)
    written = json.loads((home / ".cursor" / "hooks.json").read_text(encoding="utf-8"))
    assert written["version"] == 1
    for event in ("beforeShellExecution", "beforeMCPExecution"):
        assert any(entry.get("failClosed") for entry in written["hooks"][event])
    assert result["written"] is True


def test_fail_closed_flag_is_configurable(home):
    result = plan("claude_code", home=home, fail_closed=False)
    entries = result["merged"]["hooks"]["PreToolUse"]
    assert all("onFailure" not in entry for entry in entries)


def test_bridge_command_quotes_the_interpreter():
    command = bridge_command(python=r"C:\Program Files\Python\python.exe",
                             agent_type="claude_code")
    assert command.startswith('"C:\\Program Files\\Python\\python.exe"')
    assert "-m hook_bridge.entry" in command and "--agent claude_code" in command


def test_unknown_agent_has_no_adapter(home):
    import pytest

    with pytest.raises(ValueError):
        install("gemini_cli", home=home)