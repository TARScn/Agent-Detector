"""Hook installation: inspect, merge, remove (design section 5.2 / 9).

Rules this module obeys, in order of importance:

1. Never overwrite a user's configuration. Existing hooks, permissions and
   unrelated keys are preserved; only entries we own are touched, and a backup
   is written before the first modification.
2. Never write without being asked. ``apply=False`` (the default everywhere,
   including the API) returns the exact JSON that *would* be written.
3. Never claim protection that is not there: ``inspect`` reports the actual
   state of the config file, so the UI can show 已启用 / 仅审计 / 未安装.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path

from agent_detector.core.config import HOOK_TIMEOUT_SECONDS
from agent_detector.core.enums import HookState
from agent_detector.interception.hooks.base import HookAdapter, HookInstallation, read_config
from agent_detector.interception.hooks.installer_support import count_owned, merge_entry, remove_entry
from agent_detector.interception.hooks.registry import ADAPTERS, get_adapter

# Which hook events each Agent's Phase-1 integration uses. Claude also gets
# PostToolUse: it is the only way to learn whether an allowed call actually ran
# (design section 7: decision=allow != execution_status=success).
HOOK_EVENTS: dict[str, tuple[str, ...]] = {
    "claude_code": ("PreToolUse", "PostToolUse"),
    "codex_cli": ("PreToolUse",),
    "cursor": ("beforeShellExecution", "beforeMCPExecution"),
}

_BRIDGE_MODULE = "hook_bridge.entry"


def bridge_command(*, python: str | None = None, agent_type: str) -> str:
    """Command line the Agent will run for each hook event.

    Quoted for both cmd.exe and POSIX shells: the interpreter path is the same
    interpreter that runs the service, so no PATH assumptions are made.
    """
    interpreter = python or os.getenv("AGENT_DETECTOR_PYTHON") or sys.executable
    return f'"{interpreter}" -m {_BRIDGE_MODULE} --agent {agent_type}'


def events_for(agent_type: str) -> tuple[str, ...]:
    return HOOK_EVENTS.get(agent_type, ("PreToolUse",))


def _config_defaults(agent_type: str) -> dict:
    # Cursor's hook file carries a schema version; write it on creation only.
    return {"version": 1} if agent_type == "cursor" else {}


def inspect(adapter: HookAdapter, home: Path | None = None) -> HookInstallation:
    """Read-only state check of one Agent's hook configuration."""
    path = adapter.config_path(home)
    notes: list[str] = []
    data, error = read_config(path)
    if error:
        return HookInstallation(
            agent_type=adapter.spec.agent_type, display_name=adapter.spec.display_name,
            config_path=path, state=HookState.CONFLICT, support=adapter.spec.support,
            schema_verified=adapter.spec.schema_verified, notes=[error])
    assert data is not None
    owned = count_owned(data, events_for(adapter.spec.agent_type), adapter.owns_entry)
    expected = len(events_for(adapter.spec.agent_type))
    if owned == 0:
        state = HookState.NOT_INSTALLED
    elif owned < expected:
        state = HookState.PARTIAL
        notes.append(f"仅 {owned}/{expected} 个事件接入，保护不完整")
    else:
        state = HookState.INSTALLED
    if not adapter.spec.schema_verified:
        notes.append("Hook Schema 未按本机版本核对（待验证）")
    return HookInstallation(
        agent_type=adapter.spec.agent_type, display_name=adapter.spec.display_name,
        config_path=path, state=state, support=adapter.spec.support,
        schema_verified=adapter.spec.schema_verified, entries=owned, notes=notes,
        spec_notes=[adapter.spec.notes] if adapter.spec.notes else [])


def inspect_all(home: Path | None = None) -> list[dict]:
    return [inspect(adapter, home).to_dict() for adapter in ADAPTERS.values()]


def plan(agent_type: str, *, home: Path | None = None,
         python: str | None = None, timeout: float | None = None,
         fail_closed: bool = True) -> dict:
    """Compute the merged configuration without writing anything."""
    adapter = get_adapter(agent_type)
    if adapter is None:
        raise ValueError(f"没有 {agent_type} 的 Hook 适配器")
    path = adapter.config_path(home)
    data, error = read_config(path)
    if error:
        raise ValueError(f"{path} 无法解析，已中止：{error}")
    base = {**_config_defaults(adapter.spec.agent_type), **(data or {})}
    command = bridge_command(python=python, agent_type=adapter.spec.agent_type)
    seconds = HOOK_TIMEOUT_SECONDS if timeout is None else timeout
    merged = base
    for event in events_for(adapter.spec.agent_type):
        merged = merge_entry(merged, event, adapter.install_fragment(
            command, timeout=seconds, fail_closed=fail_closed), adapter.owns_entry)
    return {"agent_type": adapter.spec.agent_type, "config_path": str(path),
            "command": command, "events": list(events_for(adapter.spec.agent_type)),
            "fail_closed": fail_closed, "existing": data or {},
            "merged": merged, "changed": merged != (data or {}),
            # `plan` never writes; these fields exist so callers can treat the
            # dry-run and apply results with one code path.
            "written": False, "backup": None}


def install(agent_type: str, *, home: Path | None = None, apply: bool = False,
            python: str | None = None, timeout: float | None = None,
            fail_closed: bool = True) -> dict:
    """Merge our hook entry into the Agent's config (``apply=True`` writes it)."""
    result = plan(agent_type, home=home, python=python, timeout=timeout,
                  fail_closed=fail_closed)
    result["written"] = False
    result["backup"] = None
    if not apply or not result["changed"]:
        return result
    path = Path(result["config_path"])
    if path.exists():
        backup = path.with_suffix(path.suffix + f".agent-detector.{int(time.time())}.bak")
        shutil.copy2(path, backup)
        result["backup"] = str(backup)
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_atomic(path, result["merged"])
    result["written"] = True
    return result


def uninstall(agent_type: str, *, home: Path | None = None,
              apply: bool = False) -> dict:
    """Remove only the entries Agent Detector wrote."""
    adapter = get_adapter(agent_type)
    if adapter is None:
        raise ValueError(f"没有 {agent_type} 的 Hook 适配器")
    path = adapter.config_path(home)
    data, error = read_config(path)
    if error:
        raise ValueError(f"{path} 无法解析，已中止：{error}")
    remaining = data or {}
    removed = 0
    for event in events_for(adapter.spec.agent_type):
        remaining, count = remove_entry(remaining, event, adapter.owns_entry)
        removed += count
    result = {"agent_type": adapter.spec.agent_type, "config_path": str(path),
              "removed": removed, "merged": remaining,
              "changed": remaining != (data or {}), "written": False}
    if apply and result["changed"]:
        if path.exists():
            backup = path.with_suffix(path.suffix + f".agent-detector.{int(time.time())}.bak")
            shutil.copy2(path, backup)
            result["backup"] = str(backup)
        if remaining:
            _write_atomic(path, remaining)
        else:
            path.unlink(missing_ok=True)
        result["written"] = True
    return result


def config_snippet(agent_type: str, *, python: str | None = None,
                   timeout: float | None = None, fail_closed: bool = True) -> dict:
    """The fragment a user can paste by hand when they prefer to edit configs."""
    adapter = get_adapter(agent_type)
    if adapter is None:
        raise ValueError(f"没有 {agent_type} 的 Hook 适配器")
    command = bridge_command(python=python, agent_type=adapter.spec.agent_type)
    seconds = HOOK_TIMEOUT_SECONDS if timeout is None else timeout
    return {"config_path": adapter.spec.config_path,
            "events": {event: [adapter.install_fragment(
                command, timeout=seconds, fail_closed=fail_closed)]
                for event in events_for(adapter.spec.agent_type)}}


def _write_atomic(path: Path, data: dict) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8")
    os.replace(temp, path)