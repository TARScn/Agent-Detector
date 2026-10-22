"""JSON-config merge helpers shared by the adapters.

Every adapter answers two questions: which key holds the hook list, and what
does one of *our* entries look like. The merging itself is identical across
Agents, and it must never destroy a user's own hooks — existing entries are
kept, only entries carrying the marker are replaced or removed.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Callable

# Marker written into entries we create, so removal is exact even after the
# command string changes (different venv, different Python path).
MARKER = "__agentDetector"

OwnsEntry = Callable[[dict], bool]


def hook_list(data: dict, event_key: str) -> list:
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("配置中的 hooks 字段不是对象")
    entries = hooks.setdefault(event_key, [])
    if not isinstance(entries, list):
        raise ValueError(f"配置中的 hooks.{event_key} 不是数组")
    return entries


def merge_entry(data: dict, event_key: str, fragment: dict,
                owns: OwnsEntry) -> dict:
    """Insert ``fragment``, replacing any earlier entry we own."""
    merged = deepcopy(data)
    entries = hook_list(merged, event_key)
    remaining = [entry for entry in entries
                 if not (isinstance(entry, dict) and owns(entry))]
    remaining.append(deepcopy(fragment))
    merged["hooks"][event_key] = remaining
    return merged


def remove_entry(data: dict, event_key: str, owns: OwnsEntry) -> tuple[dict, int]:
    """Delete our entries; returns the new config and how many were removed."""
    result = deepcopy(data)
    hooks = result.get("hooks")
    if not isinstance(hooks, dict):
        return result, 0
    entries = hooks.get(event_key)
    if not isinstance(entries, list):
        return result, 0
    remaining = [entry for entry in entries
                 if not (isinstance(entry, dict) and owns(entry))]
    removed = len(entries) - len(remaining)
    if remaining:
        hooks[event_key] = remaining
    else:
        hooks.pop(event_key, None)
    if not hooks:
        result.pop("hooks", None)
    return result, removed


def count_owned(data: dict, event_keys: tuple[str, ...], owns: OwnsEntry) -> int:
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return 0
    total = 0
    for key in event_keys:
        entries = hooks.get(key)
        if not isinstance(entries, list):
            continue
        total += sum(1 for entry in entries
                     if isinstance(entry, dict) and owns(entry))
    return total