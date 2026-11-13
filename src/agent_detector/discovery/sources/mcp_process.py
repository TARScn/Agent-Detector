"""stdio MCP process correlation: does a declared server have a live process?

Config discovery proves a client *declares* e.g. ``filesystem`` with some
interpreter command; this module checks whether a matching process is alive
right now and whether an Agent client process sits in its ancestor chain —
the shape ``client → interpreter → MCP server`` predicts. Command basenames
(``node``/``uvx``) alone are weak evidence, so the status vocabulary stays
honest: ``correlated`` needs the ancestor proof, ``running_unlinked`` means a
matching process exists without one, ``ambiguous`` means several candidates,
``not_running`` means none. A stdio server only runs while its client runs,
so ``not_running`` is informational, never an absence verdict.

C10: commands are re-read from the config in memory for matching and never
persisted — the persisted result is statuses and pids only.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from agent_detector.core.models import HostFacts
from agent_detector.discovery.sources.mcp import (McpConfigReference,
                                                  reload_stdio_command)

# Ancestor walk depth: client → shell → interpreter → server fits easily.
_MAX_ANCESTORS = 8
_MAX_REFS = 200


@dataclass(frozen=True)
class StdioCorrelation:
    ref: McpConfigReference
    status: str            # correlated / running_unlinked / ambiguous / not_running
    pids: tuple[int, ...] = ()


def correlate_stdio_processes(refs: list[McpConfigReference], facts: HostFacts,
                              agent_pids: set[int],
                              home=None) -> list[StdioCorrelation]:
    """Correlate every stdio reference against the process snapshot."""
    results: list[StdioCorrelation] = []
    stdio_refs = [ref for ref in refs if ref.transport == "stdio"][:_MAX_REFS]
    if not stdio_refs:
        return results

    processes = {proc.pid: proc for proc in facts.processes}
    for ref in stdio_refs:
        command = reload_stdio_command(ref, home=home)
        if not command:
            # Entry vanished or unreadable between the two config reads.
            results.append(StdioCorrelation(ref=ref, status="not_running"))
            continue
        candidates = _matching_processes(command, ref.name, processes)
        if not candidates:
            results.append(StdioCorrelation(ref=ref, status="not_running"))
            continue
        linked = [pid for pid in candidates
                  if _has_agent_ancestor(pid, processes, agent_pids)]
        if linked:
            status = "correlated" if len(linked) == 1 else "ambiguous"
            results.append(StdioCorrelation(ref=ref, status=status,
                                            pids=tuple(sorted(linked))))
            continue
        status = "running_unlinked" if len(candidates) == 1 else "ambiguous"
        results.append(StdioCorrelation(ref=ref, status=status,
                                        pids=tuple(sorted(candidates))))
    return results


def _base_name(value: str) -> str:
    """Executable basename without a Windows launcher extension, so a config
    command ``node`` matches the process name ``node.exe``."""
    base = value.replace("\\", "/").rsplit("/", 1)[-1].strip().lower()
    for ext in (".exe", ".cmd", ".bat", ".com"):
        if base.endswith(ext):
            return base[: -len(ext)]
    return base


def _matching_processes(command: str, server_name: str,
                        processes: dict) -> list[int]:
    """Pids whose name/exe/argv0 basename matches the command; narrowed by the
    server name appearing in the command line when several processes match."""
    needle = _base_name(command)
    name_token = server_name.lower()
    matches: list[int] = []
    for pid, proc in processes.items():
        bases = [_base_name(proc.name)]
        if proc.exe:
            bases.append(_base_name(proc.exe))
        if proc.cmdline:
            bases.append(_base_name(str(proc.cmdline[0])))
        if needle not in bases:
            continue
        matches.append(pid)
    if len(matches) > 1:
        narrowed = [pid for pid in matches
                    if name_token in " ".join(processes[pid].cmdline).lower()]
        if narrowed:
            return narrowed
    return matches


def _has_agent_ancestor(pid: int, processes: dict,
                        agent_pids: set[int]) -> bool:
    seen: set[int] = set()
    current = pid
    for _ in range(_MAX_ANCESTORS):
        proc = processes.get(current)
        if proc is None or proc.ppid is None:
            return False
        parent = proc.ppid
        if parent in agent_pids:
            return True
        if parent in seen:  # pid reuse cycle guard
            return False
        seen.add(parent)
        current = parent
    return False
