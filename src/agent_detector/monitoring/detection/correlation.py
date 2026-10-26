"""Correlation: which Agent does this OS-level activity belong to? (§4.2)

Correlation strength is ranked, and the ranking is enforced by what each path
is allowed to *claim*:

    native hook direct evidence  >  ProcessGuid parent chain  >  session context
    >  same-time / same-cwd similarity (low-confidence candidates only)

This module owns the middle of that ladder. Time and working-directory
similarity never creates an asset link here: an unprovable relationship stays
unattributed, which the UI shows as such (design section 3.3).

``ProcessGraph``/``AgentAttributor`` are re-exported so callers have a single
correlation entry point; their implementations live in ``process_graph`` and
``attribution``.
"""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from agent_detector.monitoring.detection.attribution import AgentAttributor, Attribution
from agent_detector.monitoring.detection.process_graph import ProcNode, ProcessGraph, live_process
from agent_detector.storage import AgentInventoryRepository

logger = logging.getLogger(__name__)

__all__ = ["AgentAttributor", "Attribution", "ProcNode", "ProcessGraph",
           "live_process", "resolve_instance_for_pid", "process_ancestry",
           "CORRELATION_ORDER"]

CORRELATION_ORDER = ("native_hook", "process_guid", "process_tree",
                     "session_context", "similarity")

# How far up the process tree a hook's parent chain is walked before giving up.
_MAX_ANCESTRY = 8


def process_ancestry(pid: int | None, *, max_depth: int = _MAX_ANCESTRY) -> list[dict]:
    """Walk up from ``pid``; returns [{pid, ppid, name}, ...] closest first."""
    chain: list[dict] = []
    seen: set[int] = set()
    current = pid
    while current and current not in seen and len(chain) < max_depth:
        seen.add(current)
        info = live_process(current)
        if info is None:
            break
        chain.append({"pid": info.pid, "ppid": info.ppid, "name": info.name})
        current = info.ppid
    return chain


def resolve_instance_for_pid(pid: int | None, session: Session, *,
                             max_depth: int = _MAX_ANCESTRY) -> dict | None:
    """Find the Agent instance that (transitively) spawned ``pid``.

    A hook bridge is started *by* the Agent, so its parent chain is direct
    evidence: the first ancestor that matches a known running instance is the
    correlation, tagged ``process-tree``. Nothing is inferred when no ancestor
    matches.
    """
    if not pid:
        return None
    repository = AgentInventoryRepository(session)
    for depth, node in enumerate(process_ancestry(pid, max_depth=max_depth)):
        if depth == 0:
            continue  # the bridge itself is not an Agent
        instance = repository.find_instance_by_pid(node["pid"])
        if instance is None:
            continue
        enriched = dict(instance)
        enriched["matched_by"] = "process_tree"
        enriched["matched_pid"] = node["pid"]
        enriched["depth"] = depth
        return enriched
    return None