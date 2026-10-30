"""Attribute behavior facts to agents through the process tree.

The first ancestor that matches wins (the closest agent ancestor). Matching uses
the same fingerprint primitives as the scan detectors, and a candidate asset_id
is only attached when that asset already exists in the database — attribution
never invents assets.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from agent_detector.monitoring.detection.process_graph import ProcNode, ProcessGraph
from agent_detector.core.models import ProcessInfo
from agent_detector.discovery.fingerprints.match import match_client_process, match_signature_process
from agent_detector.discovery.fingerprints.schema import ClientRule, SignatureRule
from agent_detector.core.identity import build_asset_id, normalize_path, slugify


@dataclass(frozen=True)
class Attribution:
    agent_label: str
    asset_id: str | None
    evidence: tuple[str, ...]
    ancestor_pid: int | None = None


class AgentAttributor:
    def __init__(self, *, hostname: str, graph: ProcessGraph, pid_map: dict[int, str],
                 known_asset_ids: set[str], client_rules: Sequence[ClientRule] = (),
                 signature_rules: Sequence[SignatureRule] = (),
                 home: Path | None = None, max_depth: int = 12,
                 container_map: dict[str, tuple[str, str]] | None = None):
        self.hostname = hostname
        self.graph = graph
        self.pid_map = pid_map
        self.known_asset_ids = known_asset_ids
        self.client_rules = tuple(client_rules)
        self.signature_rules = tuple(signature_rules)
        self.home = home
        self.max_depth = max_depth
        # container hex-ID prefix -> (asset_id, agent name), from the Docker
        # discovery channel's container-origin assets
        self.container_map = dict(container_map or {})

    def attribute(self, *, pid: int, ppid: int | None, process_name: str,
                  container_id: str | None = None) -> Attribution:
        if container_id and self.container_map:
            # Container processes report host-namespace PIDs (Tetragon runs on
            # the host) while Docker discovery stores container-namespace PIDs,
            # so instance-level pid matching is impossible by construction —
            # container events match at the asset level only.
            for prefix, (asset_id, name) in self.container_map.items():
                if prefix and (container_id.startswith(prefix)
                               or prefix.startswith(container_id)):
                    return Attribution(name or process_name or f"pid-{pid}",
                                       asset_id, ("container_id",), None)
        for index, node in enumerate(self.graph.ancestors_of(
                pid, ppid=ppid, max_depth=self.max_depth)):
            asset_id = self.pid_map.get(node.pid)
            if asset_id:
                label = node.name or process_name or f"pid-{node.pid}"
                tag = "self_asset_pid" if index == 0 else "ancestor_asset_pid"
                return Attribution(label, asset_id, (tag,), node.pid)
            matched = self._fingerprint(node)
            if matched is not None:
                return matched
        return Attribution(process_name or f"pid-{pid}", None, ("unattributed",), None)

    def _fingerprint(self, node: ProcNode) -> Attribution | None:
        proc = ProcessInfo(pid=node.pid, name=node.name, cmdline=tuple(node.cmdline),
                           create_time=node.create_time, ppid=node.ppid)
        for rule in self.client_rules:
            reason = match_client_process(rule, proc)
            if reason:
                candidate = None
                if self.home is not None:
                    candidate = build_asset_id(
                        self.hostname, rule.id,
                        f"user-home:{normalize_path(self.home)}")
                return Attribution(rule.name, self._known_asset(candidate),
                                   ("process_fingerprint", f"rule:{rule.id}",
                                    f"match:{reason}"), node.pid)
        for rule in self.signature_rules:
            if match_signature_process(rule, proc):
                exe = proc.cmdline[0] if proc.cmdline else proc.name
                candidate = build_asset_id(self.hostname, slugify(rule.name),
                                           f"process:{normalize_path(exe)}")
                return Attribution(rule.name, self._known_asset(candidate),
                                   ("process_fingerprint", "signature"), node.pid)
        return None

    def _known_asset(self, candidate: str | None) -> str | None:
        if candidate and candidate in self.known_asset_ids:
            return candidate
        return None