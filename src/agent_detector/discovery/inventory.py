"""Agent inventory: logical asset + instances + protection status (§3.4, §1.3).

The detector answers "what is installed and running"; this module turns that
into the product's own vocabulary — one Agent asset, N running instances, a
capability row and an honest protection status. Nothing here may claim more
than the evidence supports:

* ``PROTECTED`` only when the Agent's hook config actually contains our entry
* ``DEGRADED`` when a hook was installed before but its config is now missing
  or only partly wired (design section 11.2: 检测配置变化，标记保护已失效)
* ``MONITOR_ONLY`` when we only observe it, ``UNPROTECTED`` when neither
  hooks nor a telemetry channel cover it
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from agent_detector.discovery.agents import LoadedMatrix, load_agent_matrix
from agent_detector.discovery.mcp import for_agent as mcp_for_agent
from agent_detector.discovery.mcp import scan_mcp_servers
from agent_detector.domain.enums import (AssetState, AssetType, HookState, ProtectionStatus)
from agent_detector.domain.models import (AgentInstance, AgentInventoryItem, DetectedAsset,
                                         HostFacts)
from agent_detector.hooks.installer import inspect as inspect_hook
from agent_detector.hooks.registry import get_adapter
from agent_detector.storage.repositories import AgentInventoryRepository

# Where our own hook entry is expected relative to a home directory; used to
# tell "never installed" from "was installed and disappeared".
_HOOK_TRACE = {
    "claude_code": "~/.claude/settings.json",
    "codex_cli": "~/.codex/hooks.json",
    "cursor": "~/.cursor/hooks.json",
}


def build_instance_id(asset_id: str, pid: int, started_at: str | None) -> str:
    """PID alone is not an identity on Windows; add the process start time."""
    seed = f"{asset_id}|{pid}|{started_at or 'unknown'}"
    return "inst-" + hashlib.sha256(seed.encode("utf-8", "replace")).hexdigest()[:16]


def protection_for(hook_state: HookState, asset_states: set[AssetState],
                   has_telemetry: bool) -> ProtectionStatus:
    if hook_state is HookState.INSTALLED:
        return ProtectionStatus.PROTECTED
    if hook_state in (HookState.PARTIAL, HookState.CONFLICT):
        return ProtectionStatus.DEGRADED
    if has_telemetry or AssetState.RUNNING in asset_states:
        return ProtectionStatus.MONITOR_ONLY
    if not asset_states:  # nothing detected at all
        return ProtectionStatus.UNKNOWN
    return ProtectionStatus.UNPROTECTED


class InventoryBuilder:
    """Turns scan results into the agent_assets / agent_instances tables."""

    def __init__(self, *, home: Path | None = None, matrix: LoadedMatrix | None = None,
                 telemetry_sources: tuple[str, ...] = ("netmon",)):
        self.home = Path(home) if home else Path.home()
        self.matrix = matrix or load_agent_matrix()
        self.telemetry_sources = telemetry_sources
        self.mcp_servers = []
        self.warnings: list[str] = []

    def refresh_mcp(self) -> None:
        try:
            self.mcp_servers = scan_mcp_servers(self.home)
        except Exception as exc:  # a broken MCP config must not break a scan
            self.mcp_servers = []
            self.warnings.append(f"MCP 配置读取失败：{exc}")

    def apply_scan(self, session: Session, detected: list[DetectedAsset],
                   facts: HostFacts) -> list[dict]:
        """Upsert Agent assets/instances for one scan; returns the asset dicts."""
        repository = AgentInventoryRepository(session)
        self.refresh_mcp()
        processes = {proc.pid: proc for proc in facts.processes}
        seen: list[dict] = []
        seen_asset_ids: set[str] = set()
        instances: list[AgentInstance] = []
        for asset in detected:
            if asset.asset_type is not AssetType.AGENT_CLIENT:
                continue
            entry = self.matrix.for_type(self._agent_key(asset))
            agent_type = entry.id if entry else self._agent_key(asset)
            item = self._inventory_item(asset, agent_type, entry)
            repository.upsert_asset(item)
            seen_asset_ids.add(asset.asset_id)
            instances.extend(self._instances(asset, processes, agent_type))
            seen.append({"asset_id": item.asset_id, "agent_type": agent_type,
                         "name": item.name, "protection_status": item.protection.value,
                         "hook_state": item.hook_state.value,
                         "capabilities": item.capabilities,
                         "instance_count": len(asset.running_pids)})
        if instances or seen_asset_ids:
            repository.upsert_instances(instances, seen_asset_ids)
        return seen

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _agent_key(asset: DetectedAsset) -> str:
        """Rule id (`claude_code`) or slugified display name for signature hits."""
        key = asset.detector or ""
        if key and key != "signatures":
            return key
        return (asset.name or "").strip().lower().replace(" ", "_")

    def _inventory_item(self, asset: DetectedAsset, agent_type: str, entry) -> AgentInventoryItem:
        adapter = get_adapter(agent_type)
        hook_state = HookState.UNSUPPORTED
        notes: list[str] = []
        if adapter is not None:
            installation = inspect_hook(adapter, self.home if self.home != Path.home() else None)
            hook_state = installation.state
            notes.extend(installation.notes)
        elif entry is not None and entry.hook is None:
            notes.append("前置拦截未适配：仅被动监测（不会阻断）")
        elif entry is None:
            notes.append("未适配的 Agent：能力不做保证")
        if entry is not None:
            notes.extend(entry.notes)
        capabilities = entry.capabilities() if entry else {
            "discovery": "P2", "monitor": "P2", "protect": "PLANNED"}
        return AgentInventoryItem(
            asset_id=asset.asset_id, agent_type=agent_type,
            name=entry.name if entry else asset.name,
            vendor=entry.vendor if entry else "",
            version=asset.version, states=tuple(sorted(asset.states, key=str)),
            confidence=asset.confidence,
            protection=protection_for(hook_state, asset.states,
                                      bool(self.telemetry_sources)),
            hook_state=hook_state, capabilities=capabilities,
            executable=asset.executable,
            config_paths=tuple(asset.config_paths),
            mcp_servers=tuple(server["name"] for server in mcp_for_agent(
                self.mcp_servers, agent_type)),
            notes=tuple(dict.fromkeys(notes)),
            last_seen_at=_now())

    def _instances(self, asset: DetectedAsset, processes: dict,
                   agent_type: str) -> list[AgentInstance]:
        instances: list[AgentInstance] = []
        for pid in asset.running_pids:
            proc = processes.get(pid)
            start = _iso(proc.create_time) if proc and proc.create_time else None
            instances.append(AgentInstance(
                instance_id=build_instance_id(asset.asset_id, pid, start),
                asset_id=asset.asset_id, agent_type=agent_type, pid=pid,
                ppid=proc.ppid if proc else None,
                process_name=proc.name if proc else "",
                executable=asset.executable,
                cmdline=_cmdline(proc), cwd=None,
                started_at=start, last_seen_at=_now(),
                parent_chain=_chain(proc, processes),
                evidence=("scan", "running_pids")))
        return instances


def _chain(proc, processes: dict, *, limit: int = 5) -> tuple[str, ...]:
    """Parent chain by name, closest first — audit context, not identity."""
    chain: list[str] = []
    current = proc
    seen: set[int] = set()
    while current is not None and len(chain) < limit and current.pid not in seen:
        seen.add(current.pid)
        chain.append(f"{current.name}({current.pid})")
        current = processes.get(current.ppid) if current.ppid else None
    return tuple(chain[1:])  # drop the process itself


def _cmdline(proc) -> str:
    if proc is None or not proc.cmdline:
        return ""
    from agent_detector.common.security import redact
    return redact(" ".join(proc.cmdline))[:400]


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="seconds")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def hook_trace_path(agent_type: str, home: Path | None = None) -> str:
    """Config path that indicates whether a hook was ever installed."""
    relative = _HOOK_TRACE.get(agent_type)
    if not relative:
        return ""
    base = Path(home) if home else Path.home()
    return str(base / relative.lstrip("~/"))