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
from pathlib import Path, PurePosixPath

from sqlalchemy.orm import Session

from agent_detector.discovery.sources.agents import LoadedMatrix, load_agent_matrix
from agent_detector.discovery.sources.deps import interest_names
from agent_detector.discovery.fingerprints.loader import load_rules
from agent_detector.discovery.sources.llm_config import endpoints_for
from agent_detector.discovery.sources.mcp import for_agent as mcp_for_agent
from agent_detector.discovery.sources.mcp import scan_mcp_servers
from agent_detector.core.enums import (AssetState, AssetType, HookState, ProtectionStatus,
                                         VersionSource)
from agent_detector.core.models import (AgentInstance, AgentInventoryItem, DetectedAsset,
                                          HostFacts, ProjectInfo)
from agent_detector.interception.hooks.installer import inspect as inspect_hook
from agent_detector.interception.hooks.registry import get_adapter
from agent_detector.core.security import redact
from agent_detector.storage import AgentInventoryRepository, ApplicationRepository

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
                 telemetry_sources: tuple[str, ...] = ("netmon",),
                 client_rules: list | None = None,
                 framework_ids: set[str] | None = None,
                 framework_rules: list | None = None):
        self.home = Path(home) if home else Path.home()
        self.matrix = matrix or load_agent_matrix()
        self.telemetry_sources = telemetry_sources
        if client_rules is None:
            loaded = load_rules()
            client_rules = loaded.client_rules
            if framework_ids is None:
                framework_ids = {rule.id for rule in loaded.framework_rules}
            if framework_rules is None:
                framework_rules = loaded.framework_rules
        self._rule_by_id = {rule.id: rule for rule in client_rules}
        self._framework_ids = framework_ids or set()
        self._framework_rules = {rule.id: rule for rule in (framework_rules or [])}
        deps = {name for rule in self._framework_rules.values()
                for name in (*rule.dependencies.any, *rule.dependencies.all)}
        self._verification_interest = interest_names(deps)
        self.mcp_servers = []
        self.warnings: list[str] = []

    def refresh_mcp(self) -> None:
        try:
            self.mcp_servers = scan_mcp_servers(self.home)
        except Exception as exc:  # a broken MCP config must not break a scan
            self.mcp_servers = []
            self.warnings.append(f"MCP 配置读取失败：{exc}")

    def apply_scan(self, session: Session, detected: list[DetectedAsset],
                   facts: HostFacts, *,
                   app_links: dict[str, dict] | None = None,
                   failed_detectors: tuple[str, ...] | set[str] = (),
                   docker_context: dict | None = None) -> list[dict]:
        """Upsert Agent assets/instances for one scan; returns the asset dicts.

        ``app_links`` maps a self-built framework asset id to its application
        ({app_id, app_name}); CLI-client assets never have one.
        ``failed_detectors`` are detector names that crashed this scan — assets
        they own are never marked removed, because their absence proves nothing.
        ``docker_context`` carries the Docker channel's result ({failed,
        containers_seen, candidates_seen, links}); ``links`` maps a container
        asset id to its container ({container_id, image, state, started_at,
        command, processes}).
        """
        repository = AgentInventoryRepository(session)
        self.refresh_mcp()
        processes = {proc.pid: proc for proc in facts.processes}
        app_links = app_links or {}
        container_links = (docker_context or {}).get("links") or {}
        seen: list[dict] = []
        seen_asset_ids: set[str] = set()
        instances: list[AgentInstance] = []
        for asset in detected:
            is_client = asset.asset_type is AssetType.AGENT_CLIENT
            # Agent 平台产品（n8n 等）与终端 client 同列表、同生命周期；
            # 副作用：签名集里的平台 sighting（如 Dify）也从此进入列表，
            # 进程消失后由 sighting-only 复核自动 removed。
            is_platform = asset.asset_type is AssetType.AGENT_PLATFORM
            is_framework = (asset.asset_type is AssetType.AGENT_RUNTIME
                            and asset.detector in self._framework_ids)
            if not (is_client or is_platform or is_framework):
                continue
            entry = self.matrix.for_type(self._agent_key(asset))
            agent_type = entry.id if entry else self._agent_key(asset)
            link = app_links.get(asset.asset_id) if is_framework else None
            container = container_links.get(asset.asset_id)
            item = self._inventory_item(asset, agent_type, entry, link=link,
                                        container=container)
            repository.upsert_asset(item)
            seen_asset_ids.add(asset.asset_id)
            instances.extend(self._instances(asset, processes, agent_type,
                                             container=container))
            seen.append({"asset_id": item.asset_id, "agent_type": agent_type,
                         "name": item.name, "protection_status": item.protection.value,
                         "hook_state": item.hook_state.value,
                         "app_id": item.app_id,
                         "capabilities": item.capabilities,
                         "llm_endpoints": [dict(e) for e in item.llm_endpoints],
                         "instance_count": len(asset.running_pids)})
        if instances or seen_asset_ids:
            repository.upsert_instances(instances, seen_asset_ids)
        self._verify_stale(session, repository, seen_asset_ids, app_links,
                           failed_detectors, docker_context=docker_context)
        return seen

    def _verify_stale(self, session: Session, repository: AgentInventoryRepository,
                      seen_asset_ids: set[str], app_links: dict[str, dict],
                      failed_detectors: tuple[str, ...] | set[str],
                      docker_context: dict | None = None) -> None:
        """Re-verify assets that did not show up in this scan (重扫复核).

        Four verification rules, one per asset kind:

        * 终端 agent (client rule): the scan already ran the rule's
          install/config probes, so absence from the results means the
          probes found nothing — removed. Exception: the detector itself
          errored this scan, in which case absence proves nothing.
        * 自建 agent (framework asset with an app link): re-check the
          application on disk — project dir gone → hard delete (user
          decision: deleted agents must not linger); **venv gone or the
          framework's packages no longer installed → hard delete too**
          (user decision 2026-10-23: 空壳目录不算 agent 资产); deps still
          installed but no live process → inactive. Only *installed*
          evidence counts — a pyproject declaration alone does not keep
          an asset alive.
        * Sighting-only assets (signature hits, no app link): their whole
          existence claim was the process; gone → removed.
        * 容器资产 (container_id set): the host-path rules above do not
          apply — project roots are container-internal and unreachable
          without the daemon. The Docker channel's own result is the
          verdict: container gone → hard delete; deep-scanned this round
          but the asset did not come back → the framework left the
          container → hard delete (宿主"依赖已卸载"的容器等价); container
          present but not deep-scanned → inactive (no verdict possible).
          When the docker channel failed or was disabled, container assets
          get no verdict at all — same guard as a crashed detector.
        """
        from agent_detector.discovery.sources.frameworks import rule_matches
        docker = docker_context or {}
        docker_failed = bool(docker.get("failed"))
        containers_seen = set(docker.get("containers_seen") or ())
        candidates_seen = set(docker.get("candidates_seen") or ())
        applications = ApplicationRepository(session)
        apps_by_id = {app["app_id"]: app
                      for app in applications.all_for_verification()}
        failed = {name.replace("-", "_") for name in failed_detectors}
        frameworks_failed = "frameworks" in failed

        unseen_framework: dict[str, list[dict]] = {}
        for row in repository.list_assets(include_removed=True):
            if row["asset_id"] in seen_asset_ids:
                continue
            if row.get("container_id"):
                if docker_failed:
                    continue  # docker channel silent: no verdict for containers
                container_id = row["container_id"]
                if container_id not in containers_seen:
                    repository.delete_asset(row["asset_id"])  # 容器已删除
                elif container_id in candidates_seen:
                    repository.delete_asset(row["asset_id"])  # 深扫未见：容器内已卸载
                else:
                    repository.set_status(row["asset_id"], "inactive")  # 无法复核
                continue
            if row["agent_type"].replace("-", "_") in failed:
                continue  # its detector crashed: absence proves nothing
            is_framework = row["agent_type"] in self._framework_ids and row.get("app_id")
            if is_framework and frameworks_failed:
                continue  # dependency re-check impossible this scan: no verdict
            if is_framework:
                unseen_framework.setdefault(row["app_id"], []).append(row)
            else:
                repository.set_status(row["asset_id"], "removed")

        seen_apps = {link.get("app_id") for link in app_links.values()
                     if link.get("app_id")}
        for app_id, rows in unseen_framework.items():
            app = apps_by_id.get(app_id)
            if app is None or not Path(app["root_path"]).exists():
                for row in rows:
                    repository.delete_asset(row["asset_id"])
                applications.delete_application(app_id)
                continue
            installed = self._installed_dependencies(app)
            if installed is None:
                # environment not re-checkable (system python): path verdict only
                for row in rows:
                    repository.set_status(row["asset_id"], "inactive")
                applications.set_status(app_id, "inactive")
                continue
            for row in rows:
                rule = self._framework_rules.get(row["agent_type"])
                if rule is not None and not rule_matches(rule, installed):
                    repository.delete_asset(row["asset_id"])  # 依赖已卸载
                else:
                    repository.set_status(row["asset_id"], "inactive")
            if installed:
                if app_id not in seen_apps:
                    applications.set_status(app_id, "inactive")
            else:
                applications.delete_application(app_id)  # venv 空壳

        for app_id, app in apps_by_id.items():
            if app_id in seen_apps or app_id in unseen_framework:
                continue
            container_id = app.get("container_id")
            if container_id:
                # Container application with no asset rows re-seen: the asset
                # verdicts above already handled the assets; here the
                # application row follows the container, not the host path.
                if not docker_failed:
                    if container_id in containers_seen:
                        # 容器在而框架资产未再现：可能仅剩 SDK 依赖，置 inactive；
                        # 依赖彻底清空的容器由下一扫描的 upsert 语义自然重建或维持。
                        applications.set_status(app_id, "inactive")
                    else:
                        applications.delete_application(app_id)  # 容器已删除
                continue
            if frameworks_failed:
                continue
            if not Path(app["root_path"]).exists():
                applications.delete_application(app_id)
                continue
            installed = self._installed_dependencies(app)
            if installed is None or installed:
                applications.set_status(app_id, "inactive")
            else:
                applications.delete_application(app_id)

        # Verdicts are in: removed/inactive assets have no live process by
        # definition, so their instance rows must not stay "running" (they
        # feed the dashboard's 运行中 count — leaving them produces ghost
        # 运行中 entries). Assets skipped over a crashed detector keep both
        # their active status and their instances.
        repository.stop_instances_of_unrunnable_assets()

    def _installed_dependencies(self, app: dict) -> set[str] | None:
        """AI-relevant package names still *installed* in the app's environment.

        Returns ``None`` when the environment cannot be re-checked (no venv on
        record — system-python apps are only path-verified, never deleted on
        guesswork). Only PACKAGE_METADATA provenance counts: a declared or
        locked dependency does not prove the environment still exists.
        """
        environment = app.get("environment_path")
        if not environment:
            return None
        if not Path(environment).exists():
            return set()  # venv deleted: nothing is installed there anymore
        from agent_detector.discovery.sources.deps import scan_project_dependencies
        project = ProjectInfo(project_id=f"verify:{app['app_id']}",
                              root=app["root_path"], name="",
                              runtime=app.get("runtime") or "python",
                              environment_path=environment,
                              resolver_status="resolved")
        try:
            result = scan_project_dependencies([project], self._verification_interest)
        except Exception:
            return None
        return {component.name for component in result.get(project.project_id, [])
                if component.version_source is VersionSource.PACKAGE_METADATA}

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _agent_key(asset: DetectedAsset) -> str:
        """Rule id (`claude_code`) or slugified display name for signature hits."""
        key = asset.detector or ""
        if key == "docker":
            # Docker-channel client asset: the channel marker is not a rule
            # id; the display-name slug ("OpenClaw" -> "openclaw") hits the
            # capability matrix like a signature hit does.
            return (asset.name or "").strip().lower().replace(" ", "_")
        if key and key != "signatures":
            return key
        return (asset.name or "").strip().lower().replace(" ", "_")

    def _inventory_item(self, asset: DetectedAsset, agent_type: str, entry,
                        *, link: dict | None = None,
                        container: dict | None = None) -> AgentInventoryItem:
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
        if container:
            notes.insert(0, f"容器资产：{container.get('image', '')}"
                            f"（{container.get('state', '')}）")
        capabilities = entry.capabilities() if entry else {
            "discovery": "P2", "monitor": "P2", "protect": "PLANNED"}
        rule = self._rule_by_id.get(asset.detector or "")
        llm_endpoints = [endpoint.to_dict() for endpoint in
                         endpoints_for(rule, home=self.home)] if rule else []
        # Self-built framework asset: name carries the project so several
        # LangChain projects stay distinguishable in one list.
        name = entry.name if entry else asset.name
        if link:
            name = f"{name} · {link.get('app_name', '')}".rstrip(" ·")
            notes.insert(0, "自建框架资产：由项目依赖元数据识别（非进程名匹配）")
        return AgentInventoryItem(
            asset_id=asset.asset_id, agent_type=agent_type,
            name=name,
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
            llm_endpoints=tuple(llm_endpoints),
            app_id=link.get("app_id") if link else None,
            origin="docker" if container else "host",
            container_id=container.get("container_id") if container else None,
            notes=tuple(dict.fromkeys(notes)),
            last_seen_at=_now())

    def _instances(self, asset: DetectedAsset, processes: dict,
                   agent_type: str, *,
                   container: dict | None = None) -> list[AgentInstance]:
        if container is not None:
            return self._container_instances(asset, container, agent_type)
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
                cmdline=_cmdline(proc),
                cwd=proc.cwd if proc else None,
                started_at=start, last_seen_at=_now(),
                parent_chain=_chain(proc, processes),
                evidence=("scan", "running_pids")))
        return instances

    def _container_instances(self, asset: DetectedAsset, container: dict,
                             agent_type: str) -> list[AgentInstance]:
        """容器内实例：pid 是容器内 PID，身份锚定容器 StartedAt —— 容器重启
        产生新 StartedAt，自然形成新实例；停止容器没有 running_pids，无实例行。"""
        processes_seen = container.get("processes") or {}
        started_at = container.get("started_at") or None
        instances: list[AgentInstance] = []
        for pid in asset.running_pids:
            cmdline = str(processes_seen.get(str(pid))
                          or container.get("command") or "")
            tokens = cmdline.split()
            first = tokens[0] if tokens else ""
            instances.append(AgentInstance(
                instance_id=build_instance_id(asset.asset_id, pid, started_at),
                asset_id=asset.asset_id, agent_type=agent_type, pid=pid,
                process_name=PurePosixPath(first.replace("\\", "/")).name if first else "",
                executable=asset.executable,
                cmdline=redact(cmdline)[:400] if cmdline else "",
                started_at=started_at, last_seen_at=_now(),
                evidence=("scan", "container:top"),
                origin="docker",
                container_id=container.get("container_id")))
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
    from agent_detector.core.security import redact
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