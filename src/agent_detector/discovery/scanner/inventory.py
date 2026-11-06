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

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_detector.discovery.sources.agents import LoadedMatrix, load_agent_matrix
from agent_detector.discovery.sources.deps import interest_names
from agent_detector.discovery.fingerprints.loader import load_rules
from agent_detector.discovery.sources.llm_config import endpoints_for
from agent_detector.discovery.sources.mcp import for_agent as mcp_for_agent
from agent_detector.discovery.sources.mcp import scan_mcp_servers
from agent_detector.core.config import legacy_delete_enabled
from agent_detector.core.enums import (AssetState, AssetType, HookState, ProtectionStatus,
                                         VersionSource)
from agent_detector.coverage import (ABSENT, PRESENT, UNVERIFIED,
                                     reconfirm_application,
                                     reconfirm_container, reconfirm_paths)
from agent_detector.core.models import (AgentInstance, AgentInventoryItem, DetectedAsset,
                                          HostFacts, ProjectInfo)
from agent_detector.interception.hooks.installer import inspect as inspect_hook
from agent_detector.interception.hooks.registry import get_adapter
from agent_detector.core.security import redact
from agent_detector.storage import AgentInventoryRepository
from agent_detector.storage.identity_repository import IdentityRepository
from agent_detector.storage.models import (AgentInstanceRow, EntityAttributeRow,
                                           EntityLocationRow)

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
    """Turns scan results into canonical entities/instances.

    Detector ids (``asset_id``) stay internal here: identity shadowing maps them
    to ``entity_id`` before anything is persisted or reported.
    """

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
        # P0-B: absence candidates recorded by the stale verification; the
        # scan coordinator persists them after apply_scan returns.
        self.removal_candidates: list[dict] = []
        # Entities this scan could not check at all (docker engine unreachable,
        # rule crashed). The projection must not fall back to older evidence
        # for them, otherwise a long-gone container keeps reading RUNNING.
        self.unverified: dict[str, str] = {}
        self._coverage = None

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
                   docker_context: dict | None = None,
                   coverage=None) -> list[dict]:
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
        self.removal_candidates = []
        self.unverified = {}
        self._coverage = coverage
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
            # Canonical attributes/locations are written by write_scan_evidence
            # after identity shadow; this builder only constructs instances.
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
        """Re-verify canonical entities that did not appear in this scan."""
        from agent_detector.discovery.sources.frameworks import rule_matches
        docker = docker_context or {}
        docker_failed = bool(docker.get("failed"))
        containers_seen = set(docker.get("containers_seen") or ())
        candidates_seen = set(docker.get("candidates_seen") or ())
        failed = {name.replace("-", "_") for name in failed_detectors}
        frameworks_failed = "frameworks" in failed

        identities = IdentityRepository(session)
        seen_entities = {
            entity_id
            for asset_id in seen_asset_ids
            if (entity_id := identities.resolve_alias(asset_id))
        }

        docker_scope_key = docker.get("scope_key") or "local"
        engine_required = (("docker_engine_enumeration", docker_scope_key,
                            "container_presence"),)
        project_required = (("project_candidate_universe", "scan",
                             "application_presence"),)
        engine_complete = (self._coverage is not None
                           and self._coverage.is_complete(
                               "docker_engine_enumeration", docker_scope_key,
                               "container_presence"))

        for attr in session.scalars(select(EntityAttributeRow).where(
                EntityAttributeRow.inventory_kind == "agent")):
            if attr.entity_id in seen_entities:
                continue
            if attr.container_id:
                if docker_failed:
                    self._mark_unverified(
                        attr.entity_id, "容器状态：docker 引擎本轮不可达")
                    continue
                container_id = attr.container_id
                if legacy_delete_enabled():
                    attr.status = "inactive"
                    continue
                deep_status = (self._coverage.predicate_status(
                    "container_deep_scan", container_id, "component_presence")
                    if self._coverage is not None else None)
                verdict = reconfirm_container(
                    container_id, engine_complete=engine_complete,
                    containers_seen=containers_seen,
                    candidates_seen=candidates_seen,
                    deep_scan_status=deep_status)
                required = engine_required
                if container_id in containers_seen:
                    required = engine_required + (
                        ("container_deep_scan", container_id,
                         "component_presence"),)
                self._record_entity_absence(
                    attr, predicate="container_presence",
                    required_scopes=required, verdict=verdict.verdict,
                    reason=verdict.reason, entity_kind="container")
                continue
            if attr.agent_type.replace("-", "_") in failed:
                self._mark_unverified(
                    attr.entity_id, f"产品规则 {attr.agent_type} 本轮失败")
                continue
            location = session.get(EntityLocationRow, attr.entity_id)
            if location is not None:
                if frameworks_failed and attr.agent_type in self._framework_ids:
                    self._mark_unverified(
                        attr.entity_id, "自建框架扫描本轮失败")
                    continue
                root_verdict = reconfirm_application(location.root_path)
                if root_verdict.verdict == ABSENT:
                    self._record_entity_absence(
                        attr, predicate="component_presence",
                        required_scopes=project_required,
                        verdict=root_verdict.verdict,
                        reason=root_verdict.reason, entity_kind="application")
                    continue
                app = {
                    "app_id": attr.entity_id,
                    "root_path": location.root_path,
                    "environment_path": location.environment_path,
                    "runtime": location.runtime,
                }
                installed = self._installed_dependencies(app)
                if installed is None:
                    attr.status = "inactive"
                    continue
                rule = self._framework_rules.get(attr.agent_type)
                if rule is not None and not rule_matches(rule, installed):
                    self._record_entity_absence(
                        attr, predicate="component_presence",
                        required_scopes=project_required, verdict=ABSENT,
                        reason=f"installed packages no longer match {attr.agent_type}",
                        entity_kind="application")
                else:
                    attr.status = "inactive"
                continue
            try:
                import json
                paths = list(json.loads(attr.config_paths_json or "[]"))
            except ValueError:
                paths = []
            if attr.executable:
                paths.append(attr.executable)
            verdict = reconfirm_paths(paths)
            self._record_entity_absence(
                attr, predicate="product_presence",
                required_scopes=self._product_required_scopes(attr.agent_type),
                verdict=verdict.verdict, reason=verdict.reason,
                entity_kind="product")

        active = {attr.entity_id for attr in session.scalars(
            select(EntityAttributeRow).where(
                EntityAttributeRow.status == "active"))}
        for instance in session.scalars(select(AgentInstanceRow)):
            if instance.entity_id not in active and instance.status == "running":
                instance.status = "stopped"
        # Unverified entities keep their attributes but their instances were
        # not observed this round; "running" would be an assumption.
        if self.unverified:
            for instance in session.scalars(select(AgentInstanceRow).where(
                    AgentInstanceRow.entity_id.in_(list(self.unverified)),
                    AgentInstanceRow.status == "running")):
                instance.status = "unverified"

    def _mark_unverified(self, entity_id: str, reason: str) -> None:
        """Record that this run could not check the entity (no absence proof)."""
        self.unverified.setdefault(entity_id, reason)

    # -- P0-B absence helpers ------------------------------------------------

    def _coverage_complete(self,
                           required: tuple[tuple[str, str, str], ...]) -> bool:
        if self._coverage is None or not required:
            return False
        return all(self._coverage.is_complete(scope_type, scope_key, predicate)
                   for scope_type, scope_key, predicate in required)

    def _product_required_scopes(self, agent_type: str
                                 ) -> tuple[tuple[str, str, str], ...]:
        """Prefer the asset's own rule scope; fall back to every rule.

        The fallback is deliberately conservative: if the stored agent type
        cannot be mapped to one rule, a failure in any rule blocks the absence
        candidate rather than guessing which rule owned the asset.
        """
        if self._coverage is None:
            return ()
        scopes = [scope for scope in self._coverage.scopes()
                  if scope.scope_type == "product_rule"]
        by_key = {scope.scope_key.replace("-", "_"): scope for scope in scopes}
        for key in (agent_type, agent_type.replace("-", "_")):
            scope = by_key.get(key.replace("-", "_"))
            if scope is not None:
                return ((scope.scope_type, scope.scope_key,
                         "product_presence"),)
        return tuple((scope.scope_type, scope.scope_key, "product_presence")
                     for scope in scopes)

    def _record_entity_absence(self, attr: EntityAttributeRow, *,
                               predicate: str,
                               required_scopes: tuple[tuple[str, str, str], ...],
                               verdict: str, reason: str,
                               entity_kind: str) -> None:
        """Archive a canonical entity; never hard-deletes it."""
        attr.status = "inactive"
        if legacy_delete_enabled():
            return
        if self._coverage is None:
            return
        if verdict == ABSENT and not self._coverage_complete(required_scopes):
            return
        self.removal_candidates.append({
            "asset_id": attr.entity_id,
            "entity_id": attr.entity_id,
            "entity_kind": entity_kind,
            "predicate": predicate,
            "status": ("CONFIRMED_ABSENT" if verdict == ABSENT
                       else "UNVERIFIED"),
            "reason": reason,
            "coverage_refs": [f"{scope_type}:{scope_key}:{predicate_name}"
                              for scope_type, scope_key, predicate_name
                              in required_scopes],
        })

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
        """Rule id (`claude_code`), or the display-name slug when the detector
        marker is a channel rather than a rule id."""
        key = asset.detector or ""
        if key == "docker":
            # Docker-channel client asset: the channel marker is not a rule
            # id; the display-name slug ("OpenClaw" -> "openclaw") hits the
            # capability matrix like a client-rule id does.
            return (asset.name or "").strip().lower().replace(" ", "_")
        if key:
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
            # compose 归并资产：主容器只是代表，备注交代整个部署的规模
            members = container.get("containers") or []
            scope = f"，compose 项目 {container['compose_project']}" \
                if container.get("compose_project") else ""
            extra = f"，共 {len(members)} 个容器" if len(members) > 1 else ""
            notes.insert(0, f"容器资产：{container.get('image', '')}"
                            f"（{container.get('state', '')}{scope}{extra}）")
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
        产生新 StartedAt，自然形成新实例；停止容器没有 running_pids，无实例行。
        compose 归并资产（link 带 ``containers`` 列表）按成员容器逐一展开，
        每个实例锚定自己容器的 StartedAt 与 container_id。"""
        members = container.get("containers")
        if members:
            instances: list[AgentInstance] = []
            for member in members:
                instances.extend(
                    self._container_instances(asset, member, agent_type))
            return instances
        processes_seen = container.get("processes") or {}
        started_at = container.get("started_at") or None
        instances = []
        if "running_pids" in container:
            pids = container["running_pids"]  # compose 成员：只属本容器
        else:
            pids = asset.running_pids
        for pid in pids:
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