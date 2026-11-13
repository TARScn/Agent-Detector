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
from agent_detector.discovery.sources.mcp import McpConfigReference, legacy_servers
from agent_detector.discovery.sources.mcp import scan_mcp_configs
from agent_detector.core.enums import (AssetState, AssetType, HookState, ProtectionStatus,
                                         VersionSource)
from agent_detector.aggregation.state_resolver import (ABSENT, FAILED,
                                                       NOT_CHECKED, PRESENT,
                                                       ScopeRef, entity_context,
                                                       product_scope_refs)
from agent_detector.coverage import (UNVERIFIED as R_UNVERIFIED,
                                     reconfirm_application, reconfirm_paths)
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
        self.mcp_refs: list[McpConfigReference] = []
        self.mcp_servers: list = []
        self.warnings: list[str] = []
        # Evidence only: presence observations for entities that did not show
        # up in this scan. The scan coordinator writes them as claims; the
        # state resolver decides absent/active/archived from them.
        self.observations: list[dict] = []
        # Entities this scan could not check at all (docker engine unreachable,
        # rule crashed). Kept as a read model for scan stats.
        self.unverified: dict[str, str] = {}
        self._coverage = None

    def refresh_mcp(self, refs: list[McpConfigReference] | None = None) -> None:
        """Adopt the scan stage's config references, or scan the home ourselves.

        The scan coordinator passes the full user+project reference list; a
        broken config must not break a scan, so every failure degrades to a
        warning with the legacy view emptied.
        """
        try:
            self.mcp_refs = list(refs) if refs is not None else scan_mcp_configs(self.home)
            self.mcp_servers = legacy_servers(self.mcp_refs)
        except Exception as exc:  # a broken MCP config must not break a scan
            self.mcp_refs = []
            self.mcp_servers = []
            self.warnings.append(f"MCP 配置读取失败：{exc}")

    def apply_scan(self, session: Session, detected: list[DetectedAsset],
                   facts: HostFacts, *,
                   app_links: dict[str, dict] | None = None,
                   failed_detectors: tuple[str, ...] | set[str] = (),
                   docker_context: dict | None = None,
                   coverage=None,
                   mcp_refs: list[McpConfigReference] | None = None) -> list[dict]:
        """Upsert Agent assets/instances for one scan; returns the asset dicts.

        ``app_links`` maps a self-built framework asset id to its application
        ({app_id, app_name}); CLI-client assets never have one.
        ``failed_detectors`` are detector names that crashed this scan — assets
        they own are never marked removed, because their absence proves nothing.
        ``docker_context`` carries the Docker channel's result ({failed,
        containers_seen, candidates_seen, links}); ``links`` maps a container
        asset id to its container ({container_id, image, state, started_at,
        command, processes}).
        ``mcp_refs`` is the scan stage's MCP config reference list; ``None``
        makes the builder scan the home's user-level configs itself (tests and
        standalone callers).
        """
        repository = AgentInventoryRepository(session)
        self.observations = []
        self.unverified = {}
        self._coverage = coverage
        self.refresh_mcp(mcp_refs)
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
                         "container_id": item.container_id,
                         "origin": item.origin,
                         "instance_count": len(asset.running_pids)})
        if instances or seen_asset_ids:
            repository.upsert_instances(instances, seen_asset_ids)
        self._reconfirm_unseen(session, seen_asset_ids, failed_detectors,
                               docker_context=docker_context)
        return seen

    def _reconfirm_unseen(self, session: Session, seen_asset_ids: set[str],
                          failed_detectors: tuple[str, ...] | set[str],
                          docker_context: dict | None = None) -> None:
        """Collect presence observations for entities this scan did not see.

        This method only *collects*: it writes no status, chooses no
        lifecycle and creates no absence candidate. ``scan_evidence`` turns
        the observations into claims; the state resolver decides what they
        mean for the console.
        """
        from agent_detector.discovery.sources.frameworks import rule_matches
        docker = docker_context or {}
        docker_failed = bool(docker.get("failed"))
        docker_disabled = str(docker.get("error") or "") == "disabled"
        containers_seen = set(docker.get("containers_seen") or ())
        candidates_seen = set(docker.get("candidates_seen") or ())
        projects_seen = set(docker.get("projects_seen") or ())
        failed = {name.replace("-", "_") for name in failed_detectors}
        frameworks_failed = "frameworks" in failed

        identities = IdentityRepository(session)
        seen_entities = {
            entity_id
            for asset_id in seen_asset_ids
            if (entity_id := identities.resolve_alias(asset_id))
        }

        docker_scope_key = docker.get("scope_key") or "local"
        engine_ref = ScopeRef("docker_engine_enumeration", docker_scope_key,
                              "container_presence")
        engine_complete = (self._coverage is not None
                           and self._coverage.is_complete(
                               "docker_engine_enumeration", docker_scope_key,
                               "container_presence"))
        engine_status = (self._coverage.predicate_status(
            "docker_engine_enumeration", docker_scope_key,
            "container_presence") if self._coverage is not None else None)

        for attr in session.scalars(select(EntityAttributeRow).where(
                EntityAttributeRow.inventory_kind == "agent")):
            if attr.entity_id in seen_entities:
                continue
            context = entity_context(session, attr.entity_id)
            if context.entity_kind == "COMPOSE_DEPLOYMENT":
                self._observe_compose(
                    attr, context, docker_failed=docker_failed,
                    docker_disabled=docker_disabled, engine_complete=engine_complete,
                    engine_status=engine_status, projects_seen=projects_seen,
                    engine_ref=engine_ref)
                continue
            if attr.container_id or context.entity_kind == "CONTAINER_DEPLOYMENT":
                self._observe_container(
                    attr, docker_failed=docker_failed,
                    docker_disabled=docker_disabled, engine_complete=engine_complete,
                    engine_status=engine_status, containers_seen=containers_seen,
                    candidates_seen=candidates_seen, engine_ref=engine_ref)
                continue
            if attr.agent_type.replace("-", "_") in failed:
                self._observe_unverified(
                    attr, f"产品规则 {attr.agent_type} 本轮失败",
                    verification=FAILED)
                continue
            location = session.get(EntityLocationRow, attr.entity_id)
            if location is not None:
                self._observe_application(
                    attr, location, frameworks_failed=frameworks_failed,
                    rule_matches=rule_matches)
                continue
            self._observe_product(attr)

    # -- observations --------------------------------------------------------

    def _observe(self, attr: EntityAttributeRow, *, presence: str,
                 predicate: str, reason: str,
                 required: tuple[ScopeRef, ...],
                 verification: str | None = None,
                 reason_code: str = "",
                 entity_kind: str = "") -> None:
        self.observations.append({
            "entity_id": attr.entity_id,
            "asset_id": attr.entity_id,
            "entity_kind": entity_kind or "UNKNOWN",
            "predicate": predicate,
            "presence": presence,
            "reason": reason,
            "required_scopes": [ref.as_dict() for ref in required],
            "verification": verification,
            "reason_code": reason_code,
        })
        if presence not in (PRESENT, ABSENT):
            self._mark_unverified(attr.entity_id, reason)

    def _observe_unverified(self, attr: EntityAttributeRow, reason: str, *,
                            verification: str,
                            required: tuple[ScopeRef, ...] = (),
                            reason_code: str = "scope_failed") -> None:
        self._observe(attr, presence=R_UNVERIFIED, predicate="entity_presence",
                      reason=reason, required=required,
                      verification=verification, reason_code=reason_code)

    def _observe_compose(self, attr: EntityAttributeRow, context, *,
                         docker_failed: bool, docker_disabled: bool,
                         engine_complete: bool, engine_status,
                         projects_seen: set[str],
                         engine_ref: ScopeRef) -> None:
        required: tuple[ScopeRef, ...] = (engine_ref,)
        project = context.project or ""
        if project and self._coverage is not None:
            membership = ScopeRef("compose_membership", project,
                                  "compose_membership")
            if self._coverage.get(membership.scope_type,
                                  membership.scope_key) is not None:
                required = required + (membership,)
        if docker_failed:
            if not docker_disabled and project and project in projects_seen:
                # 降级复核（T2）：list 层面确认 compose 项目仍在，但深探测
                # 失联没能复核内部。出正存在性证据 + FAILED 标记，可见、
                # 待复核，绝不冒充 RUNNING/INSTALLED。
                self._observe(
                    attr, presence=PRESENT, predicate="compose_membership",
                    reason=(f"compose 项目仍在（本轮枚举确认）：{project}，"
                            "深探测失联未复核"),
                    required=required, entity_kind="COMPOSE_DEPLOYMENT",
                    verification=FAILED, reason_code="deep_probe_stalled")
                return
            self._observe_unverified(
                attr, self._docker_reason(docker_disabled),
                verification=NOT_CHECKED if docker_disabled else FAILED,
                required=required,
                reason_code="scope_not_run" if docker_disabled else "scope_failed")
            return
        if not engine_complete:
            self._observe_unverified(
                attr, "Docker 枚举不完整，本轮无法确认 compose 项目",
                verification=(FAILED if engine_status is not None
                              and engine_status.value == "FAILED"
                              else NOT_CHECKED),
                required=required, reason_code="scope_incomplete")
            return
        if project and project in projects_seen:
            self._observe(attr, presence=PRESENT,
                          predicate="compose_membership",
                          reason=f"compose 项目仍在：{project}",
                          required=required, entity_kind="COMPOSE_DEPLOYMENT")
            return
        if project:
            self._observe(attr, presence=ABSENT, predicate="compose_membership",
                          reason=f"compose 项目已不在完整枚举中：{project}",
                          required=required, entity_kind="COMPOSE_DEPLOYMENT")
            return
        self._observe_unverified(
            attr, "compose 项目标识缺失，无法复核",
            verification=NOT_CHECKED, required=required,
            reason_code="scope_not_run")

    def _observe_container(self, attr: EntityAttributeRow, *,
                           docker_failed: bool, docker_disabled: bool,
                           engine_complete: bool, engine_status,
                           containers_seen: set[str],
                           candidates_seen: set[str],
                           engine_ref: ScopeRef) -> None:
        container_id = attr.container_id or ""
        required: tuple[ScopeRef, ...] = (engine_ref,)
        deep_ref = ScopeRef("container_deep_scan", container_id,
                            "component_presence")
        if container_id and self._coverage is not None \
                and self._coverage.get(deep_ref.scope_type,
                                       deep_ref.scope_key) is not None:
            required = required + (deep_ref,)
        if docker_failed:
            if not docker_disabled and container_id and container_id in containers_seen:
                # 降级复核（T2）：枚举确认容器仍在，但深探测失联没能复核
                # 容器内部。正存在性证据 + FAILED 标记，可见、待复核。
                self._observe(
                    attr, presence=PRESENT, predicate="container_presence",
                    reason="容器仍在（本轮枚举确认），深探测失联未复核",
                    required=required, entity_kind="CONTAINER_DEPLOYMENT",
                    verification=FAILED, reason_code="deep_probe_stalled")
                return
            self._observe_unverified(
                attr, self._docker_reason(docker_disabled),
                verification=NOT_CHECKED if docker_disabled else FAILED,
                required=required,
                reason_code="scope_not_run" if docker_disabled else "scope_failed")
            return
        if not engine_complete:
            self._observe_unverified(
                attr, "Docker 枚举不完整，本轮无法确认容器",
                verification=(FAILED if engine_status is not None
                              and engine_status.value == "FAILED"
                              else NOT_CHECKED),
                required=required, reason_code="scope_incomplete")
            return
        if not container_id:
            self._observe_unverified(
                attr, "容器标识未记录，无法复核", verification=NOT_CHECKED,
                required=required, reason_code="scope_not_run")
            return
        if container_id not in containers_seen:
            self._observe(attr, presence=ABSENT, predicate="container_presence",
                          reason="容器已不在完整枚举中",
                          required=required, entity_kind="CONTAINER_DEPLOYMENT")
            return
        if container_id not in candidates_seen:
            self._observe_unverified(
                attr, "容器仍在，但本轮未深扫", verification=NOT_CHECKED,
                required=required, reason_code="scope_not_run")
            return
        deep_status = (self._coverage.predicate_status(
            "container_deep_scan", container_id, "component_presence")
            if self._coverage is not None else None)
        if deep_status is not None and deep_status.value == "COMPLETE":
            self._observe(attr, presence=ABSENT, predicate="component_presence",
                          reason="容器深扫完成，但未再发现该资产",
                          required=required, entity_kind="CONTAINER_DEPLOYMENT")
        else:
            self._observe_unverified(
                attr, f"容器深扫不完整：{deep_status.value if deep_status else 'NOT_RUN'}",
                verification=NOT_CHECKED, required=required,
                reason_code="scope_incomplete")

    def _observe_application(self, attr: EntityAttributeRow, location,
                             *, frameworks_failed: bool, rule_matches) -> None:
        required = (
            ScopeRef("project_candidate_universe", "scan",
                     "application_presence"),
            ScopeRef("host_process_enumeration", "host", "process_inventory"),
        )
        if frameworks_failed and attr.agent_type in self._framework_ids:
            self._observe_unverified(
                attr, "自建框架扫描本轮失败", verification=FAILED,
                required=required)
            return
        root_path = location.root_path or ""
        if attr.origin == "docker" or root_path.startswith(
                ("container:", "engine:")):
            self._observe_unverified(
                attr, "容器内应用路径无法在宿主复核", verification=NOT_CHECKED,
                required=required, reason_code="scope_not_run")
            return
        root_verdict = reconfirm_application(root_path)
        if root_verdict.verdict == ABSENT:
            self._observe(attr, presence=ABSENT, predicate="component_presence",
                          reason="项目目录已不存在", required=required,
                          entity_kind="SELF_BUILT_APPLICATION")
            return
        if root_verdict.verdict == R_UNVERIFIED:
            self._observe_unverified(
                attr, "未记录可复核的项目目录", verification=NOT_CHECKED,
                required=required, reason_code="scope_not_run")
            return
        app = {
            "app_id": attr.entity_id,
            "root_path": root_path,
            "environment_path": location.environment_path,
            "runtime": location.runtime,
        }
        installed = self._installed_dependencies(app)
        rule = self._framework_rules.get(attr.agent_type)
        if installed is not None and rule is not None \
                and not rule_matches(rule, installed):
            self._observe(attr, presence=ABSENT, predicate="component_presence",
                          reason="已安装依赖不再匹配该框架",
                          required=required,
                          entity_kind="SELF_BUILT_APPLICATION")
            return
        self._observe(attr, presence=PRESENT, predicate="component_presence",
                      reason="项目目录仍在", required=required,
                      entity_kind="SELF_BUILT_APPLICATION")

    def _observe_product(self, attr: EntityAttributeRow) -> None:
        try:
            import json
            paths = list(json.loads(attr.config_paths_json or "[]"))
        except ValueError:
            paths = []
        if attr.executable:
            paths.append(attr.executable)
        verdict = reconfirm_paths(paths)
        required = product_scope_refs(self._coverage, attr.agent_type)
        if verdict.verdict == ABSENT:
            self._observe(attr, presence=ABSENT, predicate="product_presence",
                          reason="记录的安装路径均已不存在", required=required,
                          entity_kind="PRODUCT_INSTALL")
            return
        if verdict.verdict == R_UNVERIFIED:
            self._observe_unverified(
                attr, "未记录可复核的安装路径", verification=NOT_CHECKED,
                required=required, reason_code="scope_not_run")
            return
        self._observe(attr, presence=PRESENT, predicate="product_presence",
                      reason="记录的安装路径仍存在", required=required,
                      entity_kind="PRODUCT_INSTALL")

    @staticmethod
    def _docker_reason(disabled: bool) -> str:
        return ("docker 通道本轮未启用" if disabled
                else "容器状态：docker 引擎本轮不可达")

    def _mark_unverified(self, entity_id: str, reason: str) -> None:
        """Record that this run could not check the entity (no absence proof)."""
        self.unverified.setdefault(entity_id, reason)

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