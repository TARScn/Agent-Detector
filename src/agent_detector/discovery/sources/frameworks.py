"""Framework identity per resolved project, from dependency metadata only.

Design §6: dependency hits prove a framework *environment* (INSTALLED), and
only the process→project link upgrades that to RUNNING — never process-name
matching, which self-built agents defeat by design. Honesty rule for one
project hosting several frameworks (design §6.3): the RUNNING state and the
process instances stay with the application asset alone; framework assets
keep INSTALLED unless the app has exactly one framework, because we cannot
tell which framework a given process actually exercises.

The application asset itself requires AI-relevant components to exist at all
(design §9: a plain FastAPI service must not confirm an Agent). Projects
without any framework or LLM-SDK dependency produce no assets.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from agent_detector.core.security import redact
from agent_detector.discovery.sources.deps import normalize_name
from agent_detector.discovery.fingerprints.schema import FrameworkRule
from agent_detector.core.identity import build_asset_id, slugify
from agent_detector.core.enums import AssetState, AssetType, EvidenceKind, VersionSource
from agent_detector.core.models import (ComponentInfo, DetectedAsset, Evidence, ProcessInfo,
                                          ProjectInfo, VersionInfo)

_CMDLINE_TEXT_LIMIT = 400

_VERSION_CONFIDENCE = {VersionSource.PACKAGE_METADATA: 0.9,
                       VersionSource.LOCKED: 0.8,
                       VersionSource.DECLARED: 0.6}

_MAX_PROCESS_EVIDENCE = 4


@dataclass
class ApplicationBundle:
    """One AI-relevant application: its asset, framework identities, components."""

    asset: DetectedAsset
    project: ProjectInfo
    components: list[ComponentInfo] = field(default_factory=list)
    frameworks: list[DetectedAsset] = field(default_factory=list)

    @property
    def app_id(self) -> str:
        return self.asset.asset_id

    @property
    def framework_ids(self) -> list[str]:
        return [item.detector for item in self.frameworks]

    def to_summary(self) -> dict:
        return {"app_id": self.app_id, "name": self.project.name,
                "root_path": self.project.root, "runtime": self.project.runtime,
                "frameworks": self.framework_ids,
                "components": [c.to_dict() for c in self.components],
                "pids": list(self.project.pids)}


def rule_matches(rule: FrameworkRule, component_names: set[str]) -> bool:
    any_names = {normalize_name(name) for name in rule.dependencies.any}
    all_names = {normalize_name(name) for name in rule.dependencies.all}
    if any_names and not (any_names & component_names):
        return False
    return not all_names or all_names <= component_names


def _version_of(component: ComponentInfo) -> VersionInfo:
    return VersionInfo(component.version, component.version_source,
                       _VERSION_CONFIDENCE.get(component.version_source, 0.3))


def _process_evidence(processes_by_pid: dict[int, ProcessInfo],
                      pids: tuple[int, ...]) -> list[Evidence]:
    evidence: list[Evidence] = []
    for pid in list(pids)[:_MAX_PROCESS_EVIDENCE]:
        proc = processes_by_pid.get(pid)
        if proc is None:
            continue
        evidence.append(Evidence(
            kind=EvidenceKind.PROCESS,
            summary=f"进程 {pid} 关联项目目录 {proc.cwd or '未知'}",
            detail={"pid": pid, "name": proc.name,
                    "cmdline": redact(" ".join(proc.cmdline))[:_CMDLINE_TEXT_LIMIT],
                    "cwd": proc.cwd},
            confidence=0.85))
    return evidence


def _component_evidence(component: ComponentInfo, *, rule: str | None = None) -> Evidence:
    detail: dict[str, object] = {"name": component.name, "version": component.version,
                                 "source": component.version_source.value,
                                 "path": component.source_path}
    if rule:
        detail["rule"] = rule
    return Evidence(
        kind=EvidenceKind.DEPENDENCY_METADATA,
        summary=f"依赖组件 {component.name} {component.version}"
                f"（{component.version_source.value}）",
        detail=detail,
        confidence=_VERSION_CONFIDENCE.get(component.version_source, 0.3))


def detect_frameworks(projects: list[ProjectInfo],
                      components_by_project: dict[str, list[ComponentInfo]],
                      rules: list[FrameworkRule], hostname: str,
                      processes_by_pid: dict[int, ProcessInfo] | None = None,
                      ports_by_pid: dict[int, list[int]] | None = None
                      ) -> list[ApplicationBundle]:
    """Group AI-relevant projects into application bundles with framework assets."""
    processes_by_pid = processes_by_pid or {}
    ports_by_pid = ports_by_pid or {}
    bundles: list[ApplicationBundle] = []

    for project in projects:
        if project.resolver_status != "resolved":
            continue  # no stable identity without a root; still counted in scan stats
        components = components_by_project.get(project.project_id, [])
        if not components:
            continue  # no AI-relevant dependency -> no claim at all
        names = {component.name for component in components}
        matched = [rule for rule in rules if rule_matches(rule, names)]

        ports = sorted({port for pid in project.pids for port in ports_by_pid.get(pid, [])})
        app_id = build_asset_id(hostname, slugify(project.name), f"project:{project.root}")
        app_evidence = [Evidence(
            kind=EvidenceKind.FILE_METADATA,
            summary=f"项目解析：{project.name}（运行时 {project.runtime}）",
            detail={"path": project.root, "environment_path": project.environment_path,
                    "entry": project.entry, "entry_kind": project.entry_kind,
                    "resolver_status": project.resolver_status},
            confidence=0.8)]
        app_evidence.extend(_process_evidence(processes_by_pid, project.pids))
        app_evidence.extend(_component_evidence(component) for component in components)
        app_asset = DetectedAsset(
            asset_id=app_id, name=project.name, asset_type=AssetType.AI_APPLICATION,
            states={AssetState.RUNNING},
            confidence=0.7,  # 项目-进程关联 0.5 + AI 依赖证据 0.2
            version=VersionInfo.unknown(),
            evidence=app_evidence, running_pids=list(project.pids),
            listening_ports=ports, detector="frameworks",
            executable=project.executable)

        # Framework assets: INSTALLED on dependency evidence; RUNNING (+ the
        # app's processes) only when this framework is the app's only one.
        single = len(matched) == 1
        framework_assets: list[DetectedAsset] = []
        for rule in matched:
            rule_deps = {normalize_name(name) for name in rule.dependencies.any} | \
                        {normalize_name(name) for name in rule.dependencies.all}
            hit = [component for component in components if component.name in rule_deps]
            best = max(hit, key=lambda c: _VERSION_CONFIDENCE.get(c.version_source, 0.3),
                       default=None)
            states = {AssetState.INSTALLED}
            running_pids: list[int] = []
            if single:
                states.add(AssetState.RUNNING)
                running_pids = list(project.pids)
            spec = rule.confidence
            confidence = spec.base + (spec.installed if hit else 0.0) + \
                (spec.running if single else 0.0)
            framework_assets.append(DetectedAsset(
                asset_id=build_asset_id(hostname, rule.id, f"project:{project.root}"),
                name=rule.name, asset_type=AssetType.AGENT_RUNTIME,
                states=states,
                confidence=round(min(spec.cap, confidence), 2),
                version=_version_of(best) if best else VersionInfo.unknown(),
                evidence=[_component_evidence(component, rule=rule.id) for component in hit],
                running_pids=running_pids,
                detector=rule.id, executable=project.executable))

        bundles.append(ApplicationBundle(asset=app_asset, project=project,
                                         components=components,
                                         frameworks=framework_assets))
    return bundles
