"""Docker 容器内的 Agent 发现与识别（Docker Core）。

链路（设计第三节）：Docker API 枚举全部容器（含已停止）→ 基础信息采集
（镜像 / 启动命令 / top 进程）→ 候选筛选 → 容器内静态文件与依赖元数据 →
框架与版本识别 → 资产与证据。全程只读 API，绝不 docker exec。

诚实规则在容器场景的延续：

* 依赖命中只证明框架*环境*（INSTALLED）。容器运行且存在进程证据时才由
  detect_frameworks 的"单一框架才挂进程"规则升级 RUNNING；已停止（或拿
  不到进程列表）的容器永不 RUNNING —— 静态指纹能回答"容器里有什么框架"，
  不能证明 Agent 正在执行任务。
* 一个容器是一个项目边界：容器内全部进程归属该应用（类比宿主路径上的
  venv），这是容器场景下进程→项目归属的等价物。
* 版本出处链：已安装包元数据 > 锁定文件 > 声明依赖 > 镜像标签 > UNKNOWN，
  任何一级都读不到就返回 UNKNOWN，绝不猜测。

客户端识别在容器内由通用容器 client 机制承担：client_rule 声明 ``container``
段（npm 全局根 / 配置文件 / 进程 token / 镜像关键词），本模块按规则定向
只读探测 —— 宿主与容器共用同一条产品规则（OpenClaw、n8n 均走此机制）。
一个容器可以产出多个框架资产；同一框架出现在多个容器时是彼此独立的资产
（scope 含容器短 ID），跨容器合并留待后续迭代。
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from importlib.resources import files as resource_files
from pathlib import Path, PurePosixPath

import yaml

from agent_detector.core.config import (DOCKER_ARCHIVE_BYTE_CAP,
                                        DOCKER_ARCHIVE_TIME_CAP_S,
                                        DOCKER_MAX_CONTAINERS,
                                        DOCKER_READ_MAX_BYTES,
                                        DOCKER_TIMEOUT_S)
from agent_detector.core.enums import AssetState, AssetType, EvidenceKind, VersionSource
from agent_detector.core.identity import build_asset_id
from agent_detector.core.models import (ComponentInfo, DetectedAsset, Evidence, ProcessInfo,
                                        ProjectInfo, VersionInfo)
from agent_detector.core.security import redact
from agent_detector.discovery.sources import dockerapi
from agent_detector.discovery.sources.deps import (components_from_lock_text,
                                                   components_from_pyproject_text,
                                                   components_from_requirements_text,
                                                   interest_names, normalize_name)
from agent_detector.discovery.sources.dockerapi import ContainerBrief, DockerUnavailable, TopProcess
from agent_detector.discovery.sources.frameworks import ApplicationBundle, detect_frameworks

logger = logging.getLogger(__name__)

_PACKAGED_HINTS = resource_files("agent_detector.discovery").joinpath("data/docker_hints.yaml")

# 与 data/docker_hints.yaml 保持一致；YAML 不可读时降级到这里（筛选只影响
# 成本，降级为内置默认而不是空集，避免整条通道静默失效）。
_DEFAULT_HINTS: dict[str, set[str]] = {
    "image_keywords": {"agent", "agentic", "langchain", "langgraph", "crewai", "autogen",
                       "openclaw", "claude", "codex", "cursor", "opencode", "hermes",
                       "openai", "anthropic", "llm"},
    "command_tokens": {"langchain", "langgraph", "langgraph_cli", "crewai", "autogen",
                       "openclaw"},
    "runtime_image_bases": {"python", "python3", "node", "nodejs"},
    "runtime_process_names": {"python", "python3", "node", "nodejs", "npm", "npx",
                              "bun", "deno", "uvicorn", "gunicorn"},
}
_NODE_RUNTIME_NAMES = {"node", "nodejs", "npm", "npx", "bun", "deno"}

_PROJECT_ROOT_CANDIDATES = ("/app", "/workspace", "/srv", "/opt/app", "/usr/src/app")
_PYTHON_VERSION_PROBE = tuple(f"3.{minor}" for minor in range(14, 7, -1))
_IMAGE_TAG_VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+){0,3})$")
_PYTHON_IN_CMDLINE_RE = re.compile(r"python3\.(\d+)")

_CMDLINE_TEXT_LIMIT = 400

# 已安装(3) > 锁定(2) > 声明(1)，与 deps.scan_project_dependencies 同一出处排序。
_PROVENANCE_RANK = {VersionSource.PACKAGE_METADATA: 3,
                    VersionSource.LOCKED: 2,
                    VersionSource.DECLARED: 1}


@dataclass
class DockerScanOutcome:
    """One docker stage result: bundles + client assets + inventory context."""

    bundles: list[ApplicationBundle] = field(default_factory=list)
    assets: list[DetectedAsset] = field(default_factory=list)  # client assets (e.g. OpenClaw)
    container_links: dict[str, dict] = field(default_factory=dict)
    containers_seen: list[str] = field(default_factory=list)
    candidates_seen: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=lambda: {"containers_total": 0, "candidates": 0,
                                                 "agents": 0, "error": None})


def load_docker_hints(data_file: Path | str | None = None) -> dict[str, set[str]]:
    """Candidate-screening hints; a broken YAML degrades to the built-ins."""
    hints = {key: set(values) for key, values in _DEFAULT_HINTS.items()}
    target = Path(data_file) if data_file else Path(str(_PACKAGED_HINTS))
    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError):
        logger.warning("docker_hints.yaml unreadable; using built-in hints")
        return hints
    for key in hints:
        values = raw.get(key)
        if isinstance(values, list):
            hints[key] = {str(value).strip().lower() for value in values
                          if str(value).strip()}
    return hints


def scan_docker_agents(framework_rules: list, hostname: str, *,
                       client_rules: list | tuple = (),
                       client=None,
                       hints: dict[str, set[str]] | None = None,
                       max_containers: int = DOCKER_MAX_CONTAINERS,
                       read_max_bytes: int = DOCKER_READ_MAX_BYTES,
                       archive_byte_cap: int = DOCKER_ARCHIVE_BYTE_CAP,
                       archive_time_cap: float = DOCKER_ARCHIVE_TIME_CAP_S
                       ) -> DockerScanOutcome:
    """Enumerate every container, screen candidates, identify agents inside.

    ``client_rules`` carry the ``container`` sections that drive the generic
    container-client loop. Daemon/SDK problems raise nothing: they degrade
    into ``stats["error"]`` so the scan continues and the inventory's stale
    verification knows the docker channel said nothing this round.
    """
    outcome = DockerScanOutcome()
    if client is None:
        try:
            client = dockerapi.build_client(DOCKER_TIMEOUT_S)
        except DockerUnavailable as exc:
            outcome.stats = {"containers_total": 0, "candidates": 0, "agents": 0,
                             "error": str(exc)}
            return outcome
    hints = _with_rule_keywords({key: set(values) for key, values
                                 in (hints or load_docker_hints()).items()},
                                client_rules)
    interest = interest_names({name for rule in framework_rules
                               for name in (*rule.dependencies.any,
                                             *rule.dependencies.all)})
    try:
        containers = dockerapi.list_all_containers(client, max_containers)
    except Exception as exc:
        logger.warning("docker container listing failed: %s", exc)
        outcome.stats = {"containers_total": 0, "candidates": 0, "agents": 0,
                         "error": f"容器枚举失败: {exc}"}
        return outcome

    outcome.containers_seen = [brief.container_id for brief in containers]
    errors: list[dict] = []
    for brief in containers:
        try:
            top = (dockerapi.container_top(client, brief.container_id)
                   if brief.state == "running" else [])
        except Exception as exc:
            logger.warning("container %s: top failed: %s", brief.short_id, exc)
            top = []
        reasons = screen_candidate(brief, hints, top)
        if not reasons:
            continue
        outcome.candidates_seen.append(brief.container_id)
        try:
            bundles, clients, links = _identify_container(
                client, brief, top, reasons=reasons, hostname=hostname,
                framework_rules=framework_rules, client_rules=client_rules,
                interest=interest, hints=hints,
                read_max_bytes=read_max_bytes, archive_byte_cap=archive_byte_cap,
                archive_time_cap=archive_time_cap)
        except Exception as exc:  # per-container isolation, like a detector
            logger.warning("container %s identification failed: %s",
                           brief.short_id, exc)
            errors.append({"container": brief.short_id, "error": str(exc)})
            continue
        outcome.bundles.extend(bundles)
        outcome.assets.extend(clients)
        outcome.container_links.update(links)
    outcome.stats = {"containers_total": len(containers),
                     "candidates": len(outcome.candidates_seen),
                     "agents": (sum(len(bundle.frameworks) for bundle in outcome.bundles)
                                + len(outcome.assets)),
                     "container_errors": errors,
                     "error": None}
    return outcome


# ---------------------------------------------------------------------------
# Candidate screening: permissive OR — a miss here hides an agent entirely,
# so image/command/process/runtime signals all count and the deep scan in
# the next stage makes the real decision.
# ---------------------------------------------------------------------------

def screen_candidate(brief: ContainerBrief, hints: dict[str, set[str]],
                     top: list[TopProcess]) -> list[str]:
    """Match reasons for one container; empty means "not a candidate"."""
    reasons: list[str] = []
    image = brief.image.lower()
    for keyword in sorted(hints["image_keywords"]):
        if keyword in image:
            reasons.append(f"image~{keyword}")
    command = (brief.command or "").lower()
    for token in sorted(hints["command_tokens"]):
        if token in command:
            reasons.append(f"command~{token}")
    seen_tokens: set[str] = set()
    for proc in top:
        cmdline = proc.cmdline.lower()
        for token in sorted(hints["command_tokens"]):
            if token in cmdline and token not in seen_tokens:
                seen_tokens.add(token)
                reasons.append(f"process~{token}")
    runtime = _runtime_of(brief, top, hints)
    if runtime != "unknown":
        reasons.append(f"runtime:{runtime}")
    return reasons


def _with_rule_keywords(hints: dict[str, set[str]],
                        client_rules) -> dict[str, set[str]]:
    """Merge every client rule's ``container.image_keywords`` into screening.

    Product rules know their own container image names (n8n, openclaw, …);
    the generic hint list stays small and the rules stay the single source.
    """
    for rule in client_rules:
        spec = getattr(rule, "container", None)
        if spec is None:
            continue
        hints["image_keywords"] |= {keyword.strip().lower()
                                    for keyword in spec.image_keywords
                                    if keyword.strip()}
    return hints


def _image_base(image: str) -> str:
    """Last path segment of the repository, minus tag/digest."""
    repo = image.split("@", 1)[0]
    tail = repo.rsplit("/", 1)[-1]
    return tail.split(":", 1)[0].lower()


def _runtime_of(brief: ContainerBrief, top: list[TopProcess],
                hints: dict[str, set[str]]) -> str:
    for proc in top:
        first = proc.cmdline.split()[0] if proc.cmdline.split() else ""
        base = PurePosixPath(first.replace("\\", "/")).name.lower()
        for name in hints["runtime_process_names"]:
            if base == name or base.startswith(name):
                return "node" if name in _NODE_RUNTIME_NAMES else "python"
    base = _image_base(brief.image)
    if base in hints["runtime_image_bases"]:
        return "node" if base in _NODE_RUNTIME_NAMES else "python"
    return "unknown"


# ---------------------------------------------------------------------------
# Per-container identification
# ---------------------------------------------------------------------------

def _identify_container(client, brief: ContainerBrief, top: list[TopProcess], *,
                        reasons: list[str], hostname: str, framework_rules: list,
                        client_rules: list | tuple,
                        interest: set[str], hints: dict[str, set[str]],
                        read_max_bytes: int, archive_byte_cap: int,
                        archive_time_cap: float,
                        ) -> tuple[list[ApplicationBundle], list[DetectedAsset],
                                   dict[str, dict]]:
    try:
        info = dockerapi.inspect_container(client, brief.container_id)
    except Exception as exc:
        logger.debug("container %s: inspect failed: %s", brief.short_id, exc)
        info = {}
    state = info.get("State") or {}
    running = brief.state == "running" and state.get("Running", True)
    started_at = str(state.get("StartedAt") or "")
    workdir = str((info.get("Config") or {}).get("WorkingDir") or "")
    internal_root = workdir or next(
        (path for path in _PROJECT_ROOT_CANDIDATES
         if dockerapi.probe_path(client, brief.container_id, path)), "/")

    # client rule 声明的包根（如 /usr/local/lib/node_modules/n8n）：官方镜像
    # 把产品与依赖树装在 npm 全局布局里，WORKDIR 探测够不着 —— 规则知道在哪。
    package_roots: list[str] = []
    for rule in client_rules:
        spec = getattr(rule, "container", None)
        if spec is None:
            continue
        package = spec.package or rule.id
        for npm_root in spec.npm_roots:
            package_roots.append(f"{npm_root.rstrip('/')}/{package}")

    runtime = _runtime_of(brief, top, hints)
    site_packages = _find_site_packages(client, brief.container_id, internal_root, top)
    if runtime == "unknown" and site_packages:
        runtime = "python"

    processes_by_pid: dict[int, ProcessInfo] = {}
    for proc in top:
        tokens = proc.cmdline.split()
        exe = tokens[0] if tokens else ""
        processes_by_pid[proc.pid] = ProcessInfo(
            pid=proc.pid, name=PurePosixPath(exe.replace("\\", "/")).name,
            cmdline=tuple(tokens), create_time=None, ppid=proc.ppid,
            exe=exe or None, cwd=None)

    def make_project(root_path: str, project_runtime: str,
                     entry_kind: str) -> ProjectInfo:
        return ProjectInfo(
            project_id="proj-" + hashlib.sha256(
                f"{brief.container_id}|{root_path}".encode("utf-8")).hexdigest()[:12],
            root=f"container:{brief.short_id}{root_path}",
            name=brief.name or brief.short_id,
            runtime=project_runtime,
            pids=tuple(proc.pid for proc in top),
            entry=brief.command or None,
            entry_kind=entry_kind,
            container_id=brief.container_id,
            resolver_status="resolved")

    projects: list[ProjectInfo] = []
    components_by_project: dict[str, list[ComponentInfo]] = {}

    main_project = make_project(internal_root, runtime, "container-command")
    main_components = _best_components(_python_components(
        client, brief, internal_root, site_packages, interest,
        read_max_bytes, archive_byte_cap, archive_time_cap))
    main_components.extend(_best_components(_node_components(
        client, brief, internal_root, interest, read_max_bytes)))
    projects.append(main_project)
    components_by_project[main_project.project_id] = main_components

    for package_root in package_roots:
        # 探 package.json（小文件）而不是目录本身 —— 探大目录会让 daemon
        # 开始生成几百 MB 的 tar，断流检测滞后会拖垮紧随其后的请求。
        if not dockerapi.probe_path(client, brief.container_id,
                                    f"{package_root}/package.json"):
            continue
        pkg_project = make_project(package_root, "node", "container-package")
        components_by_project[pkg_project.project_id] = _best_components(
            _node_components(client, brief, package_root, interest,
                             read_max_bytes, interest_probes=True))
        projects.append(pkg_project)

    bundles = detect_frameworks(projects, components_by_project,
                                framework_rules, hostname,
                                processes_by_pid=processes_by_pid)
    if not running or not top:
        _strip_running_claims(bundles, framework_rules)
    _apply_image_tag_version(bundles, brief.image)

    evidence = _container_evidence(brief, reasons, running, started_at)
    link = {"container_id": brief.container_id, "short_id": brief.short_id,
            "image": brief.image, "state": brief.state,
            "started_at": started_at, "command": brief.command,
            "processes": {str(proc.pid): proc.cmdline for proc in top}}
    links: dict[str, dict] = {}
    for bundle in bundles:
        bundle.asset.evidence.append(evidence)
        links[bundle.asset.asset_id] = link
        for framework in bundle.frameworks:
            framework.evidence.append(evidence)
            links[framework.asset_id] = link

    clients = _detect_container_clients(client, brief, running, top, hostname,
                                        client_rules, read_max_bytes)
    for asset in clients:
        asset.evidence.append(evidence)
        links[asset.asset_id] = link
    return bundles, clients, links


def _python_versions_from_cmdlines(top: list[TopProcess]) -> list[str]:
    found: list[str] = []
    for proc in top:
        for minor in _PYTHON_IN_CMDLINE_RE.findall(proc.cmdline):
            version = f"3.{minor}"
            if version not in found:
                found.append(version)
    return found


def _find_site_packages(client, container_id: str, internal_root: str,
                        top: list[TopProcess]) -> str | None:
    """Locate a site-packages directory by existence probes (no readdir).

    Interpreters seen in ``docker top`` name their version, which jumps the
    probe queue; the rest is a fixed, tiny sequence of 404s. venv layout
    first (the env that actually runs), then system prefixes.
    """
    hinted = _python_versions_from_cmdlines(top)
    versions = hinted + [v for v in _PYTHON_VERSION_PROBE if v not in hinted]
    for version in versions:
        bases = (f"{internal_root}/.venv/lib", "/usr/local/lib", "/usr/lib")
        for base in bases:
            candidate = f"{base}/python{version}/site-packages"
            if dockerapi.probe_path(client, container_id, candidate):
                return candidate
    return None


def _python_components(client, brief: ContainerBrief, internal_root: str,
                       site_packages: str | None, interest: set[str],
                       read_max_bytes: int, archive_byte_cap: int,
                       archive_time_cap: float) -> list[ComponentInfo]:
    observed: list[ComponentInfo] = []
    readers = (("pyproject.toml", components_from_pyproject_text),
               ("requirements.txt", components_from_requirements_text),
               ("uv.lock", components_from_lock_text),
               ("poetry.lock", components_from_lock_text))
    for name, parse in readers:
        raw = dockerapi.read_container_file(
            client, brief.container_id, f"{internal_root}/{name}", read_max_bytes)
        if not raw:
            continue
        source = f"container:{brief.short_id}:{internal_root}/{name}"
        observed.extend(parse(raw.decode("utf-8", "replace"), source, interest))
    if site_packages:
        for name, version, member in dockerapi.iter_dist_metadata(
                client, brief.container_id, site_packages, interest=interest,
                byte_cap=archive_byte_cap, time_cap=archive_time_cap):
            observed.append(ComponentInfo(
                name=name, version=version or "UNKNOWN",
                version_source=VersionSource.PACKAGE_METADATA,
                source_path=f"container:{brief.short_id}:{member}"))
    return observed


def _node_components(client, brief: ContainerBrief, internal_root: str,
                     interest: set[str], read_max_bytes: int, *,
                     interest_probes: bool = False) -> list[ComponentInfo]:
    observed: list[ComponentInfo] = []
    raw = dockerapi.read_container_file(
        client, brief.container_id, f"{internal_root}/package.json", read_max_bytes)
    if raw:
        try:
            data = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            data = {}
        source = f"container:{brief.short_id}:{internal_root}/package.json"
        declared: list[tuple[str, str]] = []  # (raw npm name, normalized)
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            values = data.get(section)
            if not isinstance(values, dict):
                continue
            for package in values:
                normalized = normalize_name(str(package))
                if normalized in interest:
                    declared.append((str(package), normalized))
                    observed.append(ComponentInfo(
                        name=normalized, version="UNKNOWN",
                        version_source=VersionSource.DECLARED, source_path=source))
        # Installed node metadata: exact paths from the declared names, so each
        # read is one cheap targeted get_archive instead of a tree walk.
        for package, normalized in declared:
            pkg_raw = dockerapi.read_container_file(
                client, brief.container_id,
                f"{internal_root}/node_modules/{package}/package.json", read_max_bytes)
            if not pkg_raw:
                continue
            try:
                pkg_data = json.loads(pkg_raw.decode("utf-8", "replace"))
            except ValueError:
                continue
            version = str(pkg_data.get("version") or "")
            if not version:
                continue
            observed.append(ComponentInfo(
                name=normalized, version=version,
                version_source=VersionSource.PACKAGE_METADATA,
                source_path=(f"container:{brief.short_id}:{internal_root}"
                             f"/node_modules/{package}/package.json")))
    if not interest_probes:
        return observed
    # 兴趣驱动的定向读：npm 的安装路径就是包名，不需要 readdir —— 对兴趣表
    # 里的每个名字直接探测标准提升位置 <root>/node_modules/<name>/package.json
    # （scoped 名自带 @scope/ 前缀，路径成立）。覆盖"宿主产品包内嵌 AI 依赖"
    # 的嵌套提升布局（如 n8n 内嵌 @langchain/core），与声明列表无关。
    base = f"{internal_root.rstrip('/')}/node_modules"
    for name in sorted(interest):
        pkg_raw = dockerapi.read_container_file(
            client, brief.container_id, f"{base}/{name}/package.json",
            read_max_bytes)
        if not pkg_raw:
            continue
        try:
            pkg_data = json.loads(pkg_raw.decode("utf-8", "replace"))
        except ValueError:
            continue
        version = str(pkg_data.get("version") or "")
        if not version:
            continue
        observed.append(ComponentInfo(
            name=normalize_name(name), version=version,
            version_source=VersionSource.PACKAGE_METADATA,
            source_path=f"container:{brief.short_id}:{base}/{name}/package.json"))
    return observed


def _best_components(observed: list[ComponentInfo]) -> list[ComponentInfo]:
    """Best provenance per package name, mirroring deps.scan_project_dependencies."""
    best: dict[str, ComponentInfo] = {}
    for component in observed:
        current = best.get(component.name)
        if current is None or _PROVENANCE_RANK.get(component.version_source, 0) > \
                _PROVENANCE_RANK.get(current.version_source, 0):
            best[component.name] = component
    return sorted(best.values(), key=lambda item: item.name)


def _strip_running_claims(bundles: list[ApplicationBundle],
                          framework_rules: list) -> None:
    """已停止（或拿不到进程列表）的容器永不携带 RUNNING。"""
    rules_by_id = {rule.id: rule for rule in framework_rules}
    for bundle in bundles:
        bundle.asset.states.discard(AssetState.RUNNING)
        bundle.asset.states.add(AssetState.INSTALLED)
        bundle.asset.running_pids = []
        for framework in bundle.frameworks:
            if AssetState.RUNNING in framework.states:
                framework.states.discard(AssetState.RUNNING)
                rule = rules_by_id.get(framework.detector)
                if rule is not None:
                    framework.confidence = round(max(
                        rule.confidence.base,
                        framework.confidence - rule.confidence.running), 2)
            framework.running_pids = []


def _apply_image_tag_version(bundles: list[ApplicationBundle], image: str) -> None:
    """Lowest-priority version source: the image tag, only for a container
    whose single framework has no better version anywhere."""
    tail = image.rsplit("/", 1)[-1]
    tag = tail.rsplit(":", 1)[1] if ":" in tail else ""
    match = _IMAGE_TAG_VERSION_RE.match(tag)
    if not match:
        return
    for bundle in bundles:
        if len(bundle.frameworks) != 1:
            continue
        framework = bundle.frameworks[0]
        if framework.version.known:
            continue
        framework.version = VersionInfo(match.group(1), VersionSource.IMAGE_TAG, 0.4)


def _container_evidence(brief: ContainerBrief, reasons: list[str], running: bool,
                        started_at: str) -> Evidence:
    return Evidence(
        kind=EvidenceKind.CONTAINER_METADATA,
        summary=f"容器候选 {brief.short_id}（{brief.image}，{brief.state}）",
        detail={"container_id": brief.container_id, "name": brief.name,
                "image": brief.image, "state": brief.state,
                "command": redact(brief.command or "")[:_CMDLINE_TEXT_LIMIT],
                "started_at": started_at, "running": running,
                "match_reasons": reasons},
        confidence=0.75)


def _detect_container_clients(client, brief: ContainerBrief, running: bool,
                              top: list[TopProcess], hostname: str,
                              client_rules, read_max_bytes: int
                              ) -> list[DetectedAsset]:
    """通用容器 client 识别：遍历声明了 ``container`` 段的 client_rule。

    证据语义与宿主引擎同构，全部为容器内定向只读：
    * ``<npm_root>/<package>/package.json`` → INSTALLED + 版本；
    * ``config_json``（JSON 顶层键名）/ ``config_existing``（存在性探测）
      → CONFIGURED；
    * 容器运行且 top 进程命中 ``process_tokens``（子串匹配，或首段可执行
      名精确相等 —— 覆盖官方镜像把二进制改名为产品名的情况，如 n8n）
      → RUNNING。
    置信度按各规则的 ConfidenceSpec 合成；识别不出就不造资产。
    """
    assets: list[DetectedAsset] = []
    for rule in client_rules:
        spec = getattr(rule, "container", None)
        if spec is None:
            continue
        package = spec.package or rule.id
        evidence: list[Evidence] = []
        states: set[AssetState] = set()
        version = ""
        config_paths: list[str] = []
        for npm_root in spec.npm_roots:
            package_json_path = f"{npm_root.rstrip('/')}/{package}/package.json"
            raw = dockerapi.read_container_file(
                client, brief.container_id, package_json_path, read_max_bytes)
            if not raw:
                continue
            try:
                data = json.loads(raw.decode("utf-8", "replace"))
            except ValueError:
                data = {}
            version = str(data.get("version") or "")
            states.add(AssetState.INSTALLED)
            evidence.append(Evidence(
                kind=EvidenceKind.INSTALL_METADATA,
                summary=f"npm 包 {package}（{npm_root}）",
                detail={"path": package_json_path,
                        "version": version or "UNKNOWN"},
                confidence=0.9))
            break
        for probe in spec.config_json:
            raw = dockerapi.read_container_file(
                client, brief.container_id, probe.path, read_max_bytes)
            if not raw:
                continue
            try:
                keys = list((json.loads(raw.decode("utf-8", "replace")) or {}).keys())
            except ValueError:
                keys = []
            hit = [key for key in probe.keys_any if key in keys]
            if not hit:
                continue
            states.add(AssetState.CONFIGURED)
            config_paths.append(probe.path)
            evidence.append(Evidence(
                kind=EvidenceKind.FILE_CONTENT_KEYS,
                summary=f"配置 {probe.path} 含键 {hit}",
                detail={"path": probe.path, "keys": hit},
                confidence=probe.confidence))
        for path in spec.config_existing:
            if not dockerapi.probe_path(client, brief.container_id, path):
                continue
            states.add(AssetState.CONFIGURED)
            config_paths.append(path)
            evidence.append(Evidence(
                kind=EvidenceKind.FILE_METADATA,
                summary=f"状态目录存在：{path}",
                detail={"path": path},
                confidence=0.8))
        running_pids: list[int] = []
        if running:
            tokens = [token.lower() for token in spec.process_tokens]
            for proc in top:
                parts = proc.cmdline.split()
                first = PurePosixPath(
                    (parts[0] if parts else "").replace("\\", "/")).name.lower()
                cmdline = proc.cmdline.lower()
                if any(token == first or token in cmdline for token in tokens):
                    running_pids.append(proc.pid)
        if running_pids:
            states.add(AssetState.RUNNING)
            cmdlines = " ".join(proc.cmdline for proc in top
                                if proc.pid in running_pids)
            evidence.append(Evidence(
                kind=EvidenceKind.PROCESS,
                summary=f"容器进程命中 {rule.name}（pid {running_pids}）",
                detail={"pids": running_pids,
                        "cmdline": redact(cmdlines)[:_CMDLINE_TEXT_LIMIT]},
                confidence=0.85))
        if not states:
            continue
        weights = rule.confidence
        confidence = round(min(weights.cap, weights.base
                               + (weights.installed
                                  if AssetState.INSTALLED in states else 0.0)
                               + (weights.configured
                                  if AssetState.CONFIGURED in states else 0.0)
                               + (weights.running
                                  if AssetState.RUNNING in states else 0.0)), 2)
        version_info = (VersionInfo(version, VersionSource.PACKAGE_METADATA, 0.9)
                        if version else VersionInfo.unknown())
        assets.append(DetectedAsset(
            asset_id=build_asset_id(hostname, rule.id, f"container:{brief.short_id}"),
            name=rule.name, asset_type=rule.asset_type, states=states,
            confidence=confidence, version=version_info, evidence=evidence,
            running_pids=running_pids, detector=rule.id,
            config_paths=config_paths))
    return assets
