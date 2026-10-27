"""docker_agents：候选筛选与容器内识别（fake client，无真实 Docker）。

覆盖设计要点：镜像名不可信（python-app 也能通过进程识别入选）、已停止
容器可识别、单容器多框架不挂进程、诚实 RUNNING 规则、版本出处链
（installed > declared > image-tag）、通用容器 client 机制（OpenClaw /
n8n 走声明式 container 段）。
"""
from __future__ import annotations

import pytest

from agent_detector.discovery.fingerprints.loader import load_rules
from agent_detector.discovery.fingerprints.schema import FrameworkRule
from agent_detector.discovery.sources import docker_agents, dockerapi
from agent_detector.discovery.sources.dockerapi import (ContainerBrief, DockerUnavailable,
                                                        TopProcess)
from test_dockerapi import FakeAPIClient, make_tar

LANGGRAPH_RULE = FrameworkRule.model_validate({
    "kind": "framework_rule", "id": "langgraph", "name": "LangGraph",
    "dependencies": {"any": ["langgraph"]},
})
LANGCHAIN_RULE = FrameworkRule.model_validate({
    "kind": "framework_rule", "id": "langchain", "name": "LangChain",
    "dependencies": {"any": ["langchain", "langchain-core", "@langchain/core"]},
})

CLIENT_RULES = list(load_rules().client_rules)

HINTS = docker_agents.load_docker_hints()
CID = "abcdef123456" + "0" * 52
STARTED_AT = "2026-10-26T01:02:03Z"


def state_values(asset) -> set:
    return {state.value for state in asset.states}

PYPROJECT = ('[project]\nname = "ai"\n'
             'dependencies = ["langgraph>=0.2", "fastapi"]\n')
SITE_TAR = make_tar({
    "site-packages/langgraph-0.2.6.dist-info/METADATA":
        "Name: langgraph\nVersion: 0.2.6\n\n",
})


def brief(image="registry.local/team/ai-app:1.8.0", state="running",
          name="ai-app", command="python /app/server.py"):
    return ContainerBrief(CID, name, image, state, command)


def container_client(*, image="registry.local/team/ai-app:1.8.0", state="running",
                     pyproject=PYPROJECT, site_tar=SITE_TAR,
                     processes=(("7", "1", "python /app/server.py"),),
                     name="ai-app", command="python /app/server.py"):
    """一个运行（或停止）的 python 容器：/app/pyproject 声明 langgraph，
    系统 site-packages 安装 langgraph 0.2.6。"""
    listing = {"Id": CID, "Names": [f"/{name}"], "Image": image, "State": state,
               "Command": command, "Created": 0, "Labels": {}}
    archives = {(CID, "/app/pyproject.toml"): make_tar({"/app/pyproject.toml": pyproject})}
    if site_tar is not None:
        archives[(CID, "/usr/local/lib/python3.11/site-packages")] = site_tar
    inspects = {CID: {"State": {"Running": state == "running", "StartedAt": STARTED_AT},
                      "Config": {"WorkingDir": "/app"}}}
    tops = {CID: {"Titles": ["PID", "PPID", "COMMAND"],
                  "Processes": [list(p) for p in processes]}} if state == "running" else {}
    return FakeAPIClient(containers=[listing], archives=archives, tops=tops,
                         inspects=inspects)


# ---------------------------------------------------------------------------
# 候选筛选：宽松 OR，宁多勿漏
# ---------------------------------------------------------------------------

def test_python_app_image_is_candidate_via_process_runtime():
    # 镜像名 "python-app" 不含任何关键词 —— 进程命令行暴露 python 运行时
    reasons = docker_agents.screen_candidate(brief(), HINTS,
                                             [TopProcess(7, 1, "python /app/main.py")])
    assert "runtime:python" in reasons


def test_stopped_container_is_candidate_by_image_keyword():
    reasons = docker_agents.screen_candidate(
        brief(image="my-langgraph-worker:latest", state="exited", command=""), HINTS, [])
    assert "image~langgraph" in reasons


def test_plain_nginx_container_is_not_a_candidate():
    reasons = docker_agents.screen_candidate(
        brief(image="nginx:1.25", command="nginx -g 'daemon off;'"),
        HINTS, [TopProcess(1, 0, "nginx: master process nginx -g 'daemon off;'")])
    assert reasons == []


# ---------------------------------------------------------------------------
# 识别：容器 → 框架 + 版本
# ---------------------------------------------------------------------------

def test_running_langgraph_container_end_to_end():
    outcome = docker_agents.scan_docker_agents([LANGCHAIN_RULE, LANGGRAPH_RULE], "h",
                                               client=container_client(), hints=HINTS)
    assert outcome.stats["error"] is None
    assert outcome.stats["candidates"] == 1
    assert outcome.stats["agents"] == 1
    assert outcome.containers_seen == [CID]
    (bundle,) = outcome.bundles
    (framework,) = bundle.frameworks
    assert framework.detector == "langgraph"
    assert {state.value for state in framework.states} == {"INSTALLED", "RUNNING"}
    assert framework.running_pids == [7]
    # 版本出处链：已安装元数据(0.2.6) 压过 声明(UNKNOWN) 与镜像标签(1.8.0)
    assert framework.version.value == "0.2.6"
    assert framework.version.source.value == "package-metadata"
    assert any(e.kind.value == "container_metadata" for e in framework.evidence)
    link = outcome.container_links[framework.asset_id]
    assert link["state"] == "running" and link["started_at"] == STARTED_AT
    assert link["processes"]["7"] == "python /app/server.py"
    assert bundle.asset.asset_type.value == "AI_APPLICATION"


def test_stopped_container_is_never_running():
    client = container_client(image="registry.local/team/langgraph-worker:2.0.0",
                              state="exited")
    outcome = docker_agents.scan_docker_agents([LANGGRAPH_RULE], "h",
                                               client=client, hints=HINTS)
    (bundle,) = outcome.bundles
    (framework,) = bundle.frameworks
    assert {state.value for state in framework.states} == {"INSTALLED"}
    assert framework.running_pids == []
    assert {state.value for state in bundle.asset.states} == {"INSTALLED"}


def test_image_tag_is_lowest_priority_version_source():
    # 只有声明依赖、没有任何已安装元数据 → 回落镜像标签
    client = container_client(image="docker.io/team/langgraph-app:1.8.0",
                              state="exited", site_tar=None)
    outcome = docker_agents.scan_docker_agents([LANGGRAPH_RULE], "h",
                                               client=client, hints=HINTS)
    (bundle,) = outcome.bundles
    (framework,) = bundle.frameworks
    assert framework.version.value == "1.8.0"
    assert framework.version.source.value == "image-tag"
    assert framework.version.confidence == 0.4


def test_one_container_two_frameworks_never_claims_running_pid():
    both = ('[project]\nname = "ai"\n'
            'dependencies = ["langchain>=0.2", "langgraph>=0.2"]\n')
    site = make_tar({
        "site-packages/langchain-0.3.0.dist-info/METADATA":
            "Name: langchain\nVersion: 0.3.0\n\n",
        "site-packages/langgraph-0.2.6.dist-info/METADATA":
            "Name: langgraph\nVersion: 0.2.6\n\n",
    })
    client = container_client(pyproject=both, site_tar=site)
    outcome = docker_agents.scan_docker_agents([LANGCHAIN_RULE, LANGGRAPH_RULE], "h",
                                               client=client, hints=HINTS)
    (bundle,) = outcome.bundles
    assert len(bundle.frameworks) == 2
    for framework in bundle.frameworks:
        # 诚实规则 §6.3：容器内多框架并存时无法归因进程，谁都不挂 RUNNING
        assert state_values(framework) == {"INSTALLED"}
        assert framework.running_pids == []


def test_container_without_framework_claims_nothing():
    client = container_client(pyproject='[project]\nname = "web"\n'
                                        'dependencies = ["fastapi"]\n',
                              site_tar=None)
    outcome = docker_agents.scan_docker_agents([LANGCHAIN_RULE, LANGGRAPH_RULE], "h",
                                               client=client, hints=HINTS)
    # AI 无关容器：候选进了（python 运行时），但不产出任何框架资产
    assert outcome.stats["candidates"] == 1
    assert outcome.bundles == [] and outcome.assets == []


# ---------------------------------------------------------------------------
# 容器内 client agent（OpenClaw）
# ---------------------------------------------------------------------------

def test_openclaw_container_client_identified():
    archives = {
        (CID, "/usr/local/lib/node_modules/openclaw/package.json"): make_tar({
            "/usr/local/lib/node_modules/openclaw/package.json":
                '{"name": "openclaw", "version": "1.2.3"}'}),
        (CID, "/root/.openclaw/openclaw.json"): make_tar({
            "/root/.openclaw/openclaw.json": '{"gateway": {}, "agents": {}}'}),
    }
    inspects = {CID: {"State": {"Running": True, "StartedAt": STARTED_AT},
                      "Config": {"WorkingDir": "/app"}}}
    tops = {CID: {"Titles": ["PID", "PPID", "COMMAND"],
                  "Processes": [["5", "1",
                                 "node /usr/local/lib/node_modules/openclaw/openclaw.mjs"]]}}
    listing = {"Id": CID, "Names": ["/openclaw"], "Image": "openclaw:1.2.3",
               "State": "running", "Command": "openclaw gateway", "Created": 0,
               "Labels": {}}
    client = FakeAPIClient(containers=[listing], archives=archives, tops=tops,
                           inspects=inspects)
    outcome = docker_agents.scan_docker_agents(
        [LANGCHAIN_RULE, LANGGRAPH_RULE], "h", client_rules=CLIENT_RULES,
        client=client, hints=HINTS)
    (asset,) = outcome.assets
    # detector = rule.id（通用容器 client 机制），不再是通道标记 "docker"
    assert asset.name == "OpenClaw" and asset.detector == "openclaw"
    assert asset.asset_type.value == "AGENT_CLIENT"
    assert state_values(asset) == {"INSTALLED", "CONFIGURED", "RUNNING"}
    assert asset.version.value == "1.2.3"
    assert asset.version.source.value == "package-metadata"
    assert asset.running_pids == [5]
    assert asset.config_paths == ["/root/.openclaw/openclaw.json"]


def test_openclaw_absent_claims_nothing():
    client = container_client()
    outcome = docker_agents.scan_docker_agents([LANGCHAIN_RULE, LANGGRAPH_RULE], "h",
                                               client=client, hints=HINTS)
    assert outcome.assets == []


# ---------------------------------------------------------------------------
# n8n 容器（官方镜像布局）：通用容器 client 机制 + 依赖口径并存框架资产
# ---------------------------------------------------------------------------

N8N_CID = "fedcba987654" + "1" * 52


def n8n_container_client(*, state="running"):
    """官方镜像布局：WORKDIR /home/node，npm 全局根下只有 n8n 包，
    嵌套 node_modules 含 @langchain/core，进程被改名为 n8n。"""
    listing = {"Id": N8N_CID, "Names": ["/n8n"], "Image": "n8nio/n8n:latest",
               "State": state, "Command": "", "Created": 0, "Labels": {}}
    n8n_pkg_json = ('{"name": "n8n", "version": "2.44.7", '
                    '"dependencies": {"express": "^4"}}')
    archives = {
        # 包目录本身（probe_path 的存在性探测目标）
        (N8N_CID, "/usr/local/lib/node_modules/n8n"):
            make_tar({"/usr/local/lib/node_modules/n8n/package.json": n8n_pkg_json}),
        (N8N_CID, "/usr/local/lib/node_modules/n8n/package.json"):
            make_tar({"/usr/local/lib/node_modules/n8n/package.json": n8n_pkg_json}),
        # 数据目录（config_existing 存在性探测目标）
        (N8N_CID, "/home/node/.n8n"): make_tar({"/home/node/.n8n/": None}),
        # 嵌套提升位置：n8n/node_modules/@langchain/core/package.json
        (N8N_CID, "/usr/local/lib/node_modules/n8n/node_modules/@langchain/core/package.json"):
            make_tar({"/usr/local/lib/node_modules/n8n/node_modules/@langchain/core/package.json":
                      '{"name": "@langchain/core", "version": "0.3.7"}'}),
    }
    inspects = {N8N_CID: {"State": {"Running": state == "running",
                                    "StartedAt": STARTED_AT},
                          "Config": {"WorkingDir": "/home/node"}}}
    tops = {N8N_CID: {"Titles": ["PID", "PPID", "COMMAND"],
                      "Processes": [["489", "458", "n8n"],
                                    ["501", "489", "n8n task-runner"]]}} \
        if state == "running" else {}
    return FakeAPIClient(containers=[listing], archives=archives, tops=tops,
                         inspects=inspects)


def test_n8n_container_platform_plus_langchain_assets():
    outcome = docker_agents.scan_docker_agents(
        [LANGCHAIN_RULE], "h", client_rules=CLIENT_RULES,
        client=n8n_container_client(), hints=HINTS)
    assert outcome.stats["candidates"] == 1  # 镜像词 n8n（静态 + 规则合并）
    # 平台资产：包元数据给版本，改名后的进程给 RUNNING
    (platform,) = outcome.assets
    assert platform.name == "n8n" and platform.detector == "n8n"
    assert platform.asset_type.value == "AGENT_PLATFORM"
    assert state_values(platform) == {"INSTALLED", "CONFIGURED", "RUNNING"}
    assert platform.version.value == "2.44.7"
    assert platform.version.source.value == "package-metadata"
    assert platform.running_pids == [489, 501]
    assert "/home/node/.n8n" in platform.config_paths
    # 依赖口径并存：@langchain/core 命中 → LangChain 框架资产
    (bundle,) = outcome.bundles
    assert [framework.name for framework in bundle.frameworks] == ["LangChain"]
    framework = bundle.frameworks[0]
    assert framework.version.value == "0.3.7"
    assert framework.version.source.value == "package-metadata"
    assert "RUNNING" in state_values(framework)  # 运行中的单框架容器
    # 两类资产都挂到同一容器
    assert outcome.container_links[platform.asset_id]["image"] == "n8nio/n8n:latest"
    assert framework.asset_id in outcome.container_links


def test_n8n_stopped_container_keeps_platform_without_running():
    outcome = docker_agents.scan_docker_agents(
        [LANGCHAIN_RULE], "h", client_rules=CLIENT_RULES,
        client=n8n_container_client(state="exited"), hints=HINTS)
    (platform,) = outcome.assets
    assert "RUNNING" not in state_values(platform)
    assert platform.running_pids == []
    assert platform.version.value == "2.44.7"  # 停止容器仍可读包元数据
    (bundle,) = outcome.bundles
    assert "RUNNING" not in state_values(bundle.frameworks[0])


# ---------------------------------------------------------------------------
# 阶段隔离与降级
# ---------------------------------------------------------------------------

def test_unavailable_daemon_degrades_into_stats(monkeypatch):
    def boom(timeout):
        raise DockerUnavailable("daemon down")

    monkeypatch.setattr(docker_agents.dockerapi, "build_client", boom)
    outcome = docker_agents.scan_docker_agents([LANGGRAPH_RULE], "h")
    assert outcome.stats["error"] and "daemon" in outcome.stats["error"]
    assert outcome.bundles == [] and outcome.assets == []


def test_container_identification_failure_is_isolated(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(docker_agents, "_identify_container", boom)
    outcome = docker_agents.scan_docker_agents([LANGGRAPH_RULE], "h",
                                               client=container_client(), hints=HINTS)
    assert outcome.stats["container_errors"]
    assert outcome.bundles == []
    assert outcome.containers_seen == [CID]  # 枚举仍然完整，供生命周期复核使用
