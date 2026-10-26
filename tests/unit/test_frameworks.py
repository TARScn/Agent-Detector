"""Framework detection: dependency hits → honest asset states (design §6.3).

Key honesty rules under test:
* an application asset requires AI-relevant components — plain projects yield nothing;
* framework assets stay INSTALLED unless the app has exactly one framework;
* RUNNING (and the process instances) only ride on the single-framework case.
"""
from __future__ import annotations

from agent_detector.discovery.sources.frameworks import detect_frameworks
from agent_detector.discovery.fingerprints.schema import FrameworkRule
from agent_detector.core.enums import AssetState, AssetType, VersionSource
from agent_detector.core.models import ComponentInfo, ProcessInfo, ProjectInfo

LANGCHAIN_RULE = FrameworkRule.model_validate({
    "kind": "framework_rule", "id": "langchain", "name": "LangChain",
    "dependencies": {"any": ["langchain", "langchain-core"]},
})
LANGGRAPH_RULE = FrameworkRule.model_validate({
    "kind": "framework_rule", "id": "langgraph", "name": "LangGraph",
    "dependencies": {"any": ["langgraph"]},
})


def make_project(project_id: str, name: str, root: str) -> ProjectInfo:
    return ProjectInfo(project_id=project_id, root=root, name=name, runtime="python",
                       pids=(501,), executable=f"{root}/.venv/bin/python",
                       environment_path=f"{root}/.venv", entry="main:app",
                       entry_kind="server-entry")


def component(name: str, version: str = "1.0.0") -> ComponentInfo:
    return ComponentInfo(name=name, version=version,
                         version_source=VersionSource.PACKAGE_METADATA,
                         source_path=f"/x/{name}/METADATA")


PROCS = {501: ProcessInfo(pid=501, name="python", cmdline=("python", "-m", "uvicorn"),
                          exe="/x/.venv/bin/python", cwd="/x")}


def test_single_framework_gets_running_state_and_pids():
    project = make_project("p1", "ai-todo", "/x")
    bundles = detect_frameworks([project], {"p1": [component("langchain-core")]},
                                [LANGCHAIN_RULE], "host-1", processes_by_pid=PROCS)
    assert len(bundles) == 1
    bundle = bundles[0]
    app = bundle.asset
    assert app.asset_type is AssetType.AI_APPLICATION
    assert app.states == {AssetState.RUNNING}
    assert app.running_pids == [501]
    assert app.asset_id == bundle.app_id
    framework = bundle.frameworks[0]
    assert framework.detector == "langchain"
    assert framework.states == {AssetState.INSTALLED, AssetState.RUNNING}
    assert framework.running_pids == [501]
    assert framework.version.value == "1.0.0"
    assert framework.version.source is VersionSource.PACKAGE_METADATA
    assert bundle.framework_ids == ["langchain"]
    # framework asset ids are project-scoped, stable across scans
    assert framework.asset_id == detect_frameworks(
        [project], {"p1": [component("langchain-core")]}, [LANGCHAIN_RULE],
        "host-1")[0].frameworks[0].asset_id


def test_multiple_frameworks_stay_installed_without_instances():
    project = make_project("p2", "multi-agent", "/y")
    components = [component("langchain-core"), component("langgraph")]
    bundles = detect_frameworks([project], {"p2": components},
                                [LANGCHAIN_RULE, LANGGRAPH_RULE], "host-1",
                                processes_by_pid=PROCS)
    assert len(bundles) == 1
    app, frameworks = bundles[0].asset, bundles[0].frameworks
    assert app.states == {AssetState.RUNNING}
    assert sorted(f.detector for f in frameworks) == ["langchain", "langgraph"]
    for framework in frameworks:
        assert framework.states == {AssetState.INSTALLED}
        assert framework.running_pids == []


def test_plain_project_without_ai_dependencies_yields_nothing():
    project = make_project("p3", "plain-fastapi", "/z")
    bundles = detect_frameworks([project], {"p3": []}, [LANGCHAIN_RULE], "host-1")
    assert bundles == []


def test_llm_sdk_only_project_yields_application_without_framework():
    project = make_project("p4", "chat-app", "/w")
    bundles = detect_frameworks([project], {"p4": [component("openai")]},
                                [LANGCHAIN_RULE], "host-1")
    assert len(bundles) == 1
    assert bundles[0].asset.states == {AssetState.RUNNING}
    assert bundles[0].frameworks == []
    assert bundles[0].framework_ids == []


def test_unresolved_projects_are_never_assets():
    project = ProjectInfo(project_id="p5", root="/nowhere", name="nowhere",
                          runtime="python", resolver_status="unresolved")
    bundles = detect_frameworks([project], {"p5": [component("langchain-core")]},
                                [LANGCHAIN_RULE], "host-1")
    assert bundles == []


def test_app_evidence_carries_process_and_dependency_metadata():
    project = make_project("p6", "todo", "/e")
    bundle = detect_frameworks([project], {"p6": [component("langchain-core")]},
                               [LANGCHAIN_RULE], "host-1", processes_by_pid=PROCS)[0]
    process_evidence = [e for e in bundle.asset.evidence if e.kind.value == "process"]
    assert process_evidence and process_evidence[0].detail["pid"] == 501
    dep_evidence = [e for e in bundle.asset.evidence if e.kind.value == "dependency_metadata"]
    assert dep_evidence and dep_evidence[0].detail["name"] == "langchain-core"
