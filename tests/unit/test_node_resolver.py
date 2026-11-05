"""P2.1: host Node.js project resolution and dependency scanning."""
import json

from agent_detector.core.enums import AssetState
from agent_detector.core.models import HostFacts, ProcessInfo
from agent_detector.discovery.fingerprints.schema import FrameworkRule
from agent_detector.discovery.sources.deps import (interest_names,
                                                   scan_project_dependencies)
from agent_detector.discovery.sources.frameworks import detect_frameworks
from agent_detector.discovery.scanner.resolver import resolve_projects


def _node_project(tmp_path):
    root = tmp_path / "node-agent"
    modules = root / "node_modules" / "@langchain" / "core"
    modules.mkdir(parents=True)
    (root / "package.json").write_text(json.dumps({
        "name": "node-agent",
        "dependencies": {"@langchain/core": "^0.3.0"},
    }), encoding="utf-8")
    (modules / "package.json").write_text(json.dumps({
        "name": "@langchain/core", "version": "0.3.7",
    }), encoding="utf-8")
    (root / "server.js").write_text("console.log('agent')\n", encoding="utf-8")
    proc = ProcessInfo(pid=4242, name="node", cmdline=("node", "server.js"),
                       cwd=str(root), exe="node")
    return root, proc


def test_node_process_resolves_to_project_and_installed_component(tmp_path):
    root, proc = _node_project(tmp_path)
    projects = resolve_projects(HostFacts("h", (proc,), ()))
    assert len(projects) == 1
    project = projects[0]
    assert project.runtime == "node"
    assert project.root.lower() == str(root).lower()
    assert project.entry == "server.js"
    assert project.entry_kind == "script"
    assert project.environment_path
    assert project.environment_path.lower().endswith("node_modules")

    components = scan_project_dependencies(
        [project], interest_names({"@langchain/core", "langchain"}))[
            project.project_id]
    by_name = {item.name: item for item in components}
    assert by_name["@langchain/core"].version == "0.3.7"
    assert by_name["@langchain/core"].version_source.value == "package-metadata"


def test_node_project_matches_langchain_rule(tmp_path):
    root, proc = _node_project(tmp_path)
    project = resolve_projects(HostFacts("h", (proc,), ()))[0]
    rule = FrameworkRule.model_validate({
        "kind": "framework_rule", "id": "langchain", "name": "LangChain",
        "runtimes": ["python", "node"],
        "dependencies": {"any": ["@langchain/core"]},
    })
    components = scan_project_dependencies(
        [project], interest_names({"@langchain/core"}))[project.project_id]
    bundles = detect_frameworks(
        [project], {project.project_id: components}, [rule], "h",
        processes_by_pid={proc.pid: proc}, ports_by_pid={})
    assert len(bundles) == 1
    bundle = bundles[0]
    assert bundle.asset.name == "node-agent"
    assert bundle.frameworks[0].name == "LangChain"
    assert AssetState.INSTALLED in bundle.frameworks[0].states


def test_node_inline_eval_has_no_project_entry(tmp_path):
    root, _ = _node_project(tmp_path)
    proc = ProcessInfo(pid=7, name="node", cmdline=("node", "-e", "1+1"),
                       cwd=str(root), exe="node")
    project = resolve_projects(HostFacts("h", (proc,), ()))[0]
    assert project.entry_kind == "cwd"
    assert project.runtime == "node"


def test_rule_version_prefers_the_package_named_by_the_rule(tmp_path):
    """npm keeps @langchain/core beside langchain; the framework version must
    come from langchain itself when both are installed, not from the scoped
    dependency that sorts first."""
    root = tmp_path / "node-agent"
    for name, version in (("langchain", "1.6.0"),
                          ("@langchain/core", "1.3.4")):
        package = root / "node_modules" / name
        package.mkdir(parents=True)
        (package / "package.json").write_text(json.dumps(
            {"name": name, "version": version}), encoding="utf-8")
    (root / "package.json").write_text(json.dumps({
        "name": "node-agent",
        "dependencies": {"langchain": "^1.0.0", "@langchain/core": "^1.0.0"},
    }), encoding="utf-8")
    (root / "server.js").write_text("console.log('agent')\n", encoding="utf-8")
    proc = ProcessInfo(pid=4242, name="node", cmdline=("node", "server.js"),
                       cwd=str(root), exe="node")
    project = resolve_projects(HostFacts("h", (proc,), ()))[0]
    components = scan_project_dependencies(
        [project], interest_names({"langchain", "@langchain/core"}))[
            project.project_id]
    rule = FrameworkRule.model_validate({
        "kind": "framework_rule", "id": "langchain", "name": "LangChain",
        "runtimes": ["node"],
        "dependencies": {"any": ["langchain", "@langchain/core"]},
    })
    bundles = detect_frameworks(
        [project], {project.project_id: components}, [rule], "h",
        processes_by_pid={proc.pid: proc}, ports_by_pid={})
    assert bundles[0].frameworks[0].version.value == "1.6.0"