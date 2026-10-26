"""Dependency scanner: AI-relevant package metadata per project (design §4.1).

Only name/version metadata is read — the tests build fake dist-info trees,
pyproject files and lockfiles and assert on provenance precedence.
"""
from __future__ import annotations

from pathlib import Path

from agent_detector.discovery.sources.deps import (load_llm_sdks, normalize_name,
                                           scan_project_dependencies)
from agent_detector.core.enums import VersionSource
from agent_detector.core.models import ProjectInfo

INTEREST = {"langchain", "langchain-core", "langgraph", "openai", "crewai"}


def make_project(tmp_path: Path, name: str = "ai-todo") -> ProjectInfo:
    root = tmp_path / name
    root.mkdir(parents=True, exist_ok=True)
    return ProjectInfo(project_id=f"proj-{name}", root=str(root), name=name,
                       runtime="python", pids=(1,),
                       executable=str(root / ".venv" / "Scripts" / "python.exe"),
                       environment_path=str(root / ".venv"))


def write_dist_info(site_packages: Path, package: str, version: str) -> None:
    dist = site_packages / f"{package}-{version}.dist-info"
    dist.mkdir(parents=True, exist_ok=True)
    (dist / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {package}\nVersion: {version}\n"
        "Summary: should never be captured\n\nlong description here\n",
        encoding="utf-8")


def test_normalize_name_pep503():
    assert normalize_name("LangChain_Core") == "langchain-core"
    assert normalize_name("pyautogen") == "pyautogen"
    assert normalize_name("AutoGen._AgentChat") == "autogen-agentchat"


def test_installed_version_from_dist_info_windows_layout(tmp_path):
    project = make_project(tmp_path)
    site = tmp_path / "ai-todo" / ".venv" / "Lib" / "site-packages"
    write_dist_info(site, "langchain-core", "0.3.7")
    write_dist_info(site, "requests", "2.31.0")  # not interesting -> ignored
    result = scan_project_dependencies([project], INTEREST)
    components = result[project.project_id]
    assert [(c.name, c.version) for c in components] == [("langchain-core", "0.3.7")]
    assert components[0].version_source is VersionSource.PACKAGE_METADATA
    assert components[0].source_path.endswith("METADATA")


def test_installed_version_from_posix_venv_layout(tmp_path):
    project = make_project(tmp_path, "posix-app")
    site = tmp_path / "posix-app" / ".venv" / "lib" / "python3.11" / "site-packages"
    write_dist_info(site, "openai", "1.40.0")
    result = scan_project_dependencies([project], INTEREST)
    assert [c.version for c in result[project.project_id]] == ["1.40.0"]


def test_declared_from_pyproject_and_requirements(tmp_path):
    project = make_project(tmp_path, "declared")
    root = tmp_path / "declared"
    (root / "pyproject.toml").write_text(
        '[project]\nname = "declared"\ndependencies = ["langchain>=0.2", "requests"]\n'
        '[project.optional-dependencies]\nagent = ["crewai~=0.70"]\n'
        '[tool.poetry.dependencies]\npython = "^3.11"\nopenai = "^1.0"\n',
        encoding="utf-8")
    (root / "requirements.txt").write_text(
        "# comment\nlanggraph>=0.2\n-r other.txt\nflask\n", encoding="utf-8")
    result = scan_project_dependencies([project], INTEREST)
    names = {c.name: c for c in result[project.project_id]}
    assert set(names) == {"langchain", "crewai", "openai", "langgraph"}
    assert all(c.version_source is VersionSource.DECLARED for c in names.values())
    assert all(c.version == "UNKNOWN" for c in names.values())


def test_locked_from_uv_lock_and_poetry_lock(tmp_path):
    project = make_project(tmp_path, "locked")
    root = tmp_path / "locked"
    (root / "uv.lock").write_text(
        '[[package]]\nname = "langchain"\nversion = "0.2.1"\n\n'
        '[[package]]\nname = "flask"\nversion = "3.0.0"\n', encoding="utf-8")
    (root / "poetry.lock").write_text(
        '[[package]]\nname = "openai"\nversion = "1.30.0"\n', encoding="utf-8")
    result = scan_project_dependencies([project], INTEREST)
    by_name = {c.name: c for c in result[project.project_id]}
    assert by_name["langchain"].version == "0.2.1"
    assert by_name["langchain"].version_source is VersionSource.LOCKED
    assert by_name["openai"].version == "1.30.0"
    assert "flask" not in by_name


def test_installed_beats_declared(tmp_path):
    project = make_project(tmp_path, "both")
    root = tmp_path / "both"
    (root / "pyproject.toml").write_text(
        '[project]\nname = "both"\ndependencies = ["langchain>=0.2"]\n', encoding="utf-8")
    site = root / ".venv" / "Lib" / "site-packages"
    write_dist_info(site, "langchain", "0.1.9")
    result = scan_project_dependencies([project], INTEREST)
    components = result[project.project_id]
    assert len(components) == 1
    assert components[0].version == "0.1.9"
    assert components[0].version_source is VersionSource.PACKAGE_METADATA


def test_unresolved_project_yields_no_components(tmp_path):
    project = ProjectInfo(project_id="proj-x", root=str(tmp_path / "nope"), name="nope",
                          runtime="python", resolver_status="unresolved")
    result = scan_project_dependencies([project], INTEREST)
    assert result["proj-x"] == []


def test_packaged_llm_sdk_list_loads():
    sdks = load_llm_sdks()
    assert "openai" in sdks
    assert "anthropic" in sdks
    assert all(name == normalize_name(name) for name in sdks)


def test_llm_sdk_package_is_recorded_as_component(tmp_path):
    project = make_project(tmp_path, "sdk-app")
    site = tmp_path / "sdk-app" / ".venv" / "Lib" / "site-packages"
    write_dist_info(site, "zhipuai", "2.1.0")
    interest = INTEREST | load_llm_sdks()
    result = scan_project_dependencies([project], interest)
    assert [(c.name, c.version) for c in result[project.project_id]] == \
        [("zhipuai", "2.1.0")]
