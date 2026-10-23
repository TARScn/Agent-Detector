from sqlalchemy.orm import Session

from agent_detector.discovery.scanner import scan as scan_service
from agent_detector.discovery.fingerprints.schema import FrameworkRule
from agent_detector.core.enums import AssetState, AssetType
from agent_detector.core.models import DetectedAsset, HostFacts, ProcessInfo, VersionInfo
from agent_detector.storage.database import make_engine
from agent_detector.storage import (AgentInventoryRepository,
                                                 ApplicationRepository)


class GoodDetector:
    name = "good"

    def __init__(self, asset):
        self.asset = asset

    def detect(self, facts):
        return [self.asset]


class BrokenDetector:
    name = "broken"

    def detect(self, facts):
        raise RuntimeError("boom")


def make_asset(asset_id="x--1"):
    return DetectedAsset(asset_id=asset_id, name="X", asset_type=AssetType.AGENT_CLIENT,
                         states={AssetState.RUNNING}, confidence=0.7,
                         version=VersionInfo.unknown(), evidence=[], detector="good")


def test_run_scan_isolates_detector_failures(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (), ()))
    engine = make_engine(tmp_path / "db.sqlite3")
    result = scan_service.run_scan(
        engine, detectors=[GoodDetector(make_asset()), BrokenDetector()])
    assert result["status"] == "completed"
    assert result["assets"] == 1
    assert result["errors"] == [{"detector": "broken", "error": "boom"}]
    assert result["asset_summaries"][0]["asset_id"] == "x--1"


def test_merge_assets_combines_states_and_keeps_evidence():
    first = make_asset("x--1")
    first.states = {AssetState.RUNNING}
    second = make_asset("x--1")
    second.states = {AssetState.INSTALLED, AssetState.CONFIGURED}
    second.confidence = 0.95
    (merged,) = scan_service.merge_assets([first, second])
    assert merged.states == {AssetState.RUNNING, AssetState.INSTALLED, AssetState.CONFIGURED}
    assert merged.confidence == 0.95


# ---------------------------------------------------------------------------
# Self-built agent discovery through the full scan pipeline (design §3-§6)
# ---------------------------------------------------------------------------

LANGCHAIN_RULE = FrameworkRule.model_validate({
    "kind": "framework_rule", "id": "langchain", "name": "LangChain",
    "dependencies": {"any": ["langchain", "langchain-core"]},
})


def make_self_built_host(tmp_path):
    """A live python process in a project whose venv has langchain-core."""
    root = tmp_path / "ai-todo"
    site = root / ".venv" / "Lib" / "site-packages"
    site.mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        '[project]\nname = "ai-todo"\ndependencies = ["langchain>=0.2"]\n',
        encoding="utf-8")
    dist = site / "langchain_core-0.3.7.dist-info"
    dist.mkdir()
    (dist / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: langchain-core\nVersion: 0.3.7\n\n",
        encoding="utf-8")
    exe = str(root / ".venv" / "Scripts" / "python.exe")
    proc = ProcessInfo(pid=700, name="python.exe", cmdline=(exe, "-m", "uvicorn", "main:app"),
                       create_time=1_700_000_000.0, ppid=4, exe=exe, cwd=str(root))
    return root, proc


def test_run_scan_discovers_self_built_application_and_framework(tmp_path, monkeypatch):
    root, proc = make_self_built_host(tmp_path)
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (proc,), ()))
    engine = make_engine(tmp_path / "db.sqlite3")
    result = scan_service.run_scan(engine, detectors=[], framework_rules=[LANGCHAIN_RULE])

    assert result["self_built"]["projects_resolved"] == 1
    assert result["self_built"]["applications"] == 1
    framework_summary = next(a for a in result["asset_summaries"]
                             if a["detector"] == "langchain")
    assert sorted(framework_summary["states"]) == ["INSTALLED", "RUNNING"]

    with Session(engine) as session:
        apps = ApplicationRepository(session).list_applications()
        asset = AgentInventoryRepository(session).get_asset(framework_summary["asset_id"])
        instances = AgentInventoryRepository(session).list_instances()
    assert len(apps) == 1
    application = apps[0]
    assert application["name"] == "ai-todo"
    assert application["runtime"] == "python"
    assert application["environment_path"] and ".venv" in application["environment_path"]
    # pyproject 声明的 langchain（declared）与 venv 安装的 langchain-core（installed）
    # 都要记录，各带自己的版本来源（设计 §4.1 版本类型区分）。
    assert [(c["name"], c["version"], c["version_source"])
            for c in application["components"]] == \
        [("langchain", "UNKNOWN", "declared"),
         ("langchain-core", "0.3.7", "package-metadata")]
    # Framework asset: linked to its application, MONITOR_ONLY (no hooks exist).
    assert asset["app_id"] == application["app_id"]
    assert asset["name"] == "LangChain · ai-todo"
    assert asset["protection_status"] == "MONITOR_ONLY"
    assert asset["version"] == "0.3.7"
    assert instances and instances[0]["pid"] == 700
    assert instances[0]["cwd"] is not None and "ai-todo" in instances[0]["cwd"]


def test_run_scan_plain_python_project_stays_unclaimed(tmp_path, monkeypatch):
    root = tmp_path / "plain"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        '[project]\nname = "plain"\ndependencies = ["fastapi"]\n', encoding="utf-8")
    exe = str(tmp_path / "python.exe")
    proc = ProcessInfo(pid=701, name="python.exe", cmdline=(exe, "main.py"),
                       create_time=1_700_000_000.0, ppid=4, exe=exe, cwd=str(root))
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (proc,), ()))
    engine = make_engine(tmp_path / "db.sqlite3")
    result = scan_service.run_scan(engine, detectors=[], framework_rules=[LANGCHAIN_RULE])
    # 普通 FastAPI 服务：项目被解析、统计可见，但不产出任何资产（设计 §9）
    assert result["self_built"]["projects_resolved"] == 1
    assert result["self_built"]["applications"] == 0
    assert result["assets"] == 0
    with Session(engine) as session:
        assert ApplicationRepository(session).list_applications() == []


def test_run_scan_self_built_stage_failure_is_isolated(tmp_path, monkeypatch):
    proc = ProcessInfo(pid=702, name="python.exe", cmdline=("python", "x.py"),
                       exe="python.exe", cwd=str(tmp_path))
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (proc,), ()))
    monkeypatch.setattr(scan_service, "resolve_projects",
                        lambda facts: (_ for _ in ()).throw(RuntimeError("boom")))
    engine = make_engine(tmp_path / "db.sqlite3")
    result = scan_service.run_scan(engine, detectors=[], framework_rules=[LANGCHAIN_RULE])
    assert result["status"] == "completed"
    assert result["self_built"]["error"] == "boom"


# ---------------------------------------------------------------------------
# Post-scan verification (重扫复核): deleted agents must not linger as active
# ---------------------------------------------------------------------------


def test_rescan_marks_uninstalled_client_asset_removed(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (), ()))
    engine = make_engine(tmp_path / "db.sqlite3")
    scan_service.run_scan(engine, detectors=[GoodDetector(make_asset("c--1"))])
    scan_service.run_scan(engine, detectors=[])  # probes now find nothing
    with Session(engine) as session:
        repo = AgentInventoryRepository(session)
        assert repo.list_assets() == []  # removed assets are hidden by default
        rows = repo.list_assets(include_removed=True)
    assert rows[0]["status"] == "removed"


def test_reinstalled_asset_flips_back_to_active(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (), ()))
    engine = make_engine(tmp_path / "db.sqlite3")
    scan_service.run_scan(engine, detectors=[GoodDetector(make_asset("c--1"))])
    scan_service.run_scan(engine, detectors=[])
    scan_service.run_scan(engine, detectors=[GoodDetector(make_asset("c--1"))])
    with Session(engine) as session:
        rows = AgentInventoryRepository(session).list_assets()
    assert len(rows) == 1 and rows[0]["status"] == "active"


def test_failed_detector_never_produces_a_removal_verdict(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (), ()))
    engine = make_engine(tmp_path / "db.sqlite3")
    scan_service.run_scan(engine, detectors=[GoodDetector(make_asset("c--1"))])
    result = scan_service.run_scan(engine, detectors=[BrokenDetector()])  # name "broken"
    # detector "broken" errored, but it owns no asset; "c--1" (detector "good")
    # was scanned by nothing this run — absence alone must not remove it either,
    # its detector simply did not run. Only a *failed* detector would block.
    assert any(e["detector"] == "broken" for e in result["errors"])
    with Session(engine) as session:
        rows = AgentInventoryRepository(session).list_assets(include_removed=True)
    assert rows[0]["status"] == "removed"  # detector "good" ran fine and found nothing


def test_failed_own_detector_blocks_removal(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (), ()))
    engine = make_engine(tmp_path / "db.sqlite3")
    scan_service.run_scan(engine, detectors=[GoodDetector(make_asset("c--1"))])

    class FlakyDetector:
        name = "good"  # owns asset c--1

        def detect(self, facts):
            raise RuntimeError("transient failure")

    scan_service.run_scan(engine, detectors=[FlakyDetector()])
    with Session(engine) as session:
        rows = AgentInventoryRepository(session).list_assets(include_removed=True)
    assert rows[0]["status"] == "active"  # absence proves nothing when the detector crashed


def test_self_built_hard_deleted_when_project_directory_deleted(tmp_path, monkeypatch):
    import shutil

    root, proc = make_self_built_host(tmp_path)
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (proc,), ()))
    engine = make_engine(tmp_path / "db.sqlite3")
    scan_service.run_scan(engine, detectors=[], framework_rules=[LANGCHAIN_RULE])
    shutil.rmtree(root)
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (), ()))
    scan_service.run_scan(engine, detectors=[], framework_rules=[LANGCHAIN_RULE])
    # 用户决策（2026-10-23）：路径不存在的自建 agent 直接删除，不保留 removed 行
    with Session(engine) as session:
        repo = AgentInventoryRepository(session)
        assert repo.list_assets() == []
        assert repo.list_assets(include_removed=True) == []
        assert repo.list_instances(include_stopped=True) == []
        app_repo = ApplicationRepository(session)
        assert app_repo.list_applications() == []
        assert app_repo.list_applications(include_removed=True) == []


def test_self_built_deleted_when_venv_removed_but_dir_remains(tmp_path, monkeypatch):
    """D:\\lcxWS 场景：目录还在，但 .venv（依赖环境）已被删除 —— 空壳目录
    不算 agent 资产，复核必须物理删除（pyproject 里的声明救不了它）。"""
    import shutil

    root, proc = make_self_built_host(tmp_path)
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (proc,), ()))
    engine = make_engine(tmp_path / "db.sqlite3")
    scan_service.run_scan(engine, detectors=[], framework_rules=[LANGCHAIN_RULE])
    shutil.rmtree(root / ".venv")  # 依赖环境没了，目录壳还在
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (), ()))
    scan_service.run_scan(engine, detectors=[], framework_rules=[LANGCHAIN_RULE])
    with Session(engine) as session:
        repo = AgentInventoryRepository(session)
        assert repo.list_assets(include_removed=True) == []
        assert ApplicationRepository(session).list_applications(
            include_removed=True) == []


def test_self_built_deleted_when_packages_uninstalled_but_venv_remains(tmp_path, monkeypatch):
    """venv 目录还在，但框架包已被卸载（site-packages 空了）→ 同样删除。"""
    import shutil

    root, proc = make_self_built_host(tmp_path)
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (proc,), ()))
    engine = make_engine(tmp_path / "db.sqlite3")
    scan_service.run_scan(engine, detectors=[], framework_rules=[LANGCHAIN_RULE])
    shutil.rmtree(root / ".venv" / "Lib" / "site-packages")
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (), ()))
    scan_service.run_scan(engine, detectors=[], framework_rules=[LANGCHAIN_RULE])
    with Session(engine) as session:
        assert AgentInventoryRepository(session).list_assets(
            include_removed=True) == []
        assert ApplicationRepository(session).list_applications(
            include_removed=True) == []


def test_self_built_inactive_when_directory_remains_but_not_running(tmp_path, monkeypatch):
    root, proc = make_self_built_host(tmp_path)
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (proc,), ()))
    engine = make_engine(tmp_path / "db.sqlite3")
    scan_service.run_scan(engine, detectors=[], framework_rules=[LANGCHAIN_RULE])
    # process gone, project directory still on disk
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (), ()))
    scan_service.run_scan(engine, detectors=[], framework_rules=[LANGCHAIN_RULE])
    with Session(engine) as session:
        assets = AgentInventoryRepository(session).list_assets(include_removed=True)
        apps = ApplicationRepository(session).list_applications()
    assert all(row["status"] == "inactive" for row in assets)
    assert apps and apps[0]["status"] == "inactive"
    assert apps[0]["root_path"]  # path kept for the re-check audit trail
