"""Agent inventory: asset/instance modelling and honest protection status (§3.4)."""
from __future__ import annotations

import json

from sqlalchemy.orm import Session

from agent_detector.discovery.scanner.inventory import (InventoryBuilder, build_instance_id,
                                                protection_for)
from agent_detector.core.enums import (AssetState, AssetType, HookState, ProtectionStatus,
                                         VersionSource)
from agent_detector.core.models import DetectedAsset, HostFacts, ProcessInfo, VersionInfo
from agent_detector.storage import AgentInventoryRepository


def claude_asset(pids: list[int], states=None, asset_id="claude-code--abc") -> DetectedAsset:
    return DetectedAsset(
        asset_id=asset_id, name="Claude Code", asset_type=AssetType.AGENT_CLIENT,
        states=states or {AssetState.INSTALLED, AssetState.RUNNING},
        confidence=0.9, version=VersionInfo("2.1.303", VersionSource.PACKAGE_METADATA, 0.9),
        running_pids=list(pids), detector="claude_code",
        config_paths=["C:/Users/u/.claude/settings.json"], executable="C:/node/node.exe")


def facts_with(*processes: ProcessInfo) -> HostFacts:
    return HostFacts(hostname="host-1", processes=tuple(processes), sockets=())


PROCESSES = [
    ProcessInfo(pid=100, name="explorer.exe", create_time=1_700_000_000.0, ppid=4,
                exe="C:/Windows/explorer.exe"),
    ProcessInfo(pid=3224, name="node.exe", cmdline=("node", "cli.js"),
                create_time=1_700_000_100.0, ppid=100, exe="C:/node/node.exe"),
]


def test_scan_builds_asset_instances_and_sessions(services, home):
    builder = InventoryBuilder(home=home)
    with Session(services.engine) as session:
        items = builder.apply_scan(session, [claude_asset([3224])],
                                   facts_with(*PROCESSES))
        session.commit()
        repository = AgentInventoryRepository(session)
        asset = repository.get_asset("claude-code--abc")
        instances = repository.list_instances()
    assert items[0]["agent_type"] == "claude_code"
    assert asset["capabilities"]["protect"] == "P0"
    assert asset["version"] == "2.1.303"
    assert asset["protection_status"] == ProtectionStatus.MONITOR_ONLY.value
    assert instances[0]["pid"] == 3224
    assert instances[0]["parent_chain"] == ["explorer.exe(100)"]
    # Terminal launch commands stay out of the instance row entirely.
    assert "cli.js" in instances[0]["cmdline"]


def test_instances_are_retired_when_a_later_scan_does_not_see_them(services, home):
    builder = InventoryBuilder(home=home)
    with Session(services.engine) as session:
        builder.apply_scan(session, [claude_asset([3224])], facts_with(*PROCESSES))
        session.commit()
        repository = AgentInventoryRepository(session)
        assert len(repository.list_instances()) == 1
        # A second scan where the process is gone.
        builder.apply_scan(session, [claude_asset([])],
                           facts_with(PROCESSES[0]))
        session.commit()
        assert repository.list_instances() == []
        stopped = repository.list_instances(include_stopped=True)
    assert stopped[0]["status"] == "stopped"
    assert stopped[0]["pid"] == 3224


def test_hook_install_upgrades_protection_status(services, home):
    from agent_detector.interception.hooks.installer import install

    install("claude_code", home=home, apply=True)
    builder = InventoryBuilder(home=home)
    with Session(services.engine) as session:
        builder.apply_scan(session, [claude_asset([3224])], facts_with(*PROCESSES))
        session.commit()
        asset = AgentInventoryRepository(session).get_asset("claude-code--abc")
    assert asset["hook_state"] == HookState.INSTALLED.value
    assert asset["protection_status"] == ProtectionStatus.PROTECTED.value


def test_protection_matrix():
    running = {AssetState.RUNNING}
    assert protection_for(HookState.INSTALLED, running, True) is ProtectionStatus.PROTECTED
    assert protection_for(HookState.PARTIAL, running, True) is ProtectionStatus.DEGRADED
    assert protection_for(HookState.CONFLICT, running, True) is ProtectionStatus.DEGRADED
    assert protection_for(HookState.NOT_INSTALLED, running, True) is ProtectionStatus.MONITOR_ONLY
    assert protection_for(HookState.UNSUPPORTED, running, False) is ProtectionStatus.MONITOR_ONLY
    assert protection_for(HookState.NOT_INSTALLED, set(), False) is ProtectionStatus.UNKNOWN


def test_instance_id_is_stable_per_process_lifetime():
    first = build_instance_id("asset", 3224, "2026-10-20T09:40:00+00:00")
    assert first == build_instance_id("asset", 3224, "2026-10-20T09:40:00+00:00")
    assert first != build_instance_id("asset", 3224, "2026-10-20T10:00:00+00:00")
    assert first != build_instance_id("asset", 5842, "2026-10-20T09:40:00+00:00")


def test_unknown_agent_gets_no_protection_claims(services, home):
    asset = DetectedAsset(asset_id="mystery--1", name="Mystery Bot",
                          asset_type=AssetType.AGENT_CLIENT, states={AssetState.RUNNING},
                          confidence=0.6, version=VersionInfo.unknown(),
                          running_pids=[], detector="signatures")
    builder = InventoryBuilder(home=home)
    with Session(services.engine) as session:
        builder.apply_scan(session, [asset], facts_with(*PROCESSES))
        session.commit()
        stored = AgentInventoryRepository(session).get_asset("mystery--1")
    assert stored["capabilities"]["protect"] == "PLANNED"
    assert stored["protection_status"] == ProtectionStatus.MONITOR_ONLY.value
    assert any("未适配" in note for note in stored["notes"])


def test_mcp_servers_are_attached_by_config_directory(services, home):
    (home / ".claude").mkdir(parents=True)
    (home / ".claude.json").write_text(json.dumps({
        "mcpServers": {"github": {"command": "npx", "args": ["-y", "server-github"],
                                  "env": {"TOKEN": "secret"}},
                       "search": {"url": "https://mcp.example.com"}}}), encoding="utf-8")
    builder = InventoryBuilder(home=home)
    with Session(services.engine) as session:
        builder.apply_scan(session, [claude_asset([])], facts_with(*PROCESSES))
        session.commit()
        stored = AgentInventoryRepository(session).get_asset("claude-code--abc")
    assert sorted(stored["mcp_servers"]) == ["github", "search"]
    assert "secret" not in json.dumps(stored)  # names only, never env blocks


# ---------------------------------------------------------------------------
# Self-built framework assets (design §6.3): app link, honest naming, cwd
# ---------------------------------------------------------------------------


def framework_asset(pids: list[int], states=None) -> DetectedAsset:
    return DetectedAsset(
        asset_id="langchain--proj", name="LangChain", asset_type=AssetType.AGENT_RUNTIME,
        states=states or {AssetState.INSTALLED, AssetState.RUNNING},
        confidence=0.8,
        version=VersionInfo("0.3.7", VersionSource.PACKAGE_METADATA, 0.9),
        running_pids=list(pids), detector="langchain",
        executable="C:/proj/.venv/Scripts/python.exe")


def test_framework_asset_links_to_application_and_carries_cwd(services, home):
    proc = ProcessInfo(pid=3224, name="python.exe", cmdline=("python", "-m", "uvicorn"),
                       create_time=1_700_000_100.0, ppid=100,
                       exe="C:/proj/.venv/Scripts/python.exe", cwd="C:/proj")
    builder = InventoryBuilder(home=home, framework_ids={"langchain"})
    with Session(services.engine) as session:
        items = builder.apply_scan(
            session, [framework_asset([3224])], facts_with(*PROCESSES[:1], proc),
            app_links={"langchain--proj": {"app_id": "app--1", "app_name": "ai-todo"}})
        session.commit()
        repository = AgentInventoryRepository(session)
        stored = repository.get_asset("langchain--proj")
        instances = repository.list_instances()
    assert items[0]["app_id"] == "app--1"
    assert stored["app_id"] == "app--1"
    assert stored["name"] == "LangChain · ai-todo"
    assert stored["protection_status"] == ProtectionStatus.MONITOR_ONLY.value
    assert any("自建框架资产" in note for note in stored["notes"])
    assert instances[0]["cwd"] == "C:/proj"


def test_client_assets_are_unaffected_by_app_links(services, home):
    builder = InventoryBuilder(home=home, framework_ids={"langchain"})
    with Session(services.engine) as session:
        items = builder.apply_scan(
            session, [claude_asset([3224])], facts_with(*PROCESSES),
            app_links={"claude-code--abc": {"app_id": "app--1", "app_name": "x"}})
        session.commit()
        stored = AgentInventoryRepository(session).get_asset("claude-code--abc")
    assert items[0]["app_id"] is None
    assert stored["app_id"] is None
    assert stored["name"] == "Claude Code"


def test_system_python_app_is_never_deleted_on_guesswork(services, home, tmp_path):
    """无 venv 记录（系统 Python）的应用无法复查依赖 → 只做路径判定，
    绝不因"依赖无法确认"而删除（2026-10-23 复核规则的安全边界）。"""
    from agent_detector.discovery.fingerprints.schema import FrameworkRule
    from agent_detector.storage.models import ApplicationRow, utc_now_iso

    rule = FrameworkRule.model_validate({
        "kind": "framework_rule", "id": "langchain", "name": "LangChain",
        "dependencies": {"any": ["langchain"]}})
    builder = InventoryBuilder(home=home, framework_ids={"langchain"},
                               framework_rules=[rule])
    with Session(services.engine) as session:
        session.add(ApplicationRow(app_id="app--sys", name="sysapp",
                                   root_path=str(tmp_path), runtime="python",
                                   environment_path=None, status="active",
                                   first_seen_at=utc_now_iso(),
                                   last_seen_at=utc_now_iso()))
        session.commit()
        # 第一次扫描：资产入库并与应用关联
        builder.apply_scan(
            session, [framework_asset([3224])], facts_with(),
            app_links={"langchain--proj": {"app_id": "app--sys", "app_name": "sysapp"}})
        session.commit()
        # 第二次扫描：进程没了，目录还在，但依赖无法复查
        builder.apply_scan(session, [], facts_with())
        session.commit()
        stored = AgentInventoryRepository(session).get_asset("langchain--proj")
    assert stored["status"] == "inactive"