"""Cursor CLI (cursor-agent) detection tests: rule loaded from the packaged
YAML, run against a fabricated home directory. Proves the YAML rule drives
the engine."""
from agent_detector.discovery.fingerprints.engine import ClientRuleDetector
from agent_detector.discovery.fingerprints.loader import load_rules
from agent_detector.domain.enums import AssetState, AssetType, VersionSource
from agent_detector.domain.models import HostFacts, ProcessInfo


def cursor_rule():
    return next(r for r in load_rules().client_rules if r.id == "cursor")


def make_facts(processes=(), hostname="host-a"):
    return HostFacts(hostname=hostname, processes=tuple(processes), sockets=())


def build_home(tmp_path, native=False, versions=None, cli_config=False,
               windows_root=False):
    """Fabricate a Cursor CLI installation layout under an isolated home."""
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    if native:
        bin_dir = home / ".local" / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        (bin_dir / "cursor-agent").write_bytes(b"")
    if versions:
        version_dir = (home / ".local" / "share" / "cursor-agent" / "versions"
                       / versions)
        version_dir.mkdir(parents=True, exist_ok=True)
        (version_dir / "cursor-agent").write_bytes(b"")
    if windows_root:
        win_versions = (home / "AppData" / "Local" / "cursor-agent" / "versions"
                        / (versions or "2026.10.19-6bbf2c4"))
        win_versions.mkdir(parents=True, exist_ok=True)
        (win_versions / "node.exe").write_bytes(b"")
        root = home / "AppData" / "Local" / "cursor-agent"
        (root / "cursor-agent.exe").write_bytes(b"")
        (root / "agent.exe").write_bytes(b"")
    if cli_config:
        cursor_dir = home / ".cursor"
        cursor_dir.mkdir(parents=True, exist_ok=True)
        (cursor_dir / "cli-config.json").write_text('{"model": "auto"}',
                                                    encoding="utf-8")
    return home


def detector_for(home):
    return ClientRuleDetector(cursor_rule(), home=home, run_npm_lookup=False)


def test_full_install_with_running_process(tmp_path):
    """版本目录 + cli-config + 运行进程 → 三态并存，版本来自日历版本目录。"""
    home = build_home(tmp_path, versions="2026.10.19-6bbf2c4", cli_config=True)
    proc = ProcessInfo(pid=101, name="cursor-agent",
                       cmdline=("/home/u/.local/bin/cursor-agent", "--version"))
    (asset,) = detector_for(home).detect(make_facts([proc]))
    assert asset.name == "Cursor CLI"
    assert asset.asset_type == AssetType.AGENT_CLIENT
    assert {AssetState.INSTALLED, AssetState.CONFIGURED, AssetState.RUNNING} <= asset.states
    assert asset.version.value == "2026.10.19"
    assert asset.version.source == VersionSource.INSTALLER_METADATA
    assert asset.running_pids == [101]
    assert asset.confidence >= 0.9


def test_versions_dir_yields_newest_calver(tmp_path):
    """安装脚本布局：versions/ 下多个日历版本，取三元组最大者。"""
    home = build_home(tmp_path, versions="2026.02.11-abcdef0")
    versions = home / ".local" / "share" / "cursor-agent" / "versions"
    (versions / "2026.10.19-6bbf2c4").mkdir()
    (versions / "2025.09.03-1234567").mkdir()
    (asset,) = detector_for(home).detect(make_facts())
    assert asset.states == {AssetState.INSTALLED}
    assert asset.version.value == "2026.10.19"


def test_native_install_without_config(tmp_path):
    """只有链接和版本目录 → 仅 INSTALLED，版本目录给出版本。"""
    home = build_home(tmp_path, native=True, versions="2026.10.19-6bbf2c4")
    (asset,) = detector_for(home).detect(make_facts())
    assert asset.states == {AssetState.INSTALLED}
    assert asset.version.value == "2026.10.19"


def test_cli_config_alone_is_configured(tmp_path):
    home = build_home(tmp_path, cli_config=True)
    (asset,) = detector_for(home).detect(make_facts())
    assert asset.states == {AssetState.CONFIGURED}


def test_clean_home_yields_no_asset(tmp_path):
    home = build_home(tmp_path)
    procs = [ProcessInfo(1, "python", ("python", "app.py")),
             ProcessInfo(2, "node", ("node", "server.js"))]
    assert detector_for(home).detect(make_facts(procs)) == []


def test_primary_agent_launcher_matches_via_path_token(tmp_path):
    """主命令 ~/.local/bin/agent 的进程名可能是 "agent"（symlink comm），
    精确名不匹配它，靠 argv[0] 路径 token 兜住。"""
    home = build_home(tmp_path, versions="2026.10.19-6bbf2c4")
    proc = ProcessInfo(pid=102, name="agent",
                       cmdline=("/home/u/.local/bin/agent", "chat"))
    (asset,) = detector_for(home).detect(make_facts([proc]))
    assert AssetState.RUNNING in asset.states
    assert asset.running_pids == [102]


def test_plain_agent_word_is_not_running_evidence(tmp_path):
    """裸 "agent" 进程/单词不作数：名字精确匹配不含 agent，参数里提到
    cursor-agent 文件的编辑器也不命中（token 带路径前缀）。"""
    home = build_home(tmp_path, versions="2026.10.19-6bbf2c4")
    procs = [ProcessInfo(5, "agent", ("/opt/vendor/agent", "run")),
             ProcessInfo(6, "Code.exe", ("Code", "cursor-agent-notes.md"))]
    (asset,) = detector_for(home).detect(make_facts(procs))
    assert AssetState.RUNNING not in asset.states
    assert asset.running_pids == []


def test_cursor_ide_process_is_not_cli_running_evidence(tmp_path):
    """Cursor IDE（Electron，Cursor.exe）不是 CLI 运行证据——范围刻意收窄。"""
    home = build_home(tmp_path, versions="2026.10.19-6bbf2c4")
    procs = [ProcessInfo(7, "Cursor.exe",
                         (r"C:\Users\u\AppData\Local\Programs\cursor\Cursor.exe",))]
    (asset,) = detector_for(home).detect(make_facts(procs))
    assert AssetState.RUNNING not in asset.states
    assert asset.running_pids == []


def test_asset_id_is_stable_across_scans(tmp_path):
    home = build_home(tmp_path, versions="2026.10.19-6bbf2c4", cli_config=True)
    detector = detector_for(home)
    first = detector.detect(make_facts())
    second = detector.detect(make_facts())
    assert first[0].asset_id == second[0].asset_id
    assert first[0].asset_id.startswith("cursor--")


def test_windows_native_install_with_node_process(tmp_path):
    """Windows 原生布局（实机验证过的形态）：安装在 %LOCALAPPDATA%，真正的
    agent 进程是捆绑的 node.exe，argv[0] 指向 versions 目录 —— 精确名匹配
    落空，必须靠路径 token 命中。"""
    home = build_home(tmp_path, windows_root=True, versions="2026.10.19-6bbf2c4")
    node_path = str(home / "AppData" / "Local" / "cursor-agent" / "versions"
                    / "2026.10.19-6bbf2c4" / "node.exe")
    proc = ProcessInfo(pid=34052, name="node.exe",
                       cmdline=(node_path, str(home / "AppData" / "Local"
                                               / "cursor-agent" / "versions"
                                               / "2026.10.19-6bbf2c4" / "cli.js")))
    (asset,) = detector_for(home).detect(make_facts([proc]))
    assert {AssetState.INSTALLED, AssetState.RUNNING} <= asset.states
    assert asset.running_pids == [34052]
    assert asset.version.value == "2026.10.19"
    assert asset.version.source == VersionSource.INSTALLER_METADATA


def test_windows_agent_alias_copy_matches(tmp_path):
    """根目录的 agent.exe 别名副本被直接调用（进程名 agent.exe）→ 经
    local/cursor-agent 路径 token 命中，不依赖可执行名。"""
    home = build_home(tmp_path, windows_root=True, versions="2026.10.19-6bbf2c4")
    exe = str(home / "AppData" / "Local" / "cursor-agent" / "agent.exe")
    proc = ProcessInfo(pid=201, name="agent.exe", cmdline=(exe, "chat"))
    (asset,) = detector_for(home).detect(make_facts([proc]))
    assert AssetState.RUNNING in asset.states
    assert asset.running_pids == [201]


def test_agent_matrix_maps_cursor_rule_to_cursor_entry():
    """规则 id 必须命中 agents.yaml 的 cursor 条目（Hook 适配器与保护状态依赖它）。"""
    from agent_detector.discovery.agents import load_agent_matrix
    from agent_detector.hooks.registry import get_adapter

    matrix = load_agent_matrix()
    entry = matrix.for_type(cursor_rule().id)
    assert entry is not None
    assert entry.id == "cursor"
    assert get_adapter(cursor_rule().id) is not None
