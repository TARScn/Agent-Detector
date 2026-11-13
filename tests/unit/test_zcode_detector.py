"""ZCode detection tests: rule loaded from the packaged YAML, run against
a fabricated home directory. Proves the YAML rule drives the engine."""
import json

from agent_detector.discovery.fingerprints.engine import ClientRuleDetector
from agent_detector.discovery.fingerprints.loader import load_rules
from agent_detector.core.enums import AssetState, AssetType, VersionSource
from agent_detector.core.models import HostFacts, ProcessInfo


def zcode_rule():
    return next(r for r in load_rules().client_rules if r.id == "zcode")


def make_facts(processes=(), hostname="host-a"):
    return HostFacts(hostname=hostname, processes=tuple(processes), sockets=())


def build_home(tmp_path, desktop=False, data_dir=False, config=None,
               sessions=False, updater=None):
    """Fabricate a ZCode installation layout under an isolated home."""
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    if desktop:
        app_dir = home / "AppData" / "Local" / "Programs" / "ZCode"
        app_dir.mkdir(parents=True, exist_ok=True)
        (app_dir / "ZCode.exe").write_bytes(b"")
    if data_dir or config or sessions:
        cli_dir = home / ".zcode" / "cli"
        cli_dir.mkdir(parents=True, exist_ok=True)
        if config is not None:
            (cli_dir / "config.json").write_text(json.dumps(config),
                                                 encoding="utf-8")
        if sessions:
            (cli_dir / "agents" / "sess_1").mkdir(parents=True, exist_ok=True)
    if updater:
        pending = home / "AppData" / "Local" / "@zcodedesktop-updater" / "pending"
        pending.mkdir(parents=True, exist_ok=True)
        (pending / f"ZCode Setup {updater}.exe").write_bytes(b"")
    return home


def detector_for(home):
    # No npm root involvement: the rule has no npm_packages probes, so the
    # detector never consults the real machine's npm state.
    return ClientRuleDetector(zcode_rule(), home=home, run_npm_lookup=False)


def desktop_main(pid=100):
    return ProcessInfo(pid=pid, name="ZCode.exe",
                       exe=("C:/users/u/AppData/Local/Programs/ZCode/ZCode.exe",))


def electron_child(pid, child_type):
    """Chromium 子进程：命令行一律带 --type=（主进程不带）。"""
    return ProcessInfo(
        pid=pid, name="ZCode.exe",
        cmdline=(r"C:\Users\u\AppData\Local\Programs\ZCode\ZCode.exe",
                 f"--type={child_type}",
                 r"--user-data-dir=C:\Users\u\AppData\Roaming\ZCode"))


def test_full_install_with_running_processes(tmp_path):
    """桌面本体 + 数据目录 + 配置 + 运行进程 → 三态并存；Electron GUI 子进程
    与插件工作进程被排除指纹剔除，running_pids 只含主进程、app-server、shim。"""
    home = build_home(tmp_path, desktop=True, config={"plugins": {}},
                      sessions=True)
    procs = [
        desktop_main(100),
        electron_child(101, "renderer"),
        electron_child(102, "crashpad-handler"),
        ProcessInfo(pid=103, name="node.exe",
                    cmdline=(r"C:\Program Files\nodejs\node.exe",
                             r"C:\Users\u\.zcode\gemini-shim\shim.js")),
        ProcessInfo(pid=104, name="ZCode.exe",
                    cmdline=(r"C:\...\Programs\ZCode\ZCode.exe",
                             r"C:\...\resources\glm\zcode.cjs",
                             "app-server", "--stdio", "--surface", "desktop")),
        ProcessInfo(pid=105, name="ZCode.exe",
                    cmdline=(r"C:\...\Programs\ZCode\ZCode.exe",
                             r"C:\...\resources\glm\zcode.cjs",
                             "__zcode-plugin-host", r"C:\...\plugins\pdf\0.2.2")),
    ]
    (asset,) = detector_for(home).detect(make_facts(procs))
    assert asset.name == "ZCode"
    assert asset.asset_type == AssetType.AGENT_CLIENT
    assert {AssetState.INSTALLED, AssetState.CONFIGURED,
            AssetState.RUNNING} <= asset.states
    assert asset.running_pids == [100, 103, 104]
    assert asset.confidence >= 0.9


def test_plugin_hosts_do_not_inflate_running_pids(tmp_path):
    """插件工作进程（实测一开 21 个）是内部工作者而非独立实例：名字对、
    命令行带 zcode.cjs，但 __zcode-plugin-host 排除指纹优先——不计 RUNNING。"""
    home = build_home(tmp_path, desktop=True)
    procs = [ProcessInfo(pid=201, name="ZCode.exe",
                         cmdline=(r"C:\...\ZCode\ZCode.exe",
                                  r"C:\...\resources\glm\zcode.cjs",
                                  "__zcode-plugin-host", r"C:\...\zcode-site\0.4.2")),
             ProcessInfo(pid=202, name="ZCode.exe",
                         cmdline=(r"C:\...\ZCode\ZCode.exe",
                                  r"C:\...\resources\glm\zcode.cjs",
                                  "__zcode-plugin-host", r"C:\...\documents\0.2.1"))]
    (asset,) = detector_for(home).detect(make_facts(procs))
    assert asset.running_pids == []
    assert AssetState.RUNNING not in asset.states


def test_shim_launcher_and_dir_mentions_do_not_match(tmp_path):
    """gemini-shim 的 cmd /c 启动器（转瞬即逝）和只是"提到"该目录的外部
    进程都不算运行实例——token 精确到 shim.js 本体。"""
    home = build_home(tmp_path, desktop=True)
    procs = [ProcessInfo(pid=301, name="cmd.exe",
                         cmdline=(r"C:\WINDOWS\system32\cmd.exe", "/c",
                                  r"C:\Users\u\.zcode\gemini-shim\start-shim.cmd")),
             ProcessInfo(pid=302, name="cmd.exe",
                         cmdline=(r"C:\WINDOWS\system32\cmd.exe", "/c", "dir",
                                  r"C:\Users\u\.zcode\gemini-shim"))]
    (asset,) = detector_for(home).detect(make_facts(procs))
    assert asset.running_pids == []


def test_app_server_matches_via_bundle_token(tmp_path):
    home = build_home(tmp_path)
    proc = ProcessInfo(pid=103, name="ZCode.exe",
                       cmdline=(r"C:\...\Programs\ZCode\ZCode.exe",
                                r"C:\...\resources\glm\zcode.cjs",
                                "app-server", "--stdio"))
    (asset,) = detector_for(home).detect(make_facts([proc]))
    assert asset.states == {AssetState.RUNNING}
    assert asset.running_pids == [103]


def test_electron_children_alone_do_not_claim_running(tmp_path):
    """只有 Chromium 子进程存活（主进程已退出）→ 不计 RUNNING。"""
    home = build_home(tmp_path, desktop=True)
    procs = [electron_child(101, "gpu-process"), electron_child(102, "utility")]
    (asset,) = detector_for(home).detect(make_facts(procs))
    assert AssetState.RUNNING not in asset.states
    assert asset.running_pids == []


def test_version_from_updater_pending(tmp_path):
    """electron-updater 的 pending 更新包文件名携带语义化版本。"""
    home = build_home(tmp_path, desktop=True, updater="3.17.2")
    (asset,) = detector_for(home).detect(make_facts())
    assert asset.version.value == "3.17.2"
    assert asset.version.source == VersionSource.INSTALLER_METADATA


def test_default_version_is_unknown(tmp_path):
    """无 npm 元数据、无更新缓存、GUI 程序禁用 --version 探针 → UNKNOWN。"""
    home = build_home(tmp_path, desktop=True)
    (asset,) = detector_for(home).detect(make_facts())
    assert asset.version.value == "UNKNOWN"
    assert asset.version.source == VersionSource.UNKNOWN


def test_session_dir_counts_as_configured(tmp_path):
    """cli/agents 会话目录是真实使用证据（内容永不读，只 stat 存在性）。"""
    home = build_home(tmp_path, data_dir=True, sessions=True)
    (asset,) = detector_for(home).detect(make_facts())
    assert {AssetState.INSTALLED, AssetState.CONFIGURED} == asset.states
    evidence = [e for e in asset.evidence if e.kind.value == "file_metadata"]
    assert any("agents" in e.detail["path"] for e in evidence)


def test_config_json_keys_count_as_configured(tmp_path):
    """config.json 顶层键名（plugins/mcp/hooks）计 CONFIGURED，值不入库。"""
    home = build_home(tmp_path, data_dir=True, config={"mcp": {"servers": {}}})
    (asset,) = detector_for(home).detect(make_facts())
    assert AssetState.CONFIGURED in asset.states


def test_clean_home_yields_no_asset(tmp_path):
    home = build_home(tmp_path)
    procs = [ProcessInfo(1, "python", ("python", "app.py")),
             ProcessInfo(2, "node", ("node", "server.js"))]
    assert detector_for(home).detect(make_facts(procs)) == []


def test_bare_zcode_word_is_not_running_evidence(tmp_path):
    """裸 "zcode" 单词不作数：名字精确匹配不含泛化词，token 都是产品专属
    路径片段——编辑器打开 zcode 项目目录（参数含 /work/zcode/...）不命中。"""
    home = build_home(tmp_path, desktop=True)
    procs = [ProcessInfo(5, "grep", ("grep", "zcode")),
             ProcessInfo(6, "python", ("python", r"D:\work\zcode\main.py"))]
    (asset,) = detector_for(home).detect(make_facts(procs))
    assert AssetState.RUNNING not in asset.states
    assert asset.running_pids == []


def test_desktop_main_process_matches_by_name(tmp_path):
    """只有主进程存活（无安装证据）→ 仅 RUNNING。"""
    home = build_home(tmp_path)
    (asset,) = detector_for(home).detect(
        make_facts([ProcessInfo(9, "zcode.exe", (r"C:\apps\ZCode\ZCode.exe",))]))
    assert asset.states == {AssetState.RUNNING}
    assert asset.running_pids == [9]


def test_asset_id_is_stable_across_scans(tmp_path):
    home = build_home(tmp_path, desktop=True, sessions=True)
    detector = detector_for(home)
    first = detector.detect(make_facts())
    second = detector.detect(make_facts())
    assert first[0].asset_id == second[0].asset_id
    assert first[0].asset_id.startswith("zcode--")


def test_agent_matrix_maps_zcode_rule_to_zcode_entry():
    """规则 id 必须命中 agents.yaml 的 zcode 条目；Hook 适配器未验证，
    能力矩阵应如实标注 protect=UNVERIFIED。"""
    from agent_detector.discovery.sources.agents import load_agent_matrix
    from agent_detector.interception.hooks.registry import get_adapter

    matrix = load_agent_matrix()
    entry = matrix.for_type(zcode_rule().id)
    assert entry is not None
    assert entry.id == "zcode"
    assert entry.capabilities()["protect"] == "UNVERIFIED"
    assert get_adapter(zcode_rule().id) is None
