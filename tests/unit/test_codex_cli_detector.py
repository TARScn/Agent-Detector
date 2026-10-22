"""Codex CLI detection tests: rule loaded from the packaged YAML, run against
a fabricated home directory. Proves the YAML rule drives the engine."""
import json

from agent_detector.discovery.fingerprints.engine import ClientRuleDetector
from agent_detector.discovery.fingerprints.loader import load_rules
from agent_detector.domain.enums import AssetState, AssetType, VersionSource
from agent_detector.domain.models import HostFacts, ProcessInfo


def codex_rule():
    return next(r for r in load_rules().client_rules if r.id == "codex-cli")


def make_facts(processes=(), hostname="host-a"):
    return HostFacts(hostname=hostname, processes=tuple(processes), sockets=())


def build_home(tmp_path, npm=None, native=False, codex_dir=False,
               toml_config=False, auth=False):
    """Fabricate a Codex CLI installation layout under an isolated home."""
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    if npm:
        package_dir = home / "npm-root" / "node_modules" / "@openai" / "codex"
        package_dir.mkdir(parents=True, exist_ok=True)
        (package_dir / "package.json").write_text(
            json.dumps({"name": "@openai/codex", "version": npm}),
            encoding="utf-8")
    if native:
        bin_dir = home / ".local" / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        (bin_dir / "codex.exe").write_bytes(b"")
    if codex_dir or toml_config or auth:
        state_dir = home / ".codex"
        state_dir.mkdir(parents=True, exist_ok=True)
        if toml_config:
            (state_dir / "config.toml").write_text(
                'model = "gpt-5"\n', encoding="utf-8")
        if auth:
            # 凭据文件：真实机器上绝不读内容；测试里也只用于存在性。
            (state_dir / "auth.json").write_text('{"tokens": null}', encoding="utf-8")
    return home


def detector_for(home):
    # Explicit npm root + no lookup keeps tests away from the real machine state.
    return ClientRuleDetector(codex_rule(), home=home,
                              npm_global_root=home / "npm-root" / "node_modules",
                              run_npm_lookup=False)


def test_full_install_with_running_launcher(tmp_path):
    """npm 安装 + 配置文件 + Node 启动器进程 → 三态并存，版本来自 package.json。"""
    home = build_home(tmp_path, npm="0.163.0", toml_config=True)
    proc = ProcessInfo(pid=101, name="node.exe",
                       cmdline=("node",
                                "C:/x/node_modules/@openai/codex/bin/codex.js",
                                "resume"))
    (asset,) = detector_for(home).detect(make_facts([proc]))
    assert asset.name == "Codex CLI"
    assert asset.asset_type == AssetType.AGENT_CLIENT
    assert {AssetState.INSTALLED, AssetState.CONFIGURED, AssetState.RUNNING} <= asset.states
    assert asset.version.value == "0.163.0"
    assert asset.version.source == VersionSource.PACKAGE_METADATA
    assert asset.running_pids == [101]
    assert asset.confidence >= 0.9


def test_native_release_binary_alone_is_installed(tmp_path):
    """GitHub Release 单文件安装：只有二进制和状态目录 → 仅 INSTALLED，版本 UNKNOWN。"""
    home = build_home(tmp_path, native=True, codex_dir=True)
    (asset,) = detector_for(home).detect(make_facts())
    assert asset.states == {AssetState.INSTALLED}
    assert asset.version.value == "UNKNOWN"
    assert asset.version.source == VersionSource.UNKNOWN


def test_auth_json_alone_is_configured(tmp_path):
    # auth.json 位于 ~/.codex 内，而状态目录本身就是 INSTALLED 证据，
    # 所以两种状态并存（与 claude_code 规则的 ~/.claude 同口径）。
    home = build_home(tmp_path, auth=True)
    (asset,) = detector_for(home).detect(make_facts())
    assert {AssetState.INSTALLED, AssetState.CONFIGURED} == asset.states
    evidence = [e for e in asset.evidence if e.kind.value == "file_metadata"]
    assert any("auth.json" in e.detail["path"] for e in evidence)


def test_platform_package_binary_matches(tmp_path):
    """原生子进程：exe 在 @openai/codex-win32-x64 包路径下，exe 名 codex.exe。"""
    home = build_home(tmp_path, npm="0.163.0")
    proc = ProcessInfo(
        pid=102, name="codex.exe",
        cmdline=(r"C:\x\node_modules\@openai\codex-win32-x64\codex.exe", "exec"))
    (asset,) = detector_for(home).detect(make_facts([proc]))
    assert AssetState.RUNNING in asset.states
    assert asset.running_pids == [102]


def test_app_server_daemon_is_not_running_evidence(tmp_path):
    """app-server-daemon 是随安装自启的后台守护进程，不是交互式会话——
    仅守护进程存活时不得点亮 RUNNING（Windows 实测过的误报）。"""
    home = build_home(tmp_path, npm="0.163.0")
    daemon = ProcessInfo(
        pid=31028, name="codex.exe",
        cmdline=(r"C:\Users\u\.codex\packages\app-server-daemon"
                 r"\releases\0.163.0-x86_64-pc-windows-msvc\bin\codex.exe",
                 "app-server", "daemon", "pid-update-loop"))
    (asset,) = detector_for(home).detect(make_facts([daemon]))
    assert AssetState.RUNNING not in asset.states
    assert asset.running_pids == []


def test_daemon_releases_dir_gives_version(tmp_path):
    """自管子组件的版本目录（~/.codex/packages/app-server-daemon/releases/
    <semver>-<target>/）也是版本来源，覆盖无 npm 元数据的安装。"""
    home = build_home(tmp_path, native=True, codex_dir=True)
    releases = home / ".codex" / "packages" / "app-server-daemon" / "releases"
    releases.mkdir(parents=True)
    (releases / "0.163.0-x86_64-pc-windows-msvc").mkdir()
    (asset,) = detector_for(home).detect(make_facts())
    assert asset.version.value == "0.163.0"
    assert asset.version.source == VersionSource.INSTALLER_METADATA


def test_clean_home_yields_no_asset(tmp_path):
    home = build_home(tmp_path)
    procs = [ProcessInfo(1, "python", ("python", "app.py")),
             ProcessInfo(2, "node", ("node", "server.js"))]
    assert detector_for(home).detect(make_facts(procs)) == []


def test_plain_codex_argument_is_not_running_evidence(tmp_path):
    """裸 "codex" 单词不作数（grep codex / 提及 codex 的脚本都不命中）。"""
    home = build_home(tmp_path, npm="0.163.0")
    procs = [ProcessInfo(5, "grep", ("grep", "codex")),
             ProcessInfo(6, "python", ("python", "script.py", "codex"))]
    (asset,) = detector_for(home).detect(make_facts(procs))
    assert AssetState.RUNNING not in asset.states
    assert asset.running_pids == []


def test_executable_named_codex_matches(tmp_path):
    home = build_home(tmp_path)
    (asset,) = detector_for(home).detect(
        make_facts([ProcessInfo(9, "codex", ("codex", "resume"))]))
    assert asset.states == {AssetState.RUNNING}


def test_asset_id_is_stable_across_scans(tmp_path):
    home = build_home(tmp_path, npm="0.163.0", toml_config=True)
    detector = detector_for(home)
    first = detector.detect(make_facts())
    second = detector.detect(make_facts())
    assert first[0].asset_id == second[0].asset_id
    assert first[0].asset_id.startswith("codex-cli--")


def test_agent_matrix_maps_codex_rule_to_codex_cli_entry():
    """规则 id 规范化后必须命中 agents.yaml 的 codex_cli 条目（能力/保护状态依赖它）。"""
    from agent_detector.discovery.agents import load_agent_matrix

    matrix = load_agent_matrix()
    entry = matrix.for_type(codex_rule().id)
    assert entry is not None
    assert entry.id == "codex_cli"
