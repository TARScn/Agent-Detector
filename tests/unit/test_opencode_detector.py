"""OpenCode detection tests: rule loaded from the packaged YAML, run against
a fabricated home directory. Proves the YAML rule drives the engine."""
import json

from agent_detector.discovery.fingerprints.engine import ClientRuleDetector
from agent_detector.discovery.fingerprints.loader import load_rules
from agent_detector.core.enums import AssetState, AssetType, VersionSource
from agent_detector.core.models import HostFacts, ProcessInfo


def opencode_rule():
    return next(r for r in load_rules().client_rules if r.id == "opencode")


def make_facts(processes=(), hostname="host-a"):
    return HostFacts(hostname=hostname, processes=tuple(processes), sockets=())


def build_home(tmp_path, npm=None, installer=False, data_dir=False,
               opencode_json=False, auth=False):
    """Fabricate an OpenCode installation layout under an isolated home."""
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    if npm:
        package_dir = home / "npm-root" / "node_modules" / "opencode-ai"
        package_dir.mkdir(parents=True, exist_ok=True)
        (package_dir / "package.json").write_text(
            json.dumps({"name": "opencode-ai", "version": npm}),
            encoding="utf-8")
    if installer:
        bin_dir = home / ".opencode" / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        (bin_dir / "opencode.exe").write_bytes(b"")
    if data_dir or auth:
        share_dir = home / ".local" / "share" / "opencode"
        share_dir.mkdir(parents=True, exist_ok=True)
        if auth:
            # 凭据文件：真实机器上绝不读内容；测试里也只用于存在性。
            (share_dir / "auth.json").write_text('{"provider": null}', encoding="utf-8")
    if opencode_json:
        config_dir = home / ".config" / "opencode"
        config_dir.mkdir(parents=True, exist_ok=True)
        (config_dir / "opencode.json").write_text(
            '// JSONC comment\n{"model": "x"}', encoding="utf-8")
    return home


def detector_for(home):
    # Explicit npm root + no lookup keeps tests away from the real machine state.
    return ClientRuleDetector(opencode_rule(), home=home,
                              npm_global_root=home / "npm-root" / "node_modules",
                              run_npm_lookup=False)


def test_full_install_with_running_process(tmp_path):
    """npm 安装 + 配置 + 运行进程 → 三态并存，版本来自 package.json。"""
    home = build_home(tmp_path, npm="1.0.205", opencode_json=True)
    proc = ProcessInfo(pid=101, name="opencode.exe",
                       cmdline=("C:/Users/u/.opencode/bin/opencode.exe", "run"))
    (asset,) = detector_for(home).detect(make_facts([proc]))
    assert asset.name == "OpenCode"
    assert asset.asset_type == AssetType.AGENT_CLIENT
    assert {AssetState.INSTALLED, AssetState.CONFIGURED, AssetState.RUNNING} <= asset.states
    assert asset.version.value == "1.0.205"
    assert asset.version.source == VersionSource.PACKAGE_METADATA
    assert asset.running_pids == [101]
    assert asset.confidence >= 0.9


def test_jsonc_config_counts_as_configured(tmp_path):
    """JSONC（带注释）是官方支持的格式：存在性证据必须不受注释影响。"""
    home = build_home(tmp_path, opencode_json=True)
    (asset,) = detector_for(home).detect(make_facts())
    assert AssetState.CONFIGURED in asset.states


def test_installer_binary_alone_is_installed(tmp_path):
    """安装脚本布局：只有 ~/.opencode/bin 的二进制 → 仅 INSTALLED，版本 UNKNOWN。"""
    home = build_home(tmp_path, installer=True)
    (asset,) = detector_for(home).detect(make_facts())
    assert asset.states == {AssetState.INSTALLED}
    assert asset.version.value == "UNKNOWN"
    assert asset.version.source == VersionSource.UNKNOWN


def test_auth_json_implies_installed_and_configured(tmp_path):
    """auth.json 位于数据目录内，而数据目录本身是 INSTALLED 证据，两态并存。"""
    home = build_home(tmp_path, auth=True)
    (asset,) = detector_for(home).detect(make_facts())
    assert {AssetState.INSTALLED, AssetState.CONFIGURED} == asset.states
    evidence = [e for e in asset.evidence if e.kind.value == "file_metadata"]
    assert any("auth.json" in e.detail["path"] for e in evidence)


def test_clean_home_yields_no_asset(tmp_path):
    home = build_home(tmp_path)
    procs = [ProcessInfo(1, "python", ("python", "app.py")),
             ProcessInfo(2, "node", ("node", "server.js"))]
    assert detector_for(home).detect(make_facts(procs)) == []


def test_bare_opencode_word_is_not_running_evidence(tmp_path):
    """裸 "opencode" 不作数：名字精确匹配不含泛化词，路径 token 带前缀——
    编辑器打开 opencode 项目目录（参数含 /work/opencode/...）不命中。"""
    home = build_home(tmp_path, npm="1.0.0")
    procs = [ProcessInfo(5, "grep", ("grep", "opencode")),
             ProcessInfo(6, "python", ("python", r"D:\work\opencode\main.py"))]
    (asset,) = detector_for(home).detect(make_facts(procs))
    assert AssetState.RUNNING not in asset.states
    assert asset.running_pids == []


def test_executable_named_opencode_matches(tmp_path):
    home = build_home(tmp_path)
    (asset,) = detector_for(home).detect(
        make_facts([ProcessInfo(9, "opencode", ("opencode",))]))
    assert asset.states == {AssetState.RUNNING}


def test_npm_launcher_matches_via_package_token(tmp_path):
    home = build_home(tmp_path, npm="1.0.0")
    proc = ProcessInfo(pid=102, name="node.exe",
                       cmdline=("node",
                                "C:/x/node_modules/opencode-ai/bin/opencode",
                                "serve"))
    (asset,) = detector_for(home).detect(make_facts([proc]))
    assert AssetState.RUNNING in asset.states
    assert asset.running_pids == [102]


def test_asset_id_is_stable_across_scans(tmp_path):
    home = build_home(tmp_path, npm="1.0.0", opencode_json=True)
    detector = detector_for(home)
    first = detector.detect(make_facts())
    second = detector.detect(make_facts())
    assert first[0].asset_id == second[0].asset_id
    assert first[0].asset_id.startswith("opencode--")


def test_agent_matrix_maps_opencode_rule_to_opencode_entry():
    """规则 id 必须命中 agents.yaml 的 opencode 条目；该产品无 Hook 适配器，
    能力矩阵应如实标注 protect=PLANNED（仅发现与监测）。"""
    from agent_detector.discovery.sources.agents import load_agent_matrix
    from agent_detector.interception.hooks.registry import get_adapter

    matrix = load_agent_matrix()
    entry = matrix.for_type(opencode_rule().id)
    assert entry is not None
    assert entry.id == "opencode"
    assert entry.capabilities()["protect"] == "PLANNED"
    assert get_adapter(opencode_rule().id) is None
