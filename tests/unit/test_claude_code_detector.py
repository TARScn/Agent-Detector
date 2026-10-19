"""Claude Code detection tests: rule loaded from the packaged YAML, run against
a fabricated home directory. Proves the YAML rule drives the engine."""
import json

from agent_detector.fingerprints.engine import ClientRuleDetector
from agent_detector.fingerprints.loader import load_rules
from agent_detector.domain.enums import AssetState, AssetType, VersionSource
from agent_detector.domain.models import HostFacts, ProcessInfo


def claude_rule():
    return next(r for r in load_rules().client_rules if r.id == "claude-code")


def make_facts(processes=(), hostname="host-a"):
    return HostFacts(hostname=hostname, processes=tuple(processes), sockets=())


def build_home(tmp_path, npm=None, native=False, claude_dir=False,
               claude_json_keys=None, settings=False):
    """Fabricate a Claude Code installation layout under an isolated home."""
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    if npm:
        package_dir = (home / "npm-root" / "node_modules"
                       / "@anthropic-ai" / "claude-code")
        package_dir.mkdir(parents=True, exist_ok=True)
        (package_dir / "package.json").write_text(
            json.dumps({"name": "@anthropic-ai/claude-code", "version": npm}),
            encoding="utf-8")
    if native:
        bin_dir = home / ".local" / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        (bin_dir / "claude.exe").write_bytes(b"")
    if claude_dir:
        (home / ".claude").mkdir(parents=True, exist_ok=True)
    if claude_json_keys is not None:
        (home / ".claude.json").write_text(
            json.dumps({key: {"redacted": True} for key in claude_json_keys}),
            encoding="utf-8")
    if settings:
        config_dir = home / ".claude"
        config_dir.mkdir(parents=True, exist_ok=True)
        (config_dir / "settings.json").write_text("{}", encoding="utf-8")
    return home


def detector_for(home):
    # Explicit npm root + no lookup keeps tests away from the real machine state.
    return ClientRuleDetector(claude_rule(), home=home,
                              npm_global_root=home / "npm-root" / "node_modules",
                              run_npm_lookup=False)


def test_full_install_with_running_process(tmp_path):
    home = build_home(tmp_path, npm="1.0.42", claude_json_keys=["projects", "mcpServers"],
                      settings=True)
    proc = ProcessInfo(pid=101, name="node.exe",
                       cmdline=("node",
                                "C:/x/node_modules/@anthropic-ai/claude-code/cli.js"))
    (asset,) = detector_for(home).detect(make_facts([proc]))
    assert asset.name == "Claude Code"
    assert asset.asset_type == AssetType.AGENT_CLIENT
    assert {AssetState.INSTALLED, AssetState.CONFIGURED, AssetState.RUNNING} <= asset.states
    assert asset.version.value == "1.0.42"
    assert asset.version.source == VersionSource.PACKAGE_METADATA
    assert asset.running_pids == [101]
    assert asset.confidence >= 0.9


def test_native_install_without_process(tmp_path):
    home = build_home(tmp_path, native=True, claude_dir=True)
    (asset,) = detector_for(home).detect(make_facts())
    assert asset.states == {AssetState.INSTALLED}
    assert asset.version.value == "UNKNOWN"
    assert asset.version.source == VersionSource.UNKNOWN


def test_native_installer_versions_dir_gives_clean_semver(tmp_path):
    """Native installer layout: ~/.local/share/claude/versions/<semver> (downloads emptied)."""
    home = build_home(tmp_path, native=True, claude_dir=True)
    versions = home / ".local" / "share" / "claude" / "versions"
    versions.mkdir(parents=True)
    (versions / "2.1.301").write_bytes(b"")
    (home / ".claude" / "downloads").mkdir()
    (asset,) = detector_for(home).detect(make_facts())
    assert asset.version.value == "2.1.301"
    assert asset.version.source == VersionSource.INSTALLER_METADATA
    version_evidence = [e for e in asset.evidence if "2.1.301" in e.summary]
    assert version_evidence and "path" in version_evidence[0].detail


def test_claude_json_only_is_configured(tmp_path):
    home = build_home(tmp_path, claude_json_keys=["projects"])
    (asset,) = detector_for(home).detect(make_facts())
    assert asset.states == {AssetState.CONFIGURED}


def test_clean_home_yields_no_asset(tmp_path):
    home = build_home(tmp_path)
    procs = [ProcessInfo(1, "python", ("python", "app.py")),
             ProcessInfo(2, "node", ("node", "server.js"))]
    assert detector_for(home).detect(make_facts(procs)) == []


def test_plain_claude_argument_is_not_running_evidence(tmp_path):
    home = build_home(tmp_path, npm="2.0.0")
    procs = [ProcessInfo(5, "grep", ("grep", "claude")),
             ProcessInfo(6, "python", ("python", "script.py", "claude"))]
    (asset,) = detector_for(home).detect(make_facts(procs))
    assert AssetState.RUNNING not in asset.states
    assert asset.running_pids == []


def test_claude_desktop_processes_are_excluded(tmp_path):
    """Claude Desktop (Electron chat app) is a different product sharing claude.exe."""
    home = build_home(tmp_path, npm="2.0.0")
    desktop_procs = [
        ProcessInfo(11, "claude.exe", (r"C:\Program Files\WindowsApps\Claude_2.42.0_x64\app\Claude.exe",)),
        ProcessInfo(12, "claude.exe",
                    (r"C:\Program Files\WindowsApps\Claude_2.42.0_x64\app\Claude.exe",
                     "--type=renderer", r"--user-data-dir=C:\Users\u\AppData\Roaming\Claude")),
        ProcessInfo(13, "Claude", ("/usr/lib/claude-desktop/Claude",
                                   "--user-data-dir=/home/u/.config/Claude", "--type=renderer")),
    ]
    (asset,) = detector_for(home).detect(make_facts(desktop_procs))
    assert AssetState.RUNNING not in asset.states
    assert asset.running_pids == []


def test_user_id_alone_is_not_configured(tmp_path):
    home = build_home(tmp_path, npm="1.0.0", claude_json_keys=["userID"])
    (asset,) = detector_for(home).detect(make_facts())
    assert asset.states == {AssetState.INSTALLED}


def test_executable_named_claude_matches(tmp_path):
    home = build_home(tmp_path)
    (asset,) = detector_for(home).detect(
        make_facts([ProcessInfo(9, "claude.exe", ("claude", "--resume"))]))
    assert asset.states == {AssetState.RUNNING}


def test_running_process_without_install_evidence(tmp_path):
    home = build_home(tmp_path)
    (asset,) = detector_for(home).detect(
        make_facts([ProcessInfo(11, "claude", ("claude",))]))
    assert asset.states == {AssetState.RUNNING}


def test_asset_id_is_stable_across_scans(tmp_path):
    home = build_home(tmp_path, npm="1.0.0", claude_json_keys=["projects"])
    detector = detector_for(home)
    first = detector.detect(make_facts())
    second = detector.detect(make_facts())
    assert first[0].asset_id == second[0].asset_id
    assert first[0].asset_id.startswith("claude-code--")


def test_cmdline_secrets_are_redacted(tmp_path):
    home = build_home(tmp_path, npm="1.0.0")
    proc = ProcessInfo(7, "node",
                       ("node", "x/@anthropic-ai/claude-code/cli.js",
                        "--api-key=sk-ant-abcdef1234567890"))
    (asset,) = detector_for(home).detect(make_facts([proc]))
    serialized = json.dumps([e.detail for e in asset.evidence])
    assert "sk-ant-abcdef1234567890" not in serialized
    assert "***" in serialized


def test_config_file_contents_never_stored(tmp_path):
    home = build_home(tmp_path, claude_json_keys=["projects", "mcpServers"])
    (asset,) = detector_for(home).detect(make_facts())
    serialized = json.dumps([e.detail for e in asset.evidence])
    assert "redacted" not in serialized  # values from the JSON file must not leak
    keys_evidence = [e for e in asset.evidence if e.kind.value == "file_content_keys"]
    assert keys_evidence and set(keys_evidence[0].detail["keys"]) == {"projects",
                                                                      "mcpServers"}


def test_rule_data_drives_matching(tmp_path):
    """Editing the rule (not code) must change behavior — the point of YAML rules."""
    home = build_home(tmp_path, native=True)
    modified = claude_rule().model_copy(deep=True)
    modified.name = "Renamed Product"
    modified.install.paths = []           # binary no longer counts as install
    modified.install.dirs = []
    modified.process.executable_names = ["totally-not-claude"]
    detector = ClientRuleDetector(modified, home=home, run_npm_lookup=False)
    # The real claude.exe no longer matches under the edited rule…
    assert detector.detect(
        make_facts([ProcessInfo(20, "claude.exe", ("claude", "--help"))])) == []
    # …while the name the rule now declares does.
    (asset,) = detector.detect(
        make_facts([ProcessInfo(21, "totally-not-claude", ("totally-not-claude",))]))
    assert AssetState.INSTALLED not in asset.states   # install probes removed by rule
    assert asset.running_pids == [21]                 # match follows the new exe name
    assert asset.name == "Renamed Product"
