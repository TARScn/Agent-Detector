from agent_detector.discovery.fingerprints.engine import SignatureRuleDetector
from agent_detector.core.enums import AssetState, AssetType
from agent_detector.core.models import HostFacts, ListeningSocket, ProcessInfo


def test_vllm_process_with_listener():
    facts = HostFacts(
        hostname="h",
        processes=(ProcessInfo(123, "python",
                               ("python", "-m", "vllm.entrypoints.openai.api_server")),),
        sockets=(ListeningSocket("127.0.0.1", 8000, 123),))
    (asset,) = SignatureRuleDetector().detect(facts)
    assert asset.name == "vLLM"
    assert asset.asset_type == AssetType.LLM_SERVICE
    assert AssetState.RUNNING in asset.states
    assert asset.listening_ports == [8000]
    assert asset.confidence == 0.85


def test_unrelated_process_not_reported():
    facts = HostFacts("h", (ProcessInfo(4, "python", ("python", "my_unrelated_task.py")),), ())
    assert SignatureRuleDetector().detect(facts) == []


def test_plain_claude_word_not_reported_by_signatures():
    """Claude Code belongs to its dedicated client rule; a bare word is not evidence."""
    facts = HostFacts("h", (ProcessInfo(4, "grep", ("grep", "claude")),), ())
    assert SignatureRuleDetector().detect(facts) == []


def test_dify_word_not_reported_by_signatures():
    """Dify belongs to its dedicated client rule (dify.yaml: host-side
    process: null) plus the Docker channel's compose-project merge. The loose
    word once matched postgres connection titles carrying the database name
    ("postgres: postgres dify ... idle"), grep commands and tmux paths — one
    spurious asset per connection process (VM incident, 2026-11-02)."""
    facts = HostFacts("h", (
        ProcessInfo(10, "postgres", ("postgres: postgres dify 172.20.0.12(36024) idle",)),
        ProcessInfo(11, "grep", ("grep", "-A1", "-i", "dify")),
        ProcessInfo(12, "tmux", ("tmux", "-S", "/home/dify/.local/share/tmux.sock",
                                 "start-server")),
        ProcessInfo(13, "docker", ("docker", "exec", "dify-worker-1", "ls", "/tmp")),
    ), ())
    assert SignatureRuleDetector().detect(facts) == []


def test_same_exe_restart_keeps_stable_asset_id():
    def facts():
        return HostFacts("h", (ProcessInfo(7, "ollama", ("ollama", "serve")),), ())

    first = SignatureRuleDetector().detect(facts())
    second = SignatureRuleDetector().detect(facts())
    assert first[0].asset_id == second[0].asset_id
