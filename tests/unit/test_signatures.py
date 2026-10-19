from agent_detector.fingerprints.engine import SignatureRuleDetector
from agent_detector.domain.enums import AssetState, AssetType
from agent_detector.domain.models import HostFacts, ListeningSocket, ProcessInfo


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


def test_same_exe_restart_keeps_stable_asset_id():
    def facts():
        return HostFacts("h", (ProcessInfo(7, "ollama", ("ollama", "serve")),), ())

    first = SignatureRuleDetector().detect(facts())
    second = SignatureRuleDetector().detect(facts())
    assert first[0].asset_id == second[0].asset_id
