from pathlib import Path
from agent_detector.models import Observation, Finding
from agent_detector.detectors.signatures import detect
from agent_detector.probes.http import is_local
from agent_detector.storage.sqlite import Store


def test_signature_running_and_listening():
    result = detect([Observation("process", "python -m vllm.entrypoints.openai.api_server", pid=123),
                     Observation("listen", "127.0.0.1:8000", pid=123, host="127.0.0.1", port=8000)])
    assert any(x.component == "vLLM" and x.state == "listening" and x.port == 8000 for x in result)


def test_unrelated_process_is_not_agent():
    assert detect([Observation("process", "python my_unrelated_task.py", pid=4)]) == []


def test_local_probe_guard():
    assert is_local("127.0.0.1") and is_local("::1")
    assert not is_local("8.8.8.8") and not is_local("example.com")


def test_sqlite_roundtrip(tmp_path: Path):
    store = Store(tmp_path / "test.sqlite3")
    sid = store.save(False, 1, [Finding("vLLM", "model-server", 0.8, "running",
                                      evidence=[{"kind": "process", "value": "vllm"}])])
    assert store.scans()[0]["id"] == sid
    assert store.findings(sid)[0]["evidence"][0]["value"] == "vllm"
