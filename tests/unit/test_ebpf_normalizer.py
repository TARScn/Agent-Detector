"""Tetragon normalizer: TetragonEvent -> BehaviorFact (pure, any platform)."""
from pathlib import Path

from agent_detector.core.facts import FACT_KINDS
from agent_detector.monitoring.collectors.ebpf.normalizer import normalize_lines

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "tetragon" / "sample.jsonl"
LINES = FIXTURE.read_text(encoding="utf-8").splitlines()


def facts():
    return list(normalize_lines(LINES))


def test_maps_exec_to_proc_exec_fact():
    fact = next(f for f in facts() if f.pid == 4100)
    assert fact.kind == "proc.exec"
    assert fact.kind in FACT_KINDS
    assert fact.result == "started"
    assert fact.process_name == "python3"
    assert fact.exe == "/usr/bin/python3"
    assert fact.argv == ("/usr/bin/python3", "main.py", "--serve")
    assert fact.serial == "dGVzdGhvc3Q6MTAwMDA6NDEwMA=="  # exec_id: survives pid reuse
    assert fact.container_id is None


def test_maps_exit_to_proc_exit_fact():
    fact = next(f for f in facts() if f.pid == 4101 and f.kind == "proc.exit")
    assert fact.kind == "proc.exit"
    assert fact.ppid == 4100
    assert fact.argv == ()  # exits carry no argv payload


def test_container_fact_carries_container_and_evidence_tags():
    fact = next(f for f in facts() if f.pid == 4200 and f.kind == "proc.exec")
    assert fact.container_id == "b13f15ab2a169c85976efbd3a28b57f"
    assert fact.evidence[0] == "tetragon"
    assert "event:process_exec" in fact.evidence
    assert any(tag.startswith("exec_id:") for tag in fact.evidence)
    assert "container:b13f15ab2a169c85976efbd3a28b57f" in fact.evidence


def test_connect_kprobe_maps_to_net_connect_in_both_export_shapes():
    endpoints = {f.endpoint for f in facts() if f.kind == "net.connect"}
    # CRD-style sin4 nesting and the standalone flattened sockaddr_arg both land
    assert endpoints == {"93.184.216.34:80", "198.51.100.7:443"}
    for fact in (f for f in facts() if f.kind == "net.connect"):
        assert fact.pid == 4101 and fact.process_name == "ls"
        assert "hook:security_socket_connect" in fact.evidence
        assert fact.serial.endswith("security_socket_connect")


def test_af_unix_connects_are_dropped():
    assert not any(f.endpoint and "invalid" in f.endpoint for f in facts())
    assert len([f for f in facts() if f.kind == "net.connect"]) == 2


def test_file_write_kprobe_maps_to_file_write_and_reads_stay_off():
    paths = {f.path for f in facts() if f.kind == "file.write"}
    assert paths == {"/opt/agent/state.json", "/opt/agent-lab/standalone.txt"}
    for fact in (f for f in facts() if f.kind == "file.write"):
        assert fact.pid == 4100
        assert "hook:security_file_permission" in fact.evidence
    # the MAY_READ(4) kprobe is not a fact: reads are off by default
    assert not any(f.kind == "file.read" for f in facts())


def test_normalize_lines_count():
    assert len(facts()) == 10  # 4 execs + 2 exits + 2 connects + 2 writes
