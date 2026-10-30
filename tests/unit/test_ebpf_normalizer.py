"""Tetragon normalizer: TetragonEvent -> BehaviorFact (pure, any platform)."""
from pathlib import Path

from agent_detector.core.facts import FACT_KINDS
from agent_detector.monitoring.collectors.ebpf.normalizer import (fact_from_event,
                                                                  normalize_lines)
from agent_detector.monitoring.collectors.ebpf.parser import parse_event_json

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


def test_kprobe_event_not_normalized_until_net_phase():
    events = [parse_event_json(line) for line in LINES]
    kprobe = next(event for event in events
                  if event is not None and event.etype == "process_kprobe")
    assert fact_from_event(kprobe) is None


def test_normalize_lines_count():
    assert len(facts()) == 6  # 4 execs + 2 exits; kprobe and garbage skipped
