"""Tetragon export parser: JSON line -> TetragonEvent (pure, any platform).

Shapes mirror real v1.7.1 export output captured on the validation VM;
tests/fixtures/tetragon/sample.jsonl holds the canonical lines.
"""
import json
from pathlib import Path

from agent_detector.monitoring.collectors.ebpf.parser import (_rfc3339_to_epoch,
                                                              parse_event_json)

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "tetragon" / "sample.jsonl"


def load_events():
    events = []
    for line in FIXTURE.read_text(encoding="utf-8").splitlines():
        event = parse_event_json(line)
        if event is not None:
            events.append(event)
    return events


def test_parses_host_exec_event():
    events = load_events()
    execs = [event for event in events if event.etype == "process_exec"
             and event.pid == 4100]
    assert len(execs) == 1
    event = execs[0]
    assert event.exe == "/usr/bin/python3"
    assert event.process_name == "python3"
    # Tetragon arguments exclude the program; parser prepends the binary.
    assert event.argv == ("/usr/bin/python3", "main.py", "--serve")
    assert event.ppid == 4099
    assert event.exec_id == "dGVzdGhvc3Q6MTAwMDA6NDEwMA=="
    assert event.container_id is None
    assert event.start_time is not None and event.start_time > 0
    assert 0 < event.ts < 4 * 10 ** 9


def test_parses_container_exec_event_with_docker_prefix():
    events = load_events()
    container = [event for event in events if event.etype == "process_exec"
                 and event.pid == 4200]
    assert len(container) == 1
    event = container[0]
    assert event.container_id == "b13f15ab2a169c85976efbd3a28b57f"
    assert event.exe == "/bin/sh" and event.process_name == "sh"
    assert event.argv == ("/bin/sh", "-c", "echo", "inside")
    assert event.ppid == 1  # container init, not the host docker CLI


def test_parses_exit_and_kprobe_events():
    events = load_events()
    exits = [event for event in events if event.etype == "process_exit"]
    assert {event.pid for event in exits} == {4101, 4200}
    kprobes = [event for event in events if event.etype == "process_kprobe"]
    assert {event.function_name for event in kprobes} == {
        "security_socket_connect", "security_file_permission"}
    connect = next(event for event in kprobes
                   if event.function_name == "security_socket_connect")
    assert connect.pid == 4101 and connect.exec_id


def test_fixture_yields_twelve_events_skipping_garbage_line():
    assert len(load_events()) == 12


def test_garbage_and_foreign_json_return_none():
    assert parse_event_json("") is None
    assert parse_event_json("   \n") is None
    assert parse_event_json("not json") is None
    assert parse_event_json(json.dumps({"flow": {"namespace": "x"}})) is None
    assert parse_event_json(json.dumps({"process_exec": {"process": {}}})) is None
    assert parse_event_json('{"process_exec": "truncated"') is None


def test_bytes_input_and_binary_dict_shape():
    line = json.dumps({
        "process_exec": {"process": {
            "exec_id": "abc", "pid": 9, "binary": {"path": "/bin/true"},
            "arguments": "", "start_time": "2026-01-01T00:00:00Z"},
            "parent": {"pid": 1}},
        "time": "2026-01-01T00:00:01Z"})
    event = parse_event_json(line.encode("utf-8"))
    assert event is not None
    assert event.exe == "/bin/true" and event.argv == ("/bin/true",)
    assert event.ppid == 1


def test_rfc3339_nanoseconds_and_offsets():
    base = _rfc3339_to_epoch("2026-10-30T07:01:52.256664525Z")
    assert base == _rfc3339_to_epoch("2026-10-30T07:01:52.256664525+00:00")
    # Microsecond truncation would differ by ~0.0000005; nanoseconds are kept.
    assert abs(base - round(base, 6)) > 4e-7
    assert _rfc3339_to_epoch("2026-10-30T09:01:52.256664525+02:00") == base
    assert _rfc3339_to_epoch("garbage") == 0.0
    assert _rfc3339_to_epoch(None) == 0.0
