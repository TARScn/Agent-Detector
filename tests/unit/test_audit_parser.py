from pathlib import Path

from agent_detector.behavior.audit.parser import AuditLogParser, parse_lines

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "audit" / "scenario.log"


def fixture_lines():
    return FIXTURE.read_text(encoding="utf-8").splitlines(keepends=True)


def test_groups_records_by_audit_serial():
    events = parse_lines(fixture_lines())
    assert [event.serial for event in events] == [f"9001{i:02d}" for i in range(1, 11)]


def test_first_event_record_order_and_timestamp():
    event = parse_lines(fixture_lines())[0]
    assert event.timestamp == 1760000100.101
    assert [record.type for record in event.records] == [
        "SYSCALL", "EXECVE", "CWD", "PATH", "PATH", "PROCTITLE", "EOE"]
    assert event.first("SYSCALL").fields["comm"] == "python3"
    assert event.audit_keys() == ("agent_detector_exec",)


def test_syscall_args_are_not_hex_decoded():
    fields = parse_lines(fixture_lines())[0].first("SYSCALL").fields
    assert fields["a1"] == "7ffd2c1a0b40"  # hex-looking but a numeric argument
    assert fields["pid"] == "4101"


def test_execve_args_and_proctitle_are_hex_decoded():
    event = parse_lines(fixture_lines())[0]
    assert event.first("EXECVE").fields["a1"] == "train.py"
    assert event.field("proctitle") == "python3\x00train.py\x00--epochs"


def test_continuation_line_merges_into_previous_record():
    event = parse_lines(fixture_lines())[8]  # serial 900109
    assert event.serial == "900109"
    path = event.of_type("PATH")[0]
    assert path.fields["name"] == "/home/agent/agent-lab/my文件.txt"
    assert path.fields["inode"] == "2003"


def test_event_without_key_exposes_no_keys():
    event = parse_lines(fixture_lines())[9]
    assert event.serial == "900110"
    assert event.audit_keys() == ()


def test_crlf_lines_parse_cleanly():
    event = parse_lines([
        'type=SYSCALL msg=audit(1760000100.101:900101): arch=c000003e syscall=59 '
        'success=yes exit=0 pid=4101 ppid=4100 comm="python3" '
        'exe="/usr/bin/python3.12" key="agent_detector_exec"\r\n'])[0]
    assert event.audit_keys() == ("agent_detector_exec",)
    assert event.first("SYSCALL").fields["pid"] == "4101"


def test_garbage_lines_are_ignored():
    parser = AuditLogParser()
    assert parser.feed("this is not an audit line\n") == []
    assert parser.lines_ignored == 1


def test_eoe_flushes_the_event_immediately():
    parser = AuditLogParser()
    syscall = ('type=SYSCALL msg=audit(1760000100.606:900106): arch=c000003e syscall=42 '
               'success=yes exit=0 pid=4106 ppid=4101 comm="python3" '
               'key="agent_detector_net"')
    assert parser.feed(syscall + "\n") == []
    events = parser.feed("type=EOE msg=audit(1760000100.606:900106): \n")
    assert len(events) == 1 and events[0].serial == "900106"


def test_unterminated_group_flushes_on_demand():
    parser = AuditLogParser()
    parser.feed('type=SYSCALL msg=audit(1760000200.000:900201): arch=c000003e '
                'syscall=59 success=yes exit=0 pid=1 ppid=0 comm="x" '
                'key="agent_detector_exec"\n')
    events = parser.flush()
    assert len(events) == 1 and events[0].serial == "900201"
    assert parser.flush() == []