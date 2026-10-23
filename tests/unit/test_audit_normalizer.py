from pathlib import Path

from agent_detector.monitoring.collectors.audit.normalizer import normalize_event, normalize_lines
from agent_detector.monitoring.collectors.audit.parser import AuditLogParser
from agent_detector.monitoring.collectors.audit.rules_template import EXEC_KEY, FILE_KEY, NET_KEY

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "audit" / "scenario.log"
ALL_KEYS = {EXEC_KEY, FILE_KEY, NET_KEY}


def facts(keys=ALL_KEYS):
    lines = FIXTURE.read_text(encoding="utf-8").splitlines(keepends=True)
    return list(normalize_lines(lines, keys=keys))


def by_serial(serial):
    return next(fact for fact in facts() if fact.serial == serial)


def test_exec_fact_carries_process_identity_and_argv():
    fact = by_serial("900101")
    assert fact.kind == "proc.exec"
    assert (fact.pid, fact.ppid) == (4101, 4100)
    assert fact.process_name == "python3" and fact.exe == "/usr/bin/python3.12"
    assert fact.argv == ("python3", "train.py", "--epochs")
    assert fact.result == "started"
    assert fact.keys == (EXEC_KEY,)
    assert "auditd" in fact.evidence and "syscall:execve" in fact.evidence


def test_failed_exec_is_marked_denied_with_exit_code():
    fact = by_serial("900107")
    assert fact.kind == "proc.exec" and fact.result == "denied"
    assert fact.argv == ()
    assert "exit:-13" in fact.evidence


def test_file_write_resolves_path_and_result():
    fact = by_serial("900102")
    assert fact.kind == "file.write"
    assert fact.path == "/home/agent/agent-lab/notes.md"
    assert fact.path_target is None and fact.endpoint is None
    assert fact.result == "success" and fact.syscall == "openat"


def test_file_move_pairs_delete_and_create_paths():
    fact = by_serial("900103")
    assert fact.kind == "file.move"
    assert fact.path == "/home/agent/agent-lab/notes.md"
    assert fact.path_target == "/home/agent/agent-lab/docs.md"
    assert fact.syscall == "renameat2"


def test_file_delete_uses_delete_path():
    fact = by_serial("900104")
    assert fact.kind == "file.delete"
    assert fact.path == "/home/agent/agent-lab/docs.md"


def test_file_attr_change_detected():
    fact = by_serial("900105")
    assert fact.kind == "file.attr"
    assert fact.path == "/home/agent/agent-lab/hello.py"
    assert fact.syscall == "fchmodat"


def test_net_connect_decodes_sockaddr():
    fact = by_serial("900106")
    assert fact.kind == "net.connect"
    assert fact.endpoint == "1.2.3.4:443"
    assert fact.path is None


def test_hex_encoded_name_survives_continuation_split():
    fact = by_serial("900109")
    assert fact.kind == "file.write"
    assert fact.path == "/home/agent/agent-lab/my文件.txt"


def test_key_filter_drops_foreign_and_keyless_events():
    serials = [fact.serial for fact in facts()]
    assert "900108" not in serials  # foreign key (system_audit)
    assert "900110" not in serials  # rule without -k
    only_exec = {fact.serial for fact in facts(keys={EXEC_KEY})}
    assert only_exec == {"900101", "900107"}


def test_local_ipc_connect_is_not_recorded():
    parser = AuditLogParser()
    lines = [
        'type=SYSCALL msg=audit(1760000300.000:900301): arch=c000003e syscall=42 '
        'success=yes exit=0 a0=3 a1=7ffd a2=110 a3=0 items=0 ppid=1 pid=2 '
        'comm="dbus" exe="/usr/bin/dbus" key="agent_detector_net"\n',
        'type=SOCKADDR msg=audit(1760000300.000:900301): '
        'saddr=01002F72756E2F646275732F73797374656D5F6275735F736F636B6574\n',
    ]
    events = [event for line in lines for event in parser.feed(line)]
    events.extend(parser.flush())
    assert normalize_event(events[0], keys={NET_KEY}) is None