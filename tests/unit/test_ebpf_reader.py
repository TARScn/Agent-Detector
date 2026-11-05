"""Tetragon channel plumbing: shared tail reader reuse + availability probe.

The subscription itself needs a Linux host with Tetragon installed; the tests
cover the pure half, mirroring how the Sysmon tests handle the Windows-only
half of their channel.
"""
import sys

from agent_detector.monitoring.collectors.ebpf.reader import ReplayReader, TailReader
from agent_detector.monitoring.collectors.ebpf.tetragon import (install_commands,
                                                                tetragon_available)


def test_replay_reader_reads_whole_file(tmp_path):
    log = tmp_path / "events.json"
    log.write_text('{"a":1}\n{"b":2}\n', encoding="utf-8")
    assert len(list(ReplayReader(log).lines())) == 2


def test_tail_reader_follows_append_and_truncate(tmp_path):
    log = tmp_path / "events.json"
    log.write_text("first\n", encoding="utf-8")
    reader = TailReader(log)
    assert reader.poll() == []  # existing content is skipped unless from_start
    with log.open("a", encoding="utf-8") as handle:
        handle.write("second\n")
    assert [line.strip() for line in reader.poll()] == ["second"]
    # truncate-in-place: the reader rewinds when the file shrinks below its
    # position (inode-change rotation is the same class on Linux; Windows
    # cannot rename an open file, so that half lives in the audit channel's
    # Linux-only behaviour).
    log.write_text("reset\n", encoding="utf-8")
    assert [line.strip() for line in reader.poll()] == ["reset"]
    reader.close()


def test_tail_reader_from_start(tmp_path):
    log = tmp_path / "events.json"
    log.write_text("one\ntwo\n", encoding="utf-8")
    reader = TailReader(log, from_start=True)
    assert len(reader.poll()) == 2
    reader.close()


def test_availability_on_windows_is_honest(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    status = tetragon_available("/tmp/irrelevant.json")
    assert status.available is False
    assert "非 Linux" in status.reason
    assert status.to_dict()["available"] is False


def test_availability_reports_missing_and_unreadable_files(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "linux")
    missing = tetragon_available(tmp_path / "nope.json")
    assert missing.available is False and "不存在" in missing.reason

    log = tmp_path / "events.json"
    log.write_text("{}\n", encoding="utf-8")
    readable = tetragon_available(log)
    assert readable.available is True and readable.reason == ""

    log.chmod(0o000)
    try:
        unreadable = tetragon_available(log)
        if unreadable.available:  # running as root (CI containers) skips this
            return
        assert "不可读" in unreadable.reason
    finally:
        log.chmod(0o644)


def test_install_commands_are_print_only():
    commands = install_commands()
    text = "\n".join(commands)
    assert all(command.strip().startswith(("curl", "sudo", "systemctl")) or
               command.startswith("systemctl") for command in commands)
    assert "tetragon.conf.d/export-filename" in text
    assert "install.sh" in text
    assert not any(command.startswith("rm -rf") for command in commands)
