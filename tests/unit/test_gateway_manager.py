import json
import os
import subprocess
import sys

import psutil

from agent_detector.gateway.manager import GatewayError, GatewayManager, build_command


def make_manager(tmp_path, **overrides):
    return GatewayManager(db_path=tmp_path / "db.sqlite3",
                          state_path=tmp_path / "gateway.json",
                          log_path=tmp_path / "gateway.log", **overrides)


def seed_running(manager, pid, create_time):
    manager.state_path.write_text(json.dumps(
        {"pid": pid, "create_time": create_time, "port": manager.port,
         "agent_label": manager.agent_label, "started_at": "2026-10-19T00:00:00+00:00"}),
        encoding="utf-8")


def test_build_command_is_a_fixed_template():
    command = build_command("mitmdump", 8899, " addon.py ")
    assert command[0] == "mitmdump"
    assert "--listen-host" in command and "127.0.0.1" in command
    assert "--listen-port" in command and "8899" in command
    assert command[command.index("--mode") + 1] == "regular"
    assert command[-1] == "--quiet"


def test_start_requires_mitmdump(tmp_path, monkeypatch):
    manager = make_manager(tmp_path)
    monkeypatch.setattr(manager, "mitmdump_path", lambda: None)
    try:
        manager.start()
    except GatewayError as exc:
        assert "mitmproxy is not installed" in str(exc)
    else:
        raise AssertionError("expected GatewayError")


def test_status_when_stopped(tmp_path, monkeypatch):
    manager = make_manager(tmp_path)
    monkeypatch.setattr(manager, "mitmdump_path", lambda: None)
    status = manager.status()
    assert status["running"] is False and status["available"] is False
    assert status["listen"] == f"127.0.0.1:{manager.port}"
    assert status["agent_label"] and status["observed_hosts"]


def test_start_rejects_when_already_running(tmp_path, monkeypatch):
    manager = make_manager(tmp_path)
    monkeypatch.setattr(manager, "mitmdump_path", lambda: "mitmdump")
    me = psutil.Process(os.getpid())
    seed_running(manager, os.getpid(), me.create_time())
    try:
        manager.start()
    except GatewayError as exc:
        assert "already running" in str(exc)
    else:
        raise AssertionError("expected GatewayError")


def test_stop_kills_the_recorded_process(tmp_path):
    manager = make_manager(tmp_path)
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        seed_running(manager, child.pid, psutil.Process(child.pid).create_time())
        status = manager.stop(timeout=8)
        assert status["running"] is False
        assert not manager.state_path.exists()
        child.wait(timeout=5)
        assert child.poll() is not None
    finally:
        if child.poll() is None:
            child.kill()


def test_stop_without_state_is_a_noop(tmp_path):
    manager = make_manager(tmp_path)
    assert manager.stop()["running"] is False


def test_stale_state_file_is_cleaned(tmp_path):
    manager = make_manager(tmp_path)
    dead = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        create_time = psutil.Process(dead.pid).create_time()
    finally:
        dead.kill()
        dead.wait(timeout=5)
    seed_running(manager, dead.pid, create_time)
    assert manager.status()["running"] is False
    assert not manager.state_path.exists()


def test_uptime_reported_from_state(tmp_path):
    manager = make_manager(tmp_path)
    me = psutil.Process(os.getpid())
    seed_running(manager, os.getpid(), me.create_time())
    status = manager.status()
    assert status["running"] is True and status["pid"] == os.getpid()
    assert isinstance(status["uptime_s"], int)
