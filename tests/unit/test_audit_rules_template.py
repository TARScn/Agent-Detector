import pytest

from agent_detector.behavior.audit.rules_template import (ALL_KEYS, PERSISTENT_PATH,
                                                          build_rules, install_commands,
                                                          uninstall_commands)


def test_rules_cover_exec_and_watched_directories():
    rule_set = build_rules(["/home/user/agent-lab"])
    text = "\n".join(rule_set.rules)
    assert "-S execve -S execveat -k agent_detector_exec" in text
    assert "-F dir=/home/user/agent-lab -F perm=wa -k agent_detector_file" in text
    assert "-S rename,renameat,renameat2,unlink,unlinkat,rmdir" in text
    assert "-S connect -k agent_detector_net" in text
    assert "agent_detector_kill" not in text
    assert rule_set.keys == ALL_KEYS


def test_net_and_kill_are_togglable_and_read_dirs_are_opt_in():
    quiet = build_rules(["/srv/lab"], include_net=False, include_kill=False)
    assert "connect" not in "\n".join(quiet.rules)

    loud = build_rules(["/srv/lab"], include_kill=True,
                       read_dirs=["/srv/lab/secret"])
    text = "\n".join(loud.rules)
    assert "-S kill,tkill,tgkill -k agent_detector_kill" in text
    assert "-F dir=/srv/lab/secret -F perm=r -k agent_detector_read" in text


def test_install_and_uninstall_command_shapes():
    rule_set = build_rules(["/srv/lab"])
    install = install_commands(rule_set)
    assert all(command.startswith("sudo auditctl ") for command in install)
    assert len(install) == len(rule_set.rules)

    persistent = install_commands(rule_set, persistent=True)
    assert PERSISTENT_PATH in persistent[-2]
    assert persistent[-1] == "sudo augenrules --load"

    uninstall = uninstall_commands(rule_set)
    assert uninstall[0] == "sudo auditctl -W " + ",".join(ALL_KEYS)
    assert uninstall_commands(rule_set, persistent=True)[-2] == f"sudo rm -f {PERSISTENT_PATH}"


def test_watch_dirs_must_be_absolute_posix_paths():
    for bad in ("/home/user/agent-lab".replace("/home", "C:/Program Files/Git/home"),
                r"C:\Users\me\lab", "agent-lab", ""):
        with pytest.raises(ValueError):
            build_rules([bad])
    with pytest.raises(ValueError):
        build_rules([], read_dirs=["relative/dir"])
    assert build_rules(["//home/user/agent-lab"]).rules  # Git-Bash escaped form is fine