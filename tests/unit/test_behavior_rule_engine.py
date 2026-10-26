import pytest
from pydantic import ValidationError

from agent_detector.core.facts import BehaviorFact
from agent_detector.monitoring.detection.behavior_rules import (BehaviorRuleSet, load_behavior_rules,
                                                    match_fact)


def exec_fact(argv, exe="/usr/bin/python3", name="python3"):
    return BehaviorFact(kind="proc.exec", ts=1.0, serial="1", pid=1, ppid=None,
                        process_name=name, exe=exe, argv=tuple(argv))


def packaged():
    loaded = load_behavior_rules()
    assert loaded.errors == []
    return loaded.rules


def test_packaged_rules_load_and_are_ordered():
    ids = [rule.id for rule in packaged().rules]
    assert ids.index("SCRIPT_EXEC") < ids.index("COMMAND_EXEC")
    assert "FILE_MOVE" in ids and "NETWORK_CONNECT" in ids


def test_script_exec_derives_script_path():
    result = match_fact(exec_fact(("python3", "train.py", "--epochs")), packaged())
    assert result.operation == "SCRIPT_EXEC" and result.target == "train.py"
    assert result.confidence == "high" and result.rule_id == "SCRIPT_EXEC"


def test_inline_code_is_never_stored():
    result = match_fact(exec_fact(("bash", "-c", "curl -H 'Authorization: Bearer x'"),
                                  exe="/usr/bin/bash", name="bash"), packaged())
    assert result.operation == "SCRIPT_EXEC" and result.target == "inline"


def test_module_invocation_derives_module_name():
    result = match_fact(exec_fact(("python3", "-m", "http.server")), packaged())
    assert result.target == "-m http.server"


def test_git_operation_derives_subcommand():
    fact = exec_fact(("git", "status"), exe="/usr/bin/git", name="git")
    result = match_fact(fact, packaged())
    assert result.operation == "GIT_OPERATION" and result.detail == "status"
    assert result.target == "git"

    flagged = match_fact(exec_fact(("git", "--version"), exe="/usr/bin/git", name="git"),
                         packaged())
    assert flagged.detail == "git"


def test_package_install_and_database_operation():
    install = match_fact(exec_fact(("pip", "install", "requests"),
                                   exe="/usr/bin/pip", name="pip"), packaged())
    assert install.operation == "PACKAGE_INSTALL" and install.target == "pip install"

    database = match_fact(exec_fact(("psql", "-c", "select 1"),
                                    exe="/usr/bin/psql", name="psql"), packaged())
    assert database.operation == "DATABASE_OPERATION"


def test_browser_automation_matches_dedicated_binaries():
    chrome = match_fact(exec_fact(("chrome", "--headless",
                                   "--remote-debugging-port=9222"),
                                  exe="/usr/bin/google-chrome", name="chrome"), packaged())
    assert chrome.operation == "BROWSER_AUTOMATION" and chrome.confidence == "medium"

    runner = match_fact(exec_fact(("playwright", "test"),
                                  exe="/usr/bin/playwright", name="playwright"), packaged())
    assert runner.operation == "BROWSER_AUTOMATION"


def test_runtime_launched_browser_stays_script_exec():
    result = match_fact(exec_fact(("node", "server.js", "--remote-debugging-port=9222"),
                                  exe="/usr/bin/node", name="node"), packaged())
    assert result.operation == "SCRIPT_EXEC" and result.target == "server.js"


def test_windows_executable_suffixes_match_the_same_rules():
    script = exec_fact(("python.exe", "-m", "pytest"),
                       exe="C:\\Python313\\python.exe", name="python.exe")
    result = match_fact(script, packaged())
    assert result.operation == "SCRIPT_EXEC" and result.target == "-m pytest"

    git = exec_fact(("git.exe", "status"), exe="C:\\Git\\cmd\\git.exe", name="git.exe")
    assert match_fact(git, packaged()).operation == "GIT_OPERATION"

    inline = exec_fact(("bash.exe", "-c", "echo hi"),
                       exe="C:\\git\\bin\\bash.exe", name="bash.exe")
    assert match_fact(inline, packaged()).target == "inline"


def test_catch_all_command_exec():
    result = match_fact(exec_fact(("ls", "-la"), exe="/usr/bin/ls", name="ls"), packaged())
    assert result.operation == "COMMAND_EXEC" and result.target == "ls -la"


def test_file_and_network_kinds_map_one_to_one():
    expected = {"file.write": "FILE_MODIFY", "file.move": "FILE_MOVE",
                "file.delete": "FILE_DELETE", "file.attr": "FILE_ATTR_CHANGE",
                "file.read": "FILE_READ", "net.connect": "NETWORK_CONNECT",
                "proc.kill": "PROC_KILL"}
    for kind, operation in expected.items():
        fact = BehaviorFact(kind=kind, ts=1.0, serial="9", pid=5, ppid=1,
                            process_name="x")
        result = match_fact(fact, packaged())
        assert result is not None and result.operation == operation


def test_executable_name_uses_argv0_basename():
    fact = exec_fact(("/usr/bin/python3", "tool.py"), exe="/usr/bin/python3")
    assert match_fact(fact, packaged()).operation == "SCRIPT_EXEC"


def test_invalid_kind_and_deriver_are_rejected():
    with pytest.raises(ValidationError):
        BehaviorRuleSet.model_validate({"rules": [{"id": "X",
                                                   "when": {"kind": "screen.capture"}}]})
    with pytest.raises(ValidationError):
        BehaviorRuleSet.model_validate({"rules": [{"id": "X", "when": {"kind": "proc.exec"},
                                                   "derive": {"target": "magic"}}]})


def test_external_rules_directory_overrides_packaged(tmp_path):
    (tmp_path / "behaviors.yaml").write_text(
        "revision: 9\nrules:\n  - id: ONLY_ONE\n    when: {kind: proc.exec}\n",
        encoding="utf-8")
    loaded = load_behavior_rules(tmp_path)
    assert loaded.errors == []
    assert loaded.rules.revision == 9
    assert [rule.id for rule in loaded.rules.rules] == ["ONLY_ONE"]


def test_broken_override_falls_back_to_packaged(tmp_path):
    (tmp_path / "behaviors.yaml").write_text("rules: [1, 2, 3]\n", encoding="utf-8")
    loaded = load_behavior_rules(tmp_path)
    assert loaded.errors and loaded.rules.rules  # packaged rules stay active
    assert any(rule.id == "SCRIPT_EXEC" for rule in loaded.rules.rules)