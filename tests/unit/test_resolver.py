"""ProcessProjectResolver: process → project root inference (design §3.2)."""
from __future__ import annotations

from pathlib import Path

from agent_detector.discovery.scanner.resolver import resolve_projects, runtime_of
from agent_detector.core.models import HostFacts, ProcessInfo


def make_project(tmp_path: Path, name: str = "ai-todo", *,
                 with_venv: bool = True, marker: str = "pyproject.toml") -> Path:
    root = tmp_path / name
    (root / "app").mkdir(parents=True)
    if marker == "pyproject.toml":
        (root / marker).write_text(f'[project]\nname = "{name}"\n', encoding="utf-8")
    elif marker == "requirements.txt":
        (root / marker).write_text("fastapi\n", encoding="utf-8")
    if with_venv:
        (root / ".venv" / "Scripts").mkdir(parents=True, exist_ok=True)
        (root / ".venv" / "bin").mkdir(parents=True, exist_ok=True)
    return root


def python_proc(pid: int, exe: str, cwd: str | None, *args: str) -> ProcessInfo:
    return ProcessInfo(pid=pid, name=Path(exe).name, cmdline=(exe, *args),
                       create_time=1_700_000_000.0, ppid=4, exe=exe, cwd=cwd)


def test_module_entry_resolves_root_and_venv(tmp_path):
    root = make_project(tmp_path)
    venv_exe = str(root / ".venv" / "Scripts" / "python.exe")
    facts = HostFacts("h", (python_proc(100, venv_exe, str(root), "-m", "uvicorn",
                                         "main:app"),), ())
    projects = resolve_projects(facts)
    assert len(projects) == 1
    project = projects[0]
    assert project.resolver_status == "resolved"
    assert project.name == "ai-todo"
    assert Path(project.root).resolve() == root.resolve()
    assert project.entry_kind == "module"
    assert project.entry == "uvicorn"
    assert Path(project.environment_path).resolve() == (root / ".venv").resolve()
    assert project.pids == (100,)


def test_script_entry_resolves_root_from_script_path(tmp_path):
    root = make_project(tmp_path, "svc", with_venv=False, marker="requirements.txt")
    system_exe = str(tmp_path / "Python313" / "python.exe")
    script = str(root / "app" / "main.py")
    facts = HostFacts("h", (python_proc(101, system_exe, str(tmp_path), script),), ())
    projects = resolve_projects(facts)
    assert Path(projects[0].root).resolve() == root.resolve()
    assert projects[0].entry_kind == "script"
    # System interpreter outside the project root: no venv claimed.
    assert projects[0].environment_path is None


def test_server_entry_and_cwd_fallback(tmp_path):
    root = make_project(tmp_path, "worker", with_venv=False)
    exe = str(root / "python.exe")
    facts = HostFacts("h", (python_proc(102, exe, str(root), "uvicorn", "app.api:app"),), ())
    projects = resolve_projects(facts)
    assert Path(projects[0].root).resolve() == root.resolve()
    assert projects[0].entry_kind == "server-entry"
    assert projects[0].entry == "app.api:app"


def test_unresolved_project_is_kept_not_dropped(tmp_path):
    bare = tmp_path / "nowhere"
    bare.mkdir()
    exe = str(tmp_path / "python.exe")
    facts = HostFacts("h", (python_proc(103, exe, str(bare), "-m", "something"),), ())
    projects = resolve_projects(facts)
    assert len(projects) == 1
    assert projects[0].resolver_status == "unresolved"


def test_processes_grouped_by_root(tmp_path):
    root = make_project(tmp_path, "multi")
    venv_exe = str(root / ".venv" / "bin" / "python")
    facts = HostFacts("h", (python_proc(104, venv_exe, str(root), "-m", "uvicorn", "a:app"),
                            python_proc(105, venv_exe, str(root), "worker.py")), ())
    projects = resolve_projects(facts)
    assert len(projects) == 1
    assert projects[0].pids == (104, 105)


def test_venv_detected_from_any_group_member_or_argv0(tmp_path):
    """Windows venv-launcher shape (D:\\lcxWS incident): the launcher spawns
    the base interpreter as a child — psutil reports the *base* exe for the
    child, only argv[0] (and the launcher's own exe) still carry the venv
    path. Venv detection must consider every group member and both sources."""
    root = make_project(tmp_path, "launcher-app")
    venv_exe = str(root / ".venv" / "Scripts" / "python.exe")
    base_exe = str(tmp_path / "Python313" / "python.exe")
    launcher = ProcessInfo(pid=29388, name="python.exe", cmdline=(venv_exe, "chat.py"),
                           exe=venv_exe, cwd=str(root))
    child = ProcessInfo(pid=23980, name="python.exe", cmdline=(venv_exe, "chat.py"),
                        exe=base_exe, cwd=str(root))
    # child first: it sorts first by pid, exactly the failing order
    projects = resolve_projects(HostFacts("h", (child, launcher), ()))
    assert Path(projects[0].environment_path).resolve() == (root / ".venv").resolve()
    # and it still works when ONLY argv[0] carries the venv path
    orphan = ProcessInfo(pid=24000, name="python.exe", cmdline=(venv_exe, "chat.py"),
                         exe=base_exe, cwd=str(root))
    projects = resolve_projects(HostFacts("h", (orphan,), ()))
    assert Path(projects[0].environment_path).resolve() == (root / ".venv").resolve()


def test_budget_caps_candidate_projects(tmp_path):
    roots = [make_project(tmp_path, f"p{i}", with_venv=False) for i in range(3)]
    exe = str(tmp_path / "python.exe")
    procs = [python_proc(110 + i, exe, str(root), "main.py")
             for i, root in enumerate(roots)]
    projects = resolve_projects(HostFacts("h", tuple(procs), ()), max_projects=2)
    assert len(projects) == 2


def test_non_interpreter_processes_are_ignored(tmp_path):
    root = make_project(tmp_path, "notpython", with_venv=False)
    facts = HostFacts("h", (ProcessInfo(pid=120, name="node.exe",
                                        cmdline=("node", "server.js"),
                                        exe=str(root / "node.exe"),
                                        cwd=str(root)),), ())
    assert resolve_projects(facts) == []


def test_runtime_of_recognizes_interpreters():
    assert runtime_of(ProcessInfo(pid=1, name="python.exe",
                                  exe="C:/x/python.exe")) == "python"
    assert runtime_of(ProcessInfo(pid=1, name="python3.12",
                                  exe="/usr/bin/python3.12")) == "python"
    assert runtime_of(ProcessInfo(pid=1, name="py.exe",
                                  cmdline=("py", "-3"), exe="C:/x/py.exe")) == "python"
    assert runtime_of(ProcessInfo(pid=1, name="node.exe",
                                  exe="C:/x/node.exe")) is None
    assert runtime_of(ProcessInfo(pid=1, name="explorer.exe")) is None
