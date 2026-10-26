"""ProcessProjectResolver: map running interpreter processes to project roots.

The design's first question is "which app is this process running?" — not "is
it an Agent?". This module only answers the first: from the interpreter's exe,
cmdline entry and cwd it infers a candidate project directory and its virtual
environment. Whether that project actually embeds AI code is decided later by
the dependency scanner and framework rules; a plain web service never becomes
an asset here (design §9: 普通 FastAPI 服务不能确认 Agent).

Everything is read-only path inference. A missing cwd (access denied) or an
unreadable pyproject degrades the result instead of raising — an unresolved
process stays visible in scan stats rather than being silently dropped.
"""
from __future__ import annotations

import hashlib
import tomllib
from pathlib import Path

from agent_detector.core.config import MAX_PROJECT_PROBES
from agent_detector.core.identity import normalize_path
from agent_detector.core.models import HostFacts, ProcessInfo, ProjectInfo

# How far up from the entry point we walk before giving up on a project root.
_MAX_ROOT_WALK = 6

# Directory names that mark a virtual environment below the project root.
_VENV_DIR_NAMES = {".venv", "venv", "env"}

# Project-root markers. The nearest directory containing any of these wins.
_ROOT_MARKERS = ("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt",
                 "Pipfile", "uv.lock", "poetry.lock", ".git")

_SERVER_TOOLS = {"uvicorn", "gunicorn", "celery"}


def _exe_stem(text: str | None) -> str:
    if not text:
        return ""
    return Path(text).name.rsplit(".", 1)[0].lower()


def runtime_of(proc: ProcessInfo) -> str | None:
    """"python" for CPython-ish interpreters (incl. venv wrappers); else None."""
    candidates = [_exe_stem(proc.exe)]
    if proc.cmdline:
        candidates.append(_exe_stem(proc.cmdline[0]))
    return "python" if any(stem in {"py", "pythonw"} or stem.startswith("python")
                           for stem in candidates) else None


def _extract_entry(proc: ProcessInfo) -> tuple[str, str | None]:
    """(kind, entry) from the cmdline; kinds: module | script | server-entry | cwd."""
    args = list(proc.cmdline)
    if args:
        args = args[1:]  # drop the interpreter itself
    for index, arg in enumerate(args):
        if arg == "-m" and index + 1 < len(args):
            return "module", args[index + 1]
    for arg in args:
        if arg.endswith(".py"):
            return "script", arg
    for index, arg in enumerate(args):
        if _exe_stem(arg) in _SERVER_TOOLS and index + 1 < len(args) \
                and ":" in args[index + 1]:
            return "server-entry", args[index + 1]
    return "cwd", None


def _has_marker(directory: Path) -> bool:
    try:
        return directory.is_dir() and any((directory / marker).exists()
                                          for marker in _ROOT_MARKERS)
    except OSError:
        return False


def _find_root(start: Path) -> Path | None:
    """Nearest ancestor (≤ _MAX_ROOT_WALK levels up) holding a project marker."""
    current = start
    for _ in range(_MAX_ROOT_WALK + 1):
        if _has_marker(current):
            return current
        if current.parent == current:
            return None
        current = current.parent
    return None


def _project_name(root: Path) -> str:
    """pyproject [project].name / [tool.poetry].name, else the directory name."""
    try:
        data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, tomllib.TOMLDecodeError):
        return root.name
    holders = (data.get("project"), data.get("tool", {}).get("poetry"))
    for holder in holders:
        if isinstance(holder, dict) and isinstance(holder.get("name"), str) \
                and holder["name"].strip():
            return holder["name"].strip()
    return root.name


def _venv_of(exe: str | None, root: Path) -> str | None:
    """The venv directory when the interpreter path lives under the project root."""
    if not exe:
        return None
    try:
        current = Path(exe).resolve()
        root_resolved = root.resolve()
    except OSError:
        return None
    if root_resolved not in current.parents:
        return None
    for parent in current.parents:
        if parent == root_resolved:
            return None
        if parent.name.lower() in _VENV_DIR_NAMES:
            return str(parent)
    return None


def _group_venv(procs: list[ProcessInfo], root: Path) -> str | None:
    """Venv directory from any group member's exe or argv[0].

    Windows venv launchers spawn the base interpreter as a child: psutil then
    reports the *base* python for the child's exe, while argv[0] keeps the
    venv path — so both sources, across the whole group, must be considered.
    """
    for proc in procs:
        argv0 = proc.cmdline[0] if proc.cmdline else None
        for candidate in (proc.exe, argv0):
            venv = _venv_of(candidate, root)
            if venv:
                return venv
    return None


def _project_id(root: str) -> str:
    return "proj-" + hashlib.sha256(root.encode("utf-8")).hexdigest()[:12]


def _usable_path(path: Path) -> str:
    """Real filesystem path for storage/display (identity uses normalize_path)."""
    try:
        return str(path.resolve())
    except OSError:
        return str(path)


def _build_project(root: Path, procs: list[ProcessInfo], kind: str, entry: str | None,
                   runtime: str, *, resolved: bool) -> ProjectInfo:
    key = normalize_path(root)  # identity: stable across machines' path spellings
    venv = _group_venv(procs, root)
    return ProjectInfo(
        project_id=_project_id(key),
        root=_usable_path(root),
        name=_project_name(root),
        runtime=runtime,
        pids=tuple(sorted(proc.pid for proc in procs)),
        executable=procs[0].exe,
        environment_path=_usable_path(Path(venv)) if venv else None,
        entry=entry,
        entry_kind=kind,
        resolver_status="resolved" if resolved else "unresolved",
    )


def resolve_projects(facts: HostFacts, *,
                     max_projects: int | None = None) -> list[ProjectInfo]:
    """Group interpreter processes into candidate projects, keyed by root.

    Processes whose project root cannot be determined are still returned, as
    ``unresolved`` projects anchored on their cwd — the design's principle
    that the discovery layer must not silently exclude candidates.
    """
    budget = MAX_PROJECT_PROBES if max_projects is None else max_projects
    if budget <= 0:
        return []
    candidates = [proc for proc in sorted(facts.processes, key=lambda p: p.pid)
                  if runtime_of(proc) == "python"][:budget]

    grouped: dict[str, tuple[Path, list[ProcessInfo], str, str | None]] = {}
    for proc in candidates:
        kind, entry = _extract_entry(proc)
        starts: list[Path] = []
        if kind == "script" and entry:
            script = Path(entry).expanduser()
            if not script.is_absolute() and proc.cwd:
                # "python worker.py" is relative to the *target's* cwd, not ours
                script = Path(proc.cwd).expanduser() / script
            starts.append(script.parent)
        if proc.cwd:
            starts.append(Path(proc.cwd).expanduser())
        if not starts:
            continue
        root: Path | None = None
        for start in starts:
            root = _find_root(start)
            if root is not None:
                break
        anchor = root if root is not None else starts[-1]
        key = normalize_path(anchor)
        if key in grouped:
            grouped[key][1].append(proc)
            continue
        grouped[key] = (anchor, [proc], kind, entry)

    projects: list[ProjectInfo] = []
    for anchor, procs, kind, entry in grouped.values():
        projects.append(_build_project(anchor, procs, kind, entry, "python",
                                       resolved=_has_marker(anchor)))
    return projects
