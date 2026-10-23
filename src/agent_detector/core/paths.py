"""Path and command matching primitives used by the policy engine.

Deliberately small and dependency-free so the matching rules stay readable in
``rules/policies.yaml``: a path pattern uses ``*`` (one segment), ``**`` (any
depth, including separators) and a trailing ``/`` meaning "this directory";
command patterns are ordinary regular expressions.

Command path extraction is heuristic: an agent shell command is a string, not
an argv, so the goal is to *find candidates worth checking against a protected
path list*, never to prove the command's exact semantics.
"""
from __future__ import annotations

import ntpath
import posixpath
import re
from pathlib import Path

_GLOB_CACHE: dict[tuple[str, bool], re.Pattern] = {}
_SHELL_SEPARATORS = re.compile(r"[\s;|&()<>\n\r]+")
_QUOTED = re.compile(r"""(?P<quote>['"])(?P<body>.*?)(?P=quote)""")
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
_LOOKS_LIKE_PATH = re.compile(r"[\\/]")


def normalize_path(path: str) -> str:
    """Comparable form: forward slashes, no trailing slash, lowercase on Windows."""
    text = path.strip().strip('"').strip("'")
    if not text:
        return ""
    text = text.replace("\\", "/")
    if text.endswith("/") and len(text) > 1:
        text = text.rstrip("/")
    return text.lower() if _is_windows_style(path) else text


def _is_windows_style(path: str) -> bool:
    return bool(_WINDOWS_DRIVE.match(path)) or "\\" in path


def _expand(pattern: str) -> str:
    """Translate a path glob into a regex over normalized paths."""
    out: list[str] = []
    index = 0
    length = len(pattern)
    while index < length:
        char = pattern[index]
        if char == "*":
            if pattern[index:index + 2] == "**":
                # `**/` also matches zero directories, so **/x covers x itself
                if pattern[index + 2:index + 3] == "/":
                    out.append("(?:.*/)?")
                    index += 3
                    continue
                out.append(".*")
                index += 2
                continue
            out.append("[^/]*")
            index += 1
            continue
        if char == "?":
            out.append("[^/]")
            index += 1
            continue
        out.append(re.escape(char))
        index += 1
    return "".join(out)


def compile_path_pattern(pattern: str, *, case_sensitive: bool = False) -> re.Pattern:
    key = (pattern, case_sensitive)
    cached = _GLOB_CACHE.get(key)
    if cached is None:
        normalized = pattern.replace("\\", "/")
        flags = 0 if case_sensitive else re.IGNORECASE
        cached = re.compile(_expand(normalized) + "$", flags)
        _GLOB_CACHE[key] = cached
    return cached


def match_path(pattern: str, path: str, *, case_sensitive: bool | None = None) -> bool:
    """True when ``path`` falls under ``pattern`` (or is one of several paths)."""
    if not pattern or not path:
        return False
    if case_sensitive is None:
        case_sensitive = not _is_windows_style(path) and not _is_windows_style(pattern)
    candidate = path.replace("\\", "/").rstrip("/")
    if not candidate:
        return False
    regex = compile_path_pattern(pattern.replace("\\", "/").rstrip("/"),
                                 case_sensitive=case_sensitive)
    if regex.match(candidate):
        return True
    # A directory pattern also protects everything underneath it.
    directory = pattern.replace("\\", "/")
    if directory.endswith("/"):
        prefix = compile_path_pattern(directory.rstrip("/") + "/**",
                                      case_sensitive=case_sensitive)
        return bool(prefix.match(candidate))
    return False


def _basename(path: str) -> str:
    if _WINDOWS_DRIVE.match(path):
        return ntpath.basename(path.replace("/", "\\"))
    return posixpath.basename(path)


def expand_user(path: str) -> str:
    """Expand a leading ``~`` so rules can be written against the user's home."""
    if path.startswith("~"):
        home = str(Path.home()).replace("\\", "/")
        rest = path[1:].lstrip("/\\")
        return f"{home}/{rest}" if rest else home
    return path


def is_absolute(path: str) -> bool:
    text = expand_user(path)
    return bool(_WINDOWS_DRIVE.match(text)) or text.startswith("/") or text.startswith("//")


def is_inside(path: str, root: str) -> bool:
    """True when ``path`` is ``root`` itself or sits underneath it.

    A relative path counts as inside: shell commands are interpreted relative to
    the session working directory, so ``build/`` under cwd is inside.
    """
    if not path or not root:
        return False
    candidate = normalize_path(expand_user(path))
    if not candidate:
        return False
    if not is_absolute(path):
        return True
    base = normalize_path(expand_user(root))
    return candidate == base or candidate.startswith(base.rstrip("/") + "/")


def candidates_from_command(command: str) -> list[str]:
    """Path-looking tokens in a shell command, quotes removed, ``~`` expanded."""
    tokens: list[str] = []
    for quoted in _QUOTED.finditer(command):
        body = quoted.group("body").strip()
        if body and (_LOOKS_LIKE_PATH.search(body) or _WINDOWS_DRIVE.match(body)):
            tokens.append(body)
    remainder = _QUOTED.sub(" ", command)
    for token in _SHELL_SEPARATORS.split(remainder):
        token = token.strip().strip("'\"")
        if not token or token.startswith("-"):
            continue
        if _WINDOWS_DRIVE.match(token) or _LOOKS_LIKE_PATH.search(token):
            tokens.append(token)
    return [expand_user(token) for token in tokens]


def path_related(pattern: str, path: str) -> bool:
    """Loose containment test used for command strings.

    ``True`` when the normalized path matches the pattern exactly or sits
    underneath it, without requiring the pattern to be a full glob.
    """
    normalized = normalize_path(path)
    target = pattern.replace("\\", "/").rstrip("/").lower()
    if not normalized or not target:
        return False
    if "*" in target or "?" in target:
        return match_path(pattern, path)
    return normalized == target or normalized.startswith(target + "/")


def basename_of(path: str) -> str:
    return _basename(path.replace("\\", "/"))