"""Read-only filesystem fact helpers (plan section 3.1.2).

Only metadata and top-level JSON key names are collected; file contents and
credential values are never captured.
"""
import json
from pathlib import Path
from stat import S_ISDIR

from agent_detector.domain.models import FileFact

MAX_JSON_PEEK_BYTES = 262144


def inspect_path(path) -> FileFact:
    """Stat one path and, for small JSON files, list its top-level key names."""
    resolved = Path(path).expanduser()
    try:
        stat = resolved.stat()
    except OSError:
        return FileFact(path=str(resolved), exists=False)
    is_dir = S_ISDIR(stat.st_mode)
    keys: tuple[str, ...] = ()
    if not is_dir and resolved.suffix.lower() == ".json" and stat.st_size <= MAX_JSON_PEEK_BYTES:
        keys = _top_level_keys(resolved)
    return FileFact(path=str(resolved), exists=True, is_dir=is_dir,
                    size=stat.st_size, mtime=stat.st_mtime, json_top_keys=keys)


def _top_level_keys(path: Path) -> tuple[str, ...]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError, UnicodeError):
        return ()
    if isinstance(data, dict):
        return tuple(sorted(data.keys()))
    return ()


def read_package_version(package_json) -> str | None:
    """Read the installed version field of a package.json, or None."""
    try:
        data = json.loads(Path(package_json).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError, UnicodeError):
        return None
    version = data.get("version") if isinstance(data, dict) else None
    if isinstance(version, str) and version.strip():
        return version.strip()
    return None
