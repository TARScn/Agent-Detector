"""Dependency scanner: which AI-relevant packages does a project environment hold?

Only package *metadata* is ever read — dist-info METADATA headers, dependency
declarations and lockfile entries. Nothing executes the target environment and
no file content beyond name/version header lines is captured, matching the
privacy stance of the fingerprints engine (键名/元数据 only).

Version provenance follows design §4.1: Installed (dist-info) beats Locked
(uv.lock / poetry.lock) beats Declared (pyproject / requirements). A version
that cannot be read anywhere is recorded as UNKNOWN, never guessed.
"""
from __future__ import annotations

import logging
import re
from importlib.resources import files as resource_files
from pathlib import Path

import tomllib
import yaml

from agent_detector.core.enums import VersionSource
from agent_detector.core.models import ComponentInfo, ProjectInfo

logger = logging.getLogger(__name__)

# Safety valve for huge site-packages trees: at most this many METADATA files
# are read per environment in one scan.
_MAX_METADATA_READS = 2000

_REQUIREMENT_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")

_PACKAGED_SDKS = resource_files("agent_detector.discovery").joinpath("data/llm_sdks.yaml")


def normalize_name(name: str) -> str:
    """PEP 503 package-name normalization so rule names and metadata agree."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def load_llm_sdks(data_file: Path | None = None) -> frozenset[str]:
    """Normalized SDK package names from llm_sdks.yaml; broken file -> empty."""
    target = Path(data_file) if data_file else Path(str(_PACKAGED_SDKS))
    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
        packages = raw.get("packages", [])
        return frozenset(normalize_name(str(name)) for name in packages if str(name).strip())
    except (OSError, UnicodeError, yaml.YAMLError, TypeError):
        logger.warning("llm_sdks.yaml unreadable; SDK interest list is empty")
        return frozenset()


def interest_names(framework_dependencies: set[str] | None = None) -> set[str]:
    """The normalized package set worth recording: framework deps + LLM SDKs."""
    interest = set(framework_dependencies or ())
    interest |= load_llm_sdks()
    return interest


def _site_packages_candidates(project: ProjectInfo) -> list[Path]:
    """Read-only guesses at the environment's site-packages, best first."""
    bases: list[Path] = []
    if project.environment_path:
        bases.append(Path(project.environment_path))
    elif project.executable:
        # System interpreter: site-packages lives beside it (Windows layout
        # <dir>/Lib/site-packages, POSIX <dir>/lib/python3.X/site-packages).
        bases.append(Path(project.executable).parent)
    candidates: list[Path] = []
    for base in bases:
        candidates.append(base / "Lib" / "site-packages")
        try:
            candidates.extend(sorted((base / "lib").glob("python3.*/site-packages")))
        except OSError:
            pass
    return [path for path in candidates if path.is_dir()]


def _read_dist_name_version(metadata_path: Path) -> tuple[str, str] | None:
    """(name, version) from the header block of one METADATA file."""
    name = ""
    version = ""
    try:
        with metadata_path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.rstrip("\n")
                if not line.strip():
                    break  # headers end at the first blank line
                if line.startswith("Name:") and not name:
                    name = line[len("Name:"):].strip()
                elif line.startswith("Version:") and not version:
                    version = line[len("Version:"):].strip()
                elif line.startswith("Description-"):
                    break  # long-form headers: stop reading, we only want name/version
    except OSError:
        return None
    if name:
        return name, version
    return None


def _installed_components(project: ProjectInfo, interest: set[str]) -> list[ComponentInfo]:
    found: list[ComponentInfo] = []
    reads = 0
    for site_packages in _site_packages_candidates(project):
        try:
            dist_dirs = sorted(site_packages.glob("*.dist-info"))
        except OSError:
            continue
        for dist_dir in dist_dirs:
            if reads >= _MAX_METADATA_READS:
                return found
            metadata = dist_dir / "METADATA"
            reads += 1
            parsed = _read_dist_name_version(metadata)
            if parsed is None:
                continue
            name, version = parsed
            if normalize_name(name) not in interest:
                continue
            found.append(ComponentInfo(name=normalize_name(name), version=version or "UNKNOWN",
                                       version_source=VersionSource.PACKAGE_METADATA,
                                       source_path=str(metadata)))
    return found


def _requirement_name(line: str) -> str | None:
    match = _REQUIREMENT_NAME_RE.match(line)
    return match.group(1) if match else None


def _declared_components(project: ProjectInfo, interest: set[str]) -> list[ComponentInfo]:
    found: list[ComponentInfo] = []
    pyproject = Path(project.root) / "pyproject.toml"
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, tomllib.TOMLDecodeError):
        data = {}
    project_table = data.get("project")
    if isinstance(project_table, dict):
        for requirement in project_table.get("dependencies", []) or []:
            if not isinstance(requirement, str):
                continue
            name = _requirement_name(requirement)
            if name and normalize_name(name) in interest:
                found.append(ComponentInfo(name=normalize_name(name), version="UNKNOWN",
                                           version_source=VersionSource.DECLARED,
                                           source_path=str(pyproject)))
        optional = project_table.get("optional-dependencies")
        if isinstance(optional, dict):
            for group in optional.values():
                if not isinstance(group, list):
                    continue
                for requirement in group:
                    if not isinstance(requirement, str):
                        continue
                    name = _requirement_name(requirement)
                    if name and normalize_name(name) in interest:
                        found.append(ComponentInfo(name=normalize_name(name), version="UNKNOWN",
                                                   version_source=VersionSource.DECLARED,
                                                   source_path=str(pyproject)))
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies")
    if isinstance(poetry, dict):
        for name in poetry:
            if name == "python":
                continue
            if normalize_name(str(name)) in interest:
                found.append(ComponentInfo(name=normalize_name(str(name)), version="UNKNOWN",
                                           version_source=VersionSource.DECLARED,
                                           source_path=str(pyproject)))
    requirements = Path(project.root) / "requirements.txt"
    try:
        for line in requirements.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "-")):
                continue
            name = _requirement_name(stripped)
            if name and normalize_name(name) in interest:
                found.append(ComponentInfo(name=normalize_name(name), version="UNKNOWN",
                                           version_source=VersionSource.DECLARED,
                                           source_path=str(requirements)))
    except (OSError, UnicodeError):
        pass
    return found


def _locked_components(project: ProjectInfo, interest: set[str]) -> list[ComponentInfo]:
    found: list[ComponentInfo] = []
    for lock_name in ("uv.lock", "poetry.lock"):
        lock_path = Path(project.root) / lock_name
        try:
            data = tomllib.loads(lock_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError, tomllib.TOMLDecodeError):
            continue
        for package in data.get("package", []):
            if not isinstance(package, dict):
                continue
            name = package.get("name")
            if not name:
                continue
            if normalize_name(str(name)) in interest:
                found.append(ComponentInfo(name=normalize_name(str(name)),
                                           version=str(package.get("version") or "UNKNOWN"),
                                           version_source=VersionSource.LOCKED,
                                           source_path=str(lock_path)))
    return found


def scan_project_dependencies(projects: list[ProjectInfo],
                              interest: set[str]) -> dict[str, list[ComponentInfo]]:
    """AI-relevant components per project_id, best provenance per package.

    Only ``resolved`` projects carry a real root; unresolved ones are scanned
    too (their root is a cwd hint) but routinely come back empty.
    """
    result: dict[str, list[ComponentInfo]] = {}
    for project in projects:
        if project.resolver_status != "resolved":
            result[project.project_id] = []
            continue
        best: dict[str, ComponentInfo] = {}
        rank = {VersionSource.PACKAGE_METADATA: 3,
                VersionSource.LOCKED: 2,
                VersionSource.DECLARED: 1}
        observed = (_installed_components(project, interest)
                    + _locked_components(project, interest)
                    + _declared_components(project, interest))
        for component in observed:
            current = best.get(component.name)
            if current is None or rank.get(component.version_source, 0) > rank.get(
                    current.version_source, 0):
                best[component.name] = component
        result[project.project_id] = sorted(best.values(), key=lambda item: item.name)
    return result
