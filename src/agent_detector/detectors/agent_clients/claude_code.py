"""Claude Code client detection.

Evidence sources (plan sections 3.1.2, 4.2):
- install: npm global package.json, native installer binary, ~/.claude directory
- configuration: ~/.claude.json top-level agent keys, ~/.claude/settings.json
- running: process whose executable or package path resolves to Claude Code

Only metadata and key names are read; file contents and credentials are never
stored, and nothing is executed.
"""
import re
import shutil
import subprocess
from pathlib import Path

from agent_detector.collectors.filesystem import inspect_path, read_package_version
from agent_detector.common.security import redact
from agent_detector.domain.enums import AssetState, AssetType, EvidenceKind, VersionSource
from agent_detector.domain.models import (DetectedAsset, Evidence, HostFacts, ProcessInfo,
                                          VersionInfo)
from agent_detector.recognition.identity import build_asset_id, normalize_path

AGENT_KEY = "claude-code"
DISPLAY_NAME = "Claude Code"
PACKAGE_PATH = ("@anthropic-ai", "claude-code")
_EXE_NAMES = ("claude", "claude.exe", "claude.cmd", "claude.ps1")
_CMDLINE_TEXT_LIMIT = 400
# Keys whose presence indicates configured Claude Code usage; a lone userID
# only proves the installer ran, so it does not count.
_CONFIG_JSON_KEYS = ("projects", "mcpServers")
# Claude Desktop (the Electron chat app) shares the 'claude.exe' executable
# name but is a different product; these fingerprints exclude its processes.
_DESKTOP_EXCLUDE_RE = re.compile(
    r"(?i)windowsapps[/\\]claude_|appdata[/\\]roaming[/\\]claude(?![\w.\-])"
    r"|--type=(?:renderer|gpu-process|utility|crashpad-handler|zygote)")


def _match_process(proc: ProcessInfo) -> str | None:
    """Return the match reason, or None.

    Deliberately narrow: a bare 'claude' word appearing as a plain argument
    (e.g. `grep claude`) is not evidence, so only the executable name / path
    and the scoped package path count. Claude Desktop processes are excluded
    by fingerprint before any positive rule is applied.
    """
    text = " ".join((proc.name, *proc.cmdline)).replace("\\", "/").lower()
    if _DESKTOP_EXCLUDE_RE.search(text):
        return None
    if proc.name.lower() in _EXE_NAMES:
        return "executable-name"
    if proc.cmdline:
        first = proc.cmdline[0].replace("\\", "/").lower()
        stem = first.rsplit("/", 1)[-1]
        if stem in _EXE_NAMES:
            return "executable-path"
    for arg in proc.cmdline:
        if "@anthropic-ai/claude-code" in arg.replace("\\", "/").lower():
            return "package-path"
    return None


def _npm_global_roots(home: Path, run_lookup: bool) -> list[Path]:
    roots = [
        home / "AppData" / "Roaming" / "npm" / "node_modules",
        Path("/usr/lib/node_modules"),
        Path("/usr/local/lib/node_modules"),
        home / ".npm-global" / "lib" / "node_modules",
        home / ".local" / "lib" / "node_modules",
    ]
    if run_lookup:
        npm = shutil.which("npm")
        if npm:
            try:
                proc = subprocess.run([npm, "root", "-g"], capture_output=True,
                                      text=True, timeout=5)
                output = proc.stdout.strip()
                if proc.returncode == 0 and output:
                    roots.append(Path(output.splitlines()[0].strip()))
            except (OSError, subprocess.SubprocessError, IndexError):
                pass
    return roots


def _leading_semver(name: str) -> str | None:
    """Extract a clean semver from names like 'claude-2.1.301-win32-x64.exe'."""
    match = re.search(r"(?<![\d.])(\d+)\.(\d+)\.(\d+)(?![\d])", name)
    if not match:
        return None
    return f"{match.group(1)}.{match.group(2)}.{match.group(3)}"


def _native_version_candidates(home: Path) -> list[Path]:
    """Entries the native installer populates with versioned build artifacts."""
    candidates: list[Path] = []
    claude_dir = home / ".claude"
    try:
        candidates.extend(claude_dir.iterdir())
    except OSError:
        pass
    for sub in ("versions", "downloads"):
        try:
            candidates.extend((claude_dir / sub).iterdir())
        except OSError:
            continue
    # Native installer layout: ~/.local/share/claude/versions/<semver>
    try:
        candidates.extend((home / ".local" / "share" / "claude" / "versions").iterdir())
    except OSError:
        pass
    return candidates


def _native_version(home: Path) -> tuple[str, Path] | None:
    """Newest semver-named entry across the installer's known locations."""
    best: tuple[tuple[int, int, int], str, Path] | None = None
    for entry in _native_version_candidates(home):
        found = _leading_semver(entry.name.lower())
        if found is None:
            continue
        key = tuple(int(part) for part in found.split("."))
        if best is None or key > best[0]:
            best = (key, found, entry)
    return (best[1], best[2]) if best else None


class ClaudeCodeDetector:
    """Detects the Claude Code agent client from install, config and process facts."""

    name = AGENT_KEY

    def __init__(self, home: Path | None = None, npm_global_root: Path | None = None,
                 run_npm_lookup: bool = True):
        self._home = home
        self._npm_global_root = npm_global_root
        self._run_npm_lookup = run_npm_lookup

    def detect(self, facts: HostFacts) -> list[DetectedAsset]:
        home = self._home or Path.home()
        evidence: list[Evidence] = []
        states: set[AssetState] = set()
        version = VersionInfo.unknown()

        package_json = self._find_package_json(home)
        if package_json is not None:
            states.add(AssetState.INSTALLED)
            value = read_package_version(package_json)
            evidence.append(Evidence(EvidenceKind.INSTALL_METADATA,
                                     f"npm package {package_json}",
                                     {"path": str(package_json), "version": value}, 0.9))
            if value:
                version = VersionInfo(value, VersionSource.PACKAGE_METADATA, 0.9)

        native_binary = self._find_native_binary(home)
        if native_binary is not None:
            states.add(AssetState.INSTALLED)
            evidence.append(Evidence(EvidenceKind.INSTALL_METADATA,
                                     f"native installer binary {native_binary}",
                                     {"path": str(native_binary)}, 0.85))

        claude_dir = inspect_path(home / ".claude")
        if claude_dir.exists and claude_dir.is_dir:
            states.add(AssetState.INSTALLED)
            evidence.append(Evidence(EvidenceKind.FILE_METADATA,
                                     "directory ~/.claude exists",
                                     {"path": claude_dir.path, "is_dir": True}, 0.8))
            if not version.known:
                found = _native_version(home)
                if found:
                    value, source_path = found
                    version = VersionInfo(value, VersionSource.INSTALLER_METADATA, 0.8)
                    evidence.append(Evidence(
                        EvidenceKind.INSTALL_METADATA,
                        f"installer version {value} ({source_path})",
                        {"version": value, "path": str(source_path)}, 0.8))

        claude_json = inspect_path(home / ".claude.json")
        if claude_json.exists:
            interesting = tuple(k for k in claude_json.json_top_keys
                                if k in _CONFIG_JSON_KEYS)
            if interesting:
                states.add(AssetState.CONFIGURED)
                evidence.append(Evidence(
                    EvidenceKind.FILE_CONTENT_KEYS,
                    "~/.claude.json carries Claude Code keys (values not stored)",
                    {"path": claude_json.path, "keys": list(interesting)}, 0.9))

        settings = inspect_path(home / ".claude" / "settings.json")
        if settings.exists:
            states.add(AssetState.CONFIGURED)
            evidence.append(Evidence(EvidenceKind.FILE_METADATA,
                                     "~/.claude/settings.json exists",
                                     {"path": settings.path, "size": settings.size}, 0.8))

        matched = [(proc, reason) for proc in facts.processes
                   if (reason := _match_process(proc)) is not None]
        for proc, reason in matched:
            states.add(AssetState.RUNNING)
            evidence.append(Evidence(
                EvidenceKind.PROCESS,
                f"process {proc.pid} looks like Claude Code ({reason})",
                {"pid": proc.pid, "name": proc.name,
                 "cmdline": redact(" ".join(proc.cmdline))[:_CMDLINE_TEXT_LIMIT],
                 "match": reason}, 0.85))

        if not states:
            return []
        confidence = 0.5 + (0.2 * (AssetState.INSTALLED in states)
                            + 0.2 * (AssetState.CONFIGURED in states)
                            + 0.25 * (AssetState.RUNNING in states))
        asset_id = build_asset_id(facts.hostname, AGENT_KEY,
                                  f"user-home:{normalize_path(home)}")
        return [DetectedAsset(
            asset_id=asset_id, name=DISPLAY_NAME,
            asset_type=AssetType.AGENT_CLIENT, states=states,
            confidence=round(min(confidence, 0.95), 2),
            version=version, evidence=evidence,
            running_pids=sorted({proc.pid for proc, _ in matched}),
            detector=self.name)]

    def _find_package_json(self, home: Path) -> Path | None:
        if self._npm_global_root is not None:
            roots = [self._npm_global_root]
        else:
            roots = _npm_global_roots(home, self._run_npm_lookup)
        for root in roots:
            package_json = root.joinpath(*PACKAGE_PATH) / "package.json"
            if package_json.is_file():
                return package_json
        return None

    @staticmethod
    def _find_native_binary(home: Path) -> Path | None:
        for exe in ("claude", "claude.exe"):
            candidate = home / ".local" / "bin" / exe
            if candidate.is_file():
                return candidate
        return None
