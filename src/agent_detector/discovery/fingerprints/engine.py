"""Rule interpreter: executes declarative rules against collected host facts.

All product-specific knowledge lives in the YAML files under fingerprints/
rules/; this module only knows the probing primitives (filesystem metadata,
JSON key peeking, npm root discovery, process matching) so new products are
added by editing data, never code.
"""
import re
import shutil
import subprocess
from pathlib import Path

from agent_detector.discovery.sources.filesystem import inspect_path, read_package_version
from agent_detector.core.security import redact
from agent_detector.core.enums import AssetState, EvidenceKind, VersionSource
from agent_detector.core.models import (DetectedAsset, Evidence, HostFacts, ProcessInfo,
                                          VersionInfo)
from agent_detector.discovery.fingerprints.match import (compile_excludes, match_client_process,
                                               match_signature_process, process_text)
from agent_detector.discovery.fingerprints.schema import ClientRule, SignatureRule
from agent_detector.core.identity import build_asset_id, normalize_path, slugify

_CMDLINE_TEXT_LIMIT = 400
_VERSION_CLAIM_RE = re.compile(
    r"(?<!\w)(?:--version[= ]|version[= ]|\bv)(\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?)", re.I)
_SEMVER_RE = re.compile(r"(?<![\d.])(\d+)\.(\d+)\.(\d+)(?![\d])")


def _leading_semver(name: str) -> str | None:
    """Clean semver from names like 'claude-2.1.301-win32-x64.exe' or '2.1.301'."""
    match = _SEMVER_RE.search(name)
    if not match:
        return None
    return f"{match.group(1)}.{match.group(2)}.{match.group(3)}"


def _executable_of(matched: list[tuple[ProcessInfo, str]]) -> str | None:
    """Executable path of the first matched process, falling back to argv[0]."""
    for proc, _reason in matched:
        if proc.exe:
            return proc.exe
        if proc.cmdline:
            return proc.cmdline[0]
    return None


def npm_global_roots(home: Path, run_lookup: bool = True) -> list[Path]:
    """Well-known npm global roots; `npm root -g` is consulted as a live fallback."""
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


class ClientRuleDetector:
    """Executes one client rule; the rule file is the product specification."""

    def __init__(self, rule: ClientRule, home: Path | None = None,
                 npm_global_root: Path | None = None, run_npm_lookup: bool = True):
        self.rule = rule
        self.name = rule.id
        self._home = home
        self._npm_global_root = npm_global_root
        self._run_npm_lookup = run_npm_lookup
        self._excludes = compile_excludes(rule.process)

    def detect(self, facts: HostFacts) -> list[DetectedAsset]:
        home = self._home or Path.home()
        evidence: list[Evidence] = []
        states: set[AssetState] = set()
        config_paths: list[str] = []

        found_packages = self._probe_npm_packages(home, evidence, states)
        self._probe_paths(home, evidence, states)
        self._probe_dirs(home, evidence, states)
        version, version_evidence = self._resolve_version(home, found_packages, states)
        evidence.extend(version_evidence)
        self._probe_config(home, evidence, states, config_paths)
        matched = self._match_processes(facts, evidence, states)

        if not states:
            return []
        weights = self.rule.confidence
        confidence = (weights.base + weights.installed * (AssetState.INSTALLED in states)
                      + weights.configured * (AssetState.CONFIGURED in states)
                      + weights.running * (AssetState.RUNNING in states))
        asset_id = build_asset_id(facts.hostname, self.rule.id,
                                  f"user-home:{normalize_path(home)}")
        return [DetectedAsset(
            asset_id=asset_id, name=self.rule.name,
            asset_type=self.rule.asset_type, states=states,
            confidence=round(min(confidence, weights.cap), 2),
            version=version, evidence=evidence,
            running_pids=sorted({proc.pid for proc, _ in matched}),
            detector=self.name, config_paths=config_paths,
            executable=_executable_of(matched))]

    def _resolve(self, rule_path: str, home: Path) -> Path:
        """'~' in rules means the scanned user's home, which tests can redirect."""
        if rule_path.startswith("~"):
            return home / rule_path[1:].lstrip("/\\")
        return Path(rule_path)

    def _probe_npm_packages(self, home, evidence, states) -> list[tuple[str, Path]]:
        found: list[tuple[str, Path]] = []
        if not self.rule.install.npm_packages:
            return found
        if self._npm_global_root is not None:
            roots = [self._npm_global_root]
        else:
            roots = npm_global_roots(home, self._run_npm_lookup)
        for probe in self.rule.install.npm_packages:
            parts = probe.package.split("/")
            for root in roots:
                package_json = root.joinpath(*parts) / "package.json"
                if package_json.is_file():
                    states.add(AssetState.INSTALLED)
                    found.append((probe.package, package_json))
                    evidence.append(Evidence(
                        EvidenceKind.INSTALL_METADATA,
                        f"npm package {probe.package} ({package_json})",
                        {"path": str(package_json), "package": probe.package},
                        probe.confidence))
                    break
        return found

    def _probe_paths(self, home, evidence, states) -> None:
        for probe in self.rule.install.paths:
            fact = inspect_path(self._resolve(probe.path, home))
            if fact.exists:
                states.add(AssetState.INSTALLED)
                evidence.append(Evidence(
                    EvidenceKind.INSTALL_METADATA,
                    f"installed file {fact.path}",
                    {"path": fact.path, "size": fact.size}, probe.confidence))

    def _probe_dirs(self, home, evidence, states) -> None:
        for probe in self.rule.install.dirs:
            fact = inspect_path(self._resolve(probe.path, home))
            if fact.exists and fact.is_dir:
                states.add(AssetState.INSTALLED)
                evidence.append(Evidence(
                    EvidenceKind.FILE_METADATA,
                    f"directory {fact.path} exists",
                    {"path": fact.path, "is_dir": True}, probe.confidence))

    def _resolve_version(self, home, found_packages,
                         states: set[AssetState]) -> tuple[VersionInfo, list[Evidence]]:
        for step in self.rule.version:
            if step.from_ == "npm_package_json":
                for package, package_json in found_packages:
                    value = read_package_version(package_json)
                    if value:
                        return VersionInfo(value, step.source, step.confidence), [Evidence(
                            EvidenceKind.INSTALL_METADATA,
                            f"npm package.json version {value} ({package_json})",
                            {"path": str(package_json), "version": value},
                            step.confidence)]
            elif step.from_ == "semver_dir_entries":
                best: tuple[tuple[int, int, int], str, Path] | None = None
                for rule_dir in step.dirs:
                    try:
                        entries = list(self._resolve(rule_dir, home).iterdir())
                    except OSError:
                        continue
                    for entry in entries:
                        found = _leading_semver(entry.name.lower())
                        if found is None:
                            continue
                        key = tuple(int(part) for part in found.split("."))
                        if best is None or key > best[0]:
                            best = (key, found, entry)
                if best:
                    value, entry = best[1], best[2]
                    return VersionInfo(value, step.source, step.confidence), [Evidence(
                        EvidenceKind.INSTALL_METADATA,
                        f"installer version {value} ({entry})",
                        {"version": value, "path": str(entry)}, step.confidence)]
            elif step.from_ == "executable_version_flag":
                # Harmless by design, but gated: passive probes must have
                # claimed this binary as the product (INSTALLED) before we
                # ever execute it — unknown binaries are never run.
                if AssetState.INSTALLED not in states:
                    continue
                probed = self._version_flag_probe(step, home)
                if probed is not None:
                    value, run_path = probed
                    return VersionInfo(value, step.source, step.confidence), [Evidence(
                        EvidenceKind.INSTALL_METADATA,
                        f"--version probe reported {value} ({run_path})",
                        {"version": value, "path": str(run_path),
                         "argv": list(step.argv)}, step.confidence)]
        return VersionInfo.unknown(), []

    def _version_flag_probe(self, step, home) -> tuple[str, Path] | None:
        """Run the rule's fixed read-only version probe on a claimed binary."""
        target = self._resolve(step.path, home)
        if not target.is_file():
            return None
        try:
            completed = subprocess.run(
                [str(target), *step.argv], capture_output=True, text=True,
                timeout=step.timeout_ms / 1000, cwd=str(target.parent), check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        output = f"{completed.stdout or ''}\n{completed.stderr or ''}"
        match = re.search(step.pattern, output)
        if match is None:
            return None
        value = match.group(1) if match.groups() else match.group(0)
        return value, target

    def _probe_config(self, home, evidence, states, config_paths) -> None:
        for probe in self.rule.config.json_files:
            fact = inspect_path(self._resolve(probe.path, home))
            interesting = tuple(k for k in fact.json_top_keys if k in probe.keys_any)
            if interesting:
                states.add(AssetState.CONFIGURED)
                config_paths.append(fact.path)
                evidence.append(Evidence(
                    EvidenceKind.FILE_CONTENT_KEYS,
                    f"{probe.path} carries configured keys (values not stored)",
                    {"path": fact.path, "keys": list(interesting)}, probe.confidence))
        for probe in self.rule.config.existing_files:
            fact = inspect_path(self._resolve(probe.path, home))
            if fact.exists:
                states.add(AssetState.CONFIGURED)
                config_paths.append(fact.path)
                evidence.append(Evidence(
                    EvidenceKind.FILE_METADATA,
                    f"{probe.path} exists",
                    {"path": fact.path, "size": fact.size}, probe.confidence))

    def _match_processes(self, facts, evidence, states) -> list[tuple[ProcessInfo, str]]:
        if self.rule.process is None:
            return []
        matched: list[tuple[ProcessInfo, str]] = []
        for proc in facts.processes:
            reason = match_client_process(self.rule, proc, self._excludes)
            if reason is None:
                continue
            states.add(AssetState.RUNNING)
            matched.append((proc, reason))
            evidence.append(Evidence(
                EvidenceKind.PROCESS,
                f"process {proc.pid} looks like {self.rule.name} ({reason})",
                {"pid": proc.pid, "name": proc.name,
                 "cmdline": redact(" ".join(proc.cmdline))[:_CMDLINE_TEXT_LIMIT],
                 "match": reason}, self.rule.process.confidence))
        return matched


class SignatureRuleDetector:
    """Generic command-line signatures; one process scan for the whole set."""

    def __init__(self, rules: list[SignatureRule] | None = None):
        if rules is None:
            from agent_detector.discovery.fingerprints.loader import load_rules
            rules = load_rules().signature_rules
        self.rules = rules
        self.name = "signatures"

    def detect(self, facts: HostFacts) -> list[DetectedAsset]:
        ports_by_pid: dict[int, list[int]] = {}
        for sock in facts.sockets:
            if sock.pid is not None:
                ports_by_pid.setdefault(sock.pid, []).append(sock.port)
        assets: list[DetectedAsset] = []
        for proc in facts.processes:
            text = process_text(proc)
            for rule in self.rules:
                if not match_signature_process(rule, proc):
                    continue
                assets.append(self._asset(facts, rule, proc, text,
                                          ports_by_pid.get(proc.pid, [])))
        return assets

    def _asset(self, facts: HostFacts, rule: SignatureRule, proc: ProcessInfo,
               text: str, ports: list[int]) -> DetectedAsset:
        claim = _VERSION_CLAIM_RE.search(text)
        version = (VersionInfo(claim.group(1), VersionSource.PROCESS_CLAIM, 0.3)
                   if claim else VersionInfo.unknown())
        evidence = [Evidence(EvidenceKind.PROCESS,
                             f"process {proc.pid} matches {rule.name}",
                             {"pid": proc.pid, "name": proc.name,
                              "cmdline": redact(text)[:4000]}, 0.65)]
        evidence += [Evidence(EvidenceKind.LISTENING_SOCKET,
                              f"pid {proc.pid} listens on {port}",
                              {"pid": proc.pid, "port": port}, 0.85)
                     for port in ports]
        exe = proc.cmdline[0] if proc.cmdline else proc.name
        asset_id = build_asset_id(facts.hostname, slugify(rule.name),
                                  f"process:{normalize_path(exe)}")
        return DetectedAsset(
            asset_id=asset_id, name=rule.name, asset_type=rule.asset_type,
            states={AssetState.RUNNING},
            confidence=0.85 if ports else 0.65,
            version=version, evidence=evidence,
            running_pids=[proc.pid], listening_ports=ports, detector=self.name)
