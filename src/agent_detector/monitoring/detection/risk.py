"""Risk grading for observed behavior (design section 6.1).

This is *not* a policy decision: nothing is blocked because of it. It is the
score that decides what the dashboard highlights and when a security alert is
raised, and it is deliberately conservative — a heuristic grade is labelled
``heuristic`` in the event evidence so nobody mistakes it for a verdict.

The grading is data-driven and small on purpose: an unreadable table of magic
weights is worse than five rules a reviewer can check at a glance.
"""
from __future__ import annotations

from agent_detector.core.enums import RiskLevel
from agent_detector.core.paths import path_related

# Baseline per fact/operation kind. Anything unknown is graded LOW, not guessed
# higher: an unknown operation has not been shown to be dangerous.
OPERATION_BASE: dict[str, RiskLevel] = {
    "proc.exec": RiskLevel.MEDIUM,
    "proc.kill": RiskLevel.HIGH,
    "file.write": RiskLevel.LOW,
    "file.delete": RiskLevel.MEDIUM,
    "file.move": RiskLevel.LOW,
    "file.attr": RiskLevel.MEDIUM,
    "file.read": RiskLevel.LOW,
    "net.connect": RiskLevel.LOW,
    "dns.query": RiskLevel.LOW,
    "llm.conn": RiskLevel.LOW,
}

# High-level behaviors (detection/behavior_rules.py) that deserve a higher grade
# than their low-level kind would suggest.
OPERATION_OVERRIDES: dict[str, RiskLevel] = {
    "PACKAGE_INSTALL": RiskLevel.HIGH,
    "PRIVILEGE_COMMAND": RiskLevel.HIGH,
    "PROCESS_KILL": RiskLevel.HIGH,
    "SCRIPT_EXEC": RiskLevel.MEDIUM,
    "BROWSER_AUTOMATION": RiskLevel.MEDIUM,
    "GIT_OPERATION": RiskLevel.LOW,
}

# Paths that raise the grade of any write/delete touching them.
SENSITIVE_PATHS: tuple[str, ...] = (
    "**/.ssh/**", "**/.ssh", "**/.aws/**", "**/.gnupg/**", "**/.kube/**",
    "**/.netrc", "**/.npmrc", "**/.claude/settings.json", "**/.codex/hooks.json",
    "**/.cursor/hooks.json", "C:/Windows/**", "/etc/**", "/boot/**",
    "/usr/lib/**", "**/.git/config",
)

_WRITE_LIKE = ("file.write", "file.delete", "file.move", "file.attr")

_RANK = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}


def grade(kind: str, *, operation: str | None = None, target: str | None = None,
          extra_evidence: tuple[str, ...] = ()) -> tuple[RiskLevel, list[str]]:
    """Grade one event; returns the level plus the reasons that produced it.

    The reasons become event evidence, so a user can always see *why* something
    was highlighted — and disagree with it.
    """
    level = OPERATION_OVERRIDES.get(operation or "")
    reasons: list[str] = []
    if level is None:
        level = OPERATION_BASE.get(kind, RiskLevel.LOW)
        reasons.append(f"base:{kind}")
    else:
        reasons.append(f"operation:{operation}")
    if target and kind in _WRITE_LIKE and _sensitive(target):
        level = _bump(level, RiskLevel.HIGH)
        reasons.append("sensitive_path")
    if kind == "net.connect" and target and not _is_private(target):
        level = _bump(level, RiskLevel.MEDIUM)
        reasons.append("external_endpoint")
    if extra_evidence:
        reasons.extend(extra_evidence)
    reasons.append("heuristic")
    return level, reasons


def _bump(current: RiskLevel, minimum: RiskLevel) -> RiskLevel:
    return current if _RANK[current] >= _RANK[minimum] else minimum


def _sensitive(target: str) -> bool:
    return any(path_related(pattern, target) for pattern in SENSITIVE_PATHS)


def _is_private(endpoint: str) -> bool:
    """Loopback / RFC1918 destinations are not 'external' for grading purposes."""
    host = endpoint.rsplit(":", 1)[0].strip("[]")
    if not host:
        return True
    if host in ("localhost",) or host.startswith("127.") or host == "::1":
        return True
    parts = host.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        first, second = int(parts[0]), int(parts[1])
        if first == 10 or (first == 192 and second == 168) or (
                first == 172 and 16 <= second <= 31):
            return True
    return False