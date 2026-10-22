"""Generate the Linux audit rules we recommend, plus install/uninstall commands.

The tool never elevates privileges itself: it only prints commands that the
operator runs as root (the Web card shows them read-only; the CLI prints them).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

EXEC_KEY = "agent_detector_exec"
FILE_KEY = "agent_detector_file"
READ_KEY = "agent_detector_read"
NET_KEY = "agent_detector_net"
KILL_KEY = "agent_detector_kill"
ALL_KEYS = (EXEC_KEY, FILE_KEY, READ_KEY, NET_KEY, KILL_KEY)

PERSISTENT_PATH = "/etc/audit/rules.d/agent-detector.rules"

# Directory-entry and metadata syscalls that perm=wa may not cover by itself.
FILE_SYSCALLS = ("rename", "renameat", "renameat2", "unlink", "unlinkat", "rmdir",
                 "mkdir", "mkdirat", "chmod", "fchmod", "fchmodat", "chown",
                 "fchown", "lchown", "fchownat", "truncate", "ftruncate", "creat")


@dataclass(frozen=True)
class AuditRuleSet:
    rules: tuple[str, ...]
    keys: tuple[str, ...] = ALL_KEYS


def _validate_watch_dir(directory: str) -> str:
    """auditd ``-F dir=`` needs an absolute POSIX path; catch shell/mistake variants."""
    value = str(directory).strip()
    if not value or not value.startswith("/") or "\\" in value or ":" in value:
        raise ValueError(
            f"watch dir must be an absolute POSIX path usable in auditd rules: "
            f"{directory!r} (note: Git-Bash/MSYS rewrites /home/... into C:/... — "
            f"quote it as //home/... or run the command on the target Linux host)")
    return value


def build_rules(watch_dirs: Sequence[str], *, uid_min: int = 1000,
                include_net: bool = True, include_kill: bool = False,
                read_dirs: Sequence[str] = ()) -> AuditRuleSet:
    rules: list[str] = [
        f"-a always,exit -F arch=b64 -F uid>={max(int(uid_min), 0)}"
        f" -S execve -S execveat -k {EXEC_KEY}",
    ]
    for directory in (_validate_watch_dir(item) for item in watch_dirs):
        rules.append(f"-a always,exit -F arch=b64 -F dir={directory}"
                     f" -F perm=wa -k {FILE_KEY}")
        rules.append(f"-a always,exit -F arch=b64 -F dir={directory}"
                     f" -S {','.join(FILE_SYSCALLS)} -k {FILE_KEY}")
    for directory in (_validate_watch_dir(item) for item in read_dirs):
        rules.append(f"-a always,exit -F arch=b64 -F dir={directory}"
                     f" -F perm=r -k {READ_KEY}")
    if include_net:
        rules.append(f"-a always,exit -F arch=b64 -F uid>={max(int(uid_min), 0)}"
                     f" -S connect -k {NET_KEY}")
    if include_kill:
        rules.append(f"-a always,exit -F arch=b64 -S kill,tkill,tgkill -k {KILL_KEY}")
    return AuditRuleSet(rules=tuple(rules))


def install_commands(rule_set: AuditRuleSet, *, persistent: bool = False) -> list[str]:
    commands = [f"sudo auditctl {rule}" for rule in rule_set.rules]
    if persistent:
        body = "\n".join(rule_set.rules)
        commands.append(f"sudo tee {PERSISTENT_PATH} > /dev/null <<'EOF'\n{body}\nEOF")
        commands.append("sudo augenrules --load")
    return commands


def uninstall_commands(rule_set: AuditRuleSet | None = None, *,
                       persistent: bool = False) -> list[str]:
    keys = ",".join(rule_set.keys if rule_set else ALL_KEYS)
    commands = [f"sudo auditctl -W {keys}", "sudo auditctl -l"]
    if persistent:
        commands.append(f"sudo rm -f {PERSISTENT_PATH}")
        commands.append("sudo augenrules --load")
    return commands