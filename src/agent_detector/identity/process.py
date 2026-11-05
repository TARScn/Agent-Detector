"""Process birth identity across Linux, Windows and event collectors.

A PID is never an identity. The canonical Linux key is
``(scope, boot_id, pidns_inode, pid, /proc starttime ticks)``. Windows uses
Sysmon's ProcessGuid when available, otherwise the native CreateTime plus the
boot epoch. Other sources (Tetragon, auditd) keep their original clock domain:
cross-domain comparison is only allowed after an explicit matching rule, so
``match_process_birth`` returns ``None`` (candidate) when the domains differ.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

import psutil

from agent_detector.core.models import ProcessInfo
from agent_detector.identity.canonical import canonical_json, digest

# Jiffies are 1/CLK_TCK; the kernel's time slice is normally 100 Hz, but the
# key stores raw ticks, so the value is stable even if HZ differs between hosts.
_START_TICKS_FIELD = 19  # field 22 overall, after the "(comm)" suffix


@dataclass(frozen=True)
class ProcessBirth:
    platform: str
    scope_key: str
    boot_identity: str
    pid_namespace_key: str
    pid: int
    native_birth_value: str
    clock_domain: str
    resolution: str
    canonical_start_ticks: int | None
    source: str
    verification_state: str
    process_guid: str | None = None

    @property
    def instance_key(self) -> str:
        payload = {
            "v": 1,
            "platform": self.platform,
            "scope": self.scope_key,
            "boot": self.boot_identity,
            "pidns": self.pid_namespace_key,
            "pid": self.pid,
            "birth": self.native_birth_value,
            "clock": self.clock_domain,
            "process_guid": self.process_guid or "",
        }
        return "inst-" + digest(canonical_json(payload), length=24)


def read_linux_birth(pid: int, scope_key: str, *,
                     source: str = "proc") -> ProcessBirth | None:
    """Read the canonical Linux birth facts; ``None`` when /proc is unreadable."""
    try:
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="utf-8").strip()
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        rparen = stat.rfind(")")
        if rparen < 0:
            return None
        fields = stat[rparen + 1:].split()
        start_ticks = int(fields[_START_TICKS_FIELD])
        try:
            pid_namespace = os.readlink(f"/proc/{pid}/ns/pid")
            pid_namespace_key = pid_namespace or "host"
        except OSError:
            pid_namespace_key = "host"
    except (OSError, ValueError, IndexError):
        return None
    return ProcessBirth(
        platform="linux",
        scope_key=scope_key,
        boot_identity=boot_id or f"boot:{int(psutil.boot_time())}",
        pid_namespace_key=pid_namespace_key,
        pid=pid,
        native_birth_value=str(start_ticks),
        clock_domain="boot_ticks",
        resolution="proc_starttime_ticks",
        canonical_start_ticks=start_ticks,
        source=source,
        verification_state="verified",
    )


def build_process_birth(pid: int, scope_key: str, *,
                        process_info: ProcessInfo | None = None,
                        platform: str | None = None,
                        source: str = "psutil",
                        process_guid: str | None = None) -> ProcessBirth | None:
    """Build the best available birth identity for ``pid``.

    Linux prefers /proc. Windows (and any platform where /proc is absent) uses
    the native psutil CreateTime with the boot epoch; a Sysmon ProcessGuid is
    preferred when the collector provides one.
    """
    platform = platform or sys.platform
    if platform.startswith("linux"):
        # Canonical facts come from /proc even when the trigger was psutil;
        # label the source by the fact origin, not the caller.
        birth = read_linux_birth(pid, scope_key, source="proc")
        if birth is not None:
            return birth

    create_time = process_info.create_time if process_info is not None else None
    if create_time is None:
        try:
            create_time = psutil.Process(pid).create_time()
        except (psutil.Error, OSError):
            return None
    try:
        boot_epoch = int(psutil.boot_time())
    except (psutil.Error, OSError):
        boot_epoch = 0

    windows = platform.startswith("win")
    if process_guid and windows:
        resolution = "sysmon_process_guid"
        verification = "verified"
    elif windows:
        resolution = "psutil_create_time"
        verification = "verified"
    else:
        resolution = "psutil_create_time"
        verification = "candidate"

    return ProcessBirth(
        platform=platform,
        scope_key=scope_key,
        boot_identity=f"boot:{boot_epoch}",
        pid_namespace_key="host",
        pid=pid,
        native_birth_value=f"{create_time:.6f}",
        clock_domain="epoch_seconds",
        resolution=resolution,
        canonical_start_ticks=None,
        source=source,
        verification_state=verification,
        process_guid=process_guid,
    )


def match_process_birth(left: ProcessBirth | None,
                        right: ProcessBirth | None,
                        *, tolerance_ticks: int = 1) -> bool | None:
    """Compare two birth facts under the P0-A matching rule.

    ``True`` / ``False`` mean a verified match / mismatch. ``None`` means the
    facts are not comparable (different clock domains or missing canonical
    fields), so callers must keep them as candidates rather than merging.
    """
    if left is None or right is None:
        return None
    if left.process_guid and right.process_guid:
        return left.process_guid.lower() == right.process_guid.lower()
    if left.platform != right.platform:
        return None
    if left.scope_key != right.scope_key:
        return None
    if left.pid != right.pid:
        return False
    if left.boot_identity and right.boot_identity \
            and left.boot_identity != right.boot_identity:
        return False
    if left.pid_namespace_key and right.pid_namespace_key \
            and left.pid_namespace_key != right.pid_namespace_key:
        return False
    if left.canonical_start_ticks is not None \
            and right.canonical_start_ticks is not None:
        return abs(left.canonical_start_ticks
                   - right.canonical_start_ticks) <= tolerance_ticks
    if (left.clock_domain == right.clock_domain
            and left.source == right.source):
        try:
            return abs(float(left.native_birth_value)
                       - float(right.native_birth_value)) <= 2.0
        except ValueError:
            return None
    return None