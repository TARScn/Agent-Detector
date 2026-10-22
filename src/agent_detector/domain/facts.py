"""Normalized behavior facts (design section 4.2).

A fact is the lowest-level statement the product makes about the machine:
*this process did this*, with the identity fields needed for correlation. Every
collector (Linux auditd, Windows Sysmon, unprivileged polling) produces facts,
and everything above — attribution, behavior rules, risk grading, persistence —
consumes only facts. That is what keeps two very different operating systems on
one pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass

FACT_KINDS = ("proc.exec", "file.write", "file.move", "file.delete", "file.attr",
              "file.read", "net.connect", "proc.kill")


@dataclass(frozen=True)
class BehaviorFact:
    """One normalized observation; ``argv`` never leaves this layer unredacted."""

    kind: str
    ts: float
    serial: str
    pid: int
    ppid: int | None
    process_name: str
    exe: str | None = None
    argv: tuple[str, ...] = ()
    path: str | None = None
    path_target: str | None = None
    result: str = "success"
    endpoint: str | None = None
    target_pid: int | None = None
    syscall: str | None = None
    keys: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()