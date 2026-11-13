"""Cheap, targeted re-confirmation for absence candidates.

A verdict is one of ``PRESENT`` / ``ABSENT`` / ``UNVERIFIED``. Only ``ABSENT``
may become ``CONFIRMED_ABSENT``; ``PRESENT`` cancels the candidate and
``UNVERIFIED`` keeps it for a later scan. None of these functions delete.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from collections.abc import Iterable

from agent_detector.coverage.model import CoverageStatus

PRESENT = "PRESENT"
ABSENT = "ABSENT"
UNVERIFIED = "UNVERIFIED"


@dataclass(frozen=True)
class ReconfirmResult:
    verdict: str
    reason: str
    checked: tuple[str, ...] = ()

    @property
    def absent(self) -> bool:
        return self.verdict == ABSENT


def reconfirm_paths(paths: Iterable[str]) -> ReconfirmResult:
    checked = tuple(dict.fromkeys(path for path in paths if path))
    if not checked:
        return ReconfirmResult(UNVERIFIED, "no path evidence recorded")
    for path in checked:
        try:
            if Path(path).exists():
                return ReconfirmResult(PRESENT, f"path still exists: {path}", checked)
        except OSError:
            return ReconfirmResult(UNVERIFIED, f"cannot stat: {path}", checked)
    return ReconfirmResult(ABSENT, "none of the recorded paths exists", checked)


def reconfirm_application(root_path: str | None) -> ReconfirmResult:
    if not root_path:
        return ReconfirmResult(UNVERIFIED, "application root not recorded")
    try:
        if Path(root_path).exists():
            return ReconfirmResult(PRESENT, f"project root exists: {root_path}",
                                   (root_path,))
    except OSError:
        return ReconfirmResult(UNVERIFIED, f"cannot stat: {root_path}", (root_path,))
    return ReconfirmResult(ABSENT, f"project root gone: {root_path}", (root_path,))


def reconfirm_container(container_id: str, *, engine_complete: bool,
                        containers_seen: Iterable[str],
                        candidates_seen: Iterable[str],
                        deep_scan_status: CoverageStatus | str | None
                        ) -> ReconfirmResult:
    """Container existence/deep-scan verdict from the Docker channel result."""
    if not container_id:
        return ReconfirmResult(UNVERIFIED, "container id not recorded")
    if not engine_complete:
        return ReconfirmResult(UNVERIFIED,
                               "docker enumeration incomplete this scan")
    if container_id not in set(containers_seen):
        return ReconfirmResult(ABSENT, "container absent from complete enumeration",
                               (container_id,))
    if container_id not in set(candidates_seen):
        return ReconfirmResult(
            UNVERIFIED, "container present but not deep-scanned this scan",
            (container_id,))
    status = (deep_scan_status.value
              if isinstance(deep_scan_status, CoverageStatus)
              else str(deep_scan_status or ""))
    if status == CoverageStatus.COMPLETE.value:
        return ReconfirmResult(
            ABSENT, "container deep scan completed without this asset",
            (container_id,))
    return ReconfirmResult(UNVERIFIED,
                           f"container deep scan not conclusive: {status or 'unknown'}",
                           (container_id,))