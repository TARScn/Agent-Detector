"""P0-B coverage: scoped completeness and absence eligibility.

Coverage is per scope and per predicate. A parent's PARTIAL/FAILED status
propagates to children for absence decisions, while positive evidence may
still refresh an asset. No absence verdict is derived without a COMPLETE
authoritative scope.
"""

from agent_detector.coverage.build import build_scan_coverage
from agent_detector.coverage.model import (CoverageGraph, CoverageScope,
                                           CoverageStatus)
from agent_detector.coverage.reconfirm import (ABSENT, PRESENT, UNVERIFIED,
                                               ReconfirmResult,
                                               reconfirm_application,
                                               reconfirm_container,
                                               reconfirm_paths)

__all__ = [
    "ABSENT",
    "PRESENT",
    "UNVERIFIED",
    "CoverageGraph",
    "CoverageScope",
    "CoverageStatus",
    "ReconfirmResult",
    "build_scan_coverage",
    "reconfirm_application",
    "reconfirm_container",
    "reconfirm_paths",
]