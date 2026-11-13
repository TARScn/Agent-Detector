"""Build the per-scan coverage DAG from stage results.

The builders are deliberately pure: the scan coordinator passes the stats it
already has, and tests can construct the same graph without a live host.
"""
from __future__ import annotations

from collections.abc import Iterable

from agent_detector.coverage.model import (CoverageGraph, CoverageScope,
                                           CoverageStatus)

_COMPLETE = CoverageStatus.COMPLETE


def _normalized_failed(names: Iterable[str]) -> set[str]:
    failed: set[str] = set()
    for name in names:
        failed.add(name)
        failed.add(name.replace("-", "_"))
    return failed


def build_scan_coverage(*, processes_count: int, process_source: str,
                        detector_names: Iterable[str],
                        failed_detectors: Iterable[str],
                        project_stats: dict,
                        docker_stats: dict,
                        docker_ctx: dict,
                        docker_enabled: bool,
                        max_projects: int,
                        max_containers: int,
                        docker_scope_key: str = "local") -> CoverageGraph:
    """Assemble host, product-rule, project, Docker and container scopes."""
    graph = CoverageGraph()
    failed = _normalized_failed(failed_detectors)

    graph.add(CoverageScope(
        scope_type="host_process_enumeration", scope_key="host",
        source=process_source or "psutil", own_status=_COMPLETE,
        scanned_count=processes_count,
        predicates=(("process_inventory", _COMPLETE),)))

    for name in detector_names:
        status = (CoverageStatus.FAILED
                  if name in failed or name.replace("-", "_") in failed
                  else _COMPLETE)
        graph.add(CoverageScope(
            scope_type="product_rule", scope_key=name,
            source="fingerprints", own_status=status,
            predicates=(("product_presence", status),)))

    project_error = bool(project_stats.get("error"))
    project_truncated = bool(project_stats.get("truncated"))
    if max_projects <= 0:
        project_status = CoverageStatus.DISABLED
    elif project_error:
        project_status = CoverageStatus.FAILED
    elif project_truncated:
        project_status = CoverageStatus.PARTIAL
    else:
        project_status = _COMPLETE
    graph.add(CoverageScope(
        scope_type="project_candidate_universe", scope_key="scan",
        source="frameworks", own_status=project_status,
        budget=max_projects,
        scanned_count=int(project_stats.get("candidate_processes") or 0),
        truncated=project_truncated,
        predicates=(("application_presence", project_status),)))

    docker_total = int(docker_stats.get("containers_total") or 0)
    docker_error = bool(docker_stats.get("error")) or bool(docker_ctx.get("failed"))
    docker_truncated = max_containers > 0 and docker_total >= max_containers
    if not docker_enabled or max_containers <= 0:
        docker_status = CoverageStatus.DISABLED
    elif docker_error:
        docker_status = CoverageStatus.FAILED
    elif docker_truncated:
        docker_status = CoverageStatus.PARTIAL
    else:
        docker_status = _COMPLETE
    graph.add(CoverageScope(
        scope_type="docker_engine_enumeration", scope_key=docker_scope_key,
        source="docker", own_status=docker_status,
        budget=max_containers, scanned_count=docker_total,
        truncated=docker_truncated,
        predicates=(("container_presence", docker_status),)))

    containers_seen = list(docker_ctx.get("containers_seen") or ())
    candidates_seen = set(docker_ctx.get("candidates_seen") or ())
    container_errors = {
        str(error.get("container"))
        for error in (docker_stats.get("container_errors") or ())
    }
    for container_id in containers_seen:
        if container_id in candidates_seen:
            status = (CoverageStatus.FAILED
                      if container_id[:12] in container_errors
                      else _COMPLETE)
        else:
            status = CoverageStatus.NOT_RUN  # screened out: nothing to scan
        graph.add(CoverageScope(
            scope_type="container_deep_scan", scope_key=container_id,
            source="docker", own_status=status,
            scanned_count=1 if container_id in candidates_seen else 0,
            predicates=(("component_presence", status),),
            parents=(("docker_engine_enumeration", docker_scope_key),)))

    projects: dict[str, int] = {}
    for link in (docker_ctx.get("links") or {}).values():
        project = (link or {}).get("compose_project")
        if project:
            projects[project] = projects.get(project, 0) + 1
    for project, members in projects.items():
        graph.add(CoverageScope(
            scope_type="compose_membership", scope_key=project,
            source="docker", own_status=_COMPLETE,
            scanned_count=members,
            predicates=(("compose_membership", _COMPLETE),),
            parents=(("docker_engine_enumeration", docker_scope_key),)))

    return graph