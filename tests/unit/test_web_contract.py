"""Web console contract on the canonical entity_id read model."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from agent_detector.storage.models import (AgentInstanceRow, ClaimEvidenceRow,
                                           ClaimRow, ComponentRelationRow,
                                           ComponentRow, CoveragePredicateStatusRow,
                                           CoverageScopeRow, EndpointRow,
                                           EntityAliasRow, EntityAttributeRow,
                                           EntityRow, EntitySnapshotRow,
                                           ObservationRow, RelationRow,
                                           RuleRevisionRow, SecurityAlertRow,
                                           utc_now_iso)


def _seed(services):
    now = datetime.now(timezone.utc)
    stamp = now.isoformat(timespec="seconds")
    with Session(services.engine) as session:
        session.add(EntityRow(entity_id="ent-1", entity_kind="PRODUCT_INSTALL",
                              scope_key="host"))
        session.add(EntityAttributeRow(
            entity_id="ent-1", agent_type="claude_code", name="Claude Code",
            vendor="Anthropic", version="2.0.0",
            version_source="package-metadata", origin="host", status="active",
            first_seen_at=stamp, last_seen_at=stamp, inventory_kind="agent"))
        session.add(EntitySnapshotRow(
            entity_id="ent-1", generation_id=1, agent_status="RUNNING",
            status_basis_json=json.dumps({
                "basis_version": 3, "installed": True, "configured": True,
                "running": True, "conflicts": ["running"], "claim_ids": {}}),
            hook_state="CONFIGURED", removal_verdict="NONE",
            presence="PRESENT", verification="VERIFIED", lifecycle="ACTIVE",
            last_known_status="CONFIGURED", reason_code="running_verified",
            coverage_summary_json=json.dumps({"scopes": 1, "PARTIAL": 1})))
        session.add(EntityRow(entity_id="ent-2", entity_kind="PRODUCT_INSTALL",
                              scope_key="host"))
        session.add(EntityAttributeRow(
            entity_id="ent-2", agent_type="n8n", name="n8n",
            version="1.0.0", version_source="unknown", origin="host",
            status="active", first_seen_at=stamp, last_seen_at=stamp,
            inventory_kind="agent"))
        session.add(EntitySnapshotRow(
            entity_id="ent-2", generation_id=1, agent_status="UNKNOWN",
            status_basis_json="{}", hook_state="UNKNOWN",
            removal_verdict="NONE", presence="PRESENT",
            verification="VERIFIED", lifecycle="ACTIVE",
            last_known_status="UNKNOWN", coverage_summary_json="{}"))
        session.add(EntityAliasRow(old_id="asset-1", entity_id="ent-1",
                                   status="OK"))
        session.add(AgentInstanceRow(
            instance_id="inst-1", asset_id="asset-1", entity_id="ent-1",
            agent_type="claude_code", pid=4242, process_name="claude",
            status="running", last_seen_at=stamp))

        session.add(ClaimRow(
            claim_id="clm-1", subject_ref="ent-1", predicate="running",
            object_ref="pid:4242", polarity="support", evidence_class="E3",
            verification_method="process_evidence", rule_id="claude_code",
            rule_digest="digest-1", collection_run_id=1,
            coverage_scope_id=7, observed_at=stamp, valid_from=stamp,
            valid_to=(now + timedelta(hours=1)).isoformat(timespec="seconds"),
            status="supported"))
        session.add(ObservationRow(
            observation_id="obs-1", source="discovery", source_event_uid="scan:1",
            scope_key="host", fact_type="running",
            normalized_payload_json=json.dumps({"name": "Claude Code",
                                                "version": "1.0.0"}),
            payload_digest="pd-1", observed_at=stamp, collection_run_id=1))
        session.add(ClaimEvidenceRow(claim_id="clm-1", observation_id="obs-1"))
        session.add(RuleRevisionRow(rule_id="claude_code", digest="digest-1",
                                    source_path="packaged"))

        session.add(ComponentRow(component_key="comp-1", name="LangChain",
                                 kind="FRAMEWORK", version="1.2.8"))
        session.add(ComponentRelationRow(
            entity_id="ent-1", component_key="comp-1", relation_type="DEPENDS_ON",
            version="1.2.8", version_source="package", status="confirmed",
            evidence_claim_id="clm-1", valid_from=stamp))
        session.add(EndpointRow(endpoint_id="ep-1", scope_key="host",
                                protocol="tcp", address="127.0.0.1", port=8080,
                                owner_entity_id="ent-1"))
        session.add(RelationRow(from_ref="ent-1", to_ref="ent-1",
                                relation_type="SELF", status="candidate",
                                valid_from=stamp))
        session.add(CoverageScopeRow(
            run_id=7, scope_type="container_deep_scan", scope_key="c1",
            source="docker", own_status="COMPLETE", budget=10,
            scanned_count=4, truncated=0, error_codes_json="[]",
            started_at=stamp, finished_at=stamp))
        session.add(CoveragePredicateStatusRow(
            scope_id=1, predicate="component_presence", own_status="COMPLETE"))
        session.add(SecurityAlertRow(
            risk_level="high", decision="deny", status="open",
            agent_label="Claude Code", entity_id="ent-1", event_id=1,
            title="检测到高风险工具调用", reason="deny-delete-protected-path",
            created_at=stamp))
        session.commit()


def test_overview_exposes_contract_counts(client, services):
    _seed(services)
    payload = client.get("/api/v1/overview").json()["agents"]
    assert payload["total"] == 2
    assert payload["running"] == 1
    assert payload["running_confirmed"] == 1
    assert payload["running_unconfirmed"] == 0
    assert payload["inventory_total"] == 2
    assert payload["current_detected"] == 2
    assert payload["confirmed_present"] == 2
    assert payload["needs_verification"] == 0
    assert payload["archived_total"] == 0
    assert payload["protection_summary"]["MONITOR_ONLY"] == 1
    assert payload["protection_summary"]["UNKNOWN"] == 1
    assert payload["hook_states"]["CONFIGURED"] == 1
    assert payload["by_entity_kind"]["PRODUCT_INSTALL"] == 2


def test_agent_filters_and_protection(client, services):
    _seed(services)
    items = client.get("/api/v1/agents?agent_status=RUNNING").json()["items"]
    assert [item["entity_id"] for item in items] == ["ent-1"]
    assert items[0]["protection"]["summary"] == "MONITOR_ONLY"
    assert items[0]["entity_kind"] == "PRODUCT_INSTALL"
    assert items[0]["component_count"] == 1
    assert client.get("/api/v1/agents?protection=PROTECTED").json()["total"] == 0


def test_agent_detail_includes_components_and_relations(client, services):
    _seed(services)
    detail = client.get("/api/v1/agents/ent-1").json()
    assert detail["claims_summary"]["available"] is True
    assert detail["claims_summary"]["claim_count"] == 1
    assert detail["coverage"]["available"] is False  # no scan id 7 yet
    assert any(item["label"] == "LangChain" for item in detail["relations"])
    assert detail["components"][0]["name"] == "LangChain"


def test_claims_endpoint_is_support_only_and_links_observations(client, services):
    _seed(services)
    payload = client.get(
        "/api/v1/agents/ent-1/claims?include_observations=true").json()
    assert payload["available"] is True
    assert payload["completeness"] == "support_only"
    claim = payload["items"][0]
    assert claim["predicate"] == "running"
    assert claim["observations"][0]["summary"].startswith("Claude Code")


def test_coverage_endpoint_returns_scope_status(client, services):
    _seed(services)
    with Session(services.engine) as session:
        from agent_detector.storage.models import ScanTaskRow
        session.add(ScanTaskRow(id=7, mode="discovery", status="completed",
                                started_at=utc_now_iso(),
                                finished_at=utc_now_iso(), stats_json="{}"))
        session.commit()
    payload = client.get("/api/v1/agents/ent-1/coverage").json()
    assert payload["available"] is True
    assert payload["summary"]["COMPLETE"] == 1
    assert payload["scopes"][0]["predicates"][0]["predicate"] == "component_presence"


def test_relations_endpoint_groups_components_and_endpoints(client, services):
    _seed(services)
    payload = client.get("/api/v1/agents/ent-1/relations").json()
    assert any(item["relation_type"] == "DEPENDS_ON" for item in payload["items"])
    assert payload["groups"]["endpoints"][0]["address"] == "127.0.0.1:8080"
    assert payload["groups"]["instances"][0]["pid"] == 4242


def test_asset_list_shows_candidates_and_hides_confirmed(client, services):
    """WATCH (unconfirmed absence) stays visible; only confirmed-absent hides."""
    _seed(services)
    stamp = utc_now_iso()
    with Session(services.engine) as session:
        for suffix, verdict, lifecycle, presence, check in (
                ("candidate", "CANDIDATE", "WATCH", "ABSENT", "NOT_CHECKED"),
                ("confirmed", "CONFIRMED", "ARCHIVED", "ABSENT", "VERIFIED")):
            entity_id = f"ent-{suffix}"
            session.add(EntityRow(entity_id=entity_id,
                                  entity_kind="PRODUCT_INSTALL", scope_key="host"))
            session.add(EntityAttributeRow(
                entity_id=entity_id, agent_type="openclaw", name="OpenClaw",
                status="inactive", inventory_kind="agent",
                first_seen_at=stamp, last_seen_at=stamp))
            session.add(EntitySnapshotRow(
                entity_id=entity_id, generation_id=1, agent_status="UNKNOWN",
                status_basis_json="{}", hook_state="UNKNOWN",
                removal_verdict=verdict, presence=presence,
                verification=check, lifecycle=lifecycle,
                coverage_summary_json="{}"))
        session.commit()
    visible = client.get("/api/v1/agents").json()
    assert {item["entity_id"] for item in visible["items"]} == {
        "ent-1", "ent-2", "ent-candidate"}
    assert visible["total"] == 3
    watch = next(item for item in visible["items"]
                 if item["entity_id"] == "ent-candidate")
    assert watch["lifecycle"] == "WATCH"
    everything = client.get("/api/v1/agents?include_removed=true").json()
    assert {"ent-candidate", "ent-confirmed"} <= {
        item["entity_id"] for item in everything["items"]}
    archived = next(item for item in everything["items"]
                    if item["entity_id"] == "ent-confirmed")
    assert archived["lifecycle"] == "ARCHIVED"


def test_events_after_id_detail_stats_and_timeseries(client, services):
    _seed(services)
    with Session(services.engine) as session:
        from agent_detector.storage.models import BehaviorEventRow
        for index in range(3):
            session.add(BehaviorEventRow(
                observed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                source="native_hook", agent_label="Claude Code",
                asset_id="asset-1", actor_asset_id="asset-1",
                actor_entity_id="ent-1",
                flow_id=f"f-{index}", upstream_host="",
                protocol="HOOK", event_type="tool_call", operation="shell.exec",
                endpoint="", confidence="high",
                decision="deny" if index == 0 else "allow",
                execution_status="blocked_by_hook" if index == 0 else "succeeded",
                risk_level="high", evidence_json="[]"))
        session.commit()
    first = client.get("/api/v1/events?limit=1").json()["items"][0]
    forward = client.get("/api/v1/events?after_id=1").json()
    assert forward["items"] and forward["items"][0]["id"] < forward["items"][-1]["id"]
    assert client.get(f"/api/v1/events/{first['id']}").json()["id"] == first["id"]
    stats = client.get("/api/v1/events/stats").json()
    assert stats["by_decision"]["deny"] == 1
    assert stats["by_execution_status"]["blocked_by_hook"] == 1
    series = client.get("/api/v1/events/timeseries?window=24h&bucket=hour").json()
    assert len(series["points"]) == 24
    assert sum(point["events"] for point in series["points"]) == 3
    assert sum(point["blocked"] for point in series["points"]) == 1


def test_sse_sends_ids_and_resumes_from_last_event_id(client, services):
    _seed(services)
    with Session(services.engine) as session:
        from agent_detector.storage.models import BehaviorEventRow
        for index in range(3):
            session.add(BehaviorEventRow(
                observed_at=utc_now_iso(), source="poll", agent_label="sse",
                flow_id=f"sse-{index}", upstream_host="", protocol="SYS",
                event_type="proc.exec", operation="COMMAND_EXEC", confidence="low",
                endpoint="", target=f"task_{index}.py", evidence_json="[]"))
        session.commit()
    latest = client.get("/api/v1/events?limit=1").json()["items"][0]["id"]
    with client.stream(
            "GET", "/api/v1/events/stream?max_events=2&timeout=2",
            headers={"Last-Event-ID": str(latest - 2)}) as stream:
        body = "".join(stream.iter_text())
    assert "retry: 2000" in body
    assert body.count("id: ") == 2
    assert "event: gap" not in body


def test_attention_ranks_alerts_and_claim_conflicts(client, services):
    _seed(services)
    payload = client.get("/api/v1/attention?limit=10").json()
    kinds = [item["kind"] for item in payload["items"]]
    assert "alert" in kinds
    assert "claim_conflict" in kinds
    assert payload["items"][0]["severity"] in ("high", "critical")


def test_alerts_detail_and_event_filter(client, services):
    _seed(services)
    payload = client.get("/api/v1/alerts?event_id=1").json()
    assert payload["items"][0]["title"] == "检测到高风险工具调用"
    assert payload["items"][0]["entity_id"] == "ent-1"
    alert_id = payload["items"][0]["id"]
    assert client.get(f"/api/v1/alerts/{alert_id}").json()["id"] == alert_id


def test_telemetry_health_contract(client, services):
    _seed(services)
    payload = client.get("/api/v1/telemetry/status").json()
    assert payload["health"]["state"] in ("OK", "DEGRADED", "NOT_RUNNING", "UNKNOWN")
    channels = {item["id"]: item for item in payload["channels"]}
    assert "native_hook" not in channels
    assert channels["poll"]["state"] in ("STOPPED", "STANDBY", "RUNNING")


def test_scan_status_is_idle_between_scans(client):
    assert client.get("/api/v1/discovery/scan/status").json() == {
        "running": False, "started_at": None, "mode": None}


def test_scan_status_survives_a_page_reload(client, services):
    """The browser reloads its own state away; the running flag must not go with it."""
    with services.scan_lock:
        services.scan_run.started_at = utc_now_iso()
        services.scan_run.mode = "agent"
        payload = client.get("/api/v1/discovery/scan/status").json()
    assert payload["running"] is True
    assert payload["mode"] == "agent"
    assert payload["started_at"]