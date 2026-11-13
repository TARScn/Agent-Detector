"""P2: ingest a controlled runtime/protocol trace as E5 evidence.

The trace is explicit and opt-in. Runtime records prove a framework invocation
was observed by an authorized source; protocol records prove an MCP/A2A
message/tool call was observed. Neither proves autonomous intent or complete
coverage beyond the traced path.
"""
from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import select

from agent_detector.aggregation.evidence_ledger import (EvidenceLedger,
                                                        static_claim_valid_to)
from agent_detector.core.models import DetectedAsset
from agent_detector.identity import build_process_birth
from agent_detector.identity.canonical import canonical_json, digest
from agent_detector.monitoring.collectors.trace.controlled import read_trace
from agent_detector.storage import AgentInventoryRepository
from agent_detector.storage.identity_repository import IdentityRepository
from agent_detector.storage.models import BehaviorEventRow, EntityAttributeRow
from agent_detector.storage.models import BehaviorEventRow, utc_now_iso


def write_controlled_trace(session, *, scan_id: int,
                           assets: list[DetectedAsset], host_key: str,
                           path: str | None, max_records: int = 2000) -> dict:
    events = read_trace(path, max_records=max_records)
    result = {"enabled": bool(path), "events": len(events),
              "runtime": 0, "protocol": 0, "claims": 0, "unattributed": 0,
              "error": None}
    if not events:
        return result

    actor_by_pid: dict[int, DetectedAsset] = {}
    for asset in assets:
        for pid in asset.running_pids:
            actor_by_pid.setdefault(int(pid), asset)
    identities = IdentityRepository(session)
    inventory = AgentInventoryRepository(session)
    ledger = EvidenceLedger(session)
    now = utc_now_iso()
    valid_to = static_claim_valid_to()
    rows: list[BehaviorEventRow] = []

    for index, event in enumerate(events):
        observed_at = _timestamp(event.observed_at, now)
        actor_asset = (actor_by_pid.get(event.pid)
                       if event.pid is not None else None)
        actor_asset_id = actor_asset.asset_id if actor_asset else None
        actor_entity = (identities.resolve_alias(actor_asset_id)
                        if actor_asset_id else None)
        attr = (session.get(EntityAttributeRow, actor_entity)
                if actor_entity else None)
        agent_type = ((attr.agent_type if attr else None)
                      or (actor_asset.name if actor_asset else "unknown"))
        label = ((attr.name if attr else None)
                 or (actor_asset.name if actor_asset else None)
                 or (f"pid-{event.pid}" if event.pid else "trace"))
        source = ("runtime_trace" if event.kind == "runtime"
                  else "protocol_trace")
        protocol = ("RUNTIME" if event.kind == "runtime"
                    else (event.protocol or "protocol").upper())
        event_type = ("framework.execution" if event.kind == "runtime"
                      else ("mcp.tool_call" if event.protocol == "mcp"
                            else "a2a.message"))
        operation = ("framework.call" if event.kind == "runtime"
                     else ("mcp.call" if event.protocol == "mcp"
                           else "a2a.message"))
        target = (event.framework if event.kind == "runtime"
                  else (event.server or event.method or ""))
        tool = event.framework if event.kind == "runtime" else event.tool
        source_uid = digest(canonical_json({
            "path": str(path or ""), "index": index,
            "kind": event.kind, "ts": event.observed_at,
            "pid": event.pid, "framework": event.framework,
            "protocol": event.protocol, "server": event.server,
            "tool": event.tool, "method": event.method,
            "session": event.session_id,
        }), length=24)
        existing = session.scalar(
            select(BehaviorEventRow.id).where(
                BehaviorEventRow.source == source,
                BehaviorEventRow.source_event_uid == source_uid))
        if existing is not None:
            continue  # trace line already ingested by an earlier scan

        process_key = None
        if event.pid:
            birth = build_process_birth(event.pid, host_key or "unknown")
            process_key = birth.instance_key if birth is not None else None
        row = BehaviorEventRow(
            observed_at=observed_at,
            source=source,
            agent_label=label,
            asset_id=actor_entity,
            actor_asset_id=actor_entity,
            actor_entity_id=actor_entity,
            actor_process_key=process_key,
            scope_key=host_key or None,
            attribution_method=source,
            attribution_state=("verified" if actor_entity else "unattributed"),
            source_event_uid=source_uid,
            flow_id=f"{source}-{source_uid}"[:64],
            upstream_host=target or "",
            protocol=protocol[:16],
            event_type=event_type,
            operation=operation,
            confidence="high",
            endpoint="",
            tool=tool,
            target=target or None,
            mcp_server=(event.server if event.protocol == "mcp" else None),
            session_id=event.session_id,
            pid=event.pid,
            evidence_json=json.dumps(
                [source, "E5", f"kind:{event.kind}",
                 f"direction:{event.direction or 'observed'}"],
                ensure_ascii=False),
        )
        rows.append(row)
        if event.kind == "runtime":
            result["runtime"] += 1
        else:
            result["protocol"] += 1

        if not actor_entity:
            result["unattributed"] += 1
            continue
        predicate = ("framework_execution" if event.kind == "runtime"
                     else "protocol_tool_call")
        object_ref = (event.framework if event.kind == "runtime"
                      else ":".join(filter(None, [event.protocol, event.server,
                                                  event.tool or event.method])))
        observation_id = ledger.record_observation(
            source=source, source_event_uid=source_uid,
            scope_key=host_key or "unknown", fact_type=predicate,
            payload={"pid": event.pid, "session_id": event.session_id,
                     "framework": event.framework, "protocol": event.protocol,
                     "server": event.server, "tool": event.tool,
                     "method": event.method},
            observed_at=observed_at, collection_run_id=scan_id)
        ledger.add_claim(
            subject_ref=actor_entity, predicate=predicate,
            object_ref=object_ref or protocol, evidence_class="E5",
            verification_method=source, rule_id=source,
            rule_generation=scan_id, collection_run_id=scan_id,
            observed_at=observed_at, valid_to=valid_to,
            observation_id=observation_id)
        ledger.add_claim(
            subject_ref=actor_entity, predicate="agent_capability",
            object_ref="AGENT_EXECUTION_OBSERVED", evidence_class="E5",
            verification_method=source, rule_id=source,
            rule_generation=scan_id, collection_run_id=scan_id,
            observed_at=observed_at, valid_to=valid_to,
            observation_id=observation_id)
        result["claims"] += 2
        if event.session_id:
            inventory.touch_session(
                event.session_id, agent_type, asset_id=actor_asset_id,
                tool=tool, source=source)

    session.add_all(rows)
    session.flush()
    return result


def _timestamp(value: str, fallback: str) -> str:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value
    except (TypeError, ValueError):
        return fallback