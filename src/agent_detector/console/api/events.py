"""Behavior/telemetry event feed + SSE stream (design sections 7, 8).

One endpoint serves every channel: hook events, Sysmon, auditd, polling and LLM
connection observations all land in ``behavior_events`` and are read through the
same filters.
"""
from __future__ import annotations

import json
import time

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from agent_detector.console.api.deps import Services, get_services
from agent_detector.storage import BehaviorEventRepository

router = APIRouter(prefix="/api/v1", tags=["events"])

_STREAM_POLL_SECONDS = 2.0


def _services() -> Services:
    return get_services()


@router.get("/events")
def list_events(limit: int = Query(default=100, ge=1, le=500),
                source: str | None = None, agent_label: str | None = None,
                asset_id: str | None = None, event_type: str | None = None,
                session_id: str | None = None, risk_level: str | None = None,
                decision: str | None = None, since: str | None = None,
                before_id: int | None = Query(default=None, ge=1),
                services: Services = Depends(_services)):
    """``before_id`` pages backwards: pass the oldest id you already hold."""
    with Session(services.engine) as session:
        items = BehaviorEventRepository(session).list_events(
            limit=limit, source=source, agent_label=agent_label, asset_id=asset_id,
            event_type=event_type, session_id=session_id, risk_level=risk_level,
            decision=decision, since=since, before_id=before_id)
    return {"items": items, "total": len(items),
            "next_before_id": items[-1]["id"] if len(items) == limit else None}


@router.get("/events/stats")
def event_stats(source: str | None = None, services: Services = Depends(_services)):
    with Session(services.engine) as session:
        return BehaviorEventRepository(session).stats(source=source)


@router.get("/events/stream")
def event_stream(source: str | None = None, initial: int = Query(default=0, ge=0, le=200),
                 max_events: int = Query(default=0, ge=0),
                 timeout: float = Query(default=0, ge=0, le=600),
                 services: Services = Depends(_services)):
    """Server-sent events for the live feed.

    ``initial`` sends the newest N events first so a freshly opened console is
    not blank until something happens; ``max_events`` / ``timeout`` bound the
    stream for scripts and tests (the console leaves both at 0 and reconnects).
    """
    last_id = _latest_event_id(services)
    started = time.monotonic()

    def frames():
        nonlocal last_id
        sent = 0
        idle = 0
        if initial:
            backlog = _initial_events(services, initial, source)
            for item in backlog:
                sent += 1
                yield f"event: event\ndata: {json.dumps(item, ensure_ascii=False)}\n\n"
        while True:
            items, last_id = _events_since(services, last_id, source)
            for item in items:
                sent += 1
                yield f"event: event\ndata: {json.dumps(item, ensure_ascii=False)}\n\n"
            if not items:
                idle += 1
                yield ": keep-alive\n\n"
            if max_events and sent >= max_events:
                break
            if timeout and time.monotonic() - started >= timeout:
                break
            if idle > 3600:  # ~2h without a single event
                break
            time.sleep(_STREAM_POLL_SECONDS)

    return StreamingResponse(frames(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


def _initial_events(services: Services, count: int, source: str | None) -> list[dict]:
    with Session(services.engine) as session:
        newest = BehaviorEventRepository(session).list_events(limit=count, source=source)
    return sorted(newest, key=lambda item: item["id"])


def _latest_event_id(services: Services) -> int:
    with Session(services.engine) as session:
        events = BehaviorEventRepository(session).list_events(limit=1, source=None)
    return events[0]["id"] if events else 0


def _events_since(services: Services, last_id: int,
                  source: str | None) -> tuple[list[dict], int]:
    with Session(services.engine) as session:
        events = BehaviorEventRepository(session).list_events(
            limit=50, source=source, since=None)
    fresh = [item for item in events if item["id"] > last_id]
    if not fresh:
        return [], last_id
    return sorted(fresh, key=lambda item: item["id"]), max(
        item["id"] for item in fresh)