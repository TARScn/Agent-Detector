"""Behavior/telemetry event feed + SSE stream (design sections 7, 8).

One endpoint serves every channel: hook events, Sysmon, auditd, polling and LLM
connection observations all land in ``behavior_events`` and are read through the
same filters.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query
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
                decision: str | None = None, execution_status: str | None = None,
                since: str | None = None, until: str | None = None,
                entity_id: str | None = None,
                before_id: int | None = Query(default=None, ge=1),
                after_id: int | None = Query(default=None, ge=1),
                offset: int = Query(default=0, ge=0),
                services: Services = Depends(_services)):
    """``before_id`` pages backwards; ``after_id`` pages forward for SSE catch-up;
    ``offset`` pages by position for the console table (mutually exclusive with
    the cursors)."""
    if offset and (before_id is not None or after_id is not None):
        raise HTTPException(status_code=422,
                            detail="offset 不能与 before_id/after_id 同时使用")
    if before_id is not None and after_id is not None:
        raise HTTPException(status_code=422,
                            detail="before_id 与 after_id 不能同时使用")
    with Session(services.engine) as session:
        repo = BehaviorEventRepository(session)
        items = repo.list_events(
            limit=limit, source=source, agent_label=agent_label, asset_id=asset_id,
            event_type=event_type, session_id=session_id, risk_level=risk_level,
            decision=decision, execution_status=execution_status, since=since,
            until=until, before_id=before_id, after_id=after_id,
            entity_id=entity_id, offset=offset)
        total_matches = (repo.count_events(
            source=source, agent_label=agent_label, asset_id=asset_id,
            event_type=event_type, session_id=session_id, risk_level=risk_level,
            decision=decision, execution_status=execution_status, since=since,
            until=until, entity_id=entity_id)
            if not (before_id or after_id) else None)
    next_before = (items[-1]["id"]
                   if (after_id is None and len(items) == limit) else None)
    next_after = (items[-1]["id"]
                  if (after_id is not None and len(items) == limit) else None)
    return {"items": items, "total": len(items),
            "total_matches": total_matches, "offset": offset,
            "next_before_id": next_before, "next_after_id": next_after}


@router.get("/events/stats")
def event_stats(source: str | None = None, since: str | None = None,
                services: Services = Depends(_services)):
    with Session(services.engine) as session:
        return BehaviorEventRepository(session).stats(source=source, since=since)


@router.get("/events/timeseries")
def event_timeseries(window: str = Query(default="24h", pattern="^(1h|6h|24h|7d)$"),
                     bucket: str = Query(default="hour", pattern="^(hour|day)$"),
                     source: str | None = None, risk_level: str | None = None,
                     entity_id: str | None = None,
                     since: str | None = None, until: str | None = None,
                     services: Services = Depends(_services)):
    delta = {"1h": timedelta(hours=1), "6h": timedelta(hours=6),
             "24h": timedelta(hours=24), "7d": timedelta(days=7)}[window]
    end = _parse_iso(until) if until else datetime.now(timezone.utc)
    step = timedelta(hours=1) if bucket == "hour" else timedelta(days=1)
    # Include the bucket containing "now" (or the explicit until) so a 24h
    # window always renders 24 hourly points, not 25.
    end_bucket = _floor(end, bucket) + step
    start = (_floor(_parse_iso(since), bucket)
             if since else end_bucket - delta)
    if start >= end_bucket:
        raise HTTPException(status_code=422, detail="since 必须早于 until")
    points = []
    cursor = start
    with Session(services.engine) as session:
        counts = BehaviorEventRepository(session).timeseries_counts(
            since=start.isoformat(timespec="seconds"),
            until=end_bucket.isoformat(timespec="seconds"), bucket=bucket,
            source=source, risk_level=risk_level, entity_id=entity_id)
    while cursor < end_bucket:
        nxt = cursor + step
        key = (cursor.strftime("%Y-%m-%dT%H")
               if bucket == "hour" else cursor.strftime("%Y-%m-%d"))
        item = counts.get(key, {"events": 0, "blocked": 0})
        points.append({"start": cursor.isoformat(timespec="seconds"),
                       "end": nxt.isoformat(timespec="seconds"),
                       "events": item["events"], "blocked": item["blocked"]})
        cursor = nxt
        if len(points) > 168:
            raise HTTPException(status_code=422, detail="时间范围超过 168 个桶")
    return {"bucket": bucket, "timezone": "UTC", "points": points}


def _parse_iso(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"时间格式无效：{value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _floor(value: datetime, bucket: str) -> datetime:
    if bucket == "hour":
        return value.replace(minute=0, second=0, microsecond=0)
    return value.replace(hour=0, minute=0, second=0, microsecond=0)


@router.get("/events/stream")
def event_stream(source: str | None = None, initial: int = Query(default=0, ge=0, le=200),
                 max_events: int = Query(default=0, ge=0),
                 timeout: float = Query(default=0, ge=0, le=600),
                 last_event_id: str | None = Header(default=None,
                                                   alias="Last-Event-ID"),
                 services: Services = Depends(_services)):
    """Server-sent events for the live feed.

    ``Last-Event-ID`` wins over ``initial``: the browser sends it on reconnect
    and the server replays only the missing range. A backlog larger than
    ``max_replay`` becomes an explicit ``gap`` event instead of silent loss.
    """
    resume_from = _parse_cursor(last_event_id)
    last_id = resume_from if resume_from is not None else _latest_event_id(
        services, source)
    started = time.monotonic()

    def frames():
        nonlocal last_id
        sent = 0
        idle = 0
        yield "retry: 2000\n\n"
        if resume_from is not None:
            backlog = _count_after(services, last_id, source)
            if backlog > 1000:
                latest = _latest_event_id(services, source)
                payload = json.dumps({"from_id": last_id + 1, "to_id": latest,
                                      "count": backlog}, ensure_ascii=False)
                yield f"event: gap\ndata: {payload}\n\n"
                last_id = latest
        elif initial:
            backlog = _initial_events(services, initial, source)
            for item in backlog:
                sent += 1
                yield (f"id: {item['id']}\nevent: event\n"
                       f"data: {json.dumps(item, ensure_ascii=False)}\n\n")
        while True:
            items, last_id = _events_since(services, last_id, source)
            for item in items:
                sent += 1
                yield (f"id: {item['id']}\nevent: event\n"
                       f"data: {json.dumps(item, ensure_ascii=False)}\n\n")
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


@router.get("/events/{event_id}")
def event_detail(event_id: int, services: Services = Depends(_services)):
    with Session(services.engine) as session:
        item = BehaviorEventRepository(session).get_event(event_id)
    if item is None:
        raise HTTPException(status_code=404, detail="未找到该事件")
    return item


def _parse_cursor(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return max(0, int(value))
    except ValueError:
        return None


def _initial_events(services: Services, count: int, source: str | None) -> list[dict]:
    with Session(services.engine) as session:
        newest = BehaviorEventRepository(session).list_events(limit=count, source=source)
    return sorted(newest, key=lambda item: item["id"])


def _latest_event_id(services: Services, source: str | None = None) -> int:
    with Session(services.engine) as session:
        events = BehaviorEventRepository(session).list_events(limit=1, source=source)
    return events[0]["id"] if events else 0


def _count_after(services: Services, last_id: int, source: str | None) -> int:
    with Session(services.engine) as session:
        return BehaviorEventRepository(session).count_after(last_id, source=source)


def _events_since(services: Services, last_id: int,
                  source: str | None) -> tuple[list[dict], int]:
    with Session(services.engine) as session:
        events = BehaviorEventRepository(session).list_events(
            limit=500, source=source, after_id=last_id)
    if not events:
        return [], last_id
    return events, max(item["id"] for item in events)