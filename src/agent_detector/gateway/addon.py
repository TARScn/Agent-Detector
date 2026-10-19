"""Mitmproxy addon: observe matching HTTP flows without storing original bodies.

Started by GatewayManager as:
  mitmdump --mode regular --listen-host 127.0.0.1 --listen-port <port> -s <this file>
Configuration arrives through AGD_* environment variables (gateway.config).
The package must be installed (pip install -e .) so the imports below resolve
inside the mitmdump process.

The addons list is only populated when AGD_DB_PATH is set, so an accidental
import of this module (e.g. from tests or tooling) has no side effects.
"""
from __future__ import annotations

import logging
import os
from dataclasses import replace
from datetime import datetime, timezone
from queue import Empty, Full, Queue
from threading import Event, Thread

from agent_detector.gateway.classifier import classify_agent_card, classify_request
from agent_detector.gateway.config import Settings
from agent_detector.gateway.store import BehaviorEventStore

logger = logging.getLogger("agent_gateway")


class Writer:
    """Bounded queue -> background thread -> batched inserts; drop with a warning on overflow."""

    def __init__(self, store: BehaviorEventStore, maxsize: int = 2000, batch: int = 64):
        self.store = store
        self.batch = batch
        self.q: Queue = Queue(maxsize=maxsize)
        self.stop = Event()
        self.dropped = 0
        self.worker = Thread(target=self._run, name="agent-gateway-writer", daemon=True)
        self.worker.start()

    def enqueue(self, item: dict) -> None:
        try:
            self.q.put_nowait(item)
        except Full:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 100 == 0:
                logger.warning("Gateway event queue full: dropped=%d", self.dropped)

    def _run(self) -> None:
        while not self.stop.is_set() or not self.q.empty():
            batch = []
            try:
                batch.append(self.q.get(timeout=0.3))
            except Empty:
                continue
            while len(batch) < self.batch:
                try:
                    batch.append(self.q.get_nowait())
                except Empty:
                    break
            try:
                self.store.insert_many(batch)
            except Exception:
                logger.exception("Failed to persist gateway events (batch=%d)", len(batch))
            finally:
                for _ in batch:
                    self.q.task_done()

    def close(self) -> None:
        self.stop.set()
        self.worker.join(timeout=8)


class GatewayObserver:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.writer = Writer(BehaviorEventStore(settings.db_path))

    def _event(self, flow, detection, status=None) -> None:
        data = detection.as_record()
        data.update({
            "observed_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "source": "gateway",
            "flow_id": str(flow.id),
            "agent_label": self.settings.agent_id,
            "upstream_host": flow.request.host.lower()[:255],
            "http_status": status,
        })
        self.writer.enqueue(data)

    def request(self, flow) -> None:
        req = flow.request
        if not self.settings.is_observed(req.host):
            return
        # get_content(strict=False) returns decompressed bytes when supported; never log it.
        body = None
        if req.headers.get("content-length") and req.headers.get("content-length").isdigit():
            if int(req.headers.get("content-length")) <= self.settings.parse_max_bytes:
                body = req.get_content(strict=False)
        elif req.raw_content is not None and len(req.raw_content) <= self.settings.parse_max_bytes:
            body = req.get_content(strict=False)
        if body is not None and len(body) > self.settings.parse_max_bytes:
            body = None
        detection = classify_request(req.method, req.url, req.headers, body,
                                     self.settings.parse_max_bytes)
        if detection:
            flow.metadata["agd_detection"] = detection
            self._event(flow, detection)

    def responseheaders(self, flow) -> None:
        # Never hold an SSE response open waiting for completion.
        if "text/event-stream" in flow.response.headers.get("content-type", "").lower():
            flow.response.stream = True

    def response(self, flow) -> None:
        if not self.settings.is_observed(flow.request.host):
            return
        detection = flow.metadata.get("agd_detection")
        if detection:
            self._event(flow, replace(detection, event_type="http.response"),
                        status=flow.response.status_code)
            return
        # Validate known A2A discovery response. No raw Agent Card saved.
        if flow.response.status_code != 200:
            return
        max_bytes = self.settings.parse_max_bytes
        raw = flow.response.raw_content
        if raw is None or len(raw) > max_bytes:
            return
        card = classify_agent_card(flow.request.url, flow.response.headers,
                                   flow.response.get_content(strict=False), max_bytes)
        if card:
            self._event(flow, card, status=flow.response.status_code)

    def done(self) -> None:
        self.writer.close()


addons = [GatewayObserver(Settings.load())] if os.getenv("AGD_DB_PATH") else []
