"""Loopback transport for the hook bridge: one HTTP POST, stdlib only.

Kept apart from :mod:`hook_bridge.entry` so the transport can be imported (and
tested) without argparse, and so a future Named Pipe transport can replace it
without touching the entry point.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_URL = "http://127.0.0.1:8787/internal/v1/hooks/decide"
DEFAULT_TOKEN_FILE = "data/hook.token"


class TransportError(RuntimeError):
    """Raised when the decision service cannot be reached or answered badly."""


def read_token(token: str | None = None, token_file: str | None = None) -> str:
    """Token from the argument, then ``AGENT_DETECTOR_HOOK_TOKEN``, then a file."""
    if token:
        return token.strip()
    import os

    from_env = os.getenv("AGENT_DETECTOR_HOOK_TOKEN", "").strip()
    if from_env:
        return from_env
    path = Path(token_file or os.getenv("AGENT_DETECTOR_HOOK_TOKEN_FILE",
                                        DEFAULT_TOKEN_FILE))
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def post_decision(url: str, *, payload: dict, agent_type: str | None,
                  token: str = "", timeout: float = 5.0,
                  parent_pid: int | None = None) -> dict:
    """POST one hook payload and return the service's decision document."""
    body = json.dumps({"agent_type": agent_type, "payload": payload,
                       "bridge_pid": parent_pid}, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "X-Agent-Detector-Token": token})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise TransportError(f"决策服务返回 HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise TransportError(f"无法连接决策服务 {url}: {exc}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TransportError(f"决策服务返回非 JSON 内容: {raw[:200]}") from exc