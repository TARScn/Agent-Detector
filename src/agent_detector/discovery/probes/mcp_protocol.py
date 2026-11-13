"""Controlled MCP protocol probing of configured HTTP/SSE endpoints.

Config discovery proves a client *declares* a server; this probe asks the
endpoint whether it actually *speaks* MCP. Behavior kept deliberately narrow:

* loopback endpoints only (``allow_remote`` must be set explicitly for more),
  no redirects, no proxy env, serial requests, bounded timeouts and body sizes
* the flow is ``initialize`` (protocol-version candidates, newest first, with
  ``server/discover`` as the modern-protocol fallback) → ``notifications/initialized``
  → ``tools/list`` with cursor pagination
* **tools are listed, never called** — no ``tools/call``, ``resources/read``
  or ``prompts/get`` is ever sent
* tool descriptions are untrusted input: sanitized (injection patterns
  removed, hidden characters stripped, truncated) before they are hashed and
  returned; the raw text never leaves this module

Only endpoint URLs from config references are probed — URLs are sanitized
upstream (query stripped), so no credential travels in a probe request.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from agent_detector.discovery.sources.mcp import McpConfigReference
from agent_detector.identity.canonical import canonical_json, digest

# Protocol versions we know how to offer, newest first. A server replies with
# the version it supports; whatever it picks is recorded, so an unknown future
# version still verifies.
_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2024-11-05")
_CLIENT_INFO = {"name": "AgentDetector", "version": "0.3"}
_MAX_BODY = 256 * 1024
_MAX_DESC_LEN = 500
_MAX_TOOLS = 100
_PAGINATION_ROUNDS = 8

# Untrusted-description defenses, tuned on AI-Infra-Guard's scanner hygiene:
# instructions embedded in tool metadata must not reach our consumers.
_INJECTION_PATTERNS = tuple(re.compile(pattern, re.IGNORECASE) for pattern in (
    r"ignore\s+(?:all\s+|any\s+|the\s+)*(?:previous\s+|above\s+|prior\s+)"
    r"*(?:all\s+|any\s+)*(instructions?|rules?|prompts?|constraints?)",
    r"you\s+are\s+now\s+in\b",
    r"system\s*(note|override|prompt)\s*:",
    r"\bexecute\s+(this|the)\s+(shell|command|diagnostic)\b",
    r"\brun\s+this\s+(exact\s+)?(diagnostic|command)\b",
    r"\bdo\s+not\s+tell\s+the\s+user\b",
    r"\bbefore\s+answering,?\s+first\s+call\b",
    r"\balways\s+include\s+the\s+contents\s+of\b",
    r"\bsend\s+the\s+result\s+to\b",
    r"\benvironment\s+fingerprint\b",
))
# Zero-width/bidi/control characters can smuggle instructions invisibly.
_HIDDEN_CHARS = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\x00-\x08\x0b-\x1f\x7f]")


@dataclass(frozen=True)
class McpProbeResult:
    ref: McpConfigReference
    status: str              # verified / unauthorized / timeout / not_mcp / error / skipped
    protocol_version: str = ""
    server_info: str = ""
    detail: str = ""
    tools: tuple[dict, ...] = ()   # {name, description(sanitized), desc_hash, schema_hash}


def probe_mcp_endpoints(refs: list[McpConfigReference], *, timeout: float = 2.0,
                        max_endpoints: int = 20, allow_remote: bool = False,
                        ) -> list[McpProbeResult]:
    """Probe one endpoint per distinct URL; refs sharing a URL share the result."""
    candidates: dict[str, McpConfigReference] = {}
    for ref in refs:
        if ref.transport not in ("http", "sse", "streamable_http"):
            continue
        if not ref.endpoint or not _is_local(ref.endpoint):
            if not allow_remote:
                continue
        candidates.setdefault(ref.endpoint, ref)
    results: list[McpProbeResult] = []
    for endpoint, ref in list(candidates.items())[:max_endpoints]:
        results.append(_probe_one(ref, endpoint, timeout))
    return results


def probe_result_for(results: list[McpProbeResult],
                     ref: McpConfigReference) -> McpProbeResult | None:
    """Shared result for a reference, matched by sanitized endpoint."""
    for result in results:
        if result.ref.endpoint == ref.endpoint and result.status != "skipped":
            return result
    return None


def sanitize_description(desc: str) -> str:
    cleaned = _HIDDEN_CHARS.sub("", desc or "")
    for pattern in _INJECTION_PATTERNS:
        cleaned = pattern.sub("[REMOVED]", cleaned)
    if len(cleaned) > _MAX_DESC_LEN:
        cleaned = cleaned[:_MAX_DESC_LEN] + " ... [truncated]"
    return cleaned


def tool_hashes(description: str, schema: object) -> tuple[str, str]:
    desc_hash = digest(canonical_json({"d": sanitize_description(description)}),
                       length=32)
    schema_hash = digest(canonical_json({"s": schema if isinstance(schema, dict)
                                         else {}}), length=32)
    return desc_hash, schema_hash


# ---------------------------------------------------------------------------
# Wire protocol (bare JSON-RPC; the project carries no MCP SDK dependency)
# ---------------------------------------------------------------------------


def _probe_one(ref: McpConfigReference, endpoint: str,
               timeout: float) -> McpProbeResult:
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False,
                          trust_env=False) as client:
            if ref.transport == "sse":
                return _probe_sse(client, ref, endpoint)
            return _probe_streamable_http(client, ref, endpoint)
    except httpx.TimeoutException:
        return McpProbeResult(ref=ref, status="timeout", detail=endpoint)
    except (httpx.HTTPError, OSError, ValueError) as exc:
        return McpProbeResult(ref=ref, status="error", detail=str(exc)[:200])


def _probe_streamable_http(client: httpx.Client, ref: McpConfigReference,
                           endpoint: str) -> McpProbeResult:
    session_headers: dict[str, str] = {}
    init_result, version, session_id = _initialize(client, endpoint,
                                                   session_headers)
    if session_id:
        session_headers["Mcp-Session-Id"] = session_id
    try:
        _post_json(client, endpoint,
                   {"jsonrpc": "2.0", "method": "notifications/initialized"},
                   session_headers)
        tools = _list_tools(client, endpoint, session_headers)
    except httpx.TimeoutException:
        return McpProbeResult(ref=ref, status="timeout", protocol_version=version,
                              detail="tools/list timed out")
    return _verified(ref, init_result, version, tools)


def _initialize(client: httpx.Client, url: str,
                session_headers: dict) -> tuple[dict, str, str]:
    """Initialize handshake across known versions; returns (result, version,
    mcp-session-id). Raises ``_ProbeExit`` with ``not_mcp`` when the endpoint
    answers but never speaks JSON-RPC, and with ``error`` when it answers RPC
    errors for every candidate version."""
    rpc_errors = 0
    for version in _PROTOCOL_VERSIONS:
        response = _post_json(client, url, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": version, "capabilities": {},
                       "clientInfo": _CLIENT_INFO}}, session_headers)
        payload = _json_of(response)
        if payload is None:
            raise _ProbeExit(_exit_result(url, "not_mcp", "non-JSON answer"))
        result = payload.get("result") if isinstance(payload, dict) else None
        if isinstance(result, dict) and result.get("protocolVersion"):
            session_id = response.headers.get("mcp-session-id") or ""
            return result, str(result.get("protocolVersion")), session_id
        if isinstance(payload, dict) and "error" in payload:
            rpc_errors += 1
            continue
        raise _ProbeExit(_exit_result(url, "not_mcp", "no JSON-RPC envelope"))
    # Modern (2026-07-28+) servers answer server/discover instead of initialize.
    try:
        response = _post_json(client, url, {
            "jsonrpc": "2.0", "id": 1, "method": "server/discover",
            "params": {}}, session_headers)
        payload = _json_of(response)
        result = payload.get("result") if isinstance(payload, dict) else None
        if isinstance(result, dict):
            session_id = response.headers.get("mcp-session-id") or ""
            return result, str(result.get("protocolVersion") or "2026-07-28"), session_id
    except (_ProbeExit, httpx.HTTPError, ValueError):
        pass
    raise _ProbeExit(_exit_result(
        url, "not_mcp" if rpc_errors == 0 else "error",
        "initialize rejected for all protocol versions"))


def _probe_sse(client: httpx.Client, ref: McpConfigReference,
               endpoint: str) -> McpProbeResult:
    """Legacy SSE transport: open the stream, find the message endpoint, POST
    JSON-RPC to it. Best-effort within the shared timeout budget."""
    try:
        message_url = None
        with client.stream("GET", endpoint,
                           headers={"Accept": "text/event-stream"}) as stream:
            if stream.status_code in (401, 403):
                return McpProbeResult(ref=ref, status="unauthorized",
                                      detail=f"HTTP {stream.status_code}")
            recent: list[str] = []
            for line in stream.iter_lines():
                recent.append(line)
                if line.startswith("data:"):
                    candidate = line[5:].strip()
                    tail = " ".join(recent[-3:])
                    if candidate and "endpoint" in tail \
                            and not candidate.startswith("{"):
                        message_url = _absolute(endpoint, candidate)
                        break
                if len(recent) > 50:
                    break
        if not message_url:
            return McpProbeResult(ref=ref, status="not_mcp",
                                  detail="no SSE endpoint event")
        session_headers: dict[str, str] = {}
        init_result, version, _ = _initialize(client, message_url,
                                              session_headers)
        _post_json(client, message_url,
                   {"jsonrpc": "2.0", "method": "notifications/initialized"},
                   session_headers)
        tools = _list_tools(client, message_url, session_headers)
        return _verified(ref, init_result, version, tools)
    except _ProbeExit as exit_:
        result = exit_.result
        return McpProbeResult(ref=ref, status=result.status,
                              protocol_version=result.protocol_version,
                              server_info=result.server_info,
                              detail=result.detail, tools=result.tools)
    except httpx.TimeoutException:
        return McpProbeResult(ref=ref, status="timeout", detail=endpoint)
    except (httpx.HTTPError, OSError, ValueError) as exc:
        return McpProbeResult(ref=ref, status="error", detail=str(exc)[:200])


class _ProbeExit(Exception):
    """Carries a finished result out of the initialize handshake."""

    def __init__(self, result: McpProbeResult):
        super().__init__(result.status)
        self.result = result


def _exit_result(url: str, status: str, detail: str) -> McpProbeResult:
    transport = "sse" if url.endswith("/sse") else "http"
    carrier = McpConfigReference(client="", name="", scope="user",
                                 config_path=url, transport=transport,
                                 endpoint=url, enabled="unknown", config_digest="")
    return McpProbeResult(ref=carrier, status=status, detail=detail)


def _post_json(client: httpx.Client, url: str, payload: dict,
               session_headers: dict) -> httpx.Response:
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream",
               **session_headers}
    response = client.post(url, content=json.dumps(payload), headers=headers)
    if response.status_code in (401, 403):
        raise _ProbeExit(_exit_result(url, "unauthorized",
                                      f"HTTP {response.status_code}"))
    if len(response.content) > _MAX_BODY:
        raise _ProbeExit(_exit_result(url, "error",
                                      "response exceeds 256KB cap"))
    return response


def _json_of(response: httpx.Response):
    """JSON-RPC payload from a JSON or SSE-framed body; None when neither."""
    content_type = response.headers.get("content-type", "")
    text = response.text
    if "text/event-stream" in content_type or text.lstrip().startswith("event:"):
        for block in text.split("\n\n"):
            for line in block.splitlines():
                if line.startswith("data:"):
                    try:
                        return json.loads(line[5:].strip())
                    except ValueError:
                        continue
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def _list_tools(client: httpx.Client, url: str,
                session_headers: dict) -> tuple[dict, ...]:
    """tools/list with cursor pagination; list-only, never a tool call."""
    tools: list[dict] = []
    cursor = None
    for request_id in range(10, 10 + _PAGINATION_ROUNDS):
        params: dict = {}
        if cursor:
            params["cursor"] = cursor
        response = _post_json(client, url, {
            "jsonrpc": "2.0", "id": request_id, "method": "tools/list",
            "params": params}, session_headers)
        payload = _json_of(response)
        result = payload.get("result") if isinstance(payload, dict) else None
        if not isinstance(result, dict) or not isinstance(result.get("tools"),
                                                          list):
            break
        for tool in result["tools"]:
            if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
                continue
            description = tool.get("description")
            desc_hash, schema_hash = tool_hashes(
                description if isinstance(description, str) else "",
                tool.get("inputSchema"))
            tools.append({
                "name": tool["name"][:200],
                "description": sanitize_description(
                    description if isinstance(description, str) else ""),
                "desc_hash": desc_hash, "schema_hash": schema_hash})
            if len(tools) >= _MAX_TOOLS:
                return tuple(tools)
        cursor = result.get("nextCursor")
        if not cursor:
            break
    return tuple(tools)


def _absolute(endpoint: str, candidate: str) -> str:
    if candidate.startswith(("http://", "https://")):
        return candidate
    parts = urlsplit(endpoint)
    root = f"{parts.scheme}://{parts.netloc}"
    return root + candidate if candidate.startswith("/") else root + "/" + candidate


def _verified(ref: McpConfigReference, init_result: dict, version: str,
              tools: tuple[dict, ...]) -> McpProbeResult:
    info = init_result.get("serverInfo")
    server_info = ""
    if isinstance(info, dict):
        name = str(info.get("name") or "")
        server_version = str(info.get("version") or "")
        server_info = f"{name} {server_version}".strip()[:160]
    return McpProbeResult(ref=ref, status="verified", protocol_version=version,
                          server_info=server_info, tools=tools)


def _is_local(url: str) -> bool:
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return False
    return host in ("127.0.0.1", "::1", "localhost")
