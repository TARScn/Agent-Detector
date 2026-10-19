"""Parse only bounded, necessary protocol fields. Never return prompts or credentials."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Mapping, Any
import json
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Detection:
    protocol: str
    event_type: str
    operation: str
    confidence: str
    endpoint: str
    protocol_version: str | None = None
    component_version: str | None = None
    model: str | None = None
    tool: str | None = None
    evidence: tuple[str, ...] = field(default_factory=tuple)

    def as_record(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "event_type": self.event_type,
            "operation": self.operation[:100],
            "confidence": self.confidence,
            "endpoint": self.endpoint[:150],
            "protocol_version": self.protocol_version,
            "component_version": self.component_version,
            "model": self.model,
            "tool": self.tool,
            "evidence": list(self.evidence),
        }


def _get(headers: Mapping[str, str], name: str) -> str:
    return next((str(v) for k, v in headers.items() if k.lower() == name.lower()), "")


def _json(body: bytes | None, headers: Mapping[str, str], max_bytes: int) -> dict:
    if not body or len(body) > max_bytes or "json" not in _get(headers, "content-type").lower():
        return {}
    try:
        result = json.loads(body)
        return result if isinstance(result, dict) else {}
    except (ValueError, UnicodeError, TypeError):
        return {}


def _safe_name(value: object, maxlen: int = 90) -> str | None:
    if not isinstance(value, str):
        return None
    # Keep metadata labels small; do not persist arbitrary user text.
    if not value or len(value) > maxlen:
        return None
    if not all(ch.isalnum() or ch in "-_./:" for ch in value):
        return None
    return value


MCP_METHODS = {"initialize", "server/discover", "ping", "tools/list", "tools/call",
               "resources/list", "resources/read", "prompts/list", "prompts/get",
               "completion/complete", "subscriptions/listen"}
A2A_METHODS = {"SendMessage", "SendStreamingMessage", "GetTask", "ListTasks", "CancelTask",
               "message/send", "message/stream", "tasks/get", "tasks/cancel", "tasks/resubscribe"}
LLM_ENDPOINTS = {"/v1/chat/completions", "/chat/completions", "/v1/responses",
                 "/responses", "/v1/messages"}


def classify_request(method: str, url: str, headers: Mapping[str, str],
                     body: bytes | None, max_bytes: int = 65536) -> Detection | None:
    path = urlsplit(url).path
    obj = _json(body, headers, max_bytes)
    method = method.upper()

    # Prefer protocol-level JSON-RPC evidence over potentially overlapping URI paths.
    rpc = _safe_name(obj.get("method"))
    if method == "POST" and obj.get("jsonrpc") == "2.0" and rpc in MCP_METHODS:
        raw_params = obj.get("params") if isinstance(obj.get("params"), dict) else {}
        declared = _get(headers, "MCP-Protocol-Version") or raw_params.get("protocolVersion", "")
        version = _safe_name(declared, 30)
        # Modern MCP method header reinforces certainty, but is not necessary for older peers.
        header_method = _get(headers, "Mcp-Method")
        evidence = ["jsonrpc_2.0", "mcp_method"]
        if header_method == rpc:
            evidence.append("mcp_method_header")
        if version:
            evidence.append("mcp_protocol_version")
        params = obj.get("params") if isinstance(obj.get("params"), dict) else {}
        tool = _safe_name(params.get("name")) if rpc == "tools/call" else None
        return Detection("MCP", "mcp.request", rpc, "high" if len(evidence) >= 3 else "medium",
                         path, protocol_version=version, tool=tool, evidence=tuple(evidence))

    if method == "POST" and obj.get("jsonrpc") == "2.0" and rpc in A2A_METHODS:
        version = _safe_name(_get(headers, "A2A-Version"), 30)
        return Detection("A2A", "a2a.request", rpc, "high" if version else "medium",
                         path, protocol_version=version, evidence=("jsonrpc_2.0", "a2a_method") +
                         (("a2a_version_header",) if version else ()))

    if method == "POST" and path in LLM_ENDPOINTS and isinstance(obj.get("model"), str):
        # Require known request schema too, not path alone.
        if isinstance(obj.get("messages"), list) or isinstance(obj.get("input"), (str, list, dict)):
            model = _safe_name(obj.get("model"))
            # model is metadata supplied by caller, not a verified model/version.
            return Detection("LLM", "llm.request", "model_inference", "medium",
                             path, model=model, evidence=("llm_endpoint", "model_field", "request_schema"))

    # A2A REST binding is only a candidate without a validated Agent Card or a real A2A response.
    if method == "POST" and path in ("/message:send", "/message:stream") and isinstance(obj.get("message"), dict):
        return Detection("A2A", "a2a.rest_candidate", "SendMessage", "low", path,
                         evidence=("a2a_rest_path", "message_structure"))
    return None


def classify_agent_card(url: str, headers: Mapping[str, str], body: bytes | None,
                        max_bytes: int = 65536) -> Detection | None:
    path = urlsplit(url).path
    if path not in ("/.well-known/agent-card.json", "/.well-known/agent.json"):
        return None
    obj = _json(body, headers, max_bytes)
    interfaces = obj.get("supportedInterfaces")
    skills = obj.get("skills")
    if not isinstance(obj.get("name"), str) or not isinstance(skills, list):
        return None
    # Require interface declaration (modern card) or legacy service URL.
    if not (isinstance(interfaces, list) and any(isinstance(i, dict) and i.get("url") and i.get("protocolBinding") for i in interfaces)) and not isinstance(obj.get("url"), str):
        return None
    version = None
    if isinstance(interfaces, list):
        version = next((_safe_name(i.get("protocolVersion"), 30) for i in interfaces
                        if isinstance(i, dict) and _safe_name(i.get("protocolVersion"), 30)), None)
    version = version or _safe_name(obj.get("protocolVersion"), 30)
    return Detection("A2A", "a2a.agent_card", "agent_card_discovered", "high", path,
                     protocol_version=version, component_version=_safe_name(obj.get("version"), 30),
                     evidence=("well_known_path", "valid_agent_card_shape"))
