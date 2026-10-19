import json

from agent_detector.gateway.classifier import classify_agent_card, classify_request

HEADERS = {"Content-Type": "application/json"}


def req(obj, url="http://127.0.0.1:9100/mcp", headers=None):
    return classify_request("POST", url, headers or HEADERS, json.dumps(obj).encode())


def test_mcp_modern():
    d = req({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "search", "arguments": {"secret": "do not store"}}},
            headers={**HEADERS, "MCP-Protocol-Version": "2026-07-28",
                     "Mcp-Method": "tools/call"})
    assert (d.protocol, d.event_type, d.tool, d.protocol_version) == \
        ("MCP", "mcp.request", "search", "2026-07-28")
    assert d.confidence == "high"
    assert "do not store" not in str(d.as_record())


def test_mcp_legacy_initialize():
    d = req({"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-11-25"}})
    assert d.protocol == "MCP" and d.protocol_version == "2025-11-25"
    assert "mcp_protocol_version" in d.evidence


def test_llm_request():
    d = req({"model": "test-small", "messages": [{"role": "user", "content": "hidden prompt"}]},
            url="http://127.0.0.1:9100/v1/chat/completions")
    assert d.event_type == "llm.request" and d.model == "test-small"
    assert "hidden prompt" not in str(d.as_record())


def test_llm_requires_schema_not_path_alone():
    assert req({"anything": "123"}, url="http://127.0.0.1:9100/v1/chat/completions") is None


def test_a2a_rpc():
    d = req({"jsonrpc": "2.0", "id": 2, "method": "SendMessage",
             "params": {"message": {"role": "user"}}}, url="http://127.0.0.1:9100/rpc")
    assert d.protocol == "A2A" and d.event_type == "a2a.request"


def test_a2a_agent_card():
    card = {"name": "Demo", "skills": [],
            "supportedInterfaces": [{"url": "http://localhost/rpc",
                                     "protocolBinding": "JSONRPC",
                                     "protocolVersion": "1.0"}]}
    d = classify_agent_card("http://localhost/.well-known/agent-card.json", HEADERS,
                            json.dumps(card).encode())
    assert d.event_type == "a2a.agent_card" and d.protocol_version == "1.0"
    assert d.confidence == "high" and d.component_version is None


def test_a2a_rest_is_low_confidence_candidate():
    d = req({"message": {"role": "user", "parts": []}},
            url="http://127.0.0.1:9100/message:send")
    assert d.event_type == "a2a.rest_candidate" and d.confidence == "low"


def test_plain_jsonrpc_not_agent():
    assert req({"jsonrpc": "2.0", "method": "sum", "params": {"a": 1}}) is None


def test_path_only_not_mcp():
    assert req({"anything": "123"}) is None


def test_unknown_label_shapes_are_dropped():
    d = req({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "x" * 200, "arguments": {}}})
    assert d.tool is None  # over-length label never persisted
