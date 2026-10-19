from agent_detector.gateway.store import BehaviorEventStore


def make_event(**overrides):
    event = {"observed_at": "2026-10-19T00:00:00+00:00", "source": "gateway",
             "agent_label": "demo", "flow_id": "f1", "upstream_host": "127.0.0.1",
             "protocol": "LLM", "event_type": "llm.request", "operation": "model_inference",
             "confidence": "medium", "endpoint": "/v1/chat/completions",
             "evidence": ["llm_endpoint"]}
    event.update(overrides)
    return event


def test_insert_and_list_roundtrip(tmp_path):
    store = BehaviorEventStore(tmp_path / "db.sqlite3")
    store.insert_many([make_event(), make_event(protocol="MCP", event_type="mcp.request",
                                                tool="search")])
    events = store.list_events()
    assert len(events) == 2
    assert events[0]["protocol"] == "MCP" and events[0]["tool"] == "search"
    assert events[1]["evidence"] == ["llm_endpoint"]


def test_list_filter_and_limit(tmp_path):
    store = BehaviorEventStore(tmp_path / "db.sqlite3")
    store.insert_many([make_event(flow_id=f"f{i}", protocol="MCP" if i % 2 else "LLM")
                       for i in range(6)])
    assert len(store.list_events(protocol="MCP")) == 3
    assert len(store.list_events(limit=2)) == 2


def test_stats(tmp_path):
    store = BehaviorEventStore(tmp_path / "db.sqlite3")
    store.insert_many([make_event(), make_event(protocol="MCP", event_type="mcp.request")])
    stats = store.stats()
    assert stats["event_count"] == 2
    assert stats["by_protocol"] == {"LLM": 1, "MCP": 1}
    assert stats["by_agent"] == {"demo": 2}


def test_reopen_persists(tmp_path):
    path = tmp_path / "db.sqlite3"
    BehaviorEventStore(path).insert_many([make_event()])
    assert BehaviorEventStore(path).stats()["event_count"] == 1
