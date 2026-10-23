"""The hook decision endpoint end to end: decide, record, alert (§5.1, §8)."""
from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from agent_detector.storage import (AgentInventoryRepository, AlertRepository,
                                                 BehaviorEventRepository)

TOKEN = "test-token"


@pytest.fixture(autouse=True)
def _token(monkeypatch):
    monkeypatch.setenv("AGENT_DETECTOR_HOOK_TOKEN", TOKEN)


def decide(client, payload: dict, agent_type="claude_code", token=TOKEN, pid=None):
    return client.post("/internal/v1/hooks/decide",
                       json={"agent_type": agent_type, "payload": payload,
                             "bridge_pid": pid},
                       headers={"X-Agent-Detector-Token": token})


def pre_tool_use(command: str, session: str = "session-1", cwd: str = "D:/Project-A") -> dict:
    return {"hook_event_name": "PreToolUse", "session_id": session, "cwd": cwd,
            "tool_name": "Bash", "tool_input": {"command": command}}


def test_denied_call_returns_the_platform_response_and_is_recorded(client, services):
    response = decide(client, pre_tool_use(r"Remove-Item -Recurse -Force D:\ImportantData"))
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "deny"
    assert body["response"]["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert body["policy_id"] == "deny-delete-protected-path"
    assert body["latency_ms"] >= 0

    with Session(services.engine) as session:
        events = BehaviorEventRepository(session).list_events(source="native_hook")
        alerts = AlertRepository(session).list_alerts()
        sessions = AgentInventoryRepository(session).list_sessions()
    assert len(events) == 1
    event = events[0]
    assert event["decision"] == "deny"
    assert event["execution_status"] == "blocked_by_hook"
    assert event["operation"] == "shell.exec"
    assert event["target"].startswith("Remove-Item")
    assert event["risk_level"] == "critical"
    assert event["session_id"] == "session-1"
    assert "deny-delete-protected-path" in event["evidence"]
    assert len(alerts) == 1 and alerts[0]["status"] == "open"
    assert sessions[0]["session_id"] == "session-1" and sessions[0]["event_count"] == 1


def test_allowed_call_is_recorded_without_an_alert(client, services):
    body = decide(client, pre_tool_use("git status")).json()
    assert body["decision"] == "allow"
    with Session(services.engine) as session:
        events = BehaviorEventRepository(session).list_events(source="native_hook")
        alerts = AlertRepository(session).list_alerts()
    assert events[0]["decision"] == "allow"
    assert events[0]["execution_status"] == "allowed"  # not "succeeded" (design §7)
    assert alerts == []


def test_ask_decision_is_passed_through_as_ask(client):
    body = decide(client, pre_tool_use("npm install -g typescript")).json()
    assert body["decision"] == "ask"
    assert body["response"]["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_missing_token_is_rejected(client):
    assert decide(client, pre_tool_use("git status"), token="").status_code == 401
    assert decide(client, pre_tool_use("git status"), token="wrong").status_code == 401


def test_unknown_agent_payload_fails_closed(client):
    body = decide(client, {"something": "else"}, agent_type="unheard_of").json()
    assert body["decision"] == "deny"
    assert body["response"]["permission"] == "deny"
    assert "无法规范化" in body["reason"]


def test_failure_mode_allow_opens_the_circuit(client, services, monkeypatch):
    services.hooks.failure_mode = "allow"
    body = decide(client, {"something": "else"}, agent_type="unheard_of").json()
    assert body["decision"] == "allow"


def test_cursor_payload_uses_cursor_response_shape(client):
    body = decide(client, {"hook_event_name": "beforeShellExecution",
                           "conversation_id": "conv-1",
                           "command": "rm -rf ~/.ssh"}, agent_type="cursor").json()
    assert body["decision"] == "deny"
    assert body["response"]["permission"] == "deny"
    assert "user_message" in body["response"]


def test_post_tool_use_records_a_result_not_a_decision(client, services):
    payload = {"hook_event_name": "PostToolUse", "session_id": "session-2",
               "tool_name": "Bash", "cwd": "D:/Project-A",
               "tool_input": {"command": "pytest"},
               "tool_response": {"is_error": True, "stderr": "failed"}}
    body = decide(client, payload).json()
    assert body["decision"] in ("allow", "audit")
    with Session(services.engine) as session:
        events = BehaviorEventRepository(session).list_events(source="native_hook")
    assert events[0]["event_type"] == "tool_result"
    assert events[0]["execution_status"] == "failed"


def test_disabled_policy_flips_the_verdict_via_the_api(client):
    update = client.put("/api/v1/policies/deny-delete-protected-path",
                        json={"enabled": False})
    assert update.status_code == 200 and update.json()["enabled"] is False
    body = decide(client, pre_tool_use(r"Remove-Item -Recurse -Force D:\ImportantData")).json()
    assert body["decision"] != "deny"
    client.put("/api/v1/policies/deny-delete-protected-path", json={"enabled": True})
    assert decide(client, pre_tool_use("rm -rf ~/.ssh")).json()["decision"] == "deny"