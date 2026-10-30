"""Console API surface: discovery, dashboard, policies, hooks and bridge CLI."""
from __future__ import annotations

import json

import pytest
from sqlalchemy.orm import Session

from agent_detector.storage import AgentInventoryRepository
from agent_detector.storage.models import BehaviorEventRow, utc_now_iso


def test_health_and_capabilities(client):
    health = client.get("/api/health").json()
    assert health["status"] == "ok"
    capabilities = client.get("/api/v1/capabilities").json()
    assert capabilities["modes"]["discovery"]["implemented"] is True
    assert "claude_code" in capabilities["modes"]["protect"]["agents"]
    assert "gemini_cli" in capabilities["modes"]["protect"]["not_implemented"]


def test_overview_has_the_four_console_numbers(client, services):
    with Session(services.engine) as session:
        session.add(BehaviorEventRow(
            # overview 的 by_source / blocked_today 统计"今日"事件：
            # 时间必须是当下，写死日期会在第二天起变成定时炸弹。
            observed_at=utc_now_iso(), source="native_hook",
            agent_label="Claude Code", flow_id="hook-1", protocol="HOOK",
            upstream_host="",
            event_type="tool_call", operation="shell.exec", confidence="high",
            decision="deny", risk_level="critical", endpoint="",
            evidence_json='["deny-delete-protected-path"]'))
        session.commit()
    overview = client.get("/api/v1/overview").json()
    assert "agents" in overview and "behavior" in overview
    assert overview["behavior"]["by_source"]["native_hook"] == 1
    assert overview["behavior"]["blocked_today"] == 1
    assert any("不等于已拦截" in note for note in overview["disclaimer"])
    channels = {item["id"]: item for item in overview["channels"]}
    assert "native_hook" in channels and "sysmon" in channels


def test_system_info_reports_environment_and_matrix(client):
    info = client.get("/api/v1/system").json()
    assert info["version"]
    assert info["policy"]["failure_mode"] in ("block", "allow")
    assert info["detection_rules"]["client_rules"]
    agent_ids = [item["id"] for item in info["agent_matrix"]["agents"]]
    assert "claude_code" in agent_ids and "unknown_agent" in agent_ids
    assert any("127.0.0.1" in note for note in info["scope_notes"])


def test_discovery_scan_creates_the_agent_inventory(client, services, monkeypatch):
    from agent_detector.core.enums import AssetState, AssetType
    from agent_detector.core.models import DetectedAsset, VersionInfo

    asset = DetectedAsset(asset_id="claude-code--test", name="Claude Code",
                          asset_type=AssetType.AGENT_CLIENT,
                          states={AssetState.RUNNING}, confidence=0.9,
                          version=VersionInfo.unknown(), running_pids=[4242],
                          detector="claude_code")

    class FakeDetector:
        name = "fake"

        def detect(self, facts):
            return [asset]

    from agent_detector.discovery.scanner import scan as scanner

    monkeypatch.setattr(scanner, "collect_host_facts", lambda: _facts())
    monkeypatch.setattr(scanner, "build_detectors", lambda: [FakeDetector()])
    result = client.post("/api/v1/discovery/scan", json={"active": False}).json()
    assert result["status"] == "completed"
    assert result["agent_assets"][0]["agent_type"] == "claude_code"
    assert result["agent_assets"][0]["protection_status"] == "MONITOR_ONLY"

    agents = client.get("/api/v1/agents").json()["items"]
    assert agents[0]["asset_id"] == "claude-code--test"
    assert agents[0]["instance_count"] == 1
    detail = client.get("/api/v1/agents/claude-code--test").json()
    assert detail["instances"][0]["pid"] == 4242
    assert detail["capabilities"]["protect"] == "P0"
    assert client.get("/api/v1/discovery/summary").json()["assets"] == 1


def _facts():
    from agent_detector.core.models import HostFacts, ProcessInfo

    return HostFacts(hostname="host-1",
                     processes=(ProcessInfo(pid=4242, name="node.exe",
                                            cmdline=("node", "cli.js"),
                                            create_time=1_700_000_000.0, ppid=1),),
                     sockets=())


def test_agents_list_merges_frameworks_into_entities(client, services):
    """口径 2026-10-26：清单以 Agent 实体为单位 —— 容器框架折叠进产品，
    宿主多框架折叠进应用（统一应用名）；总览计数与清单一致。"""
    from agent_detector.core.enums import AssetState, AssetType, VersionSource
    from agent_detector.core.models import (AgentInventoryItem, ComponentInfo,
                                            ProjectInfo, VersionInfo)
    from agent_detector.storage import ApplicationRepository

    def item(aid, name, agent_type, *, app_id=None, container_id=None,
             origin="host", version="1.0"):
        return AgentInventoryItem(
            asset_id=aid, agent_type=agent_type, name=name,
            version=VersionInfo(version, VersionSource.PACKAGE_METADATA, 0.9),
            states=(AssetState.INSTALLED,), confidence=0.8,
            app_id=app_id, origin=origin, container_id=container_id,
            capabilities={"discovery": "P2", "monitor": "P2",
                          "protect": "PLANNED"})

    with Session(services.engine) as session:
        repo = AgentInventoryRepository(session)
        repo.upsert_asset(item("n8n--1", "n8n", "n8n", container_id="c1",
                               origin="docker", version="2.44.7"))
        repo.upsert_asset(item("langchain--2", "LangChain · n8n", "langchain",
                               app_id="app--pkg", container_id="c1",
                               origin="docker", version="1.2.8"))
        repo.upsert_asset(item("langchain--3", "LangChain · demo", "langchain",
                               app_id="app--demo", version="1.4.7"))
        repo.upsert_asset(item("langgraph--4", "LangGraph · demo", "langgraph",
                               app_id="app--demo", version="1.2.16"))
        apps = ApplicationRepository(session)
        apps.upsert(ProjectInfo(project_id="app--pkg", runtime="node",
                                root="container:c1/usr/local/lib/node_modules/n8n",
                                name="n8n", container_id="c1",
                                resolver_status="resolved"),
                    [ComponentInfo(name="@langchain/core", version="1.2.8",
                                   version_source=VersionSource.PACKAGE_METADATA)],
                    app_id="app--pkg")
        apps.upsert(ProjectInfo(project_id="app--demo", runtime="python",
                                root="D:/code/demo", name="agentTest_langchain",
                                resolver_status="resolved"),
                    [], app_id="app--demo")
        session.commit()

    items = client.get("/api/v1/agents").json()["items"]
    by_id = {item["asset_id"]: item for item in items}
    assert set(by_id) == {"n8n--1", "langchain--3"}  # 框架行折叠，4 行 → 2 行
    n8n = by_id["n8n--1"]
    assert n8n["dependencies"][0]["name"] == "LangChain"
    assert n8n["dependencies"][0]["version"] == "1.2.8"
    demo = by_id["langchain--3"]
    assert demo["name"] == "agentTest_langchain"  # 统一应用名
    assert [d["name"] for d in demo["dependencies"]] == ["LangChain", "LangGraph"]

    detail = client.get("/api/v1/agents/n8n--1").json()
    assert detail["dependencies"][0]["name"] == "LangChain"  # 包含关系
    assert detail["application"]["components"][0]["name"] == "@langchain/core"

    overview = client.get("/api/v1/overview").json()
    assert overview["agents"]["total"] == len(items)  # 计数口径一致


def test_scan_conflict_is_reported_as_409(client, services):
    from agent_detector.discovery.scanner import scan as scanner

    def slow_scan(*_args, **_kwargs):
        assert services.scan_lock.acquire(blocking=False) is False
        return {"scan_id": 1, "status": "completed"}

    import agent_detector.console.api.discovery as discovery_router

    original = discovery_router.run_scan
    discovery_router.run_scan = slow_scan
    try:
        services.scan_lock.acquire()
        try:
            conflict = client.post("/api/v1/discovery/scan", json={"active": False})
            assert conflict.status_code == 409
        finally:
            services.scan_lock.release()
    finally:
        discovery_router.run_scan = original
    assert scanner is not None


def test_policy_endpoints_expose_and_update_rules(client):
    items = client.get("/api/v1/policies").json()["items"]
    ids = {item["policy_id"] for item in items}
    assert "deny-delete-protected-path" in ids
    assert all(item["enabled"] for item in items)

    updated = client.put("/api/v1/policies/ask-package-install",
                         json={"decision": "deny"}).json()
    assert updated["decision"] == "deny"
    reloaded = client.post("/api/v1/policies/reload").json()
    assert reloaded["status"]["rules"] >= len(items)
    assert client.put("/api/v1/policies/nope", json={"enabled": False}).status_code == 404


def test_alerts_can_be_acknowledged(client, services):
    from agent_detector.storage import AlertRepository

    with Session(services.engine) as session:
        alert_id = AlertRepository(session).raise_alert(
            title="Claude Code · shell.exec", reason="命中受保护路径删除策略",
            risk_level="critical", decision="deny", agent_label="Claude Code")
        session.commit()
    listing = client.get("/api/v1/alerts").json()
    assert listing["stats"]["open_high"] == 1
    acked = client.patch(f"/api/v1/alerts/{alert_id}", json={"status": "acknowledged"}).json()
    assert acked["status"] == "acknowledged"
    assert client.patch("/api/v1/alerts/999999", json={"status": "resolved"}).status_code == 404


def test_hook_endpoints_are_dry_run_by_default(client):
    listing = client.get("/api/v1/hooks").json()
    agent_types = {item["agent_type"] for item in listing["items"]}
    assert {"claude_code", "codex_cli", "cursor"} == agent_types
    assert all(item["state"] in ("INSTALLED", "NOT_INSTALLED", "PARTIAL", "CONFLICT")
               for item in listing["items"])

    plan = client.post("/api/v1/hooks/claude_code/plan", json={}).json()
    assert plan["changed"] is True and plan["written"] is False
    assert plan["merged"]["hooks"]["PreToolUse"]

    installed = client.post("/api/v1/hooks/claude_code/install",
                            json={"apply": False}).json()
    assert installed["written"] is False  # dry run: nothing is written

    snippet = client.get("/api/v1/hooks/cursor/snippet").json()
    assert snippet["config_path"] == "~/.cursor/hooks.json"
    assert client.post("/api/v1/hooks/gemini_cli/plan", json={}).status_code == 400


def test_hook_install_writes_only_when_applied(client, home, monkeypatch):
    from agent_detector.interception.hooks import installer

    monkeypatch.setattr(installer.Path, "home", classmethod(lambda cls: home))
    result = client.post("/api/v1/hooks/codex_cli/install", json={"apply": True}).json()
    assert result["written"] is True
    written = json.loads((home / ".codex" / "hooks.json").read_text(encoding="utf-8"))
    assert written["hooks"]["PreToolUse"]
    assert client.get("/api/v1/hooks").json()["items"][1]["state"] in ("INSTALLED",
                                                                     "NOT_INSTALLED")


# -- hook bridge CLI -------------------------------------------------------


def test_bridge_prints_the_server_response(monkeypatch, capsys):
    from hook_bridge import entry

    monkeypatch.setattr(entry, "post_decision", lambda *a, **k: {
        "decision": "deny", "response": {"hookSpecificOutput": {
            "permissionDecision": "deny", "permissionDecisionReason": "x"}}})
    payload = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash"})
    monkeypatch.setattr("sys.argv", ["entry"])
    monkeypatch.setattr("sys.stdin", _Stdin(payload))
    code = entry.main(["--agent", "claude_code", "--token", "t"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_bridge_fails_closed_when_the_service_is_unreachable(capsys):
    from hook_bridge import entry
    from hook_bridge.transport import TransportError

    def fail(*_args, **_kwargs):
        raise TransportError("connection refused")

    import sys as _sys

    original = entry.post_decision
    entry.post_decision = fail
    _sys.stdin = _Stdin("{}")
    try:
        code = entry.main(["--agent", "claude_code", "--token", "t"])
    finally:
        entry.post_decision = original
        _sys.stdin = _sys.__stdin__
    assert code == 0
    out = capsys.readouterr()
    assert "deny" in out.out and "connection refused" in out.err


def test_bridge_allows_when_failure_mode_is_audit(capsys):
    from hook_bridge import entry
    from hook_bridge.transport import TransportError

    def fail(*_args, **_kwargs):
        raise TransportError("down")

    import sys as _sys

    original = entry.post_decision
    entry.post_decision = fail
    _sys.stdin = _Stdin("{}")
    try:
        entry.main(["--agent", "cursor", "--token", "t", "--failure-mode", "allow"])
    finally:
        entry.post_decision = original
        _sys.stdin = _sys.__stdin__
    assert "allow" in capsys.readouterr().out


class _Stdin:
    def __init__(self, text: str):
        self._text = text

    def read(self) -> str:
        return self._text

    def isatty(self) -> bool:
        return False