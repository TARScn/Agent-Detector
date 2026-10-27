"""agent_view 合并层：框架行折叠进产品/应用实体（2026-10-26 用户裁定）。

口径：资产清单统计单位是 Agent 实体（容器产品或自建应用），依赖的框架
折叠为实体的 ``dependencies``，包含关系在详情页展示。
"""
from agent_detector.console.api.agent_view import merge_agent_rows


def row(asset_id, name, agent_type="langchain", *, app_id=None,
        container_id=None, origin="host", version="1.0", states=None,
        last_seen="2026-10-26T00:00:00+00:00"):
    return {"asset_id": asset_id, "name": name, "agent_type": agent_type,
            "app_id": app_id, "container_id": container_id, "origin": origin,
            "version": version, "states": list(states or ["INSTALLED"]),
            "confidence": 0.9, "protection_status": "MONITOR_ONLY",
            "status": "active", "last_seen_at": last_seen, "session_count": 0}


def test_container_framework_folds_into_product():
    assets = [
        row("n8n--1", "n8n", "n8n", container_id="c1", origin="docker",
            version="2.44.7"),
        row("langchain--2", "LangChain · n8n", app_id="app--1",
            container_id="c1", origin="docker", version="1.2.8"),
    ]
    items = merge_agent_rows(assets, {"app--1": "n8n"})
    assert len(items) == 1  # LangChain · n8n 不再单独成行
    product = items[0]
    assert product["name"] == "n8n"
    dep = product["dependencies"][0]
    assert dep["name"] == "LangChain" and dep["version"] == "1.2.8"
    assert dep["asset_id"] == "langchain--2"


def test_framework_without_product_container_groups_by_app():
    # 同容器没有产品行（纯框架容器）→ 框架行不折叠进产品，按应用分组成一行
    assets = [row("langchain--2", "LangChain · app", app_id="app--1",
                  container_id="c1", origin="docker")]
    items = merge_agent_rows(assets, {"app--1": "app"})
    assert len(items) == 1
    assert items[0]["name"] == "app"  # 统一应用名口径
    assert [d["name"] for d in items[0]["dependencies"]] == ["LangChain"]


def test_host_multi_framework_grouped_by_app_name():
    assets = [
        row("langgraph--2", "LangGraph · agentTest_langchain", "langgraph",
            app_id="app--1", version="1.2.16",
            last_seen="2026-10-26T01:00:00+00:00"),
        row("langchain--1", "LangChain · agentTest_langchain",
            app_id="app--1", version="1.4.7",
            last_seen="2026-10-26T02:00:00+00:00"),
    ]
    items = merge_agent_rows(assets, {"app--1": "agentTest_langchain"})
    assert len(items) == 1  # LangChain/LangGraph 两条合并为应用一行
    entity = items[0]
    assert entity["name"] == "agentTest_langchain"
    assert entity["asset_id"] == "langchain--1"  # 代表行 = last_seen 最新
    assert [d["name"] for d in entity["dependencies"]] == ["LangChain", "LangGraph"]
    assert entity["version"] == "1.4.7"  # 最新依赖的版本
    assert entity["states"] == ["INSTALLED"]


def test_states_union_across_group():
    assets = [
        row("a--1", "LangChain · demo", app_id="app--1", states=["INSTALLED"]),
        row("b--2", "LangGraph · demo", "langgraph", app_id="app--1",
            states=["INSTALLED", "RUNNING"]),
    ]
    (entity,) = merge_agent_rows(assets, {"app--1": "demo"})
    assert entity["states"] == ["INSTALLED", "RUNNING"]


def test_client_rows_pass_through():
    assets = [row("claude--1", "Claude Code", "claude_code", version="2.1.3")]
    items = merge_agent_rows(assets, {})
    assert len(items) == 1
    assert items[0]["dependencies"] == []
    assert items[0]["instance_count"] == 0  # merge 注入实例计数
