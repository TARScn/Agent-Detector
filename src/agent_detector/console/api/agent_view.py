"""Agent 实体视图：把框架行折叠进产品/应用实体（2026-10-26 用户口径）。

资产清单的统计单位是 **Agent 实体**：容器产品（n8n、OpenClaw…）或自建
应用（项目）。内嵌/依赖的框架不单独成行，作为实体的 ``dependencies``
属性，包含关系在详情页展示（"n8n 依赖了 LangChain 1.2.8"）。

数据模型不动：框架行仍在 agent_assets 中独立复核（容器/项目删除时自然
消失），合并只发生在视图层 —— 列表、详情、总览计数共用本模块。

合并规则：
1. 容器折叠：框架行（app_id 非空）的 container_id 与某个产品行（app_id
   空 + origin=docker + container_id 非空，如 n8n）相同 → 折叠进产品的
   dependencies。同容器无产品 → 框架行保持独立（纯框架容器）。
2. 应用分组：未折叠的框架行按 app_id 分组，每组一行，行名 = 应用名；
   代表行取 last_seen_at 最新者（asset_id 沿用），states 取组内并集，
   dependencies 列出组内全部框架（名称+版本+状态）。
3. 其余行原样透传。
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from agent_detector.storage import AgentInventoryRepository, ApplicationRepository


def _dependency_of(row: dict) -> dict:
    """折叠依赖的形状：框架品牌名（去掉 " · 应用" 后缀）+ 版本 + 状态。"""
    return {"asset_id": row["asset_id"], "agent_type": row["agent_type"],
            "name": row["name"].split(" · ")[0].strip(),
            "version": row["version"], "states": row["states"],
            "confidence": row["confidence"]}


def _is_product_row(asset: dict) -> bool:
    """容器 client 循环产出的产品行：无应用归属、有容器归属。"""
    return (not asset.get("app_id") and asset.get("origin") == "docker"
            and bool(asset.get("container_id")))


def merge_agent_rows(assets: list[dict], app_names: dict[str, str],
                     instance_counts: dict[str, int] | None = None
                     ) -> list[dict]:
    """合并为 Agent 实体行；每个 item 携带 ``dependencies``（可为空数组）。"""
    counts = instance_counts or {}
    items: list[dict] = []
    products_by_container: dict[str, dict] = {}
    for asset in assets:
        asset["instance_count"] = counts.get(asset["asset_id"], 0)
        asset["dependencies"] = []
        if _is_product_row(asset):
            products_by_container.setdefault(asset["container_id"], asset)

    grouped: dict[str, list[dict]] = {}    # app_id -> member rows
    for asset in assets:
        product = products_by_container.get(asset.get("container_id")) \
            if asset.get("app_id") and asset.get("container_id") else None
        if product is not None and product is not asset:
            product["dependencies"].append(_dependency_of(asset))
            continue  # 容器折叠：框架行不单独成行
        if asset.get("app_id"):
            grouped.setdefault(asset["app_id"], []).append(asset)
            continue
        items.append(asset)

    for app_id, members in grouped.items():
        representative = max(members,
                             key=lambda row: row.get("last_seen_at") or "")
        # 依赖列表先于改名计算 —— 代表行的品牌名（"LangChain · app"）要在
        # 折叠进 dependencies 之后才被应用名覆盖。
        representative["dependencies"] = [
            _dependency_of(row) for row in sorted(
                members, key=lambda row: row.get("last_seen_at") or "",
                reverse=True)]
        representative["name"] = app_names.get(app_id) or representative["name"]
        if representative["dependencies"]:
            representative["version"] = representative["dependencies"][0]["version"]
        representative["states"] = sorted(
            {state for row in members for state in row["states"]})
        items.append(representative)
    return items


def attach_container_relations(asset: dict, session: Session) -> None:
    """详情页的包含关系：产品资产（无 app_id）按容器关联内嵌框架与应用。

    框架/宿主资产行走既有 app_id 通路（agent_detail 已处理），这里只补
    容器产品：同容器的框架行折叠为 ``dependencies``，应用行取组件非空的
    那个嵌入 ``application``（项目与依赖卡展示 @langchain/core 等）。
    """
    if asset.get("app_id") or not asset.get("container_id"):
        return
    repository = AgentInventoryRepository(session)
    dependencies = [row for row in repository.list_assets(include_removed=False)
                    if row.get("app_id")
                    and row.get("container_id") == asset["container_id"]]
    asset["dependencies"] = [_dependency_of(row) for row in dependencies]
    with_components = [app for app
                       in ApplicationRepository(session).for_container(
                           asset["container_id"])
                       if app.get("components")]
    if with_components:
        asset["application"] = with_components[0]


def app_name_map(session: Session) -> dict[str, str]:
    """app_id → 应用名，供合并时把框架行折叠为应用实体。"""
    applications = ApplicationRepository(session).list_applications(
        include_removed=True, limit=1000)
    return {app["app_id"]: app["name"] for app in applications}
