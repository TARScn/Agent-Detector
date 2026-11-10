# Agent-Detector Web 控制台 API 契约

> 状态：**v1.0 已落地**。B0–B4 后端出口与 `frontend/` React 控制台已在本地工作区实现；  
> 仍需在目标主机完成一次真实扫描后的数据审计与最终视觉走查。  
> 日期：2026-11-05  
> 基线：`feat/evidence-aggregation` @ `4c1546e`，语义基线见 [architecture-v1.2.md](architecture-v1.2.md)。  
> 范围：`/api/v1` 读契约、SSE、错误与缓存约定；只定义前端需要的稳定表面，不改变采集、聚合、裁决算法。  
> 结论：**先按本文补齐后端出口，再开始页面开发。** 标 `[NEW]` 的端点当前不存在；标 `[EXTEND]` 的端点在现有响应上做加法；标 `[EXISTS]` 的端点已可用。

## 冻结决定（TL;DR）

1. 用户可见 Agent 状态只有 4 值 `agent_status`；`null` 表示“尚未投影”，不等于 `UNKNOWN`。
2. 新增 `protection` 对象；`PROTECTED` 只在 `ENFORCEMENT_VERIFIED` 时出现，Hook 配置完整只算 `MONITOR_ONLY`。
3. `decision` 与 `execution_status` 永远分开展示；`allow` 不等于执行成功。
4. `status_basis` 使用三态 `true/false/null`；`false` 只能来自反驳/缺席证据。
5. Coverage 是扫描范围的完整度，不按资产显示百分比，不用来删除/隐藏资产。
6. 证据接口第一版明确 `completeness:"support_only"`；没有反驳 Claim 时不显示“无争议”。
7. 路由与响应统一使用 `entity_id`；legacy `asset_id`/`app_id` 不再出现在用户可见字段。无法收敛到单一实体的历史身份进入 review case，不进入资产列表。
8. 不新增 `/ui` 命名空间；在 `/api/v1` 上做加法。P0 不做全局搜索。
9. SSE 必须带 `id:`、支持 `Last-Event-ID`，积压超限发 `gap` 事件。
10. 新 React 控制台在功能对齐前不切 `/`；用 `CONSOLE_UI=legacy|next` 选择静态目录。

---

## 0. 目的与非目标

### 0.1 目的

1. 让新控制台只消费**后端已经裁决过的事实**，不在浏览器里推断 Agent 状态、身份、覆盖率或保护能力。
2. 冻结用户可见状态词表，避免 UI 出现“已启用防护”“已允许（成功）”“未知=不存在”等过度声明。
3. 明确哪些字段来自 legacy 视图、哪些来自 V1.2 投影，给前后端一个共同的实现清单。
4. 给出可直接写成 pytest / MSW fixture 的验收场景。

### 0.2 非目标

- 不改变 `agent_status` 的投影算法、Claim 裁决、Coverage 门控或实体合并规则。
- 不把 `/internal/v1/hooks/decide` 暴露给浏览器。
- 不在本期实现全局搜索、拓扑画布、策略可视化编辑或告警通知渠道。
- 不为了前端方便新增“置信度百分比”“保护率”等后端没有的派生指标。

### 0.3 端点总览

| 方法 | 路径 | 状态 | 用途 |
| --- | --- | --- | --- |
| GET | `/api/v1/overview` | 扩展 | 总览计数 |
| GET | `/api/v1/agents` | 扩展 | 资产列表（筛选/分页） |
| GET | `/api/v1/agents/{entity_id}` | 扩展 | 资产详情 |
| GET | `/api/v1/agents/{entity_id}/claims` | 新增 | 证据 Claim |
| GET | `/api/v1/agents/{entity_id}/coverage` | 新增 | 覆盖范围 |
| GET | `/api/v1/agents/{entity_id}/relations` | 新增 | 关系/组件/端点 |
| GET | `/api/v1/agents/{entity_id}/mcp` | 已存在 | MCP 名称/传输（不含命令） |
| GET | `/api/v1/events` | 扩展 | 事件列表（双向游标） |
| GET | `/api/v1/events/{event_id}` | 新增 | 单事件 |
| GET | `/api/v1/events/stats` | 扩展 | 事件统计 |
| GET | `/api/v1/events/timeseries` | 新增 | 趋势桶 |
| GET | `/api/v1/events/stream` | 扩展 | SSE（id/恢复/gap） |
| GET | `/api/v1/attention` | 新增 | 首屏待关注 |
| GET/PATCH | `/api/v1/alerts`、`/alerts/{id}` | 扩展 | 告警队列/处置 |
| GET/PUT/POST | `/api/v1/policies`、`/policies/{id}`、`/policies/reload` | 已存在 | 策略 |
| GET/POST | `/api/v1/telemetry/status`、`/audit-rules`、`/monitor/*`、`/behavior/*` | 扩展 | 采集通道 |
| GET/POST | `/api/v1/hooks`、`/hooks/{agent}/plan\|install\|uninstall\|snippet` | 已存在 | Hook |
| GET | `/api/v1/system`、`/capabilities` | 已存在 | 环境/能力 |
| POST/GET | `/api/v1/discovery/scan`、`/discovery/scans\|assets\|applications\|summary` | 扩展 | 扫描 |
| GET | `/api/health` | 已存在 | 存活探针 |

---

## 1. 不可违反的契约规则

| # | 规则 | 后果 |
| --- | --- | --- |
| C1 | **后端裁决，前端呈现**。UI 不根据 PID、端口、同名或 E1–E5 自行合并实体或推断状态。 | 违反即视为契约违规 |
| C2 | 用户可见 Agent 状态**只有 4 值**：`RUNNING / CONFIGURED / INSTALLED / UNKNOWN`。 | 不得把 `states[]` 当状态列 |
| C3 | 保护状态与 Agent 状态**正交**。`PROTECTED` 只在 `ENFORCEMENT_VERIFIED` 时出现。 | Hook 配置文件存在 ≠ 已验证阻断 |
| C4 | `decision`（放行/阻断）与 `execution_status`（是否执行）**是两个字段**。 | `allow` 不得显示为“成功” |
| C5 | `Coverage PARTIAL/FAILED` 只表示“这次采集不完整”，**不表示资产不存在**。 | 不得据此隐藏或删除资产 |
| C6 | `lifecycle=WATCH` 是“可能已不存在、尚待复核”，**默认可见**；`lifecycle=ARCHIVED` 是“覆盖完整且确认不存在”，默认隐藏但历史保留。`include_removed=true` 才返回 ARCHIVED。 | 不得显示为“已删除”；不得因一次不完整扫描隐藏资产 |
| C7 | 身份歧义（`AMBIGUOUS/CONFLICT`）时 `entity_id=null`，UI 显示“待复核”，**不自动合并**。 | 不得把两个资产折叠成一个 |
| C8 | E1–E5 是证据类别，**不是可求和的分数**。 | 不得显示“置信度 85%” |
| C9 | 事件 `actor` 与 `target` 分离；无法归属时显示“未归属”，不得把 target 填成 actor。 | 见 §5.7 |
| C10 | 不返回文件内容、对话内容、凭据原文、环境变量、MCP 命令/参数。 | 见 §8 |

---

## 2. 状态字典（UI 唯一词表）

### 2.1 Agent 状态 `agent_status`

| 值 | UI 文案 | 含义 | 允许的辅助信息 |
| --- | --- | --- | --- |
| `RUNNING` | 运行中 | 有**身份已验证**的运行实例 | 实例数、最近确认时间 |
| `CONFIGURED` | 已配置 | 有配置/声明证据，当前未确认运行 | `installed=true/false` |
| `INSTALLED` | 已安装 | 只有安装工件证据 | 版本来源 |
| `UNKNOWN` | 未知 | 无正证据、证据冲突、覆盖不足或**本轮未能复核** | `status_basis.conflicts`、`status_basis.unverified_reason` |
| `null` | 状态待确认 | 该资产还没有 V1.2 投影 | 不得当作 `UNKNOWN` 之外的任何值 |

> UI 不得用 `states[]` 渲染状态列。`states` 只允许出现在详情/证据区，并标注“兼容字段”。

#### 2.1.1 四维正交（`basis_version=3`）

状态判定收敛到后端 `aggregation/state_resolver.py`。采集层（detectors、静态复核）只写观察、不写状态；Dashboard 的每一项都来自最近一次扫描的解析结果。

| 维度 | 取值 | 回答 |
| --- | --- | --- |
| `presence` | `PRESENT / ABSENT / UNKNOWN` | 对象还在吗 |
| `agent_status` | `RUNNING / CONFIGURED / INSTALLED / UNKNOWN` | 现在是什么状态（兼容字段） |
| `verification` | `VERIFIED / PARTIAL / FAILED / NOT_CHECKED / STALE` | 本轮结论可信吗 |
| `lifecycle` | `ACTIVE / WATCH / ARCHIVED` | 是否在当前清单 |

判定规则：

1. **RUNNING 只属于本轮**：只有本 generation 写入的运行 Claim 且 `verification in (VERIFIED, PARTIAL)` 时才投影 `RUNNING`。上一轮仍在 TTL 内的运行 Claim 不算本轮结论。
2. **未复核保留上次状态**：某实体本轮所在 scope 失败/未运行（docker 引擎不可达、产品规则崩溃）时，`presence=UNKNOWN`、`verification=FAILED/NOT_CHECKED`、`agent_status=last_known_status`（只可能是 `CONFIGURED/INSTALLED/UNKNOWN`，**绝无 `RUNNING`**），并写入 `status_basis.unverified_reason`。UI 在状态后加“（未复核）”。
3. **旧快照不冒充当前**：读取侧的 `snapshot_current=false` 表示该行不是最近一次覆盖的结果；此时 `verification=STALE`，`agent_status` 回落到 `last_known_status`，`status_basis.stale=true`。
4. **缺席分级**：`presence=ABSENT` 且实体所需 scope 全部 `COMPLETE` → `lifecycle=ARCHIVED`，同时失效旧的 `installed/configured/running` Claim；scope 不完整 → `lifecycle=WATCH`（可见）。没有完整枚举，不得归档。
5. **未知且不可复核 → WATCH**：`presence=UNKNOWN`、`verification=NOT_CHECKED` 且历史上没有任何持久状态（`last_known_status=UNKNOWN`）的实体进入 `WATCH`（“待复核”，可见），而不是伪装成在用的 `ACTIVE`。
6. **新鲜度按 owner scope**：快照记录 `owner_scope_type/owner_scope_key`；读取时与该 scope 最近一次被评估的 run 比较，而不是全局最大 generation。一个无关 scope 的运行不会让所有实体变“未复核”。
6. **每轮全量投影**：本轮看到的、复核到的、以及无法复核的实体都会写当轮快照；读取侧不需要猜。
7. **降级复核（docker 通道，T2）**：docker 深探测失联但 `containers/list` 枚举成功时，被枚举确认仍在的容器/compose 项目出 `presence=PRESENT` + `verification=FAILED`（`reason_code=deep_probe_stalled`，中文理由“容器仍在（本轮枚举确认），深探测失联未复核”），`lifecycle=WATCH`（可见待复核）。`agent_status` 保持 `last_known_status`，`basis.running=false`——枚举层面的事实**绝不**升级出 INSTALLED/RUNNING。缺席/归档结论在失联轮一律不出（规则 4/5 的守卫优先）。

> 升级到 V1.3 后，旧快照没有四维列，读取侧按 `verification=STALE` 处理并显示“（未复核）”，下一次扫描会重写。

### 2.2 保护摘要 `protection.summary`

| 值 | UI 文案 | 判定 |
| --- | --- | --- |
| `PROTECTED` | 已验证阻断 | `hook_state=ENFORCEMENT_VERIFIED`，有真实触发/强制证据 |
| `MONITOR_ONLY` | 仅监测 | Hook 已配置但未验证，或有遥测但无前置拦截 |
| `UNPROTECTED` | 未保护 | 无 Hook 且无遥测覆盖 |
| `UNKNOWN` | 未知 | 数据不足或 Hook 状态冲突 |

**禁止文案**：“已启用防护”“拦截能力已生效”“已保护”，除非 `summary=PROTECTED`。

### 2.3 Hook 状态 `protection.hook_state`

| 值 | UI 文案 | 说明 |
| --- | --- | --- |
| `NOT_CONFIGURED` | 未配置 | 没有本工具的 Hook 条目 |
| `PARTIAL` | 部分接入 | 配置存在但事件条目不完整 |
| `CONFLICT` | 配置冲突 | 文件不可解析/被其他条目占用 |
| `CONFIGURED` | 已配置（未验证） | 配置完整，尚无运行时触发证据 |
| `HOOK_OBSERVED` | 已观测触发 | 收到过该 Agent 的真实 Hook 事件 |
| `ENFORCEMENT_VERIFIED` | 已验证阻断 | 有前置阻断成功的证据 |
| `UNKNOWN` | 未知 | 无法判断 |

### 2.4 Coverage

| 值 | UI 文案 | 说明 |
| --- | --- | --- |
| `COMPLETE` | 覆盖完整 | 该 scope/predicate 可支持缺席裁决 |
| `PARTIAL` | 覆盖不足 | 有权限/截断/部分失败 |
| `FAILED` | 覆盖失败 | 采集阶段失败 |
| `NOT_RUN` | 未运行 | 该 scope 未采集 |

Coverage 是**扫描范围**的完整度，不是资产状态，也不是百分比。UI 不得显示“该资产覆盖 80%”。

### 2.5 事件决策 `decision`

| 值 | UI 文案 |
| --- | --- |
| `allow` | 放行 |
| `ask` | 需确认 |
| `deny` | 已阻断 |
| `audit` | 仅审计 |
| `error` | 决策失败 |

### 2.6 执行状态 `execution_status`

| 值 | UI 文案 |
| --- | --- |
| `pending` | 待执行 |
| `allowed` | 已放行（未确认结果） |
| `blocked_by_hook` | 被 Hook 阻断 |
| `succeeded` | 执行成功 |
| `failed` | 执行失败 |
| `unknown` | 执行结果未知 |

> 事件列表的“结果”列如果只能放一个标签，**必须叫“决策”**；执行状态放第二行或 Drawer。

### 2.7 其他枚举

| 字段 | 值 | UI 文案 |
| --- | --- | --- |
| `risk_level` | `low/medium/high/critical` | 低/中/高/严重 |
| `entity_alias_status` | `OK/AMBIGUOUS/CONFLICT/MISSING` | 已确认/待复核/身份冲突/未映射 |
| `removal_verdict` | `NONE/CANDIDATE/CONFIRMED` | 正常/移除候选/已确认不存在 |
| 关系 `status` | `confirmed/candidate/expired` | 已确认/待关联/已失效 |
| 告警 `status` | `open/acknowledged/resolved` | 未处理/已确认/已解决 |
| 通道 `state` | `OK/DEGRADED/DOWN/UNAVAILABLE/UNKNOWN` | 正常/降级/停止/不可用/未知 |

---

## 3. 通用约定

| 项 | 约定 |
| --- | --- |
| Base path | `/api/v1`；健康检查 `/api/health`（不带版本） |
| 认证 | 无；默认只监听 `127.0.0.1`。浏览器不得调用 `/internal/v1/*` |
| Content-Type | `application/json; charset=utf-8`（SSE 除外） |
| 时间 | ISO-8601，UTC，带 `+00:00`，例如 `2026-11-05T12:34:56+00:00`；UI 转为本地时区并标注 |
| ID | 用户可见主键只有 `entity_id`；legacy `asset_id`/`app_id` 仅作为内部迁移桥，不出现在响应或路由中 |
| 路径键 | 本期路径使用 `entity_id`；无法收敛的历史身份不进入资产列表 |
| 空值 | `null` 表示未知/不可用，**不等于** `false`、`0` 或空数组 |
| 数组 | 无数据返回 `[]`，不返回 `null` |
| 分页 | 列表用 `limit/offset`（agents/claims）；事件用 `before_id/after_id` 游标 |
| 错误 | `{"detail": string \| object}`；422 为 FastAPI 校验数组 |
| 未知字段 | 客户端必须忽略；后端新增字段视为兼容 |
| 响应包装 | 保持裸对象/`{items,total}`，不引入统一 envelope |

### 3.1 `entity_id` 与身份复核

- 列表/详情/事件只返回 `entity_id`；`asset_id`、`app_id`、旧容器绑定 ID 不再暴露给前端。
- `AMBIGUOUS/MISSING/CONFLICT` 的历史身份不进入资产列表，也不生成详情路由；它们写入 `identity_review_cases`，在 `/attention` 中只显示待复核数量，不显示旧 ID。
- `entity_id` 一旦返回即为 `OK`；不返回 `null` 的列表行。
- 旧版控制台不再作为回滚路径；`CONSOLE_UI=legacy` 在切换完成后下线。

### 3.2 轮询、SSE 与扫描

| 场景 | 约定 |
| --- | --- |
| 总览/告警/通道 | 15s 轮询；窗口聚焦时允许立即刷新 |
| 资产列表/详情 | 30s；页面切换不重复拉取未过期数据 |
| 事件页 | **只用 SSE**，不轮询；离开页面关闭 EventSource |
| 扫描 | 同步请求，前端只显示“扫描中”；409 表示已有扫描；不伪造百分比 |
| Hook 安装/卸载 | 先 `apply=false` 预览，用户确认后 `apply=true`；成功后重新 `GET /hooks`；卸载只移除本工具写入的条目，用户已有配置保持不变 |

---

## 4. 视图模型（TypeScript）

> 以下是新控制台的**唯一数据形状**。后端按此返回；前端不得自行拼装业务字段。

```ts
export type AgentStatus = "RUNNING" | "CONFIGURED" | "INSTALLED" | "UNKNOWN";
export type ProtectionSummary = "PROTECTED" | "MONITOR_ONLY" | "UNPROTECTED" | "UNKNOWN";
export type HookState =
  | "NOT_CONFIGURED" | "PARTIAL" | "CONFLICT" | "CONFIGURED"
  | "HOOK_OBSERVED" | "ENFORCEMENT_VERIFIED" | "UNKNOWN";
export type AliasStatus = "OK" | "AMBIGUOUS" | "CONFLICT" | "MISSING";
export type RemovalVerdict = "NONE" | "CANDIDATE" | "CONFIRMED";
export type Presence = "PRESENT" | "ABSENT" | "UNKNOWN";
export type Verification =
  | "VERIFIED" | "PARTIAL" | "FAILED" | "NOT_CHECKED" | "STALE";
export type Lifecycle = "ACTIVE" | "WATCH" | "ARCHIVED";

export interface StatusBasis {
  basis_version: 3;
  presence: Presence;
  verification: Verification;
  lifecycle: Lifecycle;
  reason_code: string;                 // 机器可读的判定原因
  reason: string;                      // 面向用户的短句
  last_known_status: AgentStatus;      // 未复核/陈旧时保留的持久状态
  installed: boolean | null;           // null = 无证据/未知；false 只能来自反驳证据
  configured: boolean | null;
  running: boolean | null;             // true 仅当本 generation 观察到运行
  conflicts: string[];                 // 冲突的 predicate
  claim_ids: Record<string, string[]>; // predicate -> [claim_id]
  verified: boolean;                   // verification in (VERIFIED, PARTIAL)
  unverified_reason?: string;          // verified=false 时的短句原因
  unverified_code?: string;            // scope_failed / scope_not_run / ...
  stale?: boolean;                     // true = 快照来自更早的覆盖
  last_generation_id?: number;         // stale 快照所属的 generation
  scope_checks?: Array<{ scope_type: string; scope_key: string;
                         predicate: string; status: string }>;
}

export interface ProtectionView {
  summary: ProtectionSummary;
  hook_state: HookState;
  basis: {
    enforcement_verified: boolean;
    hook_observed_at: string | null;
    telemetry_running: boolean;
    telemetry_scope: "asset" | "global" | "none";  // 该资产是否被采集覆盖
    reason: string;                    // 面向用户的短句，不得含路径/命令
  };
}

export interface DependencyView {
  asset_id: string;
  agent_type: string;
  name: string;
  version: string;
  states: string[];                    // 兼容字段，不用于状态列
  confidence: number;
}

export interface AgentRow {
  asset_id: string;
  entity_id: string | null;
  entity_alias_status: AliasStatus;
  entity_kind: string | null;          // PRODUCT_INSTALL / SELF_BUILT_APPLICATION / COMPOSE_DEPLOYMENT / CONTAINER_DEPLOYMENT / SERVICE / ENVIRONMENT / UNKNOWN
  name: string;
  agent_type: string;
  vendor: string | null;
  version: string;                     // 无可靠版本时为 "UNKNOWN"
  version_source: string;              // package / image-tag / process-claim / unknown
  agent_status: AgentStatus | null;
  presence: Presence;
  verification: Verification;
  lifecycle: Lifecycle;
  reason_code: string;
  reason: string;
  last_known_status: AgentStatus;      // 未复核/陈旧时展示的状态
  status_basis: Partial<StatusBasis>;  // 无投影时为 {}
  snapshot_generation_id: number | null; // 该行状态来自哪一轮
  snapshot_current: boolean;           // 该行是否属于其 owner scope 最近一次覆盖
  snapshot_projected_at: string | null;
  verified_scopes: Array<{ scope_type: string; scope_key: string;
                           predicate: string; status: string }>;
  owner_scope: { scope_type: string; scope_key: string } | null;
  removal_verdict: RemovalVerdict | null;  // 兼容别名：ARCHIVED→CONFIRMED，WATCH→CANDIDATE
  capability_tags: string[];
  protection: ProtectionView;
  instance_count: number;
  session_count: number;
  dependencies: DependencyView[];
  origin: "host" | "docker";
  container_id: string | null;
  app_id: string | null;
  confidence: number;
  first_seen_at: string;
  last_seen_at: string;

  // 兼容字段：新 UI 不得用于状态/保护列
  states: string[];
  protection_status: string;
  hook_state: string;
}

export interface ClaimsSummary {
  available: boolean;
  completeness: "support_only" | "bidirectional";
  claim_count: number;
  conflicts: string[];
  by_predicate: Record<string, number>;
}

export interface AgentDetail extends AgentRow {
  instances: InstanceView[];
  sessions: SessionView[];
  events: EventView[];                 // 最近 20 条
  evidence: EvidenceView[];            // 扫描证据，不是 Claim
  application: ApplicationView | null;
  components: ComponentView[];
  relations: RelationView[];
  claims_summary: ClaimsSummary;
  coverage: CoverageView;
}

export interface EvidenceView {
  id: number;
  scan_id: number;
  asset_id: string;
  kind: string;
  summary: string;
  detail: Record<string, unknown>;
  confidence: number;
  created_at: string;
}

export interface ApplicationComponentView {
  name: string;
  version: string;
  version_source: string;
  source_path: string | null;
}

export interface ApplicationView {
  app_id: string;
  name: string;
  root_path: string | null;
  runtime: string | null;
  environment_path: string | null;
  entrypoint: string | null;
  entry_kind: string | null;
  container_id: string | null;
  status: string;
  components: ApplicationComponentView[];
  first_seen_at: string;
  last_seen_at: string;
}
```

```ts
export interface InstanceView {
  instance_id: string;
  asset_id: string;
  agent_type: string;
  pid: number;
  ppid: number | null;
  process_guid: string | null;
  process_name: string;
  executable: string | null;
  cmdline: string | null;              // 可能被脱敏/省略
  cwd: string | null;
  parent_chain: string[];
  origin: "host" | "docker";
  container_id: string | null;
  status: "running" | "stopped" | "unverified";  // unverified = 本轮未观测到，不得显示为运行中
  evidence: string[];
  started_at: string | null;
  last_seen_at: string;
}

export interface SessionView {
  session_id: string;
  asset_id: string;
  agent_type: string;
  instance_id: string | null;
  source: string;
  cwd: string | null;
  last_tool: string | null;
  event_count: number;
  started_at: string | null;
  last_event_at: string | null;
  ended_at: string | null;
}

export interface ComponentView {
  component_key: string;
  name: string;
  kind: string;                        // FRAMEWORK / SDK / MCP_SERVER / ...
  version: string;
  version_source: string;
  relation_type: "DEPENDS_ON" | "DECLARES" | string;
  status: "confirmed" | "candidate" | "expired";
  evidence_claim_id: string | null;
}

export interface RelationView {
  relation_type: string;
  status: "confirmed" | "candidate" | "expired";
  from_ref: string;
  to_ref: string;
  label: string;
  version: string | null;
  version_source: string | null;
  evidence_claim_id: string | null;
  valid_from: string | null;
  valid_to: string | null;
}

export interface EndpointView {
  endpoint_id: string;
  protocol: string;
  address: string;
  binding_status: "confirmed" | "candidate" | "expired";
  container_id: string | null;
}
```

```ts
export interface EventActor {
  entity_id: string | null;
  asset_id: string | null;
  instance_id: string | null;
  label: string;                       // agent_label；无归属时可为 "pid-<n>"，UI 另加“未归属”标识
  alias_status: AliasStatus;
  attribution_state: "verified" | "candidate" | "unattributed";
}

export interface EventTarget {
  entity_id: string | null;
  asset_id: string | null;
  endpoint_id: string | null;
  instance_id: string | null;
  label: string | null;                // 目标未知时为 null，不回填 actor
  alias_status: AliasStatus;
}

export interface EventView {
  id: number;
  observed_at: string;
  source: string;                      // native_hook / sysmon / auditd / tetragon / poll / netmon / scan
  event_type: string | null;
  operation: string | null;
  protocol: string | null;
  tool: string | null;
  target: string | null;
  result: string | null;
  risk_level: "low" | "medium" | "high" | "critical" | null;
  decision: "allow" | "ask" | "deny" | "audit" | "error" | null;
  execution_status: "pending" | "allowed" | "blocked_by_hook"
    | "succeeded" | "failed" | "unknown" | null;
  policy_id: string | null;
  session_id: string | null;
  instance_id: string | null;
  process_name: string | null;
  pid: number | null;
  ppid: number | null;
  mcp_server: string | null;
  model: string | null;
  http_status: number | null;
  actor: EventActor;
  target_ref: EventTarget;             // 对象字段，避免与字符串 target 冲突
  evidence: string[];
}
```

> 兼容说明：现有响应已有 `entity_id`、`target_entity_id`、`agent_label`、`target` 等扁平字段；`actor`/`target_ref` 是**新增的规范化视图**，后端由现有字段组装，不改变扁平字段。

```ts
export interface ObservationView {
  observation_id: string;
  source: string;
  source_event_uid: string;
  observed_at: string;
  fact_type: string;
  summary: string;                     // 已脱敏的一行摘要
  payload: Record<string, unknown>;    // 已脱敏；不含文件/命令/凭据
  payload_digest: string;
  retention_class: string;
}

export interface ClaimView {
  claim_id: string;
  predicate: string;
  object_ref: string;
  polarity: "support" | "refute";
  evidence_class: "E1" | "E2" | "E3" | "E4" | "E5";
  verification_method: string;
  rule: { id: string; digest: string; source_path: string | null };
  coverage_scope_id: number | null;
  observed_at: string;
  valid_from: string;
  valid_to: string | null;
  status: "supported" | "superseded";
  is_current: boolean;
  supersedes_claim_id: string | null;
  observations?: ObservationView[];    // include_observations=true 时返回
}

export interface CoverageScopeView {
  scope_type: string;
  scope_key: string;
  own_status: "COMPLETE" | "PARTIAL" | "FAILED" | "NOT_RUN";
  effective_status: "COMPLETE" | "PARTIAL" | "FAILED" | "NOT_RUN";
  truncated: boolean;
  predicates: Array<{ predicate: string; status: string }>;
}

export interface CoverageView {
  available: boolean;
  reason: string | null;               // NO_ENTITY / NO_SCAN / NO_COVERAGE
  scan_id: number | null;
  generation_id: number | null;
  scope: "scan" | "entity";
  summary: {
    scopes: number;
    truncated: number;
    COMPLETE: number;
    PARTIAL: number;
    FAILED: number;
    NOT_RUN: number;
  };
  scopes: CoverageScopeView[];
  notes: string[];
}
```

```ts
export interface AlertView {
  id: number;
  created_at: string;
  asset_id: string | null;
  agent_type: string | null;
  agent_label: string;
  session_id: string | null;
  event_id: number | null;
  policy_id: string | null;
  risk_level: "low" | "medium" | "high" | "critical";
  decision: "allow" | "ask" | "deny" | "audit" | "error";
  status: "open" | "acknowledged" | "resolved";
  title: string;
  reason: string;
  detail: Record<string, unknown>;
  resolved_at: string | null;
}

export interface PolicyView {
  policy_id: string;
  name: string;
  scope: string;
  decision: "allow" | "ask" | "deny" | "audit";
  risk_level: "low" | "medium" | "high" | "critical";
  enabled: boolean;
  priority: number;
  conditions: Record<string, unknown>;
  reason: string;
  updated_at: string;
}

export interface ChannelView {
  id: string;
  name: string;
  available: boolean;
  running: boolean;
  state: "RUNNING" | "STANDBY" | "STOPPED" | "UNAVAILABLE" | "DOWN" | "UNKNOWN";
  detail: string;
  platform: "Windows" | "Linux" | "all";
  last_event_at: string | null;
  status_age_seconds: number | null;
  reason: string | null;
}
```

```ts
export interface AttentionItem {
  kind: "alert" | "identity_conflict" | "coverage_gap"
      | "collector_unhealthy" | "claim_conflict" | "scan_stale";
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
  subject: { asset_id: string | null; entity_id: string | null; label: string };
  occurred_at: string | null;
  route: string;                       // 例： "#/alerts?alert=12"
}

export interface OverviewView {
  agents: {
    total: number;                     // 默认清单口径（不含 ARCHIVED）
    inventory_total: number;           // 含 ARCHIVED 的全部实体
    current_detected: number;          // presence=PRESENT
    confirmed_present: number;         // presence=PRESENT 且已核实
    running: number;                   // 兼容：instance_count>0；新 UI 不读
    running_count: number;             // 同 running_confirmed
    running_confirmed: number;         // 仅 agent_status=RUNNING 且 verification 已核实
    running_unconfirmed: number;       // status=null 且 instance_count>0
    needs_verification: number;        // verification in (FAILED,NOT_CHECKED,STALE)
    archived_total: number;            // lifecycle=ARCHIVED
    running_basis: "agent_status" | "mixed" | "unavailable";
    new_24h: number;
    unknown_status: number;
    by_entity_kind: Record<string, number>;  // 资产类别分布（推荐用于环形图）
    by_type: Record<string, number>;         // 技术类型分布（可选）
    protection: Record<string, number>;             // 兼容：legacy protection_status
    protection_summary: Record<ProtectionSummary, number>; // 四个键必须存在
    hook_states: Partial<Record<HookState, number>>;
  };
  behavior: {
    events_today: number;
    blocked_today: number;
    by_source: Record<string, number>;
    last_event_at: string | null;
  };
  components: { total: number; by_type: Record<string, number> };
  alerts: { alert_count: number; by_status: Record<string, number>;
            by_risk: Record<string, number>; open_high: number };
  recent_events: EventView[];          // 最多 12
  recent_alerts: AlertView[];          // 最多 6
  latest_scan_id: number | null;
  disclaimer: string[];
  /** @deprecated 使用 GET /telemetry/status；新 UI 不读取 */
  channels?: unknown[];
}
```

> 新 UI 读取 `running_confirmed` 与 `running_unconfirmed` 并同时展示，避免把“有运行实例但身份未核验”算成运行中；`running` 仅为旧 UI 保留。

---

## 5. 端点契约

> 示例中的 `[AgentRow]`、`[EventView]` 等表示“该类型的数组”，是契约占位写法，不是字面 JSON；实际响应必须是合法 JSON。

### 5.1 `GET /api/v1/overview` `[EXTEND]`

**新增字段（相对现状）**

| 字段 | 类型 | 规则 | 数据来源 |
| --- | --- | --- | --- |
| `agents.running_confirmed` | int | `agent_status=RUNNING` 且 `verification in (VERIFIED,PARTIAL)` | 投影 |
| `agents.running_unconfirmed` | int | `agent_status=null` 且 `instance_count>0` | 同上 + instances |
| `agents.inventory_total` | int | 含 ARCHIVED 的实体总数 | `EntityRepository.list_agents(include_hidden=True)` |
| `agents.current_detected` | int | `presence=PRESENT`（默认清单口径） | 投影 |
| `agents.confirmed_present` | int | `presence=PRESENT` 且已核实 | 投影 |
| `agents.needs_verification` | int | `verification in (FAILED,NOT_CHECKED,STALE)` | 投影 |
| `agents.archived_total` | int | `lifecycle=ARCHIVED` | 投影 |
| `agents.running_count` | int | 同 `running_confirmed`（新字段，语义明确） | 投影 |
| `agents.running_basis` | enum | 全部有投影 `agent_status`；部分 `mixed`；全无 `unavailable` | 投影覆盖情况 |
| `agents.new_24h` | int | `first_seen_at >= now-24h` | `AgentAssetRow.first_seen_at` |
| `agents.unknown_status` | int | `agent_status in (null, UNKNOWN)` | 投影 |
| `agents.by_entity_kind` | map | 合并后实体的 `EntityRow.kind` 计数；环形图首选 | alias → `entities.kind` |
| `agents.by_type` | map | 合并后实体的 `agent_type` 计数；技术类型辅助 | view 层 |
| `agents.protection_summary` | map | `ProtectionSummary` 计数 | 见 §5.3 |
| `agents.hook_states` | map | `HookState` 计数 | 快照 hook_state |
| `agents.running` | int | **保持 legacy**：`instance_count>0`；新 UI 不读 | 现有实现 |
| `agents.protection` | map | **保持 legacy**：`protection_status` 计数；新 UI 不读 | 现有实现 |
| `agents` 其他旧字段 | — | 保持 | — |

**移除/弃用**

- `channels`：**弃用**，改由 `GET /telemetry/status` 提供；保留一个版本，新 UI 不得读取。
- 不新增 `trend`；趋势由 `GET /events/timeseries` 提供。
- 不新增 `attention` 嵌入字段；如有独立队列需求，由 `GET /attention` 提供（当前总览不展示）。

**错误**：500 仅在上游数据库不可读时；UI 显示“无法读取总览”，不回退到假数据。

---

### 5.2 `GET /api/v1/agents` `[EXTEND]`

**Query**

| 参数 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `q` | string | — | 名称/类型模糊匹配（大小写不敏感） |
| `agent_type` | string | — | 精确匹配 |
| `agent_status` | enum | — | `RUNNING/CONFIGURED/INSTALLED/UNKNOWN` |
| `protection` | enum | — | `PROTECTED/MONITOR_ONLY/UNPROTECTED/UNKNOWN` |
| `alias_status` | enum | — | `OK/AMBIGUOUS/CONFLICT/MISSING` |
| `origin` | enum | — | `host/docker` |
| `lifecycle` | enum | — | `ACTIVE/WATCH/ARCHIVED`；ARCHIVED 仅在 `include_removed=true` 时返回 |
| `verification` | enum | — | `VERIFIED/PARTIAL/FAILED/NOT_CHECKED/STALE` |
| `needs_verification` | bool | false | 等价于 `verification in (FAILED,NOT_CHECKED,STALE)` |
| `include_stopped` | bool | false | 是否包含已停止实例的资产 |
| `include_removed` | bool | false | 是否返回 `lifecycle=ARCHIVED`（已确认不存在）。`WATCH` 候选默认可见，不受此参数影响 |
| `limit` | int | 100 | 1–500 |
| `offset` | int | 0 | 合并后分页 |

**Response**

```json
{
  "items": [AgentRow],
  "total": 12,
  "limit": 100,
  "offset": 0
}
```

- `total` 是**过滤后**总数；分页发生在 `merge_agent_rows` 之后。
- 排序：`name` 升序，稳定。
- 空结果 200 + `items: []`。
- 非法枚举 422。

**UI**：列表只渲染 5–6 列（名称、状态、保护、最近确认、关注项）；`states`、MCP、实例/会话不放列表。

**合并行的保护语义**：`merge_agent_rows` 可能把框架行折叠进应用/容器实体。合并后的 `protection` 只能来自**该实体自身**的 Hook/覆盖证据；不得把某个依赖框架的 Hook 状态提升为整个应用“已保护”。无法确定时返回 `UNKNOWN`。  
同理，`agent_status` 只能取该实体自身的投影；不得从依赖成员“取最大值”推断应用运行中。没有投影时返回 `null`，由 UI 显示“状态待确认”。

---

### 5.3 `GET /api/v1/agents/{asset_id}` `[EXTEND]`

**Response**

```json
{
  "asset_id": "...",
  "entity_id": "...",
  "entity_alias_status": "OK",
  "name": "Claude Code",
  "agent_type": "claude_code",
  "agent_status": "RUNNING",
  "status_basis": { "installed": true, "configured": true, "running": true,
                    "conflicts": [], "claim_ids": {} },
  "protection": {
    "summary": "MONITOR_ONLY",
    "hook_state": "CONFIGURED",
    "basis": {
      "enforcement_verified": false,
      "hook_observed_at": null,
      "telemetry_running": true,
      "telemetry_scope": "global",
      "reason": "Hook 已配置，尚未观测到实际阻断"
    }
  },
  "instances": [InstanceView],
  "sessions": [SessionView],
  "events": [EventView],
  "evidence": [EvidenceView],          // 扫描证据，不是 Claim
  "components": [ComponentView],
  "relations": [RelationView],         // [NEW]
  "claims_summary": {                  // [NEW]
    "available": true,
    "completeness": "support_only",
    "claim_count": 8,
    "conflicts": [],
    "by_predicate": { "running": 1, "configured": 2, "installed": 1 }
  },
  "coverage": CoverageView,            // [NEW]
  "application": null,
  "dependencies": []
}
```

- `evidence` 保持现有扫描证据语义；**不得**把它当 Claim 展示。
- `404`：不存在该 `asset_id`。
- `relations`/`claims_summary`/`coverage` 在数据不可用时返回空数组/`available:false`，**不返回 404**。
- `GET /api/v1/agents/{asset_id}/mcp` 保持独立：只返回 MCP 服务名称与传输类型；命令、参数、环境变量不入库也不返回（`console/api/agents.py:104-115`）。
- 详情内联的 `instances/sessions/events/evidence` 只是最近 20 条；完整列表/分页继续用现有子端点 `/{id}/instances|sessions|events|evidence`。

**保护对象（新增）**

`protection` 是列表/详情共用字段，由后端根据快照投影：

| `hook_state` | `summary` | `reason` 示例 |
| --- | --- | --- |
| `ENFORCEMENT_VERIFIED` | `PROTECTED` | 已验证工具调用被前置阻断 |
| `HOOK_OBSERVED` | `MONITOR_ONLY` | 已观测 Hook 事件，尚未验证强制阻断 |
| `CONFIGURED` | `MONITOR_ONLY` | Hook 已配置，尚未观测到实际触发 |
| `PARTIAL/CONFLICT` | 有遥测：`MONITOR_ONLY`；无遥测：`UNKNOWN` | Hook 配置不完整/冲突 |
| `NOT_CONFIGURED` + 遥测（`telemetry_scope=asset`） | `MONITOR_ONLY` | 该资产被采集覆盖，仅监测 |
| `NOT_CONFIGURED` + 遥测（仅 `telemetry_scope=global`） | `MONITOR_ONLY`，`reason` 标注“全局采集已开启，资产覆盖未确认” | 不得声称该资产被监测 |
| `NOT_CONFIGURED` + 无遥测 | `UNPROTECTED` | 无 Hook 也无采集覆盖 |
| `UNKNOWN` | `UNKNOWN` | 保护状态无法判断 |

> 在 `ENFORCEMENT_VERIFIED` 尚未实现前，`PROTECTED` 计数应为 0。这是**预期结果**，不是 bug。  
> B0 阶段如果只能拿到全局 `behavior.running`，必须返回 `telemetry_scope:"global"`，不得冒充 `asset` 级覆盖。  
> `status_basis` 是三态：`false` 只能来自反驳/缺席证据；当前 `StatusProjection` 把“没有支持 Claim”当成 `false`，B0 必须改为 `null`，否则证据页会把“没看到”显示成“未安装”。  
> `hook_observed_at` 当前没有持久化字段，B0 返回 `null`；不得用扫描时间冒充“观测到 Hook 触发”。

```python
# B0 投影伪代码（不要放在 UI 里）
def protection_view(snapshot, telemetry_running, telemetry_scope):
    hs = snapshot.hook_state if snapshot else "UNKNOWN"
    if hs == "ENFORCEMENT_VERIFIED":
        summary = "PROTECTED"
    elif hs in ("CONFIGURED", "HOOK_OBSERVED"):
        summary = "MONITOR_ONLY"
    elif hs in ("PARTIAL", "CONFLICT"):
        summary = "MONITOR_ONLY" if telemetry_running else "UNKNOWN"
    elif hs == "NOT_CONFIGURED":
        summary = "MONITOR_ONLY" if telemetry_running else "UNPROTECTED"
    else:
        summary = "UNKNOWN"
    return {
        "summary": summary,
        "hook_state": hs,
        "basis": {
            "enforcement_verified": hs == "ENFORCEMENT_VERIFIED",
            "hook_observed_at": snapshot.hook_observed_at if snapshot else None,
            "telemetry_running": telemetry_running,
            "telemetry_scope": telemetry_scope,
            "reason": reason_for(summary, hs, telemetry_scope),
        },
    }
```

---

### 5.4 `GET /api/v1/agents/{asset_id}/claims` `[NEW]`

**Query**

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `current` | true | 只返回当前有效 Claim |
| `predicate` | — | 过滤 predicate |
| `polarity` | — | `support/refute` |
| `include_observations` | false | 是否内联 Observation |
| `limit` | 50 | 1–200 |
| `offset` | 0 | — |

**Response**

```json
{
  "available": true,
  "asset_id": "...",
  "entity_id": "...",
  "completeness": "support_only",
  "items": [ClaimView],
  "conflicts": ["running"],
  "notes": [
    "当前仅记录支持性 Claim；反驳与缺席裁决尚未接入（P0-B 之后）。",
    "Claim 的有效期由 valid_from/valid_to 决定；过期 Claim 不参与状态投影。"
  ]
}
```

- `entity_id=null` → 200，`available:false`，`reason:"NO_CANONICAL_ENTITY"`，`items:[]`。
- `completeness` 当前固定 `support_only`；后端实现反驳 Claim 后改为 `bidirectional`。
- 规则来源：`rule.source_path` 只返回打包内路径/规则 ID，不返回用户文件内容。

**UI**：证据 Tab 顶部显示结论与 `status_basis.conflicts`；列表按 predicate 分组；每条 Claim 可展开 Observation。没有反驳时显示“暂无反驳记录（能力未接入）”，**不得**显示“无争议”。

---

### 5.5 `GET /api/v1/agents/{asset_id}/coverage` `[NEW]`

**Response**

```json
{
  "available": true,
  "reason": null,
  "scan_id": 42,
  "generation_id": 42,
  "scope": "entity",
  "summary": { "scopes": 6, "truncated": 1, "COMPLETE": 3, "PARTIAL": 2,
               "FAILED": 0, "NOT_RUN": 1 },
  "scopes": [CoverageScopeView],
  "notes": [
    "Coverage 表示本次采集范围的完整度，不代表资产是否存在。",
    "PARTIAL/FAILED 不能用于隐藏或删除资产。"
  ]
}
```

- 没有扫描/覆盖：200，`available:false`，`reason:"NO_COVERAGE"`。
- `scope` 为 `entity` 时只返回与该实体相关的 scope；为 `scan` 时是全局摘要。
- **不返回百分比**。

---

### 5.6 `GET /api/v1/agents/{asset_id}/relations` `[NEW]`

**Query**：`status`（`confirmed/candidate/expired`）、`type`、`include_expired`（默认 false）。

**Response**

```json
{
  "items": [RelationView],
  "groups": {
    "components": [ComponentView],
    "instances": [InstanceView],
    "endpoints": [
      { "endpoint_id": "...", "protocol": "http", "address": "127.0.0.1:8080",
        "binding_status": "confirmed", "container_id": "..." }
    ]
  },
  "notes": [
    "candidate 关系显示为“待关联”，不得自动折叠进同一资产。",
    "Endpoint 归属只在端口拓扑闭环时标记 confirmed。"
  ]
}
```

- `candidate` → UI “待关联”；`expired` 默认不返回。
- 若实体没有 V1.2 `component_relations`（通常是 V1.2 之前发现、之后未再扫描的应用），后端回退读取该资产 `app_id` 的 `application_components`，返回只读 `DEPENDS_ON` 组件：`version_source=package-metadata` → `confirmed`，`locked/declared` → `candidate`。新图一旦写入，回退自动失效。
- 第一版不做力导向图，只做分组列表 + 紧凑树。

---

### 5.7 `GET /api/v1/events` `[EXTEND]`

**Query 新增**

| 参数 | 说明 |
| --- | --- |
| `after_id` | 向前增量（不含），用于 SSE 补发/追赶 |
| `until` | 上界时间（ISO） |
| `entity_id` | 按 canonical actor 过滤 |
| `execution_status` | 按执行状态过滤 |

保留 `before_id`、`limit`、`source`、`asset_id`、`agent_label`、`event_type`、`session_id`、`risk_level`、`decision`、`since`。

**Response**

```json
{
  "items": [EventView],
  "total": 100,
  "next_before_id": 1234,
  "next_after_id": 1300
}
```

- `total` 为本次返回条数（兼容现状），不是全库总数；翻页用 `next_before_id/next_after_id`，不适用的一侧为 `null`。
- `before_id` 用于向下翻历史；`after_id` 用于向前追赶；两者不能同时使用（422）。
- 路由注册顺序：`/events/stats`、`/events/stream` 必须在 `/events/{event_id}` 之前，避免被动态路由吞掉。
- `actor`/`target_ref` 由后端组装：
  - `actor.entity_id` 为空且 `attribution_state=unattributed` → `label` 保留 `agent_label`（可能是 `pid-123`），UI 显示“未归属”标识，**不得**伪造资产名；
  - `target_ref.entity_id/asset_id` 为空 → `label=null`，**不得**回填 actor 信息；原始命令仍看 `target` 字符串。
- `decision` 与 `execution_status` 分别返回，不允许合并成一个“结果”字段。

---

### 5.8 `GET /api/v1/events/{event_id}` `[NEW]`

- 返回单个 `EventView` + `evidence`；404 表示事件不存在。
- 用于告警 Drawer 的“关联事件”深链，避免前端再拉整页列表。

---

### 5.9 `GET /api/v1/events/stats` `[EXTEND]`

新增 query：`since`（可选，统计窗口起点）。  
新增响应字段：

| 字段 | 说明 |
| --- | --- |
| `by_decision` | `allow/ask/deny/audit/error` 计数 |
| `by_execution_status` | `pending/allowed/blocked_by_hook/succeeded/failed/unknown` 计数 |

保留 `event_count/by_protocol/by_agent/by_operation/by_source/by_risk`。

- `decision=null` 计入 `by_decision.none`；不要混入 `allow`。
- `execution_status=null` 计入 `by_execution_status.unknown`。

---

### 5.10 `GET /api/v1/events/timeseries` `[NEW]`

**Query**

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `window` | `24h` | `1h/6h/24h/7d`，与 `since/until` 二选一 |
| `bucket` | `hour` | `hour/day` |
| `source` | — | 通道过滤 |
| `risk_level` | — | 风险过滤 |
| `entity_id` | — | 归属过滤 |

**Response**

```json
{
  "bucket": "hour",
  "timezone": "UTC",
  "points": [
    { "start": "2026-11-05T00:00:00+00:00",
      "end": "2026-11-05T01:00:00+00:00",
      "events": 12, "blocked": 0 }
  ]
}
```

- 返回**连续**桶（无事件补 0），便于折线图。
- `blocked` = `decision=deny` 的计数；不是 `execution_status` 的计数。
- 最多 168 个点；超限 422。
- UI 按本地时区显示，但不得改变桶边界语义。

---

### 5.11 `GET /api/v1/events/stream` `[EXTEND]`

**SSE 契约**

| 项 | 约定 |
| --- | --- |
| `Content-Type` | `text/event-stream` |
| 帧格式 | 每条事件：`id: <event.id>` + `event: event` + `data: <EventView JSON>` |
| `retry` | 服务端发送 `retry: 2000` |
| 心跳 | 空闲时发送 `: keep-alive` 注释，不产生 UI 事件 |
| 恢复 | 支持 `Last-Event-ID` 请求头；只补发 `id > last_id` |
| 初始 | `initial=N` 先发最近 N 条（按 id 升序）；若同时带 `Last-Event-ID`，以恢复游标为准，`initial` 忽略 |
| 积压 | 若积压超过 `max_replay=1000`，发送 `event: gap` + `data: {from_id,to_id,count}`，随后从最新继续；客户端必须重新拉 `/events?after_id=from_id` |
| 断线 | 浏览器 EventSource 自动重连并携带 `Last-Event-ID`；前端不得重置游标 |
| 过滤 | 仅支持 `source`；其他过滤在前端做，避免服务端多流 |

**客户端要求**

- 按 `event.id` 去重。
- 用户向上翻历史时暂停插入，显示“有 N 条新事件”，点击后插入。
- DOM 行数上限 500；超出时移除最旧行并补偿滚动。
- 收到 `gap` 必须走一次 REST 追赶，不能只显示新事件。
- 页面卸载/切换筛选时关闭 EventSource。

> 现有实现每次只取最新 50 条再过滤，爆发时会永久跳过中间事件（`console/api/events.py:108-118`）；本契约要求改为按 `id > last_id` 的增量查询。

---

### 5.11.1 `GET /api/v1/attention` `[NEW]`

首屏“待关注”的可选来源，避免前端自己拼规则。**当前 React 总览未展示该列表**（经产品确认，首屏不再放置待关注卡）；端点保留为 API，后续如需独立队列页可直接复用。

**Query**：`limit`（默认 5，最大 20）。

**Response**

```json
{
  "items": [AttentionItem],
  "generated_at": "2026-11-05T12:34:56+00:00"
}
```

**生成规则（冻结）**

| `kind` | 触发 | `severity` | `route` |
| --- | --- | --- | --- |
| `alert` | `status=open` 且 `risk in (high,critical)` | 对应风险 | `#/alerts?alert=<id>` |
| `claim_conflict` | `status_basis.conflicts` 非空 | high | `#/assets/<asset_id>?tab=evidence` |
| `identity_conflict` | `entity_alias_status in (AMBIGUOUS,CONFLICT)` | high | `#/assets/<asset_id>` |
| `coverage_gap` | 最近扫描 `PARTIAL/FAILED` | medium | `#/collectors?tab=coverage` |
| `collector_unhealthy` | `telemetry.health.state in (DEGRADED,NOT_RUNNING)` 或任一通道 `DOWN` | high | `#/collectors` |
| `scan_stale` | 最近扫描超过 24h 或从未扫描 | low | `#/overview` |

- 按 `severity`（critical→low）再按 `occurred_at` 倒序，取前 `limit` 条。
- **不得**把开发 TODO（例如“证据聚合待完善”）作为 attention item；这类信息放设置/诊断。
- 每项必须有 `subject.label`；没有可点击对象时 `route` 指向对应列表页。

---

### 5.12 告警 `[EXTEND]`

| 端点 | 状态 | 说明 |
| --- | --- | --- |
| `GET /api/v1/alerts` | 扩展 | 新增 `event_id`、`offset`；保留 `status/risk_level/asset_id/limit` |
| `GET /api/v1/alerts/{alert_id}` | 新增 | 单条告警，404 |
| `PATCH /api/v1/alerts/{alert_id}` | 已存在 | body `{"status":"open\|acknowledged\|resolved"}`；非法值 422 |

- 列表响应保留 `stats`（含 `open_high`），供 KPI 使用。
- 告警 Drawer 通过 `event_id` 调 `GET /events/{id}`。

---

### 5.13 策略 `[EXISTS]`

| 端点 | 说明 |
| --- | --- |
| `GET /api/v1/policies` | 返回 `items/total/decision_engine/failure_mode/status` |
| `PUT /api/v1/policies/{policy_id}` | body `{"enabled"?: bool, "decision"?: "allow\|ask\|deny\|audit"}`；404/422 |
| `POST /api/v1/policies/reload` | 重新加载规则 |

- 表格列：名称、优先级、决策、风险、启用状态；条件/说明放 Drawer。
- 不提供“可视化条件编辑器”或“策略签名”；没有后端支持的能力不得出现在 UI。

---

### 5.14 采集与通道 `[EXTEND]`

`GET /api/v1/telemetry/status` 作为**唯一**通道状态源；`/overview.channels` 弃用。

**新增聚合健康**

```json
{
  "host_platform": "Windows",
  "health": {
    "state": "OK",
    "basis": ["behavior/sysmon running"],
    "last_event_at": "2026-11-05T12:00:00+00:00",
    "last_event_age_seconds": 12
  },
  "channels": [ChannelView],
  "behavior": { "running": true, "mode": "sysmon", "events": 42 },
  "monitor": { "running": true, "hits": 3 }
}
```

**聚合规则（冻结）**

“核心采集通道”指当前平台实际使用的行为通道：Sysmon / Tetragon / auditd / poll 之一；netmon 是可选通道，不折叠进全局 `health`。native_hook **不在** `channels` 清单中：Hook 是每 Agent 的安装项，状态由 `GET /api/v1/hooks` 提供（采集页 Hook 安装区），不计入全局 `health`。

**行为通道互斥（冻结）**：Sysmon / Tetragon / auditd / poll 组成一个互斥组，同一时刻**至多一个** `RUNNING`。`channels[].state` 枚举与语义（由后端计算，UI 不自行拼装）：

| state | 语义 |
| --- | --- |
| `RUNNING` | 该通道是互斥组的活跃通道，服务正在以它采集 |
| `STANDBY` | 本机可用、但活跃通道是组内另一个通道（待命） |
| `STOPPED` | 行为采集服务未运行（或 netmon 未启用） |
| `UNAVAILABLE` | 本平台不可用（如 Windows 上的 auditd） |
| `DOWN` | 活跃通道异常（服务在跑但该通道读不到数据） |

启动即切换：`POST /behavior/start` 在组内已有通道运行时**先停掉它**再启动目标通道（同一请求内完成，不返回 409）；409 仅保留给通道不可用/参数非法，且**目标通道就绪检查失败时当前通道保持不变**（Linux 上 auditd 日志 / Tetragon 导出文件通常 root-only，非 root 启动会得到带修复提示的 409）。UI 对 `STANDBY → 启动` 的切换先弹确认框。

| 条件 | `health.state` | UI |
| --- | --- | --- |
| 核心行为通道 `running=true`，且没有核心通道 `DOWN` | `OK` | 采集正常 |
| 核心行为通道 `running=true`，但存在 `DOWN` | `DEGRADED` | 部分通道异常 |
| 核心行为通道 `running=false`，且 netmon 也未运行 | `NOT_RUNNING` | 未开启采集 |
| 状态文件不可读/超时 | `UNKNOWN` | 状态未知 |

- `status_age_seconds > 120` 视为 `DEGRADED`，不得继续显示“正常”。
- `channels[].control`：`behavior`（Sysmon/Tetragon/auditd/进程采样，启停走 `/behavior/*`，start 的 mode=通道 `id`，启动即互斥切换）| `monitor`（出站连接观察，启停走 `/monitor/*`）。UI 对所有 `control` 非空的通道统一渲染启停按钮（`RUNNING` 显示“停止”，其余显示“启动”）；`available=false` 的通道按钮照常显示，**启动条件由后端校验**：不满足时 start 返回 409 与中文/英文原因文案（如"Sysmon 通道不可用：…"、"cannot read audit log …"），UI 以消息提示展示，不自行预判。
- netmon 停止不使全局变为 `DEGRADED`，通道清单中显示 `STOPPED`；Hook 是**每 Agent** 的能力，不在通道清单中，不计入全局 `health`。
- 顶部 chip 只显示 `health.state`；点击进入采集页看逐通道状态。

其他端点保持：`GET /telemetry/audit-rules`、`POST /telemetry/monitor/start|stop`、`POST /telemetry/behavior/start|stop`。

---

### 5.15 Hook `[EXISTS]`

| 端点 | 说明 |
| --- | --- |
| `GET /api/v1/hooks` | 每个 Agent 的 `state/support/schema_verified/entries/notes` + `events/docs_url` |
| `POST /api/v1/hooks/{agent_type}/plan` | dry-run；返回 `config_path/command/events/fail_closed/existing/merged/changed/written=false` |
| `POST /api/v1/hooks/{agent_type}/install` | `apply=false` 默认只预览；`apply=true` 写入并备份 |
| `POST /api/v1/hooks/{agent_type}/uninstall` | 同上 |
| `GET /api/v1/hooks/{agent_type}/snippet` | 打印片段 |

- `install/uninstall` 的 `apply=false` 必须与 `plan` 等价，且 `written=false`。
- 成功后返回 `backup` 路径；UI 必须展示，不可隐藏。
- 400：未知 `agent_type` 或配置不可解析；UI 显示原因，不重试。
- **两个 Hook 状态词表不要混用**：
  - `GET /hooks` 的 `state` 是**安装检查**枚举：`INSTALLED / NOT_INSTALLED / PARTIAL / CONFLICT / UNSUPPORTED / UNKNOWN`，用于采集页；
  - `protection.hook_state` 是**快照投影**枚举：`NOT_CONFIGURED / PARTIAL / CONFLICT / CONFIGURED / HOOK_OBSERVED / ENFORCEMENT_VERIFIED / UNKNOWN`，用于资产/总览。
  - UI 不得把 `INSTALLED` 直接映射成“已保护”。

---

### 5.16 系统与能力 `[EXISTS]`

- `GET /api/v1/system`：版本、平台、服务地址、数据库路径、策略/ Hook 状态、通道、保留策略、检测规则、支持矩阵、范围说明。设置页只读展示；敏感信息（Token）不返回。
- `GET /api/v1/capabilities`：能力清单。UI 用它隐藏未实现模式，**不得**用它宣称已保护。

---

### 5.17 发现与扫描 `[EXTEND]`

| 端点 | 说明 |
| --- | --- |
| `POST /api/v1/discovery/scan` | body `{active?:bool, docker?:bool}`；同步；409 表示已有扫描 |
| `GET /api/v1/discovery/scan/status` | `{running, started_at, mode}`；进程内真实扫描状态，页面刷新后仍据此显示"扫描中" |
| `GET /api/v1/discovery/scans` | 扫描历史；`stats` 以 `entity_id` 为键（`entity_inventory` / `entity_summaries` / `detections`），不含 `asset_id`/`app_id` |
| `GET /api/v1/discovery/assets` | 组件资产 |
| `GET /api/v1/discovery/applications` | 自建应用 |
| `GET /api/v1/discovery/summary` | 计数摘要 |

- 扫描响应已包含 `coverage`、`identity_shadow`、`errors`；UI 只显示“完成/失败/进行中”，不显示伪造进度。
- `stats.docker`（代码层字段，UI 不直接渲染）：`containers_total` / `candidates` / `agents` / `container_errors[]` / `degraded`（本轮深探测失联、走降级复核的容器数）/ `probe_cache`（`{hits, misses, stores}`，T1 摘要缓存计数）/ `error`（非空即本轮失联，缺席判定一律不出）。后端测试钉住这些键；新增键只做加法。
- `409` 文案：“已有扫描在进行中”；不得自动重试。

---

## 6. 兼容与弃用

| 字段 | 状态 | 新 UI 是否可读 | 计划 |
| --- | --- | --- | --- |
| `asset_id` / `app_id` / 嵌套 `asset_id` | 已移除 | 否 | V1.2 canonical cutover；旧 ID 仅保留在 `entity_aliases` 内部 |
| `states[]` | 已移除 | 否 | 由 `agent_status` 取代 |
| `protection_status` | 已移除 | 否 | 由 `protection.summary` 取代 |
| 扁平 `hook_state` | 已移除 | 否 | 由 `protection.hook_state` 取代 |
| `/overview.channels` | 兼容 | 否 | 由 `/telemetry/status` 取代 |
| `evidence`（资产详情） | 已移除 | 否 | 证据改用 claims/observations |
| `agent_status` | 正式 | 是 | — |
| `protection` | 新增 | 是 | 本文冻结 |
| `relations/claims/coverage` | 新增 | 是 | 见 §5 |

**过渡规则**

1. 新字段一律加法；旧字段在 canonical 切换完成后一次性移除。
2. 旧版控制台不再支持；`CONSOLE_UI` 仅保留 `next`。
3. 删除旧表前，必须有一次数据审计确认 canonical 覆盖率达标。
4. `entity_aliases` 永久保留，作为历史事件/告警的只读桥。

> **注意**：`/overview.agents.protection` 保持 legacy 语义（`protection_status`），新 UI 改读 `protection_summary`；`running` 保持 `instance_count>0`，新 UI 改读 `running_confirmed`。过渡期两套字段并存，旧 UI 不回归。  
> 因此同一资产可能在旧 UI 显示“已启用拦截”、在新 UI 显示“仅监测（Hook 已配置，未验证阻断）”。这是**语义修正**，不是数据不一致；验收时以新 UI 为准。

---

## 7. 刷新、缓存与实时（前端实现约定）

| 资源 | Query key | 刷新 |
| --- | --- | --- |
| 总览 | `["overview"]` | 15s + 窗口聚焦 |
| 资产列表 | `["agents", filters]` | 30s |
| 资产详情 | `["agent", assetId]` | 30s |
| 证据/关系/覆盖 | `["agent", id, "claims"/"relations"/"coverage"]` | 60s，切 Tab 时才请求 |
| 事件 | `["events", filters]` | 不轮询；SSE 增量 |
| 告警 | `["alerts", filters]` | 15s |
| 策略 | `["policies"]` | 60s |
| 通道 | `["telemetry"]` | 15s |
| 设置 | `["system"]` | 300s |

- 同一数据只允许一个活跃 query；切 Tab 不重复请求未过期数据。
- 事件 SSE 写入 `queryClient.setQueryData`，按 id 去重。
- 页面隐藏（`document.visibilityState=hidden`）时暂停 UI 插入，但不断开 SSE。
- 错误不自动重试 4xx；5xx 最多指数退避 2 次，之后显示重试按钮。
- 静态缓存：`index.html` `no-cache`；`/assets/*` 内容哈希 `immutable`；API `no-store`。

---

## 8. 安全与隐私

- 浏览器只访问同源 `/api/v1`；**不得**调用 `/internal/v1/hooks/decide`。
- 默认只监听 `127.0.0.1`；UI 不提供修改监听地址的入口。
- 不返回：文件内容、对话内容、凭据、环境变量、MCP 命令/参数、完整 argv（如被脱敏则 `null`）。
- Observation `payload` 必须已脱敏；`summary` 不得拼接敏感字段。
- Hook 安装：默认 dry-run；`apply=true` 才写入；写入前备份；UI 必须展示 diff/备份路径。
- 扫描/Hook 写操作必须显示明确结果；成功前不得显示最终成功状态。

---

## 9. 契约验收

### 9.1 数据诚实矩阵

| # | 场景 | 期望 API | 期望 UI |
| --- | --- | --- | --- |
| 1 | Hook 配置完整，从未触发 | `protection.summary=MONITOR_ONLY`, `hook_state=CONFIGURED` | “仅监测（Hook 已配置，未验证阻断）” |
| 2 | 有前置阻断成功证据 | `summary=PROTECTED`, `hook_state=ENFORCEMENT_VERIFIED` | “已验证阻断” |
| 3 | `agent_status=null`，有实例 | `running_unconfirmed+1` | “状态待确认”，不显示“运行中” |
| 4 | `agent_status=UNKNOWN` | 状态原样 | 灰色“未知”，不显示红色故障 |
| 4a | 没有任何安装证据 | `status_basis.installed=null` | “未知”，不显示“未安装” |
| 4b | 本轮所在 scope 无法复核（docker 引擎不可达） | `presence=UNKNOWN`, `verification=FAILED/NOT_CHECKED`, `agent_status=last_known_status`, `status_basis.verified=false` + `unverified_reason`，实例 `status=unverified` | “已配置（未复核）”；不显示“运行中”，也不把实例算进运行数 |
| 4b-1 | docker 深探测失联，但容器被枚举确认仍在（T2 降级复核） | `presence=PRESENT`, `verification=FAILED`, `reason_code=deep_probe_stalled`, `lifecycle=WATCH`, `agent_status=last_known_status`, `basis.running=false` | 可见，标“（未复核）”与中文降级理由；既不消失/归档，也不显示“运行中” |
| 4c | 快照不属于其 owner scope 最近一次覆盖 | `verification=STALE`, `agent_status=last_known_status`, `snapshot_current=false`, `status_basis.stale=true` | “（未复核）”；不沿用上一轮的 `RUNNING` |
| 4d | `presence=ABSENT` 且所需 scope 全部完整 | `lifecycle=ARCHIVED`, `removal_verdict=CONFIRMED` | 默认隐藏；`include_removed=true` 可见 |
| 4e | `presence=ABSENT` 但 scope 不完整 | `lifecycle=WATCH`, `verification=NOT_CHECKED` | 可见，标“待复核” |
| 5 | alias `AMBIGUOUS` | `entity_id=null`，claims `available=false` | “待复核”；不合并、不隐藏 |
| 6 | Coverage PARTIAL | attention `coverage_gap` | “覆盖不足”，不显示“不存在” |
| 7 | `decision=allow`, `execution_status=failed` | 两字段独立 | “放行” + “执行失败” |
| 8 | `decision=deny`, `execution_status=blocked_by_hook` | 两字段独立 | “已阻断” + “被 Hook 阻断” |
| 9 | `decision=audit` | 原样 | “仅审计” |
| 10 | 事件 target 未知 | `target_ref.label=null` | “未归属目标”，不填 actor |
| 11 | 扫描已在进行 | 409 | “已有扫描在进行中” |
| 12 | Hook `apply=false` | `written=false` | 只显示预览，不显示“已安装” |
| 13 | 策略 PUT 非法 decision | 422 | 回滚旧值 + 错误原因 |
| 14 | SSE 爆发 120 条 | `id` 连续，无跳号 | 不丢事件；重连可补 |
| 15 | SSE 积压 >1000 | `event: gap` | 自动 REST 追赶，不静默丢 |

### 9.2 后端测试

- 为 §5 每个 `[NEW]/[EXTEND]` 响应加 Pydantic response model 或 JSON Schema 快照。
- `pytest` 覆盖：空库、单资产、别名歧义、覆盖 PARTIAL、decision/execution 组合、SSE id/Last-Event-ID、409/422。
- 契约测试使用固定 `freezegun` 时间，避免 24h 桶边界漂移。

### 9.3 前端测试

- MSW fixture 必须与后端 golden JSON 同源（脚本生成或提交同一份）。
- 组件测试覆盖 §9.1 的 15 个场景；图表只测数据映射，不测画布像素。
- Playwright 只覆盖关键路径：总览→资产→事件→告警；Hook dry-run；扫描 409。

---

## 10. 实施顺序与依赖

| 批次 | 内容 | 依赖 |
| --- | --- | --- |
| **B0** | 状态/保护投影：`protection` 对象、`agent_status` 覆盖率审计、`_annotate` 暴露快照字段 | 无 |
| **B1** | `/overview` 扩展、`/agents` 过滤/分页、`/telemetry/status.health` | B0 |
| **B2** | `/events` after_id、`/events/{id}`、`/events/timeseries`、SSE id/Last-Event-ID | 无 |
| **B3** | `/attention` | B0/B1 |
| **B4** | `/agents/{id}/claims`、`/coverage`、`/relations` | B0 |
| **F0** | React 骨架、状态组件、API client、MSW | B1/B2 契约冻结 |
| **F1** | 总览、资产列表、详情（概览/行为/关系） | B1/B4 |
| **F2** | 事件工作台、告警 | B2/B3 |
| **F3** | 策略、采集、Hook、设置；切 `/` | F1/F2 |

> 前端可以先按本文的 mock 开发；但 F1 之后的联调必须以真实端点为准。

---

## 11. 待决问题（不阻塞 B0–B2）

| # | 问题 | 建议 |
| --- | --- | --- |
| 1 | “资产分布”的分类维度 | P0 用 `entity_kind`（产品安装/自建应用/容器部署/…）；不要硬编码“开发助手/工作流/对话应用”；需要产品分类时在 `agents.yaml` 增加 `category` |
| 2 | 全局搜索 | P0 只做当前页过滤；后端 `?q=` 搜索放到 P1，避免假 ⌘K |
| 3 | 反驳/缺席 Claim | 等 P0-B 接入后再把 `completeness` 改为 `bidirectional` |
| 4 | 单资产覆盖率 | 当前 `coverage_summary` 是扫描全局；需要逐 scope/entity 计算后再决定展示哪些 scope（本期不做百分比） |
| 5 | 构建产物 | 提交 dist 或 CI 构建；建议提交 `console/web/next/` 并在 pytest 校验存在性 |
| 6 | 事件 virtualization | 先用 500 行窗口 + “加载更早”，数据证明需要再上虚拟滚动 |

---

## 附录 A：legacy → 新视图映射

| 旧字段/旧 UI | 新字段 | 规则 |
| --- | --- | --- |
| `states[]` 状态徽章 | `agent_status` | 四值投影；`states` 只做证据 |
| `protection_status=PROTECTED` | `protection.summary` | Hook 配置完整 → `MONITOR_ONLY`，除非 ENFORCEMENT_VERIFIED |
| `protection_status=DEGRADED` | `protection.summary` | 对应 `hook_state=PARTIAL/CONFLICT`，按 §5.3 表映射 |
| 扁平 `hook_state` | `protection.hook_state` | 快照值优先；旧值仅兼容 |
| `overview.channels` | `telemetry/status.channels` | 单一来源 |
| 事件 `decision` 徽章 | `decision` + `execution_status` | 两个标签 |
| `/agents/{id}/evidence` | `evidence` + `/claims` | 扫描证据 ≠ Claim |
| `agent_label` | `actor.label` | 未归属显示“未归属” |
| `target` 字符串 | `target_ref.label` | 不回填 actor |

## 附录 B：字段来源

| 字段 | 来源 |
| --- | --- |
| `agent_status/status_basis/removal_verdict/capability_tags` | `EntitySnapshotRow`（`storage/agent_repository.py:114-143`） |
| `protection.hook_state` | `EntitySnapshotRow.hook_state`（当前未暴露，需补） |
| `protection.summary/basis` | 新投影函数（基于 hook_state + agent_status + 遥测） |
| `protection.basis.hook_observed_at` | 暂无存储；B0 返回 `null`，后续由 Hook 事件时间回填 |
| `coverage` | `CoverageRepository.list_scopes(scan_id)` + `CoverageGraph.summary()` |
| `claims` | `EvidenceLedger.current_claims` + `ClaimEvidenceRow` + `ObservationRow` |
| `relations` | `ComponentRepository.list_for_entity` + `RelationRow` |
| `attention` | `AlertRepository` + alias 状态 + `telemetry` + `ScanRepository` |
| `entity_kind/by_entity_kind` | `EntityRow.kind`（alias → entity） |
| `by_type` | `merge_agent_rows` 后的 `agent_type` |
| `new_24h` | `AgentAssetRow.first_seen_at` |
| `timeseries` | `behavior_events.observed_at` 分组 |

## 附录 C：相对现状的变更清单

| 变更 | 类型 | 破坏性 |
| --- | --- | --- |
| `protection` 对象 | 新增 | 否 |
| `/overview.agents.running_confirmed/protection_summary` | 新增；旧字段不变 | 否 |
| `/overview` 新计数 | 新增 | 否 |
| `/agents` 过滤/分页 | 新增参数 | 否 |
| `/agents/{id}` 的 `relations/claims_summary/coverage` | 新增 | 否 |
| `/agents/{id}/claims`、`/coverage`、`/relations` | 新增端点 | 否 |
| `/attention` | 新增端点 | 否 |
| `/events` `after_id`/`entity_id`/`execution_status` | 新增参数 | 否 |
| `/events/{id}` | 新增端点 | 否 |
| `/events/timeseries` | 新增端点 | 否 |
| SSE `id`/`Last-Event-ID`/`gap` | 行为增强 | 否（旧客户端可忽略 id） |
| `/overview.channels` | 弃用 | 否（保留） |
| `states/protection_status/hook_state` | 弃用（保留） | 否 |

## 附录 D：UI 禁止文案

- “已启用防护”“拦截能力已生效”“已保护”——除非 `protection.summary=PROTECTED`。
- “已允许”作为“执行成功”——`allow` 只代表决策。
- “未发现 = 不存在”——Coverage 不完整时只能说“未发现”。
- “已删除”——`removal_verdict` 最多是“已确认不存在”。
- “置信度 85%”——E1–E5 不是分数。
- “自动合并”“同一资产”——`candidate/AMBIGUOUS` 只能显示“待关联/待复核”。
- “扫描 60%”——同步扫描没有进度；只显示“扫描中”。
- “已安装 Hook”作为“已保护”——Hook 配置只是配置。

## 附录 E：当前实现备注

- `protection.basis.telemetry_scope` 目前只区分 `global/none`；资产级覆盖需要后续按 scope 计算。
- `/agents/{id}/coverage` 先返回扫描全局 scope（`scope:"scan"`）；逐实体归属待后续。
- `/agents/{id}/claims` 固定 `completeness:"support_only"`；反驳 Claim 由 P0-B 之后接入。
- `protection.basis.hook_observed_at` 当前返回 `null`，没有持久化时间字段。
- React 控制台使用 **TDesign React** 落地母版；参考了 AI-Infra-Guard 的 React/Vite/TanStack Query 结构与组件分层，但没有直接复制其 shadcn/Tailwind 组件，以保持与母版设计一致。