# V0.2 架构 / 验收范围

Windows V0.2 · 工程实现说明。产品设计稿见 `J:\myNotes\plans\agent探测实现.md`。

## 三种模式与三条链路

| 模式 | 做什么 | 能做到什么 | 做不到什么 |
| --- | --- | --- | --- |
| Discovery | 进程、注册表/安装记录、Agent 配置、MCP 配置、扩展目录 → 稳定资产身份 | 发现 Agent、版本（带来源）、运行实例 | 不保证判定"这个进程一定是某个 Agent"，只给证据与置信度 |
| Monitor | Sysmon / auditd / 采样 / 出站连接 / 原生 Hook 事件 → 统一行为事件 | 观察进程、文件、网络与工具调用 | 观察不等于拦截：系统级行为无法提前阻断 |
| Protect | Agent 原生 PreToolUse → 策略引擎 → 平台原生响应 | 在受支持 Agent 的工具调用**执行前** allow / ask / deny | 只覆盖接入 Hook 且经过检查点的调用；未适配的 Agent 不保证 |

## 数据链路

```
【Agent 发现】
collectors/（进程 / 文件元数据，跨平台只读）
    → HostFacts
    → discovery/fingerprints（从 rules/*.yaml 装配的规则解释器）
    → DetectedAsset（状态集 + 置信度 + 带来源版本 + 证据）
    → merge（按稳定 asset_id 合并）
    → storage（scan_tasks / assets / asset_snapshots / evidence）
    → discovery/inventory（Agent 资产 + 运行实例 + Hook 状态 + 保护状态）
    → storage（agent_assets / agent_instances）

【行为监测】
原生 Hook ────┐
Sysmon ───────┤   services/ingest（Sysmon / auditd / 采样）
auditd ───────┼──> domain/facts.BehaviorFact ──> detection/behavior_rules（高级行为）
采样 ─────────┤                                   ├─ detection/attribution（进程树 → Agent）
出站连接 ─────┘                                   ├─ detection/risk（风险分级）
                                                  └─ suppression + 速率上限 + 保留策略
                                                  → storage/behavior_events（source 区分通道）

【执行前拦截】
Agent 工具调用 → hook_bridge（stdlib，极轻量）
    → POST /internal/v1/hooks/decide（loopback + Token）
    → hooks/normalizer（统一 ToolCall，平台差异止于此）
    → detection/correlation（Hook 父进程链 → 运行实例）
    → policy/engine（确定性规则，首个命中胜出，不调用 LLM）
    → 记录事件 + 生成告警
    → hooks/adapters（转换成该 Agent 的原生响应）→ 返回 Agent
```

## 目录结构（`src/`）

```
agent_detector/
  api/          app.py 组装；routers/ 每个资源一个模块（/api/v1、/internal/v1）
  cli/          scan / agents / events / collect / policy / hooks / serve
  collectors/   原始采集：process、filesystem、sysmon、audit/（auditd）、netflow、dns_cache、poll
  common/       config（全部环境变量）、security（脱敏）
  detection/    判别层：correlation、attribution、process_graph、behavior_rules、risk、llm_intel
  discovery/    发现层：scanner、inventory、mcp、identity、agents（支持矩阵）、fingerprints/
  domain/       enums、models、facts（跨平台事实层）
  hooks/        base、registry、normalizer、installer、adapters/{claude,codex,cursor}
  policy/       schema、loader、engine、paths、rules/policies.yaml
  services/     hooks（决策编排）、ingest（系统行为）、monitor（出站连接）、retention
  storage/      database、models、repositories/
  web/          无构建步骤的控制台（index.html + assets/css + assets/js）
hook_bridge/    放进 Agent 工具调用路径里的极轻量进程（仅标准库）
```

`hook_bridge` 与 `agent_detector` 是两个独立包：前者不得依赖 FastAPI、数据库或规则引擎，
否则每次工具调用都要付出导入代价（设计文档 §11.4）。

## 核心定义

- **Asset**：稳定身份 = sha256(hostname | 规则 id | 规范化范围路径)，与 PID 无关；重扫只更新 last_seen。
- **Instance**：`instance_id` = hash(asset_id, pid, 启动时间)。Windows 会复用 PID，所以 PID 不能当身份（设计文档 §3.4）。
- **States**：INSTALLED / CONFIGURED / RUNNING 可并存，由独立证据源分别点亮。
- **Protection status**：PROTECTED / MONITOR_ONLY / DEGRADED / UNPROTECTED，只由 Hook 配置的**实际检查结果**决定。
- **Fact**：跨平台事实（kind / pid / ppid / argv / 路径 / 结果），Sysmon 与 auditd 都归一到它，上层只认事实。
- **Behavior event**：统一表 `behavior_events`，`source` 区分通道（native_hook / sysmon / auditd / poll / netmon）。
- **Decision**：allow / ask / deny / audit；`decision=allow` **不推导** `execution_status=successed`，后者要由 PostToolUse 确认。
- **Evidence**：只存路径、键名、大小、mtime、脱敏后的命令行；不存文件内容与凭据原文。

## 能力边界（写在代码与界面里，不只写在文档里）

- Hook 只覆盖经过检查点的调用：Codex 官方说明部分执行路径可能绕过 Hook，Cursor 内部文件操作不经检查点。
- Codex / Cursor 的响应 Schema 标为 `schema_verified = False`，界面显示"待验证"。
- 未安装 Hook 的 Agent 一律显示"仅监测"，界面与 CLI 都不会声称已保护。
- 用户级 Hook 不具备不可篡改性（同权限用户可改），企业级需要托管配置与签名（设计文档 §11.2）。
- WSL2 内的 Agent 不在首期范围：发行版运行在子 PID namespace，auditd 与 Windows 侧 Hook 均不可用。

## 验收（V0.2 当前状态）

1. 控制台与 API 可启动：`agent-detector serve` → `GET /api/health`、`GET /api/v1/overview`。
2. 扫描产出稳定资产身份、运行实例、版本来源与证据；Agent 资产带能力矩阵与保护状态。
3. 决策链路闭环：`hook_bridge` → `/internal/v1/hooks/decide` → 策略 → 阻断 → 事件 + 告警，
   `pytest` 覆盖策略语义、适配器响应、安装器合并/移除、决策接口与 SSE。
4. 采集通道均"如实汇报"：Sysmon 未安装时返回原因而不是空跑；auditd 无 root 时降级为采样并说明。
5. 目录、删除、凭据、配置篡改等风险行为在策略样例中给出 deny / ask；LLM 不参与必经决策。
6. 前端六个页面（总览 / Agent 资产 / 行为时间线 / 策略 / 告警 / 设置）在浏览器中验证通过，页面显式标注"待开发"的能力。

## 后续迭代

- 采集通道：eBPF（与 auditd 共用事实层）、ETW、容器内 Agent 发现、WSL2 采集模块。
- 拦截面：Gemini CLI / OpenCode / Copilot CLI 适配器，MCP 工具级策略，Windows Named Pipe + 用户 SID 的决策通道。
- 治理面：策略可视化编辑与签名、企业托管配置、告警通知与报表、多用户与权限。