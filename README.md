# Agent Detector · Windows V0.2

本机 AI Agent 的安全检测与行为治理工具：**发现 Agent → 关联进程行为 → 理解工具调用 → 执行前拦截 → 审计追溯**。

它不是 Agent 开发框架，而是独立运行在 Agent 外部的监测工具。参考 Microsoft Agent 365 / Defender 的建模方式，
结合 Claude Code、Codex CLI、Cursor 官方开放的 Hook 接口实现。

产品设计稿：`J:\myNotes\plans\agent探测实现.md`。

## 三种模式

| 模式 | 数据来源 | 能做到 |
| --- | --- | --- |
| **Discovery** | 进程、安装记录、Agent 配置、MCP 配置、Docker 容器 | 发现 Agent，给出稳定资产身份、带来源的版本、运行实例 |
| **Monitor** | Sysmon / eBPF (Tetragon) / auditd / 进程采样 / 出站连接 / 原生 Hook | 观察进程、文件、网络与工具调用行为 |
| **Protect** | Agent 原生 PreToolUse Hook | 在受支持 Agent 的**工具调用执行前** allow / ask / deny |

> 监测到进程正在删除文件，不代表能在删除前阻止它。只有接入原生 Hook 的 Agent 才能被前置阻断，
> 未接入的 Agent 在界面上一律显示"仅监测"。

## 快速开始

```powershell
# 1. 安装（创建虚拟环境 + 可编辑安装 + 通道体检 + 生成 Hook Token）
powershell -ExecutionPolicy Bypass -File scripts\install.ps1

# 2. 启动控制台（默认 http://127.0.0.1:8787）
.venv\Scripts\python.exe -m agent_detector.console.cli.main serve

# 3. 首次扫描
.venv\Scripts\python.exe -m agent_detector.console.cli.main scan
```

Linux / macOS 上等价（采集通道会自动降级）：

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[test]"
uvicorn agent_detector.console.api.app:app --host 127.0.0.1 --port 8787
```

## 控制台

无构建步骤的前端（`index.html` + 原生 ES 模块），风格参考 Microsoft 365 admin center / Agent 365：
白色命令栏、分组左导航、卡片式内容区与状态徽章。

| 页面 | 内容 |
| --- | --- |
| 总览 | 发现 Agent / 今日行为 / 已阻断 / 未启用拦截 四个数字 + 保护状态分布 + 采集通道 + 实时事件 |
| Agent 资产 | 资产清单（能力矩阵、Hook 状态、保护状态、实例与会话数）；详情页含身份、实例、会话、MCP、证据 |
| 行为时间线 | 统一事件流（Hook / Sysmon / auditd / 采样 / 网络），SSE 实时追加，可展开证据标签 |
| 安全策略 | 13 条内置规则的决策、风险、优先级与匹配条件；可停用规则或改判决策并立即生效 |
| 风险告警 | 阻断调用与高风险事件的告警，可确认 / 解决 |
| 设置 | 系统信息、采集通道、Hook 安装（dry-run → 写入并备份）、auditd 规则生成器、支持矩阵、待开发清单 |

页面上标注"待开发"的部分是明确的未完成能力（例如策略可视化编辑、告警通知渠道），不会伪装成已实现。

## Hook 与执行前拦截

```powershell
agent-detector hooks status                      # 各 Agent 的 Hook 配置状态
agent-detector hooks plan claude_code            # dry-run：打印将要写入的内容
agent-detector hooks install claude_code --apply # 写入（先备份，只增删本工具的条目）
agent-detector hooks uninstall cursor --apply    # 卸载
agent-detector policy test --command "rm -rf ~/.ssh"   # 策略自查，不需要 Agent 参与
```

链路：`hook_bridge`（仅标准库，位于 Agent 工具调用路径内）→ `POST /internal/v1/hooks/decide`
（loopback + Token）→ 策略引擎（确定性，不调用 LLM）→ 事件 + 告警 → 转换为该 Agent 的原生响应。

- 服务不可达时默认 **fail-closed**（拒绝调用），可用 `AGENT_DETECTOR_HOOK_FAILURE_MODE=allow` 改为审计放行。
- `decision=allow` 不等于执行成功：成功由 `PostToolUse` 事件确认（`execution_status`）。
- 详见 [docs/hooks.md](docs/hooks.md) 与 [docs/policy.md](docs/policy.md)。

## CLI

```
agent-detector serve                                 启动控制台与决策服务
agent-detector scan [--active] [--json]              资产扫描（+  Agent 清单刷新）
agent-detector agents list|show <asset_id>           Agent 资产、实例、会话、保护状态
agent-detector assets [--scan-id N]                  组件资产（含 MCP / 模型服务）
agent-detector events [--source X] [--risk high]     行为事件（Hook / Sysmon / auditd / 采样 / 网络）
agent-detector alerts [--status open]                安全告警
agent-detector monitor --duration 60                 出站 LLM 调用观察（零合作）
agent-detector collect --mode sysmon --duration 60   系统行为采集（sysmon / tetragon / auditd / poll）
agent-detector replay <log> [--format tetragon]      离线回放 audit 日志或 Tetragon 导出（任意平台）
agent-detector channels                              采集通道可用性体检
agent-detector audit-rules --watch-dir /path         打印 auditd 规则与安装命令（不自动提权）
agent-detector tetragon                              打印 Tetragon 通道状态与部署命令（不自动提权）
agent-detector policy list | policy test --command …  策略清单与决策自查
agent-detector hooks status|plan|install|uninstall|snippet
agent-detector purge [--older-than-days N] [--all]   保留策略清理
```

## REST API

```
GET  /api/v1/overview                          仪表盘汇总
GET  /api/v1/agents | /{id} | /{id}/mcp         Agent 资产与详情
POST /api/v1/discovery/scan                     发起扫描
GET  /api/v1/events | /events/stats | /events/stream   事件查询（before_id 游标分页）与 SSE 实时流
GET  /api/v1/policies | PUT /{id} | POST /reload        策略查询与覆盖
GET  /api/v1/alerts | PATCH /{id}               告警
GET  /api/v1/telemetry/status | /audit-rules    通道状态与 auditd 规则模板
POST /api/v1/telemetry/monitor/start|stop       出站连接观察
POST /api/v1/telemetry/behavior/start|stop      系统行为采集
GET  /api/v1/hooks | POST /{agent}/plan|install|uninstall   Hook 管理（默认 dry-run）
GET  /api/v1/system | /api/v1/capabilities      环境信息与能力清单
POST /internal/v1/hooks/decide                  Hook 决策（内部控制接口，需 Token）
```

## 数据模型

`scan_tasks` / `assets` / `asset_snapshots` / `evidence`（发现）；
`agent_assets` / `agent_instances` / `agent_sessions`（Agent 资产与运行实例）；
`behavior_events`（统一行为事件，`source` 区分通道）；
`security_policies` / `security_alerts`（策略覆盖与告警）。

- 资产身份与 PID 无关；实例身份含启动时间（Windows 会复用 PID）。
- 事件只存元数据与脱敏摘要：不含对话内容、文件内容与凭据原文。
- 版本信息一律带 `version_source`，无可靠来源输出 `UNKNOWN`。

## 环境变量（摘要）

`AGENT_DETECTOR_DB`（数据库路径）、`_HOST` / `_PORT`（监听地址，默认 127.0.0.1:8787）、
`_HOOK_TOKEN` / `_HOOK_TOKEN_FILE`、`_HOOK_FAILURE_MODE`（block|allow）、`_HOOK_TIMEOUT`、`_POLICY_DIR`、
`_AGENTS_FILE`、`_SYSMON_CHANNEL`、`_ALERT_RISK_LEVEL`、`_RULES_DIR`、`_BEHAVIOR_RULES_DIR`、
`_AUDIT_LOG`、`_TETRA_LOG`（Tetragon JSON 导出文件，默认 `/var/log/tetragon/events.json`）、
`_BEHAVIOR_*`（抑制窗口 / 速率 / 保留 / 路径策略 / 是否存 argv）等。
完整列表见 `src/agent_detector/core/config.py`。

## 范围与安全限制

- 默认只监听 `127.0.0.1`；`/internal/v1/hooks/decide` 是内部控制接口，用 Token 鉴权，不要暴露到网络。
- Sysmon 的 Event ID 3（网络连接）默认关闭，需要按 [configs/sysmon.xml](configs/sysmon.xml) 显式启用。
- Sysmon 文件事件不覆盖全部读写改名；auditd 需要 root 安装规则（工具只打印命令，不自动提权）。
- 用户级 Hook 不具备不可篡改性（同权限用户可修改）；企业级需要托管配置、ACL 与策略签名。
- WSL2 内的 Agent 不在首期范围：发行版运行在子 PID namespace，auditd 不可用，Windows 侧 Hook 也不适用。
- 不执行被发现的 Agent、MCP stdio 启动命令或 Skill；不读取通信内容与文件内容。

## 文档

[architecture.md](docs/architecture.md) · [windows.md](docs/windows.md) · [hooks.md](docs/hooks.md) ·
[policy.md](docs/policy.md) · [rules.md](docs/rules.md)（检测规则） · [behavior.md](docs/behavior.md)（网络调用观察） ·
[syscall-monitoring.md](docs/syscall-monitoring.md)（系统行为监测） ·
[ebpf-monitoring.md](docs/ebpf-monitoring.md)（eBPF/Tetragon 通道） ·
[docker-discovery.md](docs/docker-discovery.md)（容器发现）

## 测试

```bash
pytest -q          # 策略语义、适配器、安装器、决策接口、SSE、采集归一化、持久化等
```