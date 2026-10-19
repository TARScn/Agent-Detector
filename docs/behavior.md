# 网络行为监控（零合作 LLM 调用检测）

零配置识别"哪个本机进程在调用哪个 LLM API"并记录目标地址——不需要目标 Agent 做任何配合（不设代理、不改配置、不装证书）。对应产品文档 §3.1.4（网络连接与进程的关联、目标服务地址）与 M4 的"限时持续观察"模式。

> **证据等级声明**：本功能只产出**连接级证据**——证明"某进程在观测窗口内向某 LLM 目的地发起了调用"。模型名、提示词、工具参数等**内容级信息不可见**（TLS 加密），本功能不做也不声称能做到这一点。连接级证据对应 BEHAVIOR_SUSPECTED 强度；要升级到 EXECUTION_CONFIRMED 需要授权通道（如 Agent 自身的 hooks/遥测事件接入，规划中）。

## 工作原理

```
连接采集：每 2 秒一轮（可配置）
  1. 读系统 socket 表（psutil，只读）→ ESTABLISHED 出站连接 + 属主 PID
  2. PID → 进程名

DNS 关联：常驻读取器（独立线程，每 1 秒一次，免管理员）
  Get-DnsClientCache 单次调用约 350ms，不能按轮询节奏反复拉起进程；
  恒起的 PowerShell 循环持续输出缓存快照，Python 侧合并留存（默认 900 秒）。
  CDN 域名（如 open.bigmodel.cn）的解析 TTL 实测可低至 2 秒——只比对
  "当前缓存"会系统性漏检；"实时读取 + 合并留存"保证这类条目必被捕捉，
  代价是留存窗内 IP 换主时可能残留旧名（见能力边界）。

判定（behavior/rules/llm_apis.yaml 情报规则）：
  ├─ 远端 = loopback：端口命中模型服务清单（Ollama 11434 / vLLM 8000 / LM Studio 1234
  │   / llama.cpp 1337）且该端口属于扫描确认的 LLM_SERVICE 资产
  │   → local_model：host = "服务名:端口"，asset_id 直接取该资产（跨平台生效）
  │   （裸端口不判——否则任何占用 8000 的开发服务都会被当成 vLLM）
  └─ 远端 = 公网 IP：DNS 留存映射中任一域名精确命中已知 LLM API 清单
      → llm_api：host = 域名，endpoint = 真实 IP:端口

  命中 → 去重（同 pid+host 在抑制窗口内只记一条）→ 归属 → 落库
```

- **落库**：`behavior_events` 表，`source="netmon"`、`event_type="llm.conn"`、`operation` 为 `llm_api` / `local_model`，含 `upstream_host`（域名）、`endpoint`（ip:port）、`agent_label`（进程名）、`asset_id`。
- **归属**：PID 是操作系统给出的，比"操作员声明标签"强。`llm_api` 事件按 PID 匹配最新资产快照的 running_pids；`local_model` 事件直接取被调服务的资产（端口经扫描确认，归属可证）。匹配到资产时事件挂到 `asset_id`，实现"调用行为 → 资产"闭环。
- **语义**：采样式观察无法精确计数调用次数；一条事件代表"抑制窗口（默认 300 秒）内存在该调用"。

## 实测验证（2026-10-19，本机 Windows）

- 真实调用：直连 `open.bigmodel.cn:443` 保持 8 秒 → 事件 `python.exe -> open.bigmodel.cn [llm_api]`，域名与真实 IP 均正确。
- 该域名 DNS TTL 实测仅 2 秒，是"常驻读取 + 合并留存"策略的直接来源（15 秒节流读缓存的初版为此漏检）。
- 误报回归：对 `127.0.0.1:8000` 保持 6 秒连接零事件——裸端口匹配初版曾把本机 Web 服务误报为 vLLM，现要求资产佐证。

## 使用

```bash
# Web 控制台 → 监控页 → 启动监控（此后持续观察）
# 或 CLI 定时观察
agent-detector monitor --duration 60

# 查询事件
curl "http://127.0.0.1:8000/api/monitor/events?limit=50"
curl http://127.0.0.1:8000/api/monitor/stats
```

典型事件：`claude.exe -> open.bigmodel.cn [llm_api]`、`my-agent.exe -> Ollama:11434 [local_model]`。

## 配置

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `AGENT_DETECTOR_MONITOR_INTERVAL` | `2.0` | 轮询间隔秒（0.5–60） |
| `AGENT_DETECTOR_MONITOR_SUPPRESS` | `300` | 同 pid+host 去重抑制窗口秒 |
| `AGENT_DETECTOR_BEHAVIOR_RULES_DIR` | — | 外部情报名单目录（内含 `llm_apis.yaml`，有效则整体覆盖包内规则，无效则回退并告警） |

情报名单 `src/agent_detector/behavior/rules/llm_apis.yaml`：

```yaml
known_llm_hosts:      # 精确匹配（小写），命中 DNS 缓存域名即记 llm_api
  - api.anthropic.com
  - open.bigmodel.cn
  - ...
known_model_ports:    # loopback 目的端口 → 本机模型服务名
  - {port: 11434, name: Ollama}
```

## 能力边界（如实声明）

1. **无内容**：模型名、提示词、工具调用全都看不到——TLS 的物理边界，不是实现缺陷。
2. **归因盲区**：DoH（DNS over HTTPS）绕过系统缓存；留存窗（900 秒）内 IP 换主时可能残留旧域名；直连 IP 且从未经过系统解析的流量无法归因。本机模型服务需先被扫描识别为 LLM_SERVICE 资产（被动签名或深度扫描指纹），监控才会关联其端口。
3. **短连接依赖轮询节奏**：2 秒采样通常覆盖持续数秒的 LLM 调用；毫秒级连接可能落在两轮之间（对比：进程行为监测 M4 的完整版会引入更细粒度采集）。
4. **平台差异**：远程 API 归因依赖 Windows DNS 缓存（本版实现）；Linux 的 DNS 观测（eBPF/nftables）为后续增强。本机模型服务的端口关联跨平台生效。
5. **不标定调用次数**：采样 + 去重只能回答"有过调用"，不能回答"调了几次"。

## 与授权通道的关系（规划）

零合作通道给出"谁在调谁"的底图；内容级与强证据由授权通道补充（均规划中，不属本版）：

- **hooks / 遥测适配器**：Agent 运行时事件（如工具调用）以 `source="hook"` 写入同一张 `behavior_events`，可将资产升级到 EXECUTION_CONFIRMED。
- **进程行为监测**：进程树 + 子进程活动 + 更细粒度网络事件（M4 完整版），补 PPID 缺口与短连接盲区。