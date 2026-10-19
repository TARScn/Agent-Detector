# 本地网关（Agent Gateway Manager）

本地显式代理网关观察 Agent 对 **LLM / MCP / A2A** 服务的调用行为，是产品文档 M4
"Agent Trace / 事件输入适配器 + 行为事件持久化" 的第一个标准化事件输入源。协议事件
落入 `behavior_events` 表（plan §5.2），为后续 BEHAVIOR_SUSPECTED / EXECUTION_CONFIRMED
状态联动提供证据。

> **定位声明**：协议事件只能证明"调用发生了"，不能证明 Agent 在自主执行任务；
> MCP Server 不是 Agent；模型 API 请求也不等于 Agent 调用。网关不做这个推断。

## 架构

```
Agent 进程 --HTTP(S)_PROXY/SDK proxy--> mitmdump (127.0.0.1:8899, 显式代理)
    └─ addon.py（mitmproxy 回调，独立子进程）
         ├─ classifier.py  识别 LLM/MCP/A2A 协议事件（纯函数，只抽取有界元数据）
         └─ store.py       有界队列 → 后台线程 → 批量写主库 behavior_events 表
GatewayManager（web/CLI 进程内）── 启停 mitmdump，注入 AGD_* 环境变量
Web 8000 / CLI ── 同一 SQLite 读侧展示
```

- **单一 SQLite 双写**：web 侧走 SQLAlchemy（`BehaviorEventRepository` 只读），
  addon 子进程走 raw sqlite3（`gateway.store`）。`tests/test_gateway_schema_parity.py`
  保证两侧 schema 不漂移。
- **状态文件** `data/gateway.json`（pid + create_time）：web 与 CLI 任一进程都能
  启停网关；create_time 校验防止 PID 复用误判。

## 模块

| 文件 | 职责 |
|---|---|
| `gateway/config.py` | `Settings`：AGD_DB_PATH / AGD_AGENT_ID / AGD_OBSERVED_HOSTS / AGD_PARSE_MAX_BYTES |
| `gateway/classifier.py` | 协议识别：LLM 端点+结构双重校验；MCP 兼容 2025-11-25（initialize 握手）与 2026-07-28（Mcp-Method / MCP-Protocol-Version 头）两代协议；A2A JSON-RPC + Agent Card 结构校验；REST 绑定仅低置信候选 |
| `gateway/addon.py` | mitmproxy request/response/responseheaders 回调 + 写入队列线程（上限 2000、批量 64、溢出丢弃并告警）；SSE 流式放行不缓存 |
| `gateway/store.py` | behavior_events 的 raw sqlite3 写入/查询 |
| `gateway/manager.py` | GatewayManager：mitmdump 生命周期、状态文件、错误诊断（读 stderr 日志尾） |
| `gateway/mock_upstream.py` | 本地模拟 LLM/MCP/A2A 服务（演示与自测） |
| `gateway/demo_client.py` | 强制走代理发 4 类演示请求（产生 7 条事件） |

## 使用

```bash
# 1. 安装（mitmproxy 为可选依赖）
pip install -e ".[gateway]"

# 2. 启动网关（二选一）
agent-detector gateway start          # CLI
# 或 Web 控制台 → 监控页 → 启动网关

# 3. 自测（无需真实 LLM Key）
agent-detector gateway demo           # 输出 LLM/MCP/A2A/Agent Card 请求结果

# 4. 查看事件
#    Web 控制台 → 监控页（协议筛选、证据标签）
curl http://127.0.0.1:8000/api/gateway/stats
curl "http://127.0.0.1:8000/api/gateway/events?protocol=MCP&limit=20"

# 5. 停止
agent-detector gateway stop
```

### 接入真实 Agent

只对**你明确授权的那个 Agent 进程**设置代理（不要改系统代理）：

```bash
export HTTP_PROXY=http://127.0.0.1:8899
export HTTPS_PROXY=http://127.0.0.1:8899
# 在这个终端里启动该 Agent
```

HTTPS 流量需该进程信任 mitmproxy 的动态 CA（例如 curl `--cacert
~/.mitmproxy/mitmproxy-ca-cert.pem`）。**不要**用 `verify=False` / `curl -k`
绕过校验，**不要**把代理 CA 装入系统信任根。

真实上游域名需加入观测白名单（精确匹配；默认 `AGENT_DETECTOR_GATEWAY_HOSTS`
仅含 127.0.0.1,localhost），例如：

```bash
AGENT_DETECTOR_GATEWAY_HOSTS="127.0.0.1,localhost,api.anthropic.com,open.bigmodel.cn" \
  agent-detector gateway start
```

## 配置项（启动 web/CLI 进程时读取）

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `AGENT_DETECTOR_GATEWAY_PORT` | `8899` | 网关监听端口（固定 127.0.0.1） |
| `AGENT_DETECTOR_GATEWAY_LABEL` | `local-agent` | 事件 agent_label（操作员声明，非进程证明） |
| `AGENT_DETECTOR_GATEWAY_HOSTS` | `127.0.0.1,localhost` | 观测白名单，精确匹配 |
| `AGENT_DETECTOR_GATEWAY_PARSE_MAX_BYTES` | `65536` | 单请求解析上限（1KiB–256KiB） |

## 安全边界

1. 仅监听 127.0.0.1；Web 启停接口只接受固定模板的 mitmdump 命令，无任意参数入口。
2. **不持久化**请求体、提示词、工具参数、Authorization、Cookie、完整 URL Query；
   所有抽取标签经白名单净化（`_safe_name`：仅字母数字与 `-_./:`，限长）。
3. `model` 是调用者声明的值，不是验证过的部署版本；`protocol_version` 与
   `component_version` 分列，取不到即为 null。
4. 白名单只控制**采集范围**，不限制 mitmproxy 的转发目标；生产化需另加网关认证
   与 egress 策略。
5. HTTPS 内容会在 mitmproxy 进程内存中解密——"不落库"不等于"进程未接触"。
6. 队列满时丢弃并计数告警（不阻塞代理转发）；SQLite 落库失败记录异常日志。
7. `agent_label` 是操作员标签，不能证明发起进程；跨进程流量归属（每 Agent 独立
   端口 / socket→PID 关联）是下一阶段工作。
8. 事件数量不等于调用次数：同一 flow_id 会先产生 `*.request` 再产生 `http.response`。

## 已知边界（G1 范围外）

- 证书固定（cert pinning）的客户端、绕过代理的客户端不覆盖。
- MCP stdio、A2A gRPC、HTTP/2 多路复用完整语义、SSE `data:` 增量内容不解析；
  MCP stdio 未来由独立 IPC 采集器负责。
- 未实现网关启停的认证、多租户、请求/响应按 flow_id 聚合成"一次调用"。
- Windows 上跨控制台停止会退化为 terminate()，队列中未落库事件（≤64 条）可能丢失。
