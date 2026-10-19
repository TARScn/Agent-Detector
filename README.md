# Agent Detector V0.1

本机 AI Agent 资产发现工具。Python + FastAPI + SQLAlchemy/SQLite + 原生 Web UI。
产品定位面向 Linux 部署，采集与检测层跨平台（Windows 可用于开发验证）。

## 功能
- **被动扫描**：通过 psutil 采集进程、命令行与本机 TCP LISTEN 端口；由规则引擎识别 Agent 客户端、框架、模型服务和 MCP 组件。
- **声明式规则**：检测特征全部在 YAML（`fingerprints/rules/`），新增检测目标只写规则不改代码；支持 `AGENT_DETECTOR_RULES_DIR` 外部规则目录按 id 覆盖内置规则。规范见 [docs/rules.md](docs/rules.md)。
- **Claude Code 专属规则**：区分安装（npm / 原生安装器 / `~/.claude`）、配置（`~/.claude.json` 键名、`settings.json`）与运行（进程）三类证据，并排除同名但不同产品的 Claude Desktop 进程。
- **资产模型**：稳定资产 ID（与 PID 无关，重扫不重复建资产）、多状态共存（INSTALLED / CONFIGURED / RUNNING）、独立置信度。
- **版本带来源**：优先包元数据（npm `package.json`），其次安装器元数据；无可靠来源输出 `UNKNOWN`，不做猜测。
- **主动探测**：仅在手动启用时（扫描页"深度扫描"），对本机已观测的监听端口发送少量 HTTP GET 请求；不执行漏洞利用、不访问远程地址。
- **网络行为监控（零合作）**：轮询本机出站连接，结合系统 DNS 缓存与 LLM API 情报名单，识别"哪个进程在调用哪个 LLM API"并记录目标地址——无需目标 Agent 设代理、改配置或装证书；只记录连接级证据，不读取通信内容。见 [docs/behavior.md](docs/behavior.md)。
- **系统行为监测（Linux auditd）**：在系统层采集 Agent 进程及其后代进程的行为——进程执行、文件写入 / 移动 / 删除 / 属性变更、网络连接——并通过进程树回溯归属到具体 Agent；行为规则声明式配置（SCRIPT_EXEC / FILE_MOVE / GIT_OPERATION / PACKAGE_INSTALL…）。无 root 或 Windows 时降级为进程采样模式（仅进程执行级）。见 [docs/syscall-monitoring.md](docs/syscall-monitoring.md)。
- **可追溯结果**：SQLite 保存扫描任务、资产、快照、证据与行为事件；文件内容与凭证原文不入库，命令行密钥自动脱敏，启动参数原文默认不落库。
- **Web 管理控制台**：左侧导航五页 —— 扫描主页（Agent 扫描 / 深度扫描 + 概览统计）、监控页（网络行为监控启停 + 事件流）、行为页（系统行为采集启停 + auditd 规则命令卡 + 行为时间线，合并 netmon 事件）、结果页（按批次/类型/状态筛选 + 证据明细 + 扫描历史）、设置页（系统信息 + 只读规则列表）。
- **CLI 与 Web 共用同一引擎**：`agent-detector scan` / `agent-detector assets list` / `agent-detector monitor` / `agent-detector behavior …`。

## 快速启动

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[test]"
uvicorn agent_detector.web.app:app --host 127.0.0.1 --port 8000
```

访问 http://127.0.0.1:8000 。不要将无鉴权服务直接暴露到公网。

```bash
# CLI 扫描（与 Web 共用后端引擎）
agent-detector scan
agent-detector scan --active --json
agent-detector assets list

# 网络行为监控（零合作识别 LLM API 调用，Web 监控页也可启停）
agent-detector monitor --duration 60   # 观察 60 秒，输出命中的 进程 → API 地址

# 系统行为监测（Linux 需 root 安装 auditd 规则；其他平台用采样降级）
agent-detector behavior rules --watch-dir /home/user/agent-lab   # 打印规则与安装命令（root 执行）
agent-detector behavior collect --duration 120                   # auditd 采集（Linux）
agent-detector behavior collect --mode poll --duration 60        # 采样模式（无 root / Windows）
agent-detector behavior replay tests/fixtures/audit/scenario.log # 回放一份 audit 日志
agent-detector behavior events --limit 50 --source auditd
agent-detector behavior purge                                    # 应用保留策略

# REST API
curl -X POST http://127.0.0.1:8000/api/scans -H 'Content-Type: application/json' -d '{"active": false}'
curl http://127.0.0.1:8000/api/assets
curl "http://127.0.0.1:8000/api/assets/<asset_id>/evidence"
curl http://127.0.0.1:8000/api/monitor/stats
curl http://127.0.0.1:8000/api/behavior/status

pytest -q
```

可用环境变量：`AGENT_DETECTOR_DB` (默认 `./data/agent_detector.sqlite3`)、`AGENT_DETECTOR_MAX_PROBES` (默认 20)、`AGENT_DETECTOR_RULES_DIR` (外部规则目录，按 id 覆盖内置规则)、`AGENT_DETECTOR_MONITOR_INTERVAL/_SUPPRESS` 与 `AGENT_DETECTOR_BEHAVIOR_RULES_DIR` (行为规则配置，见 [docs/behavior.md](docs/behavior.md))；系统行为通道另有 `AGENT_DETECTOR_AUDIT_LOG`、`AGENT_DETECTOR_BEHAVIOR_SUPPRESS/_RETENTION_DAYS/_MAX_EVENTS_PER_MINUTE/_PATH_POLICY/_STORE_ARGV/_POLL_INTERVAL/_INCLUDE_UNATTRIBUTED`（见 [docs/syscall-monitoring.md](docs/syscall-monitoring.md)）。

## 架构（src/agent_detector/）

```
domain/        资产/证据/版本领域模型与枚举
collectors/    进程、端口、文件系统采集（跨平台）
fingerprints/  声明式检测规则（rules/*.yaml）+ 加载器 + 规则解释引擎
detectors/     Detector 协议；build_detectors() 从 YAML 规则装配检测器
recognition/   稳定资产 ID 生成
application/   扫描编排（采集 → 检测 → 合并 → 持久化，检测器异常隔离）
persistence/   SQLAlchemy 实体 + Repository（scan_tasks / assets / asset_snapshots / evidence / behavior_events）
probes/        本机 HTTP 主动指纹
behavior/      行为监测：netmon 出站连接 × DNS 缓存 × LLM 情报名单（零合作）；
               auditd/poll 系统行为采集（进程执行 / 文件操作 / 网络连接）+ 进程图归属 + 行为规则
cli/           命令行入口
web/           FastAPI 路由 + 单页 UI
common/        配置与脱敏工具
```

新增检测目标：在 `fingerprints/rules/` 添加一条 client_rule YAML（或往 signatures.yaml 加正则），
下次扫描即生效，无需改代码；也可用 `AGENT_DETECTOR_RULES_DIR` 指向外部规则目录覆盖内置规则。
规范与字段说明见 [docs/rules.md](docs/rules.md)。

## 范围与安全限制
- 其他用户进程可能需要更高系统权限，建议遵循最小权限。
- V0.1 不提供流量内容解析、POC 验证和全网扫描；网络行为监控只读系统 socket 表与 DNS 缓存，产出连接级证据（不读取通信内容），不承诺内容级确认。
- 系统行为监测只读审计日志与进程表，**不自动以 root 安装审计规则**（只打印命令）；进程树证据不等于"模型自主决定"；路径原样入库（可配置脱敏），启动参数原文默认不落库；行为事件有速率上限与保留策略。WSL2 因发行版运行在子 PID namespace，auditd 不可用（采样降级模式仍可用）。
- 版本信息如存在，均标注来源（`version_source`）；`process-claim` 类来源为未经验证的命令行声明。
- 不执行被发现的 Agent、MCP stdio 启动命令或 Skill。
- 默认仅建议本地使用；正式部署需要认证、授权、审计和访问保护。

详见 [docs/architecture.md](docs/architecture.md) 与 `J:\myNotes\plans\agent探测实现.md`（产品实现计划）。
