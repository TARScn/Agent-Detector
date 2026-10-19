# Agent Detector V0.1

本机 AI Agent 资产发现工具。Python + FastAPI + SQLAlchemy/SQLite + 原生 Web UI。
产品定位面向 Linux 部署，采集与检测层跨平台（Windows 可用于开发验证）。

## 功能
- **被动扫描**：通过 psutil 采集进程、命令行与本机 TCP LISTEN 端口；由规则引擎识别 Agent 客户端、框架、模型服务和 MCP 组件。
- **声明式规则**：检测特征全部在 YAML（`fingerprints/rules/`），新增检测目标只写规则不改代码；支持 `AGENT_DETECTOR_RULES_DIR` 外部规则目录按 id 覆盖内置规则。规范见 [docs/rules.md](docs/rules.md)。
- **Claude Code 专属规则**：区分安装（npm / 原生安装器 / `~/.claude`）、配置（`~/.claude.json` 键名、`settings.json`）与运行（进程）三类证据，并排除同名但不同产品的 Claude Desktop 进程。
- **资产模型**：稳定资产 ID（与 PID 无关，重扫不重复建资产）、多状态共存（INSTALLED / CONFIGURED / RUNNING）、独立置信度。
- **版本带来源**：优先包元数据（npm `package.json`），其次安装器元数据；无可靠来源输出 `UNKNOWN`，不做猜测。
- **主动探测**：仅在手动启用时，对本机已观测的监听端口发送少量 HTTP GET 请求；不执行漏洞利用、不访问远程地址。
- **可追溯结果**：SQLite 保存扫描任务、资产、快照与证据；文件内容与凭证原文不入库，命令行中的密钥自动脱敏。
- **Web 管理控制台**：左侧导航四页 —— 扫描主页（Agent 扫描 + 概览统计）、监控页（流量监控：本机端口 HTTP 指纹）、结果页（按批次/类型/状态筛选 + 证据明细 + 扫描历史）、设置页（系统信息 + 只读规则列表）。
- **CLI 与 Web 共用同一引擎**：`agent-detector scan` / `agent-detector assets list`。

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

# REST API
curl -X POST http://127.0.0.1:8000/api/scans -H 'Content-Type: application/json' -d '{"active": false}'
curl http://127.0.0.1:8000/api/assets
curl "http://127.0.0.1:8000/api/assets/<asset_id>/evidence"

pytest -q
```

可用环境变量：`AGENT_DETECTOR_DB` (默认 `./data/agent_detector.sqlite3`)、`AGENT_DETECTOR_MAX_PROBES` (默认 20)、`AGENT_DETECTOR_RULES_DIR` (外部规则目录，按 id 覆盖内置规则)。

## 架构（src/agent_detector/）

```
domain/        资产/证据/版本领域模型与枚举
collectors/    进程、端口、文件系统采集（跨平台）
fingerprints/  声明式检测规则（rules/*.yaml）+ 加载器 + 规则解释引擎
detectors/     Detector 协议；build_detectors() 从 YAML 规则装配检测器
recognition/   稳定资产 ID 生成
application/   扫描编排（采集 → 检测 → 合并 → 持久化，检测器异常隔离）
persistence/   SQLAlchemy 实体 + Repository（scan_tasks / assets / asset_snapshots / evidence）
probes/        本机 HTTP 主动指纹
cli/           命令行入口
web/           FastAPI 路由 + 单页 UI
common/        配置与脱敏工具
```

新增检测目标：在 `fingerprints/rules/` 添加一条 client_rule YAML（或往 signatures.yaml 加正则），
下次扫描即生效，无需改代码；也可用 `AGENT_DETECTOR_RULES_DIR` 指向外部规则目录覆盖内置规则。
规范与字段说明见 [docs/rules.md](docs/rules.md)。

## 范围与安全限制
- 其他用户进程可能需要更高系统权限，建议遵循最小权限。
- V0.1 不提供网络抓包、外部流量嗅探、POC 验证和全网扫描。
- 版本信息如存在，均标注来源（`version_source`）；`process-claim` 类来源为未经验证的命令行声明。
- 不执行被发现的 Agent、MCP stdio 启动命令或 Skill。
- 默认仅建议本地使用；正式部署需要认证、授权、审计和访问保护。

详见 [docs/architecture.md](docs/architecture.md) 与 `J:\myNotes\plans\agent探测实现.md`（产品实现计划）。
