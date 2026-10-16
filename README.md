# Agent Detector V0.1

面向 Linux 的本机 AI Agent 资产发现原型。Python + FastAPI + SQLite + 原生 Web UI。

## 能力
- **被动扫描**：通过 psutil 读取进程名称、命令行与本机 TCP LISTEN 端口；按可扩展规则识别 Agent 框架、开发工具、模型服务和 MCP 组件。
- **行为证据**：进程正在运行、网络服务正在监听，属于运行态线索；不能证明存在实际模型调用。后续可扩展 eBPF、审计日志、流量镜像。
- **主动探测**：可选、手动触发，**仅针对本机已观测到的监听端口**发送少量 HTTP GET（/, /health, /openapi.json）；不执行漏洞利用或访问外部地址。
- **可追溯结果**：SQLite 保存扫描批次、发现项、证据、检测策略与版本来源；版本不可确认时返回 null，不臆造版本。
- **Web 页面**：启动扫描、查看资产、筛选与查看证据。

## Linux 快速启动

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn agent_detector.web.app:app --host 127.0.0.1 --port 8000
```

访问 http://127.0.0.1:8000 。默认仅监听 loopback；不要直接暴露到公网。

```bash
# 被动扫描
curl -X POST http://127.0.0.1:8000/api/scans -H 'Content-Type: application/json' -d '{"active": false}'
# 主动扫描：仅本机已监听 HTTP 服务
curl -X POST http://127.0.0.1:8000/api/scans -H 'Content-Type: application/json' -d '{"active": true}'
curl http://127.0.0.1:8000/api/findings
pytest -q
```

可用环境变量：`AGENT_DETECTOR_DB` (默认 `./data/agent_detector.sqlite3`)、`AGENT_DETECTOR_MAX_PROBES` (默认 20)。

## 限制
- 需要 Linux 环境并有权限查看目标进程；普通用户可能无法读取其他用户进程。
- V0.1 **不抓包、不嗅探外部流量、不执行 POC、不进行全网扫描**；主动探测只面向本机监听套接字。
- 版本优先来自进程命令行或 HTTP 明确信息，均标记为 claimed，未经独立验证不视为可信安装版本。
- 规则识别有误报；证据不足时不要认定为 Agent。仅使用于授权设备。
- Web API 暂无鉴权，面向单机测试；生产部署须增加鉴权、TLS、权限隔离与限流。

更多设计见 [docs/architecture.md](docs/architecture.md)。
