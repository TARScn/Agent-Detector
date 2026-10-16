# Agent Detector V0.1

面向 Linux 的本机 AI Agent 资产发现原型。Python + FastAPI + SQLite + 原生 Web UI。

## 功能
- **被动扫描**：通过 psutil 采集进程、命令行与本机 TCP LISTEN 端口；按可扩展规则识别 Agent 框架、开发工具、模型服务和 MCP 组件。
- **运行态证据**：进程正在运行、服务正在监听；不等同于已验证的模型 API 调用行为。
- **主动探测**：仅在手动启用时，对本机已观测的监听端口发送少量 HTTP GET 请求；不执行漏洞利用、不访问远程地址。
- **可追溯结果**：SQLite 保存扫描批次、组件、证据、置信度与版本来源；无法确认版本时显示未知。
- **Web 页面**：启动扫描、查看资产、扫描批次及证据。

## Linux 快速启动

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
uvicorn agent_detector.web.app:app --host 127.0.0.1 --port 8000
```

访问 http://127.0.0.1:8000 。不要将无鉴权服务直接暴露到公网。

```bash
curl -X POST http://127.0.0.1:8000/api/scans -H 'Content-Type: application/json' -d '{"active": false}'
curl -X POST http://127.0.0.1:8000/api/scans -H 'Content-Type: application/json' -d '{"active": true}'
curl http://127.0.0.1:8000/api/findings
pytest -q
```

可用环境变量：`AGENT_DETECTOR_DB` (默认 `./data/agent_detector.sqlite3`)、`AGENT_DETECTOR_MAX_PROBES` (默认 20)。

## 范围与安全限制
- 仅支持 Linux；其他用户进程可能需要更高系统权限，建议遵循最小权限。
- V0.1 不提供网络抓包、外部流量嗅探、POC 验证和全网扫描。
- 版本信息如存在，可能是未经验证的命令行声明；`version_source` 指明来源。
- 规则匹配会有误报，尤其是包含可疑词汇的命令行参数；需要结合证据复核。
- 默认仅建议本地使用；正式部署需要认证、授权、审计和访问保护。

详见 [docs/architecture.md](docs/architecture.md)。
