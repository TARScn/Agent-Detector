# V0.1 Architecture / 验收范围

## 数据链路
Linux psutil process+listen snapshot -> observations -> signature detector -> (opt-in bounded localhost HTTP probe) -> findings -> SQLite -> FastAPI -> Web.

## 数据定义
- `observations`：一次采集中的进程或监听地址；网络监听不表示该进程已经发生模型 API 交互。
- `findings`：匹配规则的组件、运行状态、证据 JSON、confidence、pid、port、可选 version。
- `scans`：每一次扫描的时间、模式、观测条数、发现数量。
- 版本来源 `version_source` 为 process-claim 时仅表示从进程命令行提取；不要声称经过包管理器验证。

## 可扩展接口
- collectors：未来增加 /proc、docker、systemd、auditd、eBPF、netflow。
- detectors：签名匹配、上下文关联、行为序列识别、风险评分。
- probes：HTTP、协议握手（受 allowlist 和速率约束）。
- storage：后续可拆 PostgreSQL / 队列与扫描 Worker。
- web：增加身份认证、RBAC、异步任务、版本规则管理、资产趋势。

## V0.1 验收
1. Linux 上可以启动 API 与 Web UI；GET /api/health 正常返回。
2. 被动扫描可持久化扫描批次；带特征的进程匹配成发现并保留 PID 与证据。
3. 主动模式不会扫描远程地址、不跟随 HTTP 重定向；允许手动选择。
4. SQLite 的 findings 与 scans 跨进程重启保留。
5. 无可靠版本信息时版本为空；不凭进程名称臆测版本。
6. pytest 单元测试验证签名、边界与持久化。

## 后续迭代建议
V0.2：规则 YAML、进程二进制与安装版本取证、进程-网络关联、容器支持；
V0.3：授权网络流量被动检测（镜像/eBPF）、协议解析、Agent 行为序列；
V0.4：统一资产模型、权限与 API key、异步扫描、规则更新、审计。
