# V0.1 Architecture / 验收范围

## 数据链路

```
【资产发现】
collectors（进程/端口/文件系统，跨平台只读采集）
  → HostFacts
  → detectors（从 fingerprints/rules/*.yaml 装配的规则解释器）
  → DetectedAsset（状态集 + 置信度 + 带来源版本 + 证据）
  → merge（按稳定 asset_id 合并）
  → SQLite（scan_tasks / assets / asset_snapshots / evidence，WAL）

【行为观察（零合作）】
behavior/netmon（出站连接轮询 + DNS 缓存关联 + LLM API 情报名单）
  → NetObservation（pid/进程/目标域名/证据标签）
  → MonitorManager（抑制窗口去重 + pid→asset 归属）
  → SQLite（behavior_events，source="netmon"）

→ FastAPI（/api/scans /api/assets /api/assets/{id}/evidence /api/monitor/*）+ CLI
```

检测规则与检测代码分离：产品特征全部在 YAML（见 [rules.md](rules.md) 与
[behavior.md](behavior.md)），引擎只实现探测原语（文件元数据、JSON 键名窥视、
npm 根发现、进程匹配、连接与 DNS 关联）。单个检测器异常被扫描服务隔离记录，
不影响其他检测器与扫描任务；监控单轮异常同样被隔离，不中断观察线程。

## 核心定义

- **Asset**：稳定资产身份 = sha256(hostname | 规则 id | 规范化范围路径)，与 PID 无关；重扫只更新 last_seen。
- **States**：INSTALLED / CONFIGURED / RUNNING 可并存（文档 §2.3），由独立证据源分别点亮；行为状态（BEHAVIOR_SUSPECTED 等）由行为事件累积，同样叠加而非覆盖。
- **Behavior event**：统一行为事件表 `behavior_events`，`source` 区分通道（当前 `netmon`；预留 hook/trace/process_monitor）；连接级证据（谁调了哪个 API），不含通信内容。
- **Version**：必须带 `version_source`（package-metadata > installer-metadata > process-claim）；无可靠来源输出 UNKNOWN，禁止猜测。
- **Evidence**：只存路径、键名、大小、mtime、脱敏后的命令行；不存文件内容与凭证原文。
- **Snapshot**：每次扫描对每个资产落一条快照，支持历史对比与变更观察。

## 可扩展接口

- collectors：未来增加 /proc 深取、docker、systemd、auditd、eBPF。
- detectors：新增检测目标 = 新增一条 client_rule YAML 或 signature 规则；
  全新产品探测原语时才扩展引擎。
- behavior：情报名单（llm_apis.yaml）与外部目录覆盖；后续通道（hooks 事件适配器、
  进程行为监测、ETW/eBPF）都以 behavior_events 为统一落点。
- probes：HTTP（已实现，loopback 限定）、协议握手（受 allowlist 和速率约束）。
- persistence：Repository 接口隔离，后续可换 PostgreSQL。
- web：身份认证、RBAC、异步扫描、SSE 进度。

## V0.1 验收

1. API 与 Web UI 可启动；GET /api/health 正常返回。
2. 被动扫描发现资产并保留状态、版本来源与证据；Claude Code 区分安装/配置/运行。
3. 主动模式不访问远程地址、不跟随重定向；手动开启。
4. 网络行为监控零配置可用：启动后本机进程的 LLM API 调用（连接级）落库并可归属资产；读操作全部只读，不解析通信内容。
5. SQLite 数据跨进程重启保留；资产不因重扫重复；行为事件历史可查。
6. 无可靠版本信息时输出 UNKNOWN；process-claim 来源明确标注。
7. pytest 覆盖规则加载、检测行为、身份稳定性、持久化、故障隔离与行为监控匹配/去重/归属。

## 后续迭代建议

V0.2：进程二进制取证、PPID 进程树、hooks/遥测事件适配器（内容级证据通道）、容器支持；
V0.3：授权网络流量观察增强（ETW/eBPF、SNI 补盲）、MCP/A2A 协议解析、Agent 行为序列；
V0.4：统一资产模型、权限与 API key、异步扫描、规则集中分发与热更新、审计。
