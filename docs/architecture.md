# V0.1 Architecture / 验收范围

## 数据链路

```
collectors（进程/端口/文件系统，跨平台只读采集）
  → HostFacts
  → detectors（从 fingerprints/rules/*.yaml 装配的规则解释器）
  → DetectedAsset（状态集 + 置信度 + 带来源版本 + 证据）
  → merge（按稳定 asset_id 合并）
  → SQLite（scan_tasks / assets / asset_snapshots / evidence，WAL）
  → FastAPI（/api/scans /api/assets /api/assets/{id}/evidence）+ CLI
```

检测规则与检测代码分离：产品特征全部在 YAML（见 [rules.md](rules.md)），
引擎只实现探测原语（文件元数据、JSON 键名窥视、npm 根发现、进程匹配）。
单个检测器异常被扫描服务隔离记录，不影响其他检测器与扫描任务。

## 核心定义

- **Asset**：稳定资产身份 = sha256(hostname | 规则 id | 规范化范围路径)，与 PID 无关；重扫只更新 last_seen。
- **States**：INSTALLED / CONFIGURED / RUNNING 可并存（文档 §2.3），由独立证据源分别点亮。
- **Version**：必须带 `version_source`（package-metadata > installer-metadata > process-claim）；无可靠来源输出 UNKNOWN，禁止猜测。
- **Evidence**：只存路径、键名、大小、mtime、脱敏后的命令行；不存文件内容与凭证原文。
- **Snapshot**：每次扫描对每个资产落一条快照，支持历史对比与变更观察。

## 可扩展接口

- collectors：未来增加 /proc 深取、docker、systemd、auditd、eBPF。
- detectors：新增检测目标 = 新增一条 client_rule YAML 或 signature 规则；
  全新产品探测原语时才扩展引擎。
- probes：HTTP（已实现，loopback 限定）、协议握手（受 allowlist 和速率约束）。
- persistence：Repository 接口隔离，后续可换 PostgreSQL。
- web：身份认证、RBAC、异步扫描、SSE 进度。

## V0.1 验收

1. API 与 Web UI 可启动；GET /api/health 正常返回。
2. 被动扫描发现资产并保留状态、版本来源与证据；Claude Code 区分安装/配置/运行。
3. 主动模式不访问远程地址、不跟随重定向；手动开启。
4. SQLite 数据跨进程重启保留；资产不因重扫重复。
5. 无可靠版本信息时输出 UNKNOWN；process-claim 来源明确标注。
6. pytest 覆盖规则加载、检测行为、身份稳定性、持久化与故障隔离。

## 后续迭代建议

V0.2：进程二进制取证、进程-网络关联、容器支持、行为监测（时间窗口）；
V0.3：授权网络流量被动检测（镜像/eBPF）、MCP/A2A 协议解析、Agent 行为序列；
V0.4：统一资产模型、权限与 API key、异步扫描、规则集中分发与热更新、审计。
