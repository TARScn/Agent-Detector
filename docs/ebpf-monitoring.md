# 系统行为监测 · eBPF 通道（Tetragon 采集 + 进程树归属）

在 Linux 上经 eBPF 观察进程执行与退出，可选加载 TracingPolicy 观察网络连接与关键目录写入，作为行为监测系统的**动态证据增强通道**——与 auditd / Sysmon / 采样模式共用同一条事实管线，不另建库、不另设规则。对应 docs/architecture.md §采集通道 与 docs/behavior.md 的"Linux DNS/内核观测后续增强"。

> **证据等级声明**：与 auditd 相同——进程树证明"该行为出自某 Agent 的进程或后代进程"，**不等于**"模型自主决定执行了该操作"；exec 事件证明"已启动"，exit 事件仅用于维护进程生命周期。语言无关 ≠ 框架可见：eBPF 能观察 Python/Node/Java/Go 的系统调用，**不能**据此断言执行了哪个框架函数（LangChain 已安装 + Langflow 进程外联 ≠ LangChain 已执行）；系统行为证据对应 BEHAVIOR_SUSPECTED 强度，不承诺内容级能力（HTTPS 内容、模型名、MCP 消息均不可见）。

## 数据链路

```
Tetragon（systemd 单机部署，内核 eBPF；本工具不接触内核）
   │  /var/log/tetragon/events.json（JSON 行导出，--export-filename，50MB×3 轮转）
   ▼
collectors/ebpf/reader      TailReader（EOF 起读、轮转感知，与 auditd 同一实现）｜ ReplayReader（回放）
   ▼
collectors/ebpf/parser      parse_event_json：process_exec / process_exit /（预留 kprobe·tracepoint·uprobe）
   ▼
collectors/ebpf/normalizer  fact_from_event → BehaviorFact
   │                          proc.exec（argv[0]=可执行文件，与其它通道同形）
   │                          proc.exit（仅生命周期：逐出进程图节点，不落库、不计风险）
   │                          事件携带 container_id（Tetragon docker 字段）与 exec_id（内核侧进程身份，抗 PID 复用）
   ▼
detection/process_graph → detection/attribution → behavior_rules（behaviors.yaml，与 auditd 完全同一套）
   ▼
services/ingest（抑制窗口 + 速率上限 + 保留清理）→ SQLite behavior_events（source=tetragon）
   ▼
Web 行为时间线 + /api/v1/events + CLI（collect --mode tetragon / replay --format tetragon）
```

## 采集通道

| 模式 | 前提 | 覆盖 | 盲区 |
|---|---|---|---|
| `tetragon` | Linux + 内核 ≥4.19（建议有 BTF）；Tetragon 已部署且导出文件可读 | 进程执行（binary/argv/ppid/容器身份）、进程退出；网络连接与关键目录写入（安装 configs/tetragon 的 TracingPolicy，可选） | 依赖 Tetragon 所装 TracingPolicy 的范围；HTTPS 内容不可见 |
| `auditd` | root 审计规则（见 syscall-monitoring.md） | 同前 | 需 root 规则管理 |
| `poll` | 无 | 仅进程执行 | 降级模式 |

默认模式：Linux 上优先 `tetragon`（导出文件存在且可读时），否则 `auditd`；其他平台 `poll`。`AGENT_DETECTOR_TETRA_LOG` 可改导出文件路径。

## Tetragon 部署（工具只打印，不自动提权）

```bash
agent-detector tetragon        # 打印当前可用状态 + 完整部署/卸载命令
agent-detector channels        # 查看全部通道可用性
```

标准部署（systemd 单机方式，已在验证机 Ubuntu 26.10 / 内核 7.3 上验证）：

```bash
curl -fSL -o /tmp/tetragon.tar.gz https://github.com/cilium/tetragon/releases/download/v1.7.1/tetragon-v1.7.1-amd64.tar.gz
sudo tar -xzf /tmp/tetragon.tar.gz -C /tmp
sudo bash /tmp/tetragon-v1.7.1-amd64/install.sh
sudo mkdir -p /var/log/tetragon
sudo printf '/var/log/tetragon/events.json\n' > /etc/tetragon/tetragon.conf.d/export-filename
sudo printf 'true\n' > /etc/tetragon/tetragon.conf.d/enable-process-ns
sudo systemctl restart tetragon
```

要点：

- **容器身份**：开启 Tetragon 的 Docker netns 感知后，容器内进程事件带 `docker` 字段——实测为完整 64 位容器 ID 的**前 31 个十六进制字符**，与 `agent_assets.container_id` 做前缀匹配即可（见下文归属）。
- **事件体量**：导出文件按 50MB×3 轮转（`export-file-max-size-mb` / `export-file-max-backups`）；`enable-process-ns` 提供命名空间信息（宿主/容器判定），代价是事件略大。
- **权限**：导出文件默认 `600 root:root`——采集进程需 root，或放宽该文件权限；不可读时启动会返回明确错误与修复指引（与 auditd 的 `log_group` 提示同风格）。
- **多通道并存**：tetragon 与 auditd 可同时运行；抑制窗口键不含来源，同一行为不会双份入库。

## 判定与归属

事实 → 行为沿用 `monitoring/data/behaviors.yaml`（首个命中规则胜出）：proc.exec 命中 SCRIPT_EXEC / GIT_OPERATION / PACKAGE_INSTALL / … / COMMAND_EXEC 兜底，与 auditd 完全一致。`proc.exit` **不进入规则引擎**——它在规则匹配前被消费，仅用于把已退出进程从进程图逐出（保持 PID 复用防护的准确性），既不落库也不产生风险分。

归属算法与 auditd 相同（祖先回溯 ≤12 层，`running_pids` → 指纹规则 → 永不凭空创建资产）。容器事件的处理原则：

1. **宿主进程**：与 auditd 完全一致，宿主 PID + 进程树归属；
2. **容器进程**（事件带 `container_id`）：Tetragon 在宿主 PID 命名空间运行，上报的是**宿主 PID**，而 Docker 发现产出的实例行记录的是**容器内 PID**——两个 PID 空间不可互换，因此容器事件**不做实例级 PID 匹配**，只做资产级归属（`container_id` 前缀匹配 Docker 通道发现的容器资产）；匹配不上时按未归属处理，不强行绑定。

## 落库字段与语义

在 `behavior_events` 新增（幂等 `ALTER TABLE` 迁移）：

| 列 | 语义 |
|---|---|
| `source` | `tetragon`（既有列，行为页新增 eBPF 筛选） |
| `container_id` | Tetragon `docker` 字段（容器 ID 前缀）；宿主进程为空 |
| `flow_id` | `tetragon-{exec_id}`——exec_id 是内核侧进程身份（`节点:单调时钟:pid` 的 base64），抗 PID 复用 |

`evidence_json` 证据标签示例：`tetragon` / `event:process_exec` / `exec_id:...` / `container:b13f15ab...` / `rule:SCRIPT_EXEC` / `self_asset_pid`。

**语义**：抑制窗口（默认 300 秒）键 = Agent + 行为 + 目标 + **pid**——同一进程的重复行为在窗口内只记一条；不同进程的同类行为各自成行（auditd 通道同享此修正）；键不含来源，auditd 与 Tetragon 并存时同一行为跨通道去重。一条事件代表"窗口内该进程存在该行为"，不是精确次数。

## 隐私与安全

- **只读采集**：本工具只 tail 导出文件，不加载 eBPF 程序、不写内核、不与 Tetragon gRPC 通信；Tetragon 本身以 root 运行，部署命令只打印。
- **不存内容**：环境变量、文件内容、网络载荷不入库（`--enable-process-environment-variables` 保持默认关闭）。
- **路径与 argv 策略**：与 auditd 通道同一套（`BEHAVIOR_PATH_POLICY` / `BEHAVIOR_STORE_ARGV` / 脱敏 / 400 字符截断）。
- **防膨胀**：速率上限 + 保留策略 + 导出文件轮转三重限制。
- **攻击面**：Tetragon 具备运行时阻断（enforcer）能力，本集成**只用于监测**；不把内核级阻断接入 Hook 策略系统——"观测到了什么"与"能在执行前控制什么"是两个不同的概念。

## 能力边界（如实声明）

1. **进程树 ≠ 模型自主决定**（同 auditd）；MCP Server 等长驻进程需要协议级证据。
2. **exec 证明已启动，exit 仅生命周期**：本通道不把进程退出当风险行为，也不依赖 exit 码（v1.7 导出格式不含）。
3. **语言无关 ≠ 框架可见**：不能因 eBPF 观察到行为就把已安装的框架依赖升级为 EXECUTION_CONFIRMED。
4. **加密流量不可见**：只有连接级事实（IP:port），无域名（Phase 3 起配合 TracingPolicy 也只有 connect 参数）、无模型名、无 MCP 消息。
5. **容器归属边界**：容器事件资产级归属依赖 Docker 通道先发现该容器；未被发现的容器按未归属处理（可开关记录）。
6. **内核要求**：Tetragon 官方最低内核 4.19，部分功能需更高版本；无 BTF 时需要额外 BTF 文件。WSL2 限制同 auditd（子 PID namespace）——本通道同样必须在真实 Linux 主机验证。
7. **数据缺失≠无行为**：Tetragon 未启动、权限不足、导出文件被轮转截断时，事件不完整——观测不完整不能推断"目标没有行为"。

## 使用

```bash
# Linux 主机（root，或可读导出文件的用户）
agent-detector tetragon                    # 状态 + 部署命令打印
agent-detector collect --mode tetragon --duration 120
agent-detector events --limit 50 --source tetragon

# 任意平台（含 Windows）
agent-detector replay tests/fixtures/tetragon/sample.jsonl --format tetragon
agent-detector purge --all --source tetragon   # 清空演示数据
```

Web：行为页来源筛选新增 eBPF；通道状态卡显示 tetragon 可用性（`/api/v1/telemetry/status` 的 `channels[]`）。

```
GET  /api/v1/capabilities                    # monitor.channels 含 tetragon
GET  /api/v1/telemetry/status
POST /api/v1/telemetry/behavior/start        # body: {"mode": "tetragon", "log_path": ..., "from_start": ...}
GET  /api/assets/{asset_id}/events?source=tetragon
```

## 配置

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `AGENT_DETECTOR_TETRA_LOG` | `/var/log/tetragon/events.json` | Tetragon JSON 导出文件路径 |
| `AGENT_DETECTOR_BEHAVIOR_*` | 同 auditd 通道 | 抑制/速率/保留/路径/argv 策略共用 |

## 验收记录（P0–P3，2026-10-30，验证机 192.168.106.131）

**环境**：VMware 虚拟机，Ubuntu 26.10，内核 7.3.0-9-generic，BTF 存在，初始 PID namespace（非 WSL2）；Tetragon v1.7.1 systemd 部署，RSS ≈ 100MB；导出文件 0644（`export-file-perm` conf），50MB×3 轮转。

| 阶段 | 结果 |
|---|---|
| P0 样本 | 宿主 + 容器（busybox 探针）exec/exit 事件全部可观测；`docker` 字段 = 完整容器 ID 前 31 个 hex 字符（与 `docker inspect` 实测比对）；样本固化为 `tests/fixtures/tetragon/sample.jsonl` |
| P1 通道 | 真机 `collect --mode tetragon`：激励进程 exec/exit 正确入库（source=tetragon、flow_id=tetragon-{exec_id}、container_id 列、证据标签齐全） |
| P2 容器归属 | 真实 dify-api 容器内 `docker exec` 事件经 container_id 前缀匹配挂到容器资产（asset_id/agent_label/evidence 正确）；宿主进程保持未归属路径 |
| P3 策略 | connect + file-writes 两份 TracingPolicy 加载成功；真实事件回放全链路：5 条 INET 连接 → NETWORK_CONNECT（endpoint=IP:port），5 条 MAY_WRITE → FILE_MODIFY |

**已知观察（不影响验收）**：

1. **独立导出的 kprobe args 是扁平结构**（`file_arg` / `int_arg` / `sockaddr_arg`，与 K8s CRD 的 `{type, value}` 包装不同）——normalizer 两种形状都支持。
2. `security_file_permission` 的 file 路径带 Tetragon 附加的 inode 后缀（`path.<inode>`），target 保留原样；目录的写意图也会产生 FILE_MODIFY。
3. `security_socket_connect` 的 sockaddr 在 **index 1**（index 0 是 `struct socket *`）；本地 IPC（AF_UNIX，addr 为 "invalid IP"）不入库。
4. TracingPolicy 加载约需 30–40 秒：重启 tetragon 后再产生激励。
5. 策略音量：connect 全系统低频可长期挂载；file-writes 按路径前缀限域（演示用的 `/home/` 范围过宽，验收后已从验证机卸载，需要时按 configs/tetragon 内说明重装）。
6. Docker 通道对超大镜像（dify-api ~4GB）的深度探测在 2 核 VM 上耗时 10 分钟以上——属 docker-discovery 分支的性能边界，与本通道无关，但影响"扫描立资产→事件归属"的整链路体验，后续可调 `AGENT_DETECTOR_DOCKER_ARCHIVE_*` 预算或对大镜像降级。
