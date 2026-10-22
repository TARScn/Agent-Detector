# 系统行为监测（auditd 采集 + 进程树归属）

在 Linux 系统层采集 Agent 进程及其后代进程的行为——进程执行、文件写入 / 移动 / 删除 / 属性变更、网络连接——并通过进程树回溯把行为归属到具体 Agent。对应产品文档 §3.1.5（运行行为检测）与 M4 的"限时进程活动观察"。Windows 与无 root 的 Linux 主机提供**采样降级模式**（仅进程执行级）。

> **证据等级声明**：进程树证明"该行为出自某 Agent 的进程或后代进程"，**不等于**"模型自主决定执行了该操作"；auditd 只证明进程"已启动"（不提供退出码），文件操作只证明"已发生 / 被拒绝"。系统行为证据对应 BEHAVIOR_SUSPECTED 强度，**不承诺内容级能力**（提示词、工具参数、文件内容均不可见、不入库）。

## 数据链路

```
Linux audit 子系统（由操作者以 root 安装的最小化规则，键 agent_detector_*）
   │  /var/log/audit/audit.log ← TailReader（EOF 起读、轮转感知）｜ ReplayReader（文件回放）
   ▼
collectors/audit/parser     按 audit(msg=audit(ts:serial)) 分组，续行合并，十六进制字段解码
   ▼
collectors/audit/normalizer → BehaviorFact（事实层：kind / pid / ppid / 进程名 / argv / 路径对 / 结果）
   ▲
   │  poll 模式（无权限降级）：psutil 采样 (pid, create_time) 差集 → 仅 proc.exec 事实
   ▼
detection/process_graph  ProcessGraph（pid + create_time 身份；快照种子 + exec 事实更新 + /proc 实时校验）
   ▼
detection/attribution  祖先回溯（≤12 层）→ 资产快照 running_pids / 指纹规则（与扫描同一套匹配原语）
   ▼
detection/behavior_rules（detection/rules/behaviors.yaml）事实 → 高级行为（首个命中规则胜出，兜底 COMMAND_EXEC）
   ▼
services/ingest（抑制窗口去重 + 速率上限 + 保留清理）→ SQLite behavior_events（source=auditd/poll）
   ▼
Web 行为页时间线 + /api/v1/events + CLI（channels / collect / replay / events / purge）
```

## 采集通道

| 模式 | 前提 | 覆盖 | 盲区 |
|---|---|---|---|
| `auditd` | root 安装审计规则；采集进程可读 `audit.log`（root 或 auditd `log_group`） | 进程执行（含 argv/ppid）、文件写 / 属性 / 删除 / 移动、connect、可选 kill | 读事件默认关闭；跨文件系统移动表现为"复制 + 删除"；毫秒级 exec 也可能被内核审计正常捕获（无采样盲区） |
| `poll` | 无（普通用户、Windows 可用） | 仅进程执行（cmdline 可得） | 短命进程可能落在两次采样之间；无文件 / 网络事件；这是**降级模式**，产出会标注证据 `poll/sampled` |
| `replay` | 一份保存的 audit 日志 | 与 auditd 相同（离线） | 一次性处理；重新回放会再次入库（抑制窗口内不重复） |

默认模式：Linux 上 `auditd`，其他平台 `poll`。

## auditd 规则（工具只打印，不自动提权）

```bash
# 查看推荐规则与安装/卸载命令（--persistent 追加 rules.d + augenrules 形式）
agent-detector rules --watch-dir /home/user/agent-lab --persistent
```

生成的规则形如：

```
-a always,exit -F arch=b64 -F uid>=1000 -S execve -S execveat -k agent_detector_exec
-a always,exit -F arch=b64 -F dir=/home/user/agent-lab -F perm=wa -k agent_detector_file
-a always,exit -F arch=b64 -F dir=/home/user/agent-lab -S rename,renameat,renameat2,unlink,unlinkat,rmdir,mkdir,mkdirat,chmod,fchmod,fchmodat,chown,fchown,lchown,fchownat,truncate,ftruncate,creat -k agent_detector_file
# 可选：-S connect -k agent_detector_net（默认包含）、-S kill,tkill,tgkill（默认关闭，噪声大）
```

要点：

- 规则**只审计指定 uid 范围与指定目录**（`-F dir=` 为递归目录过滤），避免全系统噪声与性能开销；exec 审计有开销，建议先在实验目录验证再扩大范围。
- 采集器按 `-k` 键过滤（默认 `agent_detector_*`，可用 `AGENT_DETECTOR_AUDIT_KEYS` 覆盖），不会读取其它工具的审计事件。
- **读事件默认关闭**：`-F perm=r` 会产生海量事件，仅在确有需要时用 `--read-dir` 显式开启（证据与行为都标注为 `FILE_READ`）。
- **audit.log 默认仅 root 可读**：以 root 运行采集器（CLI / systemd），或在 `/etc/audit/auditd.conf` 设置 `log_group = <组名>` 并让采集用户入组；Web 进程读不到日志时启动会返回明确错误与修复指引。
- 卸载：`sudo auditctl -W agent_detector_exec,agent_detector_file,agent_detector_read,agent_detector_net,agent_detector_kill`（持久化规则另需删除 `/etc/audit/rules.d/agent-detector.rules` 后 `augenrules --load`）。

## 判定与归属

低层事实 → 高级行为（`detection/rules/behaviors.yaml`，规则按顺序匹配、首个命中胜出）：

| 事实 kind | 触发 | 高级行为 | 置信度 |
|---|---|---|---|
| proc.exec | 解释器 + 脚本参数（python/node/bash…） | SCRIPT_EXEC（target=脚本路径，`-c` 内联代码记为 `inline` 不入库） | high |
| proc.exec | git | GIT_OPERATION（detail=子命令） | high |
| proc.exec | pip/npm/apt/cargo… | PACKAGE_INSTALL | high |
| proc.exec | psql/mysql/sqlite3… | DATABASE_OPERATION | high |
| proc.exec | 含 --remote-debugging-port / playwright / puppeteer… | BROWSER_AUTOMATION | medium |
| proc.exec | 其余 | COMMAND_EXEC（兜底，target=前两个参数） | high |
| file.write | 写 / 创建 | FILE_MODIFY | high |
| file.move | rename 系列（源 → 目标成对解析） | FILE_MOVE | high |
| file.delete | unlink / rmdir | FILE_DELETE | high |
| file.attr | chmod / chown / setxattr… | FILE_ATTR_CHANGE | high |
| file.read | perm=r（默认关闭） | FILE_READ | medium |
| net.connect | connect（SOCKADDR 解码，仅 AF_INET/6） | NETWORK_CONNECT（target=IP:port，无域名） | high |
| proc.kill | kill 系列（默认关闭） | PROC_KILL | high |

可执行名比较会忽略 Windows 后缀（`.exe` / `.cmd` / `.bat` / `.ps1`），因此同一套规则在 Linux 与 Windows 采样模式下行为一致。

归属算法（自事件进程向父进程回溯，首个命中胜出）：

1. 祖先 PID ∈ 最新资产快照 `running_pids` → 事件挂到该 `asset_id`（证据 `self_asset_pid` / `ancestor_asset_pid`）；
2. 否则用扫描同一套指纹原语匹配进程（client_rule 的 ProcessSpec、signature 正则）→ `agent_label` = 规则名；若按与扫描一致的公式能算出候选 `asset_id`（client rule: `sha256(hostname|规则 id|user-home)`；signature: `sha256(hostname|规则名|process:可执行路径)`）**且该资产已存在于库中**才挂接（证据 `process_fingerprint`），**永不凭空创建资产**；
3. 全部未命中 → 证据 `unattributed`，默认**不落库**（`AGENT_DETECTOR_BEHAVIOR_INCLUDE_UNATTRIBUTED=1` 可改为记录，agent_label 取进程名）。

进程身份为 `(pid, create_time)`：exec 事实更新进程镜像信息，实时校验时 `create_time` 不一致即判定 PID 复用并丢弃缓存节点。

## 落库字段与语义

`behavior_events` 在原表基础上新增（幂等 `ALTER TABLE` 迁移，无需 Alembic）：

| 列 | 语义 |
|---|---|
| `pid` / `ppid` | 事件进程与内核记录的父进程 |
| `process_name` | 实际执行进程名（如 python3、mv） |
| `target` | 行为对象：文件路径、`源 -> 目标`、脚本路径、可执行名；网络事件的 IP:port 在既有 `endpoint` 列 |
| `result` | `started`（exec 成功启动）/ `success` / `denied`（EACCES/EPERM）/ `failed` |
| `source` | `auditd` 或 `poll`（与既有的 `netmon` 同表，行为页按来源筛选） |

其余沿用既有列：`agent_label`（归属 Agent 或进程名）、`asset_id`、`flow_id`=`{source}-{audit 序号}`、`protocol`=`SYS`、`event_type`=事实 kind、`operation`=高级行为、`confidence`、`evidence_json`（证据标签数组，如 `auditd` / `key:...` / `rule:SCRIPT_EXEC` / `ancestor_asset_pid` / `detail:status` / `exit:-13` / `unclassified_syscall`）。

**语义**：抑制窗口（默认 300 秒，键 = Agent + 行为 + 目标）内同一行为只记一条——一条事件代表"窗口内存在该行为"，不是精确次数。

## 隐私与安全

- **只读采集**：仅读审计日志与进程表；不执行被发现的 Agent / Skill / MCP 启动命令，不注入进程，不改配置，不装证书。
- **不存内容**：文件内容、提示词、工具参数、凭证原文一律不入库。
- **路径**：默认原样入库（审计目的是看清"动了哪个文件"）；`AGENT_DETECTOR_BEHAVIOR_PATH_POLICY=basename` 可收紧为"文件名 + 目录 SHA256 前 12 位"。派生的执行目标只保留脚本名 / 子命令 / 前两个参数。
- **argv 原文默认不落库**：仅在 `AGENT_DETECTOR_BEHAVIOR_STORE_ARGV=1` 时以脱敏（`sk-***`/Bearer/密码风格自动遮蔽）与 400 字符截断形式进入证据；`-c` 内联代码永不入库。
- **不提权**：auditd 规则命令只打印（CLI / Web 展示），由操作者自行以 root 执行。
- **防膨胀**：速率上限（默认 600 事件/分钟，超出丢弃并计数）+ 保留策略（默认 30 天，采集服务每日自动清理，`behavior purge` 手动执行；`purge --all --source auditd` 可清空演示数据）。

## 能力边界（如实声明）

1. **进程树 ≠ 模型自主决定**：归属证明"操作出自某 Agent 的进程或后代"，不证明该操作由模型决策（对照：长期驻留的 MCP Server 不是 Agent 子进程，需协议通道证据）。
2. **auditd 只证明"已启动"**：exec 事件不代表脚本成功退出（无退出码）；文件操作只证明系统调用已发生或被拒绝。
3. **不覆盖**（本版明确不做）：文件读取（默认关）、跨文件系统移动的 MOVE 推断、MCP 工具名 / 参数、浏览器 CDP 内容、SQL 语句、自主循环 / 失败重试（行为序列分析，二期）。
4. **采样降级模式**：短命进程可能漏检，且没有文件与网络事件。
5. **WSL2 不可用（重要）**：WSL 发行版运行在**子 PID namespace** 中（`/proc/2` 是 WSL 的 init 而非内核线程），而内核 audit netlink 只服务初始命名空间（`audit_netlink_ok` 的硬性检查）——即使内核 `CONFIG_AUDIT/AUDITSYSCALL` 均为 y、进程拥有全部 capability，`auditctl` 仍一律返回 `Operation not permitted`。这与内核编译选项无关，**自编译 WSL 内核同样无法解决**；Docker Desktop（WSL2 后端）内同理（引擎自身也在该 pidns 中）。auditd 采集必须在一台真实 Linux 主机（物理机 / 虚拟机 / 云主机）上验证。
6. **fixture 校准**：本版解析器的单元测试基于按 auditd 日志格式构造的样例（`tests/fixtures/audit/scenario.log`）；rename 的 `nametype` 组合等细节应在首次真机验收时用真实日志复核（解析器对未知 syscall 会降级为按 PATH nametype 推断并标注 `unclassified_syscall`）。

## 使用

```bash
# Linux 主机（root 或已加入 log_group 的用户）
agent-detector rules --watch-dir /home/user/agent-lab   # 打印规则与安装命令（root 执行）
agent-detector collect --duration 120                   # 限时观察，实时打印命中的行为
agent-detector status                                   # 采集状态与计数
agent-detector events --limit 50 --source auditd        # 查询事件

# 任意平台（含 Windows）
agent-detector collect --mode poll --duration 60        # 采样降级模式
agent-detector replay tests/fixtures/audit/scenario.log # 回放验证
agent-detector purge                                    # 应用保留策略
```

Web：行为页（启动/停止采集、状态与计数、auditd 规则卡片、按 Agent / 来源筛选的行为时间线；netmon 的 LLM 调用事件与系统行为在同一时间线，按 `source` 区分）。

```
GET  /api/v1/telemetry/status （含 stats 与事件过滤）
POST /api/v1/telemetry/behavior/start  (body: {mode, log_path, from_start})
POST /api/v1/telemetry/behavior/stop
GET  /api/v1/telemetry/audit-rules?watch_dir=&uid_min=
GET  /api/assets/{asset_id}/events        # 资产维度的行为事件（产品文档 §7）
```

## 配置

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `AGENT_DETECTOR_AUDIT_LOG` | `/var/log/audit/audit.log` | audit 日志路径 |
| `AGENT_DETECTOR_AUDIT_KEYS` | `agent_detector_*`（5 个键） | 只处理这些 `-k` 键的事件 |
| `AGENT_DETECTOR_BEHAVIOR_SUPPRESS` | `300` | 抑制窗口秒（0–86400） |
| `AGENT_DETECTOR_BEHAVIOR_INCLUDE_UNATTRIBUTED` | `0` | 是否记录未归属事件 |
| `AGENT_DETECTOR_BEHAVIOR_RETENTION_DAYS` | `30` | 保留天数（0=关闭自动清理） |
| `AGENT_DETECTOR_BEHAVIOR_MAX_EVENTS_PER_MINUTE` | `600` | 入库速率上限（0=不限） |
| `AGENT_DETECTOR_BEHAVIOR_PATH_POLICY` | `full` | `full` 原样 / `basename` 脱敏 |
| `AGENT_DETECTOR_BEHAVIOR_STORE_ARGV` | `0` | 是否在证据中存脱敏后的 argv |
| `AGENT_DETECTOR_BEHAVIOR_POLL_INTERVAL` | `2.0` | 采样模式间隔秒（0.5–60） |
| `AGENT_DETECTOR_BEHAVIOR_RULES_DIR` | — | 外部行为规则目录（`behaviors.yaml` / `llm_apis.yaml`，有效则整体覆盖包内规则） |

## Linux 真机验收步骤（待执行）

1. 目标主机安装 auditd，`agent-detector rules --watch-dir <工作目录>` 后以 root 执行规则；确认 `auditctl -l` 有 5 组键。
2. 运行场景脚本（在监视目录内）：创建文件 → 运行 `python3 hello.py` → `mv` 重命名 → `rm` 删除 → `git status` →（可选）外联 connect。
3. 启动真实 Agent（推荐 Claude Code，已有指纹；或经 `AGENT_DETECTOR_RULES_DIR` 注入演示指纹），让它执行同样操作。
4. 验收标准：行为页（或 `behavior events`）出现归属正确的 SCRIPT_EXEC / FILE_MOVE / FILE_DELETE / GIT_OPERATION 等事件，`pid/ppid/进程名/目标/证据/置信度` 齐全；非 Agent 树进程默认不落库；记录事件率 / CPU / `auditctl -s` 的 backlog 与 lost 计数。
5. 用真实日志复核解析细节（如 rename 的 PATH 记录组合），必要时更新 fixture。