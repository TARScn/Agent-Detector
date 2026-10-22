# Windows 部署与 Sysmon 采集

首期目标是 Windows 10/11 原生运行的 Agent。本文说明 Windows 侧的通道选择、Sysmon 配置与已知限制。

## 通道选择

`agent-detector channels` 会如实报告本机状态（不会为了"看起来正常"而假装可用）：

| 通道 | Windows 可用性 | 说明 |
| --- | --- | --- |
| Sysmon | 需手动安装并启用通道 | 进程创建 / 网络连接 / 文件创建与删除；Event ID 3 默认关闭 |
| auditd | 不可用 | Linux 专用 |
| 进程采样（poll） | 始终可用 | 无需权限，只有进程执行级信息 |
| 出站连接观察（netmon） | 始终可用 | 只读 socket 表与 DNS 缓存，连接级证据 |
| 原生 Hook | 按 Agent 安装 | 唯一的**执行前拦截**通道 |

`agent-detector collect` 在 Windows 上的默认模式：Sysmon 通道可读时用 `sysmon`，否则自动降级为 `poll`。

## 安装并配置 Sysmon

```powershell
# 1. 下载并安装（管理员权限；本工具不做这一步）
#    https://learn.microsoft.com/sysinternals/downloads/sysmon
sysmon64.exe -accepteula -i

# 2. 合并采集配置：先导出你现有的配置，再把 configs\sysmon.xml 的开关并进去
sysmon64.exe -c            # 打印当前配置
sysmon64.exe -c configs\sysmon.xml

# 3. 验证通道可读
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5
```

- 采集器通过 Windows 事件日志 API（`wevtapi.dll` 的 `EvtSubscribe`）订阅，不轮询 PowerShell（设计文档 §4.3）。
- 工具只在启动时用 `EvtOpenChannelConfig` 检查通道是否存在且启用；不存在时返回"未安装 Sysmon：事件通道不存在"，
  而不是静默产出空数据流。
- 只用四类事件：`ProcessCreate(1)`、`NetworkConnect(3)`、`FileCreate(11)`、`FileDelete(23/26)`。
  其余事件（含 `ProcessTerminate(5)`、`DnsQuery(22)`）解析器认识但暂不落库。

## 行为归属

Sysmon 事件带 `ProcessGuid` / `ParentProcessGuid`。本工具用 `ProcessGuid` 作为事件的关联标识，
并用进程树（pid + ppid + 启动时间）回溯到 Agent 资产；`ProcessGuid` 会写进事件证据里便于核对。

归属强度遵循固定顺序（设计文档 §4.2）：原生 Hook 直接证据 > 进程父子链 > 同一会话上下文 >
时间 / 工作目录相似（只生成低置信度候选）。无法证明的关系保持"未归属"，界面如实显示。

## Windows 上的 Hook 安装

```powershell
# 先看状态与计划（dry-run，不写文件）
agent-detector hooks status
agent-detector hooks plan claude_code

# 确认后写入（会先备份原配置，只增删本工具自己的条目）
agent-detector hooks install claude_code --apply
```

- Claude Code：`%USERPROFILE%\.claude\settings.json`，`PreToolUse` + `PostToolUse`。
- Codex CLI：`%USERPROFILE%\.codex\hooks.json`，使用 `command_windows` 字段。
- Cursor：`%USERPROFILE%\.cursor\hooks.json`，`beforeShellExecution` + `beforeMCPExecution`。

生成命令使用当前 Python 解释器的绝对路径（`"<python.exe>" -m hook_bridge.entry --agent <type>`），
不依赖 PATH。若服务装在别处，可用 `AGENT_DETECTOR_PYTHON` 指定解释器后再安装。

## 已知限制

- **Sysmon 文件事件不完整**：只覆盖创建与配置的删除事件，读取、改名、追加写不在其中（设计文档 §4.1）。
- **Event ID 3 默认关闭**：不显式开启就没有网络连接事件。
- **WSL2 不在首期范围**：发行版运行在子 PID namespace，auditd 不可用；Windows 侧 Hook 也不适用于 WSL 内的 Agent。
  检测方法：`agent-detector channels` 会显示 auditd 不可用；WSL 内的 Agent 进程不会出现在 Windows 进程表中。
- **权限**：读取其他用户的进程元数据可能需要更高权限；工具按最小权限设计，不自动提权。