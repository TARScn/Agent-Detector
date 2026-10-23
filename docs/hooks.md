# 执行前拦截：Hook 适配与 hook_bridge

只有接入原生 Hook 的 Agent 才能在工具调用**执行前**被阻断。本文说明适配层结构、各平台响应格式、
安装/卸载语义与故障处置。

## 链路

```
Agent 决定调用工具
   → 执行 Hook 配置里的命令： "<python>" -m hook_bridge.entry --agent claude_code
   → hook_bridge 读取 stdin 的 JSON，POST 到 /internal/v1/hooks/decide（loopback + Token）
   → hooks/normalizer 规范化成 ToolCall（平台差异至此为止）
   → policy/engine 判定 allow / ask / deny / audit
   → 记录 native_hook 行为事件、更新会话、必要时生成告警
   → interception/hooks 转换成该 Agent 的原生响应，由 hook_bridge 打印到 stdout
```

`hook_bridge` 只依赖标准库：它位于 Agent 的工具调用路径内，任何导入都是用户能感知的延迟（设计文档 §11.4）。
服务不可达时按配置的失败处置返回（见下文"故障处置"）。

## 适配器

| Agent | 配置文件 | 事件 | 响应字段 | Schema 状态 |
| --- | --- | --- | --- | --- |
| Claude Code | `~/.claude/settings.json` | `PreToolUse`、`PostToolUse` | `hookSpecificOutput.permissionDecision` = allow/ask/deny | 已按官方 hooks 参考核对 |
| Codex CLI | `~/.codex/hooks.json` | `PreToolUse`（含 `command_windows`） | `{decision, reason}` | **待验证**：需按已安装版本核对 |
| Cursor | `~/.cursor/hooks.json` | `beforeShellExecution`、`beforeMCPExecution` | `{permission, user_message, agent_message}` + `failClosed` | **待验证**：首期只接两个检查点 |

"待验证"会一路显示到界面：设置页与 `agent-detector hooks status` 都会标注，不会把未核对的适配说成已支持。

各平台的原始载荷示例（Claude）：

```json
{
  "session_id": "session-1001",
  "hook_event_name": "PreToolUse",
  "cwd": "D:\\Project-A",
  "tool_name": "Bash",
  "tool_input": { "command": "Remove-Item -Recurse -Force D:\\ImportantData" }
}
```

本工具返回：

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "[Agent Detector] 命中受保护路径删除策略"
  }
}
```

## 安装与卸载

```bash
agent-detector hooks status                  # 每个 Agent 的配置状态
agent-detector hooks plan claude_code        # dry-run：打印将要写入的内容
agent-detector hooks install claude_code --apply
agent-detector hooks uninstall claude_code --apply
agent-detector hooks snippet cursor          # 手工粘贴用片段
```

安装器遵守三条规则：

1. **绝不覆盖用户配置**：只增删带标记（`__agentDetector`）的条目，其他 Hook、权限与无关键原样保留。
2. **未确认不写文件**：`apply=False`（CLI 默认、API 默认）只返回"将会写入什么"。
3. **写前备份**：首次修改前生成 `settings.json.agent-detector.<ts>.bak`；写入使用临时文件 + 原子替换。

状态机：`INSTALLED`（事件齐全）/ `PARTIAL`（只接了部分事件，界面显示保护降级）/ `NOT_INSTALLED` /
`CONFLICT`（配置不是合法 JSON，安装器拒绝改动并报错）。

## 故障处置（fail-closed / 审计放行）

| 场景 | 行为 |
| --- | --- |
| 决策服务不可达、超时、返回非 JSON | 按 `AGENT_DETECTOR_HOOK_FAILURE_MODE`：`block`（默认）拒绝调用；`allow` 放行并在消息中说明 |
| 策略规则里引擎异常 | 同上，`PolicyEngine.decide_error` 生成对应结论 |
| 载荷不是合法 JSON | 视为故障，按同样规则处置（不会静默放行） |
| Hook 配置被移除 | `inspect` 检测到，Agent 保护状态变为"未安装/降级"，界面与 CLI 都会显示 |

`decision=allow` 不等于执行成功：成功与否由 `PostToolUse` 事件确认，写入 `execution_status`
（`allowed` / `blocked_by_hook` / `succeeded` / `failed`）。设计文档 §7 明确要求不要把两者混为一谈。

## 决策接口

```
POST /internal/v1/hooks/decide
Header: X-Agent-Detector-Token: <data/hook.token 的内容>
Body:   {"agent_type": "claude_code", "payload": {…平台原始载荷…}, "bridge_pid": 1234}
```

- 只监听 loopback；Token 首次使用时生成到 `data/hook.token`（POSIX 下 chmod 600）。
- 正式桌面产品应换成带用户 SID 访问控制的 Named Pipe，见设计文档 §8 与"待开发"清单。
- `bridge_pid` 是桥进程的父 PID：服务用它沿父进程链找到 Agent 运行实例，作为归属的直接证据。

## 性能

一次判定包含：规范化 → 规则匹配（内存中，正则预编译）→ 一次 SQLite 写入。响应里带 `latency_ms`，
事件表也记录了耗时来源。压力测试方法与 P95 目标见设计文档 §11.4。