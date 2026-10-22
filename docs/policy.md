# 安全策略引擎

规则是声明式 YAML，引擎是纯函数：输入一个规范化后的工具调用，输出 allow / ask / deny / audit。
**LLM 不参与必经决策**（推理延迟、模型不可用与误判都会直接影响 Agent 正常工作，见设计文档 §6.2）。

## 文件位置

- 内置默认：`src/agent_detector/policy/rules/policies.yaml`
- 外部覆盖：`AGENT_DETECTOR_POLICY_DIR=/path/to/dir`，同名文件整体替换内置文件
- 运行时覆盖：界面/API 修改的"启用状态"与"决策"存数据库（`security_policies`），不改规则文件

## 规则结构

```yaml
kind: policy_set
revision: 1
defaults:
  decision: allow        # 未命中任何规则时的决策
  risk: low
  reason: 未命中任何策略规则（默认放行，仅记录）
rules:
  - id: deny-delete-protected-path      # 小写 slug，唯一
    name: 禁止删除受保护目录
    decision: deny                       # allow | ask | deny | audit
    risk: critical                       # low | medium | high | critical
    priority: 10                         # 升序求值，首个命中的规则决定结果
    enabled: true
    reason: 命中受保护路径删除策略        # 返回给 Agent 与告警的原因
    match:
      tools: [bash, shell]               # 工具名（大小写不敏感）
      command_patterns: ['remove-item\b.*-recurse', '\brm\s+-\w*r\w*f']
      path_patterns: ['D:/ImportantData/**', '**/.ssh/**']
      text_patterns: ['sk-ant-[a-z0-9_-]{8,}']
      command_contains: ['--force']
      command_not_contains: ['--dry-run']
      tool_args: [command, cmd, script]   # 要求参数里出现这些键
      cwd_patterns: ['D:/Project-*']
      agent_types: [claude_code]
      outside_cwd: true
```

## 匹配语义

- **字段之间是 AND，列表内部是 OR**：`tools: [Bash]` 且 `command_patterns` 命中其一 ⇒ 命中。
- `command_patterns` / `text_patterns` 是正则（`re.IGNORECASE`），加载时预编译，非法正则直接报错。
- `path_patterns`：`*` 匹配单段，`**` 匹配任意层级（`**/x` 也匹配 `x` 本身）。目录要同时写 `**/.ssh` 与 `**/.ssh/**`。
  路径会从工具参数（`file_path` / `path` / …）与 shell 命令行中的路径样 token 中提取，`~` 会展开为当前用户主目录。
- `outside_cwd`：调用提到的**所有**路径都在会话工作目录之外才算命中；工作目录未知或解析不出路径时**不命中**
  （不能证明的关系不能当成违规）。
- 优先级：`priority` 升序，首个命中的规则决定结果。deny / ask 规则要排在 allow / audit 兜底规则之前。
- 空 `match` 的规则被拒绝加载；字段写错（未知键）同样报错，避免规则静默失效。

## 判定结果

```json
{"decision": "deny", "risk_level": "critical",
 "reason": "命中受保护路径删除策略",
 "matched_rules": ["deny-delete-protected-path", "ask-recursive-delete-outside-project"],
 "policy_id": "deny-delete-protected-path"}
```

`matched_rules` 保留后续命中的规则（最多 3 条）作为审计线索；`policy_id` 是真正做决定的规则。

自查命令（不需要 Agent、不需要 Hook）：

```bash
agent-detector policy list
agent-detector policy test --command "rm -rf ~/.ssh"
agent-detector policy test --tool Write --path "C:/Users/me/.claude/settings.json"
agent-detector policy test --command "Remove-Item -Recurse -Force D:\ImportantData" --cwd "D:\Project-A"
```

## 内置样例规则

| 规则 | 决策 | 说明 |
| --- | --- | --- |
| deny-delete-protected-path | deny | 受保护目录上的删除 / 格式化（示例路径 `D:/ImportantData` 请按需替换） |
| ask-recursive-delete-outside-project | ask | 递归删除目标全部在会话目录之外 |
| deny-credential-read | deny | SSH 私钥、云凭据、Token 文件（含 `.kube/config`、`.npmrc`） |
| deny-credential-exfil | deny | 私钥 / API Key 出现在参数中且同一条命令含外发动作 |
| deny-agent-config-write / -tool | deny | 改写本机 Hook 与安全配置 |
| deny-system-path-write | deny | 系统目录写入 |
| ask-download-and-run | ask | 下载后在同一条命令里执行 |
| ask-package-install | ask | 包管理器安装（含 `npm -g`、`pip install`） |
| ask-mcp-high-risk-tool | ask | 浏览器自动化 / 外发消息类 MCP 工具 |
| ask-network-upload | ask | 向外部地址上传数据 |
| audit-git-write | audit | 提交、推送、回退：记录但不阻断 |
| allow-read-only-shell | allow | 只读浏览命令，明确放行便于审计区分 |

这只是首期样例：命令里出现 `Remove-Item` 或 `curl` 并不等于恶意，真实处置要结合操作类型、目标路径、
文件敏感级别与目标域名（设计文档 §6.1）。

## 与监测的关系

策略只作用于 Hook 通道（Agent 的工具调用）。Sysmon / auditd 采集到的系统行为**不经过策略引擎**：
它们走 `detection/risk` 的风险分级，达到阈值只生成告警，不会阻断——因为系统级事件没有前置检查点，
声称"已阻断"是不诚实的。这一点在总览、策略页与行为页都有明确说明。