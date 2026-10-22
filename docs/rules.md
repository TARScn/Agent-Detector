# 检测规则规范

检测规则是纯声明式 YAML，存放于包内 `src/agent_detector/discovery/fingerprints/rules/`。
引擎（`discovery/fingerprints/engine.py`）只实现探测原语；**新增/调整检测目标只改数据，不改代码**。

## 规则加载

按顺序读取，后者覆盖前者：

1. 包内规则目录 `discovery/fingerprints/rules/*.yaml`
2. 环境变量 `AGENT_DETECTOR_RULES_DIR` 指向的外部目录
3. `load_rules(extra_dir=...)` 显式传入的目录

合并语义：`client_rule` 按 `id` 覆盖（外部目录可整体替换某个产品的规则）；
`signature_set` 的规则累加。解析失败或校验不通过的文件被跳过并记录错误，
不会影响其他规则和扫描任务。

所有模型 `extra="forbid"`：手写 YAML 的拼写错误会在加载时立即报错，
而不是静默改变检测行为。正则表达式在加载时预编译校验。

## 规则类型一：client_rule（一个产品一条，全证据源融合）

完整示例见 `rules/claude_code.yaml`。字段结构：

```yaml
kind: client_rule
id: claude-code              # 资产 ID 组成部分 & 覆盖键
name: Claude Code
asset_type: AGENT_CLIENT     # domain/enums.py::AssetType
revision: 2                  # 规则修订号，调整特征时递增

install:                     # INSTALLED 证据：命中任意一项
  npm_packages:              # 拼接到已知 npm 全局根下找 package.json
    - {package: '@anthropic-ai/claude-code', confidence: 0.9}
  paths:                     # 文件存在（原生安装器二进制）
    - {path: '~/.local/bin/claude', confidence: 0.85}
  dirs:                      # 目录存在
    - {path: '~/.claude', confidence: 0.8}

version:                     # 按优先级尝试，命中即停；全失败 → UNKNOWN
  - from: npm_package_json   # 读已安装包 package.json 的 version 字段
    source: package-metadata
    confidence: 0.9
  - from: semver_dir_entries # 目录下语义化版本命名条目取最新
    dirs: ['~/.claude/versions', '~/.local/share/claude/versions']
    source: installer-metadata
    confidence: 0.8

config:                      # CONFIGURED 证据：只看键名/存在性，永不读值
  json_files:
    - {path: '~/.claude.json', keys_any: [projects, mcpServers], confidence: 0.9}
  existing_files:
    - {path: '~/.claude/settings.json', confidence: 0.8}

process:                     # RUNNING 证据：排除先于正向匹配
  executable_names: [claude, claude.exe, claude.cmd, claude.ps1]
  cmdline_tokens: ['@anthropic-ai/claude-code']
  exclude_patterns:          # 命中即跳过（如同名不同产品的 Desktop 排除）
    - '(?i)windowsapps[/\\]claude_'
  confidence: 0.85

confidence:                  # 合成公式 base + 命中状态权重，封顶 cap
  {base: 0.5, installed: 0.2, configured: 0.2, running: 0.25, cap: 0.95}
```

要点：

- `~` 表示被扫描用户的 home（多用户主机上各用户独立成资产）。
- `json_files.keys_any` 是"键名存在性"检查——这是产品使用行为特征，
  值永不读取；列出的键应是只有真实使用才会出现的（如 `projects`），
  安装引导键（如 `userID`）不要列。
- `exclude_patterns` 在正向匹配之前执行，用于排除同名不同产品的进程。
- 路径必须使用 `~` 相对形式，禁止写绝对路径——规则要跨机器复用。

## 规则类型二：signature_set（一组通用命令行正则，廉价初筛）

完整示例见 `rules/signatures.yaml`：

```yaml
kind: signature_set
rules:
  - name: Ollama
    asset_type: LLM_SERVICE
    pattern: '(?<![\w-])ollama(?:\s+serve)?(?![\w-])'
```

匹配语义：对全部进程命令行做大小写不敏感搜索。仅命中 → RUNNING、置信度 0.65；
同时按 PID 关联到本机 LISTEN 端口 → 置信度 0.85。命令行中声明的版本号
会提取为 `process-claim` 来源（低可信，未经包管理器验证）。

**写正则的红线**：只匹配可执行文件名、模块路径、可识别 token；
禁止 `agent`、`python`、`claude` 这类裸单词——误报率会失控。
有专属 client_rule 的产品不要同时放进 signature_set，避免两套逻辑抢证据。

## 验证修改

改完规则跑 `pytest -q`（打包规则会被加载器真实解析并被检测测试消费），
再对目标机器执行 `agent-detector scan --json` 核对结果。
