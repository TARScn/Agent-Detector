# 检测规则规范

检测规则是纯声明式 YAML，存放于包内 `src/agent_detector/discovery/data/fingerprints/`。
引擎（`discovery/fingerprints/engine.py`）只实现探测原语；**新增/调整检测目标只改数据，不改代码**。

## 规则加载

按顺序读取，后者覆盖前者：

1. 包内规则目录 `discovery/data/fingerprints/*.yaml`
2. 环境变量 `AGENT_DETECTOR_RULES_DIR` 指向的外部目录
3. `load_rules(extra_dir=...)` 显式传入的目录

合并语义：`client_rule` 按 `id` 覆盖（外部目录可整体替换某个产品的规则）。
解析失败或校验不通过的文件被跳过并记录错误，不会影响其他规则和扫描任务。

所有模型 `extra="forbid"`：手写 YAML 的拼写错误会在加载时立即报错，
而不是静默改变检测行为。

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
  - from: executable_version_flag  # 产品的 --version 只读探针（无害执行，见下）
    path: '~/.local/bin/claude.exe'
    pattern: '(\d+\.\d+\.\d+)'     # 首个匹配；用分组收窄提取范围
    timeout_ms: 5000               # 500~15000，硬超时
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

**无害执行约定（`executable_version_flag`）**：探测默认不执行被发现的
程序；唯一例外是产品的 `--version` 类只读探针——它不改变系统状态。
红线：仅在被动证据已确认安装（INSTALLED）后执行；argv 只能来自规则
数据（永不取自进程命令行）；不经 shell、硬超时；只保留首个正则匹配
作为版本号。npm shim（.cmd/.ps1）不能作为探针目标——无 shell 时无法
执行，请指向真实二进制。

## 规则类型二：framework_rule（自建框架，依赖元数据识别）

完整示例见 `rules/framework_langchain.yaml` 与 `framework_langflow.yaml`：

```yaml
kind: framework_rule
id: langchain
name: LangChain
runtimes: [python, node]
dependencies:
  any:            # 任一命中即可（PEP 503 归一化 / npm scoped 包名）
    - langchain
    - langchain-core
    - '@langchain/core'
```

匹配语义：对"进程 → 项目解析 → 依赖元数据"得到的组件清单做包名匹配
（dist-info METADATA / lock / pyproject 依赖声明），不做进程名正则。
`runtimes` 是硬过滤——项目 runtime 不在规则声明内则不匹配（Docker 通道
给 npm 包根造的是 node 项目，python-only 规则不再误配；runtime 未知
（如已停止容器）对所有规则保持兼容）。证据分级：组件仅来自声明类出处
（`declared`/`locked`，未经 dist-info 确认）时框架资产状态为 CONFIGURED
而非 INSTALLED——"声明过"不等于"装上了"；任一组件有已安装元数据才回
INSTALLED。依赖命中只证明框架**环境**；RUNNING 由进程-项目关联单独给出
（frameworks.py 的多框架诚实规则：RUNNING 只归应用资产）。

跨来源归并（scan.py `correlate_assets`）：HTTP 主动探测按
`listen-port:{port}` 建资产，Docker 通道按 `compose:`/`container:` 建——
同一部署两者 asset_id 必然不同。同主机、规范化产品名相同（`Dify`/`dify`
同键）时，探测资产折叠进基础设施资产（证据与端口并入）；无对应方的探测
资产保留独立行。

> **签名通道已退役（2026-11-02）**：原 `signature_set`（通用命令行正则
> 廉价初筛）整通道删除。它拿不到版本、会在参数/路径/进程标题撞上同名单词
> （实证：`\bdify\b` 把 postgres 连接标题、grep/tmux 命令行全部误报成
> "Dify 运行中"，每个连接各生成一个 asset_id）。产品发现一律走专属
> `client_rule`（安装/配置/进程全证据源）或 `framework_rule`（依赖口径）；
> 新产品验证时按实勘数据提取专属指纹，不再回流通用正则。

## 验证修改

改完规则跑 `pytest -q`（打包规则会被加载器真实解析并被检测测试消费），
再对目标机器执行 `agent-detector scan --json` 核对结果。
