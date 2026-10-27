# Docker 容器 Agent 发现（Docker Core）

通过只读 Docker API 发现本机容器中运行的 Agent：枚举全部容器（含已停止），
筛选候选，读取容器内静态文件与依赖元数据，识别 Agent 框架与版本，连同证据
写入 SQLite。不引入 Docker Events 监听与 eBPF；每次 `agent-detector scan`
做一次全量容器扫描。

> **证据等级声明**：Docker Core 能回答"容器里存在什么框架、什么版本"。依赖
> 命中只证明框架*环境*（INSTALLED）；只有容器处于运行状态且存在进程证据时，
> 资产才会带 RUNNING 状态。静态指纹**不能证明** Agent 正在实际执行任务——
> 运行行为确认依赖后续的 Docker Events / 行为检测迭代。

## 数据链路

```
Docker API（只读：list / inspect / top / get_archive，绝不 docker exec）
    ↓
枚举全部容器（运行中 + 已停止）
    ↓  sources/dockerapi.py        传输层：四个只读调用 + 读门槛（allow/deny）
    ↓  sources/docker_agents.py    候选筛选（宽松 OR：镜像/命令/进程/运行时）
    ↓
候选容器深扫：
    ├─ 声明依赖   requirements*.txt / pyproject.toml / uv.lock / poetry.lock / package.json
    ├─ 已安装(Python)  site-packages 目录归档流式扫描 *.dist-info/METADATA
    ├─ 已安装(Node)    node_modules/<pkg>/package.json 定向读取
    └─ 容器内 client   OpenClaw：npm 全局包 + ~/.openclaw/openclaw.json + top 进程
    ↓
detect_frameworks(...)（复用宿主侧同一框架识别与打分）
    ↓
scan.py 合并入库：assets / evidence / applications / agent_assets / agent_instances
    ↓
CLI（agent-detector scan / agents list）· Web API（/api/v1/agents）· 控制台徽标
```

## 采集通道

| 模式 | 前提 | 覆盖 | 盲区 |
| --- | --- | --- | --- |
| Docker API（默认） | 本机 daemon 可达（Windows npipe / Linux socket） | 运行中与已停止容器内的 Python/Node 框架环境、OpenClaw 等容器内 client | daemon 不可达时整条通道静默降级（stats 记 `error`）；容器需挂载真实文件系统 |
| `--no-docker` / `{"docker": false}` | —— | 跳过容器通道 | 容器资产失去复核（已有资产保持原状，不做判定） |

## 候选筛选

筛选是**宽松 OR，宁多勿漏**：容器名与镜像名都不可信（`python-app` 完全可能
在跑 LangGraph）。命中任一信号即进入深扫，筛选只影响成本、不做资产结论：

1. 镜像名/标签命中 `docker_hints.yaml` 的 `image_keywords`；
2. 启动命令命中 `command_tokens`；
3. `docker top` 进程命令行命中 `command_tokens`；
4. 镜像仓库末段或进程名暴露 python/node 运行时（`runtime_image_bases` /
   `runtime_process_names`）——运行时容器全量进入依赖扫描。

已停止容器没有进程列表，靠 1/2 与镜像运行时判断；`get_archive` 对停止容器
同样可用，深扫不受影响。

## 识别与版本

- **框架识别**复用宿主侧 `detect_frameworks`：容器视为一个项目边界（类比
  venv），容器内全部进程归属该应用。依赖命中 → INSTALLED；"单一框架才挂
  进程"的诚实规则原样生效——一个容器内多框架并存时谁都不挂 RUNNING。
- **已停止（或拿不到进程列表）的容器永不 RUNNING**（识别后强制剥离，置信度
  相应扣回 `running` 权重）。
- **版本出处链**：已安装包元数据（dist-info METADATA / node_modules
  package.json）> 锁定文件（uv.lock / poetry.lock）> 声明依赖（requirements /
  pyproject / package.json）> 镜像标签（仅单框架且别无版本时，confidence
  0.4）> `UNKNOWN`。任何一级读不到就返回 UNKNOWN，绝不猜测。
- **容器内 client**：v1 覆盖 OpenClaw——npm 全局根（`/usr/local/lib/node_modules`、
  `/usr/lib/node_modules`）的 `openclaw/package.json` 给出 INSTALLED 与版本，
  `/root/.openclaw/openclaw.json` 顶层键（gateway/agents/models）给出
  CONFIGURED，top 进程命令行命中给出 RUNNING。

### 生命周期（与宿主资产同一套账）

- 资产身份：`build_asset_id(hostname, rule_id, "container:<短ID>")`——与宿主
  资产永不冲突；同一框架出现在多个容器时是彼此独立的资产（v1 不做跨容器合并）。
- 实例身份：容器内 PID + 容器 `StartedAt` 锚定——容器重启即新实例；停止容器
  没有 running_pids，自然没有实例行。
- 复核（`_verify_stale` 容器分支，宿主路径规则不适用）：
  - 容器已删除 → 资产与应用**硬删**；
  - 容器被深扫但框架资产未再现 → 资产**硬删**（依赖已卸载），应用行置
    inactive（无法区分"仅剩 SDK 依赖"与"依赖全清空"，保守处理）；
  - 容器在但不构成候选（如运行时进程已退出）→ 资产与应用置 **inactive**
    （本轮无判定）；
  - Docker 通道故障或被禁用 → 容器资产**不做任何判定**（与 detector 崩溃
    同一守卫），绝不因"缺席"误删。
- 库存行带 `origin`（host/docker）与 `container_id`（agent_assets 与
  agent_instances 各一份，经 `_ADDITIVE_COLUMNS` 幂等迁移）。

## 安全边界

- **只读 API**：仅 `containers/list`、`containers/{id}/inspect`、`top`、
  `get_archive`（下载方向）。**绝不 docker exec**，被扫描容器无感知。
- **读取允许名单**：只有清单/锁定/包元数据文件名可读（pyproject.toml、
  requirements*.txt、uv.lock、poetry.lock、package.json、package-lock.json、
  `*.dist-info/METADATA`、node_modules 内 package.json、已知 agent 配置文件）。
- **拒绝名单双保险**：含 `.env`、`secret`、`credential`、`passwd`、`shadow`、
  `token`、`id_rsa`、`.pem`、`.key`、`.git/`、`.ssh/` 等片段的路径一律不读、
  连存在性都不探测。宁可误伤（如 tokenizers 包的元数据被挡）也不冒密钥风险。
- **读取封顶**：单文件默认 256KB（`DOCKER_READ_MAX_BYTES`）；目录归档流式
  扫描受字节（默认 256MB）与时间（默认 60s）双封顶，兴趣包命中齐全即提前
  断流（关闭流，daemon 随即停止生成 tar）。
- **最小权限提示**：Docker API 等价于宿主 root。请确保运行扫描器的账号本身
  受控，不要把 docker socket/npipe 暴露给不可信进程；本工具只发起上表四个
  只读调用，但不改变 daemon 的权限面。

## 配置项（环境变量）

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `AGENT_DETECTOR_DOCKER_ENABLED` | 1 | 总开关（CLI 另有 `--no-docker`） |
| `AGENT_DETECTOR_DOCKER_TIMEOUT` | 20 | daemon 单次调用超时（秒，1–300） |
| `AGENT_DETECTOR_DOCKER_MAX_CONTAINERS` | 200 | 单次扫描容器数上限（≤5000） |
| `AGENT_DETECTOR_DOCKER_READ_MAX_BYTES` | 262144 | 单文件读取上限（字节） |
| `AGENT_DETECTOR_DOCKER_ARCHIVE_BYTE_CAP` | 268435456 | 目录归档流字节封顶 |
| `AGENT_DETECTOR_DOCKER_ARCHIVE_TIME_CAP` | 60 | 目录归档流时间封顶（秒） |

## 平台产品跨环境识别（container 段通用机制）

client_rule 支持可选的 `container:` 段（schema.py `ContainerSpec`）：声明
容器内 npm 全局根、包目录名、配置文件路径、进程 token 与镜像关键词。docker
通道按规则做定向只读探测，**宿主与容器共用同一条产品规则**——OpenClaw、
n8n 均走此机制（OpenClaw 的容器识别已从硬编码迁入其 YAML）。

以 n8n 为例的覆盖矩阵：

| n8n 形态 | 通道 | 关键证据 | 版本 |
| --- | --- | --- | --- |
| Docker 容器（任意宿主 OS） | docker 通道 | 镜像词 `n8n` 筛选 → `/usr/local/lib/node_modules/n8n/package.json`、`/home/node/.n8n`、容器内进程名 `n8n` | package.json（实勘 2.44.7） |
| Windows 宿主 npm -g | client_rule 引擎 | `%APPDATA%\npm\node_modules\n8n` + `~/.n8n` + cmdline `node_modules/n8n` | package.json |
| Linux 宿主 npm -g | client_rule 引擎 | `/usr/local/lib/node_modules` 或 `/usr/lib/node_modules` | 同上 |
| macOS / nvm / 自定义 prefix | client_rule 引擎 | `npm root -g` 活探测兜底 | 同上 |
| n8n Cloud（SaaS） | 不适用 | 本机无资产 | —— |

依赖口径并存：产品包根（如 `.../node_modules/n8n`）注册为容器内已知项目根，
对其做**兴趣驱动的定向读**（npm 安装路径即包名，逐个探测
`<root>/node_modules/<名>/package.json`，不需要 readdir，与声明列表无关）。
`framework_langchain.yaml` 的 any 名单含 npm scoped 名 `@langchain/core`，
因此 n8n 容器同时产出 n8n 平台资产（AGENT_PLATFORM）与 LangChain 框架资产
（真实安装版本）。AGENT_PLATFORM 资产经库存第三道门进入 Agent 列表
（签名集里的平台 sighting 同样开始进入列表，无进程后自动 removed）。

**资产清单按实体合并（2026-10-26 用户裁定）**：清单的统计单位是 Agent
实体 —— 容器产品或自建应用一行；依赖的框架**不单独成行**，折叠为实体的
`dependencies`（列表页显示"依赖 LangChain 1.2.8"小字）。包含关系在详情页
由「项目与依赖」的组件表呈现（n8n 的 `@langchain/core` 1.2.8），
2026-10-27 起**不再单独渲染"识别的框架"卡** —— 同一依赖在详情页只出现
一次。自建项目统一用应用名（agentTest_langchain 一行，详情显示识别为
LangChain + LangGraph 及各自版本）。数据模型不动：框架行仍在库中独立
复核，合并发生在视图层（`console/api/agent_view.py`），列表、详情、总览
计数（`/overview`、`/discovery/summary`）与 CLI 共用同一合并函数，数字
永远一致。

两个工程细节：包根/状态目录的存在性探测探**小文件或目录 tar 首块**，探大
目录会让 daemon 开始生成几百 MB 归档、断流检测滞后拖垮后续请求 —— 归档
调用带一次超时重试兜底；容器内进程被官方镜像改名为产品名（n8n）时，按
「首段可执行名精确相等」匹配 process_tokens。

## 真机验证手册

单元测试全程使用 fake client（内存 tar），不依赖真实 Docker。真机冒烟：

```bash
# 0. 启动 Docker Desktop，确认 daemon 可达
docker ps

# 1. 造四个验证容器
docker run -d --name lg-running python:3.12-slim \
  sh -c "pip install langgraph && sleep infinity"
docker create --name lg-stopped python:3.12-slim \
  sh -c "pip install langchain && exit"          # 只装不跑的停止容器
docker run -d --name web nginx:alpine             # 负样本：AI 无关
# openclaw 容器按你的镜像实际情况准备（node + npm 全局 openclaw）

# 2. 扫描并查看
agent-detector scan --json
agent-detector agents list                        # 容器资产带 container=<短ID>
agent-detector agents show <asset_id>             # 证据含 container_metadata
```

期望：`lg-running` 产出 LangGraph 资产（INSTALLED+RUNNING，实例为容器内
PID）；`lg-stopped` 产出仅 INSTALLED；`web` 不产出任何资产；`stats.docker`
显示 `containers_total=4`（或按实际数量）。

## 已知局限与后续

- 静态指纹不能证明 Agent 正在执行任务（见顶部声明）；行为确认需要
  Docker Events 监听与运行行为检测（后续迭代）。
- 一个 Agent 由多个容器组成时，各容器产出独立资产，不做跨容器合并。
- client 规则引擎未做容器感知：容器内 Claude Code 等仅覆盖定向读取范围；
  `--version` 探测需要 exec，v1 明确禁用。
- `docker top` 依赖容器内有 ps：alpine/busybox 镜像不支持 `-eo` 自定义格式时
  自动回退 daemon 默认 `-ef`（解析器兼容其列名）；连 ps 都没有的镜像拿不到
  进程列表，按"停止容器"的诚实规则处理（绝不虚标 RUNNING）。
- site-packages 归档枚举在超大镜像下受字节/时间封顶约束，极端情况枚举不全，
  版本降级到声明/镜像标签出处（置信度相应更低）。
