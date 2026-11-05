# Agent-Detector V1.2 产品架构修订：身份、覆盖、证据、行为与资产聚合

> 状态：架构基线；P0-A 身份基础（shadow write）、P0-B 覆盖门控（旧硬删除默认关闭，缺席只产生候选）、P0-C Actor/Target + Endpoint 拓扑（模型端口不再写入 actor 字段）、P0-D canonical 回填与 alias 读标注（`identity backfill`，歧义 alias 不静默跟随）已按本文实现。P1 的 evidence ledger（Observations/Claims/ClaimEvidence/RuleRevision）、PredicateRegistry、4 值 `agent_status` 投影、能力标签/hook/coverage 维度、组件依赖图（components/component_relations，`DEPENDS_ON`/`DECLARES`，按覆盖率关闭失效关系，MCP 配置映射为声明组件）已接入扫描与 API。P2 已实现宿主 Node.js 项目解析与 node_modules/package-lock 依赖扫描（Docker 与宿主共用 package.json 匹配器）、受控 runtime/protocol JSONL trace（opt-in E5：`framework_execution`/`protocol_tool_call`，MCP/A2A session 关联，不做自动内容采集）、Hook 的 MCP 工具分类（`mcp_server` + E5 执行 Claim）以及 observation 级 evidence replay（`replay-evidence`，重算 Claim/状态，不重新采集、不重跑原始文件探测）；环境实体、Claim 冲突复核 UI 仍待后续。console 仍以 legacy id 为行主键，完整 canonical 视图切换留到 UI 阶段。单元测试通过；2026-11-05 已在真实 Linux 主机（Xubuntu VM + Tetragon）完成冒烟：LangFlow 应用与 LangChain/LangGraph 框架资产分离、同一框架在不同应用中的版本隔离、Node 项目解析（含 registry 缺失 cwd 的实时补齐）、受控 trace E5、evidence replay、identity backfill 均验证通过；期间修复了 console/collector 并发初始化竞争（`create_all` 与 WAL pragma）和 npm 规则版本选取。Windows/Sysmon 与真实 Docker 容器通道冒烟仍待执行。  
> 代码基线：`TARScn/Agent-Detector` / `feat/linux-ebpf` / `e3da74c5c4f8c235456575355372058cbd0dda6d`。  
> 范围：单机 / 指定 Docker Engine 的 Agent 识别、证据聚合和行为归属；不包含 Web、不引入消息队列和图数据库。  
> **本版结论**：保留 Discovery / Monitor / Protect；将 `Identity & Correlation` 与 `Evidence & Projection` 作为共享内核。所有“合并、当前状态、缺席删除”都经专门裁决器，不允许任一采集器自行决定。

## 0. V1.2 相对 V1.1 的修订

| 编号 | 修订 | 原因 |
| --- | --- | --- |
| 1 | 用户可见状态收敛为 **4 值 `agent_status`**：`RUNNING / CONFIGURED / INSTALLED / UNKNOWN` | V1.1 的正交维度适合作为内部证据，不适合作为产品状态；状态过多且互相重叠 |
| 2 | P0 表清单补 `entities`、`scan_generations`、`endpoints`、`coverage_scope_edges`、`coverage_scope_predicates` | V1.1 的 `entity_keys` / alias 没有父实体表，generation 在 P0 被引用但表在 P1 |
| 3 | `CoverageScope` 改为显式 DAG 边表，区分 `own_status` 与 `effective_status`，增加逐谓词状态 | `parent_id` 只能表示树；单一 `status` 无法表达父范围传播和同 scope 内不同谓词的完整度 |
| 4 | `Endpoint` 身份与观测时间窗分离，新增 `endpoints` / `endpoint_bindings` | V1.1 把 `observed_at` 放进 `EndpointKey`，导致同一端点无法跨事件关联，`EXPOSES`/`ROUTES_TO` 无对象可指 |
| 5 | `ProcessBirth` / `InstanceKey` / `Entity` / `BehaviorEvent` 统一 `scope_key = host_key \| engine_key` | 远程 Docker Engine 的 `host_key` 可能为空，V1.1 的实例键在远程引擎上不成立 |
| 6 | 补幂等键、netmon 窗口键、`event_time` / `observed_at` 字段统一 | 重放、轮询和多源去重需要可计算的唯一键，不能依赖 `pid:ip:port` |
| 7 | 收窄 P0-C：反向代理只要求第一跳或 null；补 Tetragon `process_birth_matching` 规格 | 避免 P0 范围失控；否则 P0-C 的归属等级无法确定性测试 |
| 8 | 补 `PredicateRegistry`、枚举 contract、`normalizer_version`、旧枚举兼容 adapter、关闭旧硬删除 | 让 §5/§6 的策略可执行，并避免 P0 上线前旧 `_verify_stale` 继续清历史 |

## 0.1 本次评审裁决（ADR）

| 编号 | 决议 | 实现强制项 |
| --- | --- | --- |
| ADR-01 | 实体 `entity_id` 采用不可变不透明 UUID，规范化身份键另存版本化 `entity_keys` | 改键算法只变 key/alias，不改变实体 ID |
| ADR-02 | 主机身份与 Docker 引擎身份分离；远程引擎不能隐式当作本机 | `host_key`、`engine_key`、`engine_host_binding` 明确分层；实例/实体/事件统一 `scope_key` |
| ADR-03 | 进程身份使用同一时钟域可验证的出生事实；不同来源不许盲目比较时间戳 | `ProcessBirth` 保留原始域、转换方法、精度与验证状态 |
| ADR-04 | 端口归属采用拓扑解析器，不以监听 PID、产品名或相同 IP 直接合并 | `DockerPortResolver` / `ProxyHop`；无法闭环则 target 为空 |
| ADR-05 | Coverage 是按 scope 的 DAG；负证据需要“有权限的完整覆盖 + 目标性复核” | `REMOVAL_CANDIDATE` 不是 `REMOVED`；`own_status` 与 `effective_status` 分离 |
| ADR-06 | **产品状态只有 4 值**；安装、配置、运行、能力、保护、覆盖是内部证据维度 | 采集器不得写 `agent_status`；状态由投影派生；`UNKNOWN` 不等于 `FALSE` |
| ADR-07 | Observation 是脱敏后不可变事实；Claim 是可修订解释；Event 具有归属修订历史 | 多对多证据映射、规则 digest、Coverage 归属、幂等键 |
| ADR-08 | 高频网络样本与运行实例有界保存；SQLite 批量写入 | 低频 Claim、高频观测按窗口保存，明确丢弃计数 |
| ADR-09 | Endpoint 身份与观测窗口分离；端口映射是带有效期的 binding | `Endpoint` 不含 `observed_at`；事件引用 `endpoint_id` + 时间窗 |
| ADR-10 | 每个 predicate 的有效期、权威证据、复核策略、冲突处理集中在 `PredicateRegistry` | 不允许投影层各自解释“什么算安装/运行/配置” |
| ADR-11 | 旧读路径兼容优先；旧硬删除在 P0-B 关闭 | 历史账本不因当前逻辑删除而清空；已删除历史按 best effort 处理 |

---

## 1. 产品级边界与模块

数据面：`collectors`（psutil / Tetragon / Sysmon / auditd / Docker API / file / Hook）输出标准化 Observation 和 Coverage。  
识别面：`discovery` 只输出 ProductCandidate / ApplicationCandidate / ComponentClaim，不直接生成最终资产身份。  
关联面：`correlation` 持有 Host/Engine 身份、ProcessRegistry、DockerPortResolver、EndpointResolver、EntityResolver、AttributionResolver。  
聚合面：`aggregation` 维护 EvidenceLedger、ClaimResolver、RelationResolver、CoverageEvaluator、LifecycleReconciler、StatusProjection、AssetProjection。  
控制面：`interception` 的 Hook 和 Policy 仍然独立运行，读取经过验证的身份上下文，不能反向篡改 Observation。  
持久层：SQLite；CLI 和 API 仅是消费者，本版不安排 Web 变更。

**依赖法则**：采集器不 import 聚合器；规则不直接 upsert canonical 资产；行为分类器不直接做资产同一性判断；投影只读已确认的 Claim、Relation 和 Coverage，不能重新猜身份；`agent_status` 只能由 `StatusProjection` 从证据派生。

---

## 2. 主机、引擎和实例身份

### 2.1 HostIdentity

```text
HostIdentity = {
  host_key(UUID), identity_version, identity_basis,
  raw_fingerprint_hash?, installation_id,
  trust_state, first_seen, identity_verified_at
}
```

优先级：`显式 operator host-id（须做跨已登记主机冲突检查） > 经过平台验证的 machine-id / MachineGuid 与持久安装 UUID 的组合 > 安装态持久随机 UUID`。不能仅凭 hostname / IP。

- `host_key` 是第一次确认时分配的**本地稳定 UUID**；外部 machine-id / MachineGuid 作为 `host_identity_claim` 锚点保留，避免主键随平台字段变化而重算。
- 安装 UUID 存放在受保护本地状态目录，与业务 SQLite 分离。**DB 备份/恢复到新机器不得自动继承 host_key**；状态目录丢失时生成新 host_key，并记录 `identity_basis=installation_uuid` 的重置事件。
- Linux 本机读取宿主 `/etc/machine-id`（不是容器内部）；Windows MachineGuid 仅作佐证。读取失败仍可使用安装 UUID。
- 克隆镜像：若 machine-id 与安装 UUID 均被克隆，单机离线检测**无法必然识别两台机器不同**。部署前清除镜像内安装状态、允许 operator 覆盖、有中心登记时校验冲突；检测到冲突标 `CONFLICT` 并禁止跨主机合并。这是不可消除的单机识别边界。
- 若 agent 部署在容器中：必须显式获取宿主 HostIdentity（host 挂载或部署配置），不可读取容器自身 machine-id 当作宿主身份；拿不到只生成 `detector-local` scope，不跨主机合并。
- `identity_basis = operator_override | platform_and_installation | installation_uuid | unresolved`；`trust_state = VERIFIED | CONFLICT | UNVERIFIED`。
- 所有身份键使用版本化规范化序列化（字段排序、UTF-8、SHA-256）后哈希，不允许裸拼接多义字符串。

### 2.2 DockerEngineIdentity 与远程引擎

```text
DockerEngineIdentity = {
  engine_key, engine_id_claim?, endpoint_aliases[],
  engine_host_key?, binding_state
}
```

- 本机 Docker：只有确认 Docker Engine 属于当前 host（Unix socket / 命名管道与端点校验）后，可将 `engine_host_key = local host_key`。
- `DOCKER_HOST=tcp://remote...`：Docker daemon ID、endpoint 和证书身份提供 `engine_key` 的候选锚，**不能**由请求发起方的 `host_key` 代替。运行端主机的 `host_key` 只有在独立证明或 operator 映射后才填；否则实体所属 `scope_key = engine_key`、`host_key=null`，不会把远程容器错误归本地。
- endpoint URL 改动不应造成实体迁移：保持 `engine_key`，新增 endpoint alias；daemon ID 改动/克隆时做冲突审查，必要时新引擎身份。
- Host 的进程事件和远程 Docker 实例不可通过“PID 相同”合并；只允许相同、已验证的 host/engine 关系后再做 namespace bridge。

### 2.3 ProcessInstanceIdentity

```text
ProcessBirth:
  platform, scope_key(host_key | engine_key), boot_identity,
  pid_namespace_key, pid, native_birth_value, clock_domain,
  resolution, canonical_start_ticks?, source, verification_state

InstanceKey:
  linux_v1(scope_key, boot_id, pidns_inode, pid, proc_start_ticks)
  windows_sysmon_v1(scope_key, boot_epoch_id, process_guid)
  windows_live_v1(scope_key, boot_epoch_id, pid, creation_native_value)
```

- Linux：`/proc/<pid>/stat` 第 22 字段 `starttime` 是开机后 clock ticks，配合 `/proc/sys/kernel/random/boot_id` 与 `/proc/<pid>/ns/pid` inode；在已授权可读时获取为 canonical key。`btime` 只用于展示/辅助校验，不进入唯一身份计算。
- Tetragon 提供的进程启动时间 / `exec_id` 保留原始域。**P0-A 必须交付 `process_birth_matching` 规格**：
  1. 记录来源原始单位与时钟域（boot 相对 ns / epoch ns / ticks）；
  2. 给出到 `proc_start_ticks` 的换算公式与校准样本；
  3. 允许误差（默认 ±1 tick；超出则 candidate）；
  4. 匹配优先级：同源 `exec_id` → `(pid, start_ticks)` 精确 → 带容差匹配 → `source_scoped_process_ref`；
  5. 未校准前不得做跨源强合并，只能 candidate。
- PID namespace：记录 namespace inode、host PID、namespace PID、转换来源；Docker Top / Tetragon 的 PID 语义必须通过数据源适配器明示，不预设它是 host PID 还是 container PID。PID namespace inode 可能被内核回收，只有 boot_id + pid + start_ticks 同时一致时才可能碰撞，遇到歧义降级 candidate。
- Windows：优先 Sysmon `ProcessGuid` 加 boot epoch；纯 psutil / WinAPI 必须保留原生 CreateTime 精度信息。`boot_epoch_id` 来自 `LastBootUpTime`，需记录来源与精度；若碰撞、重启不明或事件身份不一致，退回 candidate，不强归属。
- **硬规则**：`pid` 单独不能标识 Instance；`start_time epoch` 不能作为所有来源的统一强键；没有可信 boot identity 时不做跨源强合并；进程结束是事件时间上的事实，不能因为新进程占据同 PID 而覆盖旧实例历史。

---

## 3. 统一实体身份

### 3.1 实体与身份键

```text
Entity {
  entity_id(UUID), entity_kind, created_at
}

EntityKey {
  key_type, canonical_key, identity_version, entity_id,
  valid_from, valid_to, confidence_basis
}
```

`entity_kind` 是唯一分类口径，不再另设 `identity_class`：

```text
PRODUCT_INSTALL | SELF_BUILT_APPLICATION | COMPOSE_DEPLOYMENT |
CONTAINER_DEPLOYMENT | SERVICE | ENVIRONMENT | UNKNOWN
```

- `SERVICE` 覆盖模型服务、独立 MCP 服务、独立 HTTP 服务；
- `ENVIRONMENT` 指共享 venv / npm 环境；它可以是实体，也可以只作为组件关系目标，由是否具有独立证据决定；
- `PRODUCT_INSTALL` 是产品安装，不是产品定义本身；同一产品的不同用户/安装路径可以是不同实体。

身份解析采用 **候选生成 → 强锚校验 → 已有 Entity 匹配 → 冲突否决 → 创建/关联**。产品名、镜像关键字、cwd、相同 IP、单独端口、未知出生时间的 PID 只能生成 `POSSIBLE_SAME_AS`，不能自动合并。

| 实体范围 | 优先强锚 | 不足时处理 |
| --- | --- | --- |
| 用户级产品安装 | `scope_key + 账户稳定标识 + product_rule + 规范安装路径/包根` | 仅配置目录 → 候选安装；同名不同 home 不合并 |
| 自建项目 | `scope_key + canonical 项目/服务根`；独立入口的 monorepo 加 `entry_key` | cwd 为 `/` 或无根标记 → 候选，不凭 cwd 造确定实体 |
| 共享运行环境 | `scope_key + 规范 venv/npm 环境路径或已验证环境 ID` | 一个环境可关联多个 Application，不直接认为它们是同一应用 |
| Compose 部署 | `engine_key + 可信 project 标记 + verified working_dir / config_files 或显式 deployment-id` | 只有 project 名、缺关键标签 → 候选部署，不自动跨容器合并 |
| 独立 Docker 容器 | `engine_key + 完整 container ID + product` | 重建后默认新实体，记录 `POSSIBLE_SUCCESSOR_OF`，不自动 alias |
| 独立服务 | `scope_key + 明确的服务注册或部署 ID` | 仅一个监听端口不算稳定实体键 |
| 独立 MCP 服务 | `scope_key + 已验证进程或服务部署标识` | stdio 子进程优先作为 client 的 runtime/component，不重复造独立实体 |

**项目根算法**：1) 入口脚本/模块安装分发定位；2) 入口向上查找最近的可信 `pyproject.toml` / `package.json` / `setup.cfg` 等；3) venv 的明确安装归属；4) cwd 仅兜底候选。解析路径时要求同一文件系统命名空间、symlink 与 Windows canonical path 可验证；若入口与 cwd 指向两个项目，则记录冲突而不是硬选其中一个。monorepo 若发现多个彼此独立的可执行入口/服务单元，使用 `root + entry_key` 为二级身份；仅目录不同或依赖不同不自动拆分。

**位置不等于内容**：同一路径被删除并部署了完全不同的项目时，不能机械续接。保存 `deployment_epoch` 与 `config_fingerprint`；当权威入口/产品身份变更且有明确断代事实时新建 Entity 或 epoch，保留 `REPLACED_BY`，不对旧证据重新归属。

- `config_fingerprint` 只包含**身份相关字段**：入口路径/模块、manifest 名称、产品规则、Compose project 标签、服务名；**排除版本号、依赖清单、配置值**。否则正常升级会触发断代。
- 断代事实：入口被替换、manifest/产品身份改变、Compose 项目身份改变、路径被无关项目复用。普通依赖升级、配置项修改不新建实体，只记录版本/变更历史。

**组件是角色**：Langflow 可作为独立 `SERVICE` 实体，也可以作为另一个应用的 Component；以 `SOFTWARE_COMPONENT` / `INSTANCE_OF` 连接，不按软件名称去重实体。共享 venv 的 `ENVIRONMENT_CONTAINS_COMPONENT` 属于环境，应用通过 `USES_ENVIRONMENT` / `RUNS_WITH` 继承环境证据，不能直接声称每个应用都执行了组件。MCP 独立监听实体与 stdio 子进程的归类按服务边界而非名称判断。

**P0 必须提供最小 `entities` 表**（`entity_id, entity_kind, created_at`）；`entity_keys` / `entity_aliases` 不能指向一个 P1 才存在的表。

---

## 4. Endpoint 身份与端口拓扑

### 4.1 Endpoint 与 EndpointBinding

```text
Endpoint {
  endpoint_id, scope_key, protocol, address, port, namespace,
  valid_from, valid_to, owner_entity_id?
}

EndpointBinding {
  binding_id, host_endpoint_id, container_endpoint_id,
  container_id, binding_source, valid_from, valid_to
}
```

`endpoint_id` 不包含 `observed_at`。事件引用 `endpoint_id` + `window_start/end`；端口映射的有效期放在 binding 上。`EXPOSES` 表达 entity → endpoint，`ROUTES_TO` 表达 endpoint → endpoint（代理）或 service → service（有拓扑证据时）。

### 4.2 DockerPortResolver

解析层次：

1. **直接监听**：根据经过验证的 socket owner、ProcessInstanceKey 和 namespace 得到 owner Entity。
2. **Docker published port**：读取 `NetworkSettings.Ports`、`HostConfig.PortBindings`，建立 `host_ip:host_port/protocol → container_id:container_port → container Entity / Compose service`。必须校验绑定确实属于当前 engine，不能盲用本地 socket PID；记录 docker-proxy / iptables DNAT 分支。
3. **容器内 network**：根据目标 IP、网络 ID、容器 endpoint / 动态 IP 绑定（含有效时间）解析；出现 NAT 和多网络歧义则 candidate。
4. **反向代理**：HTTP probe 命中 Dify 只证明**被探测 endpoint 返回了 Dify 特征**。如果 listener 是 nginx，`target` 第一跳为 nginx（若其身份可确认）；只有从受支持代理配置/拓扑/trace 得到唯一 upstream 时，才能再建 `ROUTES_TO` 到 Dify。不能把 Dify 直接折叠进 nginx Compose 实体。
5. **多候选或缺少端口绑定**：`target_entity_id=null`、`target_endpoint_id` 保留，`POSSIBLE_TARGET_OF` 关系可另存，不能猜测。

Docker 端口映射证明目标容器的网络归属，但**不自动证明这个容器里哪一个产品服务处理请求**。多应用容器/共享端口/多级代理必须进一步验证；只凭 compose 同项目也不能给所有服务同一 target。

**P0-C 完成定义**：直接监听、published port、docker-proxy/DNAT、多候选 → 正确 target/null；反向代理只要求第一跳正确或 null，nginx→Dify 第二跳放 P1/P2。

---

## 5. CoverageScope：可计算的负证据门控

### 5.1 结构与状态

```text
CoverageScope {
  id, run_id, generation_id?, scope_type, scope_key, source,
  own_status, budget, scanned_count, truncated, error_codes[],
  started_at, finished_at
}

CoverageScopeEdge { parent_id, child_id }
CoveragePredicateStatus { scope_id, predicate, own_status, error_code? }
```

```text
scope_type = host_process_enumeration | product_rule | project_candidate_universe |
             project_probe | docker_engine_enumeration | container_inspect |
             compose_membership | container_deep_scan | file_probe |
             listener_enumeration | network_observation | hook_probe

own_status = COMPLETE | PARTIAL | FAILED | NOT_RUN | DISABLED
```

- `CoverageScope` 是 DAG，不是树；需要多父时使用 `CoverageScopeEdge`。
- `own_status` 表示本 scope 自身的结果；`effective_status` 由所有祖先路径的最差状态计算（查询时计算，不落库，避免丢失 own 信息）。
- `predicate_set` 不再作为单一状态字段；`CoveragePredicateStatus` 为每个谓词保存独立状态。一个容器 inspect 可以确认“容器存在”COMPLETE，但包枚举因权限 PARTIAL。
- `(run_id, scope_type, scope_key)` 唯一；`run_id` 通过 `scan_generations` 映射到已发布代。
- `DISABLED` 表示 operator 主动关闭；`NOT_RUN` 表示调度未执行；两者都不得产生负证据。

父范围的 PARTIAL/FAILED 对“缺席检测”向子范围传播；子范围已成功拿到**正证据**仍可支持对应的 `RUNNING / CONFIGURED / INSTALLED` 结论。Coverage 的状态是“这次对指定集合/谓词是否完整”，不等同资产是否存在。

- Docker 枚举 COMPLETE + 容器深扫 FAILED：容器本身可以被确认存在，但其组件/安装负证据不可用。
- Python 候选列表被预算截断：被实际探测的项目可以产出正证据；整个候选 universe 不完整，未出现的旧项目不能被否定。
- YAML 规则 A 加载 FAILED：只撤销 A 相关的缺席裁决资格，规则 B 的完整结果仍有效。
- 枚举数量恰好等于 budget 时，若数据源不能证明“确实已经枚举到底”，状态应 PARTIAL；不要凭恰好返回 budget 个对象推断 COMPLETE。

### 5.2 谓词绑定与可执行规则

每种负证据定义一个 `ReconfirmationStrategy(entity_kind, predicate, required_scopes[], authoritative_probes[], timeout, policy_version)`；策略集中在 `PredicateRegistry`（§6）。

```python
eligible_for_absence(entity, predicate, generation):
    for strategy in authoritative_strategies(entity.entity_kind, predicate):
        closure = strategy.required_scope_closure(entity, generation)
        if all(effective_status(scope) == COMPLETE for scope in closure):
            if not strategy.has_current_positive_evidence(entity, generation):
                return True
    return False

reconcile_absence(entity):
    if not eligible_for_absence(...):
        return UNVERIFIED
    mark_removal_candidate(entity)
    verdict = targeted_reconfirm(entity)   # 复核结果：PRESENT / ABSENT / UNVERIFIED（不是 agent_status）
    if verdict == ABSENT:
        return CONFIRMED_ABSENT  # active list removes; history retains last status
    return UNVERIFIED if verdict == UNVERIFIED else PRESENT
```

**唯一删除策略**：`COMPLETE → REMOVAL_CANDIDATE → 目标性复核 → CONFIRMED_ABSENT`，从不 `COMPLETE → REMOVED`。权限不足、超时、规则不可用、端口歧义全部记 `UNVERIFIED`，并增加 `freshness_age`；有仍然存在的确切证据则保留正证据。历史账本永不因当前逻辑“删除”而清空。

### 5.3 各类便宜复核器

| 对象 | 针对性复核 | 特别说明 |
| --- | --- | --- |
| 安装类产品 | 原安装包、固定可执行路径、相关有效配置路径做 `stat` / 元数据读取 | 安装不在但配置仍在：`installed=FALSE, configured=TRUE` → `agent_status=CONFIGURED`，不要简单“资产已移除” |
| Compose 部署 | 完整 project 成员列表 + 各成员 inspect | 单成员消失只更新 membership；部署确认全部不存在才移除 |
| 独立 Docker 容器 | daemon inspect 精确完整 container ID | daemon 失联/权限不足 → UNVERIFIED |
| 项目应用 | 项目根 + 可信 entry / manifest / environment 组合验证 | root 在但入口被替换，要核对 epoch；root 不在且权限明确可见才能确认缺失 |
| 纯网络服务 | 明确作用域的 endpoint/监听所有权重查 | 无监听通常表示 `process_state=STOPPED`，不是软件卸载；没有持久身份锚不能轻易移除 |
| MCP stdio | 父会话/配置加进程存活核验 | 子进程退出只影响 instance，不代表 MCP 配置删除 |

---

## 6. 证据、Claim 和裁决语义

### 6.1 证据等级与状态映射

证据等级保持 E1–E5，但不能当求和的分数。

| 类别 | 可验证事实 | 例子 | 可支持的 `agent_status` | 不能推断 |
| --- | --- | --- | --- | --- |
| E1 声明/弱线索 | 声明了组件或可疑名称 | requirements、lock、镜像词 | 仅显式配置/声明可支持 `CONFIGURED`；仅名称匹配 → `UNKNOWN` | 已安装、运行 |
| E2 静态确认 | 磁盘安装/配置可核验 | dist-info、配置键、可执行文件 | 安装工件 → `INSTALLED`；配置 → `CONFIGURED` | 正在调用框架 |
| E3 身份拓扑 | 已证明对象/进程/网络归属 | boot+pidns+birth、Docker 端口绑定、服务 endpoint 指纹 | 已验证运行实例/服务 → `RUNNING` | 框架函数执行 |
| E4 系统操作 | 操作发生的事实 | eBPF exec/connect、Sysmon 文件事件、Hook bridge 启动 | 不直接改状态；用于行为/归属 | Agent 自主意图 |
| E5 精确调用 | 可信工具/框架/协议调用被观察 | 原生 Hook 工具事件、获授权的 runtime instrumentation | 不直接改状态；增加 `AGENT_EXECUTION_OBSERVED` 标签 | 没有被仪表化的所有执行路径 |

Hook **安装/配置 = E2**；Hook bridge 进程执行 = E4；Hook 实际报工具调用 = E5。`evidence_class` 描述类型而非可简单比较的可信度；不同谓词不得跨 E1–E5 排序。

### 6.2 数据字段

```text
Observation {
  observation_id, collection_run_id, source_event_uid, observed_at,
  ingested_at, source, scope_key, process_ref?, endpoint_id?,
  fact_type, normalized_redacted_payload, payload_digest,
  normalizer_version, retention_class
}

Claim {
  claim_id, subject_ref, predicate, object_value/ref, polarity,
  evidence_class, verification_method, rule_id, rule_digest, rule_generation,
  collection_run_id, coverage_scope_id, observed_at,
  valid_from, valid_to, status, supersedes_claim_id?
}

ClaimEvidence { claim_id, observation_id, role }
Relation { relation_id, from_ref, relation_type, to_ref,
           valid_from, valid_to, status, verified_by_claim_id }
```

枚举 contract（实现前冻结）：

```text
Claim.status = supported | disputed | expired | withdrawn | superseded
Relation.status = confirmed | candidate | disputed | expired
ClaimEvidence.role = supports | refutes | context
observation.fact_type = process_birth | process_exec | process_exit |
                        net_connect | file_op | tool_call | config |
                        package_installed | service_fingerprint | ...
retention_class = raw_short | summary_long | evidence_audit
```

**幂等约束**：

- `Observation`：唯一 `(source, source_event_uid)`；
- `Claim`：唯一 `(subject_ref, predicate, object_ref, rule_id, rule_digest, coverage_scope_id)` 或等价的规范化内容哈希；
- `ClaimEvidence`：唯一 `(claim_id, observation_id)`。

### 6.3 PredicateRegistry

每个 predicate 一行，集中定义投影和复核语义：

```text
PredicatePolicy {
  predicate, subject_kind, object_kind,
  validity: static_scan | config_file | instance_life | observation_window | ttl,
  authority: ordered verification_methods,
  reconfirm: strategy ref,
  conflict: prefer_positive | prefer_negative | conflict
}
```

`authoritative_strategies`、`verification_method authority`、`validity policy` 都从这张表读取；不允许各投影/各检测器自行解释“什么算安装、运行、配置”。

### 6.4 Claim 裁决

1. 检查是否仍在有效观察周期、scope 是否有权威覆盖，排除 superseded / expired。
2. 只在**对同一个 predicate 可比较的证据**之间按 `verification_method authority`、正/反命中证明强度、规则代际、时间新鲜度排序；`rule_digest` 只做版本溯源和确定性 tie-break，不代表“新”。
3. 高优先级支持与高优先级反驳冲突时输出 `CONFLICT / UNKNOWN`，不要为了排序强行选择。可用 `supporting_claims`、`disputing_claims` 给出解释。
4. `supersedes` 只用于同一规则/范围的新判断取代旧判断；不能自动撤销其他来源的独立佐证。
5. 任何 Claim 必须有 `claim_evidence`，且可定位到规则 digest、采集代和 CoverageScope；保留期结束后可定位**脱敏摘要与规则摘要**，不能承诺永久可回溯原始字节。

### 6.5 validity policy 与三态

- 配置/安装 Claim：绑定校验路径、文件 identity、mtime/hash、覆盖它的扫描代；可因 TTL 转 `UNVERIFIED`，只有目标性完整检查才产生 `FALSE`。
- 运行实例：持续时间由 birth 到 exit，漏报退出时用当前实例核验与 TTL，历史事件关联允许时间窗但不应用当前 PID 代替。
- 网络连接：观察时刻/窗口有效，历史事件不随实例结束而消失；不把早期 `net.connect` 投影为当前仍有活动。
- Hook 配置、Hook 触发、阻断验证分别独立计时，验证后覆盖能力仅覆盖当时的工具/Agent 版本/配置路径。

---

## 7. Agent 状态：对外 4 值，对内正交

### 7.1 唯一的产品状态 `agent_status`

```text
agent_status = RUNNING | CONFIGURED | INSTALLED | UNKNOWN
```

派生优先级：**RUNNING > CONFIGURED > INSTALLED > UNKNOWN**。

| 当前、有效证据 | `agent_status` | 说明 |
| --- | --- | --- |
| 已验证运行实例（进程 birth 匹配 / 容器主进程 / 服务 endpoint / Hook session） | `RUNNING` | 只认**已验证**实例；裸 TCP 连接、未归属 PID 不算 |
| 无运行实例；有配置/声明证据（配置文件、项目声明、Compose 文件、Hook 配置、endpoint 注册） | `CONFIGURED` | 已配置但当前未确认运行；`installed=false` 时在详情标注 |
| 无运行/配置；有安装工件（dist-info、可执行文件、镜像、项目入口+环境） | `INSTALLED` | 已安装但未配置/未运行 |
| 无正证据、证据冲突、覆盖不足 | `UNKNOWN` | 不得用“没看到”推导为不存在 |

**为什么 CONFIGURED 高于 INSTALLED**：配置完成是比“仅有安装工件”更强的就绪信号。一个已安装并已配置、但当前未运行的 Agent，显示“已配置”比“已安装”更接近用户要判断的状态；详情仍显示 `installed=true`。

典型组合：

| 场景 | `agent_status` |
| --- | --- |
| 已安装 + 已配置 + 进程运行 | `RUNNING` |
| 已安装 + 已配置 + 进程停止 | `CONFIGURED` |
| 已安装 + 未配置 + 进程停止 | `INSTALLED` |
| 仅配置存在（包/可执行文件不在） | `CONFIGURED`（详情 `installed=false`） |
| 仅 pyproject/lock 声明依赖 | `CONFIGURED`（详情 `installed=false`） |
| 仅名称/镜像词/目录名匹配 | `UNKNOWN` |
| 进程在跑但实例身份未验证 | `UNKNOWN`（不能标 RUNNING） |
| 覆盖 PARTIAL 且无正证据 | `UNKNOWN` |
| 已确认不存在（targeted reconfirm） | 不进入 `agent_status`；`removal_verdict=CONFIRMED`，从活跃清单归档 |

`agent_status` 是**派生字段**：采集器、检测器、Hook 都不能直接写；只由 `StatusProjection` 从当前 Claim / Relation / Coverage 计算。

```python
def derive_agent_status(entity, generation):
    basis = current_status_basis(entity, generation)  # 只取当前有效证据
    if basis.has_conflict and not basis.has_positive_evidence:
        return UNKNOWN
    if basis.verified_running_instances:
        return RUNNING
    if basis.configured:
        return CONFIGURED
    if basis.installed:
        return INSTALLED
    return UNKNOWN
```

`verified_running_instances` 只包含身份已验证的实例；`configured` / `installed` 只包含仍在有效期内的证据。过期证据不参与派生，但保留在 `status_basis` 供解释。

### 7.2 内部证据维度（不是状态）

以下维度保存在投影内部/详情，不作为产品状态展示，也不参与列表颜色/排序：

```text
status_basis {
  installed: TRUE | FALSE | UNKNOWN,
  configured: TRUE | FALSE | UNKNOWN,
  process_state: RUNNING | STOPPED | UNKNOWN,
  service_reachable: TRUE | FALSE | UNKNOWN,
  running_instance_ids[], install_evidence_ids[], config_evidence_ids[],
  conflicts[], last_verified_at
}
```

- 列表/API 默认只返回 `agent_status`；
- 详情/诊断 API 可展开 `status_basis`，用于解释“为什么是 RUNNING/CONFIGURED”；
- `status_basis` 的 `UNKNOWN` 不等于 `FALSE`；
- 任何维度缺失都不会被“强行计算为否”。

```text
AssetSnapshot {
  entity_id, generation_id,
  agent_status,                 # 唯一产品状态
  status_basis,                 # 内部证据维度，详情用
  capability_tags[],            # AI_RELATED / AGENT_CAPABLE / AGENT_EXECUTION_OBSERVED
  hook_state,
  removal_verdict,              # NONE / CANDIDATE / CONFIRMED
  coverage_summary,
  component_relation_ids[], active_instance_ids[],
  supporting_claim_ids[], disputing_claim_ids[],
  projected_at
}
```

### 7.3 移除与归档（不是 Agent 状态）

```text
removal_verdict = NONE | CANDIDATE | CONFIRMED
```

- `CONFIRMED` 只在 §5 的目标性复核返回 ABSENT 后出现；
- 归档后实体保留历史，不出现在活跃清单；需要查看时用 `removal_verdict=CONFIRMED` 过滤；
- 不设 `REMOVED` 作为 `agent_status` 的第五个值，避免把“当前状态”和“生命周期动作”混在一起。

### 7.4 能力标签（不是状态）

```text
capability_tags = [AI_RELATED, AGENT_CAPABLE, AGENT_EXECUTION_OBSERVED]
```

最小证据集：

- `AI_RELATED`：项目/环境可信关联且发现 AI 相关包、配置或模型调用连接之一；不能因此标为确定 Agent。
- `AGENT_CAPABLE`：已知 Agent 产品强产品身份证据，或自建项目存在已验证的工具/工作流编排能力声明（不仅是 langchain 安装）。
- `AGENT_EXECUTION_OBSERVED`：可信原生工具 Hook、明确运行时/协议执行轨迹，且关联到已确认的运行实例或 session；`proc.exec`、`net.connect` 不足。

能力标签可以同时存在，不是互斥状态；它们不改变 `agent_status`。

### 7.5 保护维度（不是状态）

```text
hook_state = NOT_CONFIGURED | PARTIAL | CONFLICT | CONFIGURED |
             HOOK_OBSERVED | ENFORCEMENT_VERIFIED | UNKNOWN
```

- Hook 配置缺事件项 = `PARTIAL`，配置不可读/非法 = `CONFLICT`；
- 仅 Hook 文件完整存在 = `CONFIGURED`；
- Hook bridge 启动/工具事件实际出现 = `HOOK_OBSERVED`；
- 受控阻断测试或可信平台决策回执 = `ENFORCEMENT_VERIFIED`；
- 遥测通道是否存在由 `coverage_summary` 表达，不塞进 `hook_state`；
- 面向旧 UI 可派发 `protection_summary = PROTECTED | MONITOR_ONLY | UNPROTECTED | UNKNOWN`，但它是保护摘要，不是 Agent 状态。

### 7.6 旧枚举兼容

`AssetState` 目前是非互斥集合（INSTALLED / CONFIGURED / RUNNING / BEHAVIOR_SUSPECTED / EXECUTION_CONFIRMED / UNKNOWN）。投影适配器按以下规则生成旧字段，直到 console/API 迁移完成：

```text
legacy_status:
  RUNNING in states              -> RUNNING
  CONFIGURED in states           -> CONFIGURED
  INSTALLED in states            -> INSTALLED
  otherwise                      -> UNKNOWN

legacy ProtectionStatus:
  hook_state ENFORCEMENT_VERIFIED -> PROTECTED
  hook_state HOOK_OBSERVED        -> PROTECTED
  hook_state PARTIAL/CONFLICT     -> DEGRADED
  hook_state CONFIGURED           -> MONITOR_ONLY  # 保守映射：尚未观测到实际触发
  hook_state NOT_CONFIGURED + telemetry -> MONITOR_ONLY
  hook_state NOT_CONFIGURED + no telemetry -> UNPROTECTED
  hook_state UNKNOWN              -> UNKNOWN
```

`CONFIGURED -> MONITOR_ONLY` 是过渡期的保守映射，避免旧 UI 把“文件存在”误显示为 PROTECTED；新 API 以 `hook_state=CONFIGURED` 为准。

P1 切换前，API 同时输出旧 `states` / `protection_status` 与新 `agent_status` / `hook_state`；UI 不需要即时改版。

---

## 8. 行为链、Actor/Target 和事件多源去重

`BehaviorObservation` 先分类、归一化和脱敏；`LogicalBehaviorEvent` 是行为窗口/可证明同一操作的聚合；`BehaviorAttributionRevision` 表达当前归属判断。历史 Observation 不进行原地回填。

```text
BehaviorEvent {
  event_id, event_time, kind, scope_key,
  actor_process_key?, actor_entity_id?, actor_instance_id?,
  target_endpoint_id?, target_entity_id?, target_instance_id?,
  attribution_method, attribution_state,
  actor_relation_claim_id?, target_relation_claim_id?,
  source_observation_id?, event_semantics,
  window_start, window_end
}

BehaviorEventEvidence { event_id, observation_id, evidence_role }
AttributionRevision { event_id, revision_no, actor_entity_id?, target_entity_id?,
                      method, verified_by_claim_id?, asserted_at,
                      supersedes_revision? }
```

- 统一时间字段为 `event_time`；P0-C 实现沿用既有 `behavior_events.observed_at` 列作为事件时间（避免一次迁移全部调用方），语义等同 `event_time`；新表/新 API 使用 `event_time`。
- `attribution_state = verified | candidate | unattributed | conflict | target_only`；`target_only` 表示 actor 无法归属但 target 已识别，不能把 target 写进 actor 字段。`attribution_method` 必填（`verified_instance`、`verified_session`、`container_membership`、`verified_parent_chain`、`pid_snapshot`、`target_scan_listen_port`、`unattributed` 等）。
- Actor、Target 可分别为 null；Target 不得覆盖 Actor。
- `target_instance_id` 在目标为具体进程时填写；目标为服务实体时可以只填 `target_entity_id`。

**归属等级**：A) 相同 native Hook session / 可信 process reference；B) 共享 InstanceKey；C) 已验证容器成员关系（单归属且无冲突）；D) 身份完整的父子进程链；E) 弱相似候选（不可写确定 actor）。孤儿 systemd/nohup 进程父链失效时优先已有进程实例或 session；否则 unknown，不能用 cwd 猜。

**重复语义**：

- `source_event_uid = collector_id + source_cursor/event_native_id` 用于同源重放幂等；没有 native ID 用本轮观测序号，不允许用 `pid:remote_ip:port` 充当事件唯一 ID。
- 多源事件只有同实例、同操作、同目标且具备可靠的操作关联键时才真正 dedup；否则标 `CORRELATED_WITH` 而非强行折成一条。`BehaviorEventEvidence` 保留所有佐证。
- netmon 是**连接采样**：
  ```text
  flow_window_key = (scope_key, instance_id, protocol,
                     local_ip:port, remote_ip:port)
  gap > 2 × sampling_interval -> 新窗口
  ```
  同一窗口只生成一个 `connection_sample` 事件，不等于一次 LLM 调用，也不累加 `connect_count`；两个真实独立连接必须因新窗口/新实例而分开。
- `AttributionRevision` 唯一 `(event_id, revision_no)`；只有归属变化时才新增 revision，正常观测不写修订历史。

---

## 9. SQLite 逻辑存储及关键约束

### 9.1 P0 最小新增

```text
entities
host_identities, host_identity_claims
docker_engines, engine_host_bindings
entity_keys, entity_aliases
process_births
endpoints, endpoint_bindings
coverage_scopes, coverage_scope_edges, coverage_scope_predicates
scan_generations
removal_candidates
attribution_revisions
behavior_events 扩展（Actor/Target/Process/Endpoint/Method/Scope）
```

`behavior_events` 先用兼容 adapter 写旧表；P0 不要求旧列立刻清退。

### 9.2 P1 统一账本

```text
entity_epochs
components, environments, component_relations
observations, claims, claim_evidence
relations                  # from_ref / to_ref 可为 entity 或 endpoint
behavior_event_evidence
rule_revisions
sessions
asset_snapshots
```

### 9.3 关键约束

```sql
-- 规范 key 在同一时间只属于一个实体；冲突时先关闭旧 key
CREATE UNIQUE INDEX uq_entity_key_open
ON entity_keys(identity_version, key_type, canonical_key)
WHERE valid_to IS NULL;

-- 相同有向关系和类型只能有一条有效关系
CREATE UNIQUE INDEX uq_relation_open
ON relations(from_ref, to_ref, relation_type)
WHERE valid_to IS NULL AND status = 'confirmed';

CREATE UNIQUE INDEX uq_alias_old ON entity_aliases(old_id);
CREATE UNIQUE INDEX uq_claim_observation ON claim_evidence(claim_id, observation_id);
CREATE UNIQUE INDEX uq_observation_source ON observations(source, source_event_uid);
CREATE UNIQUE INDEX uq_claim_idempotent
ON claims(subject_ref, predicate, object_ref, rule_id, rule_digest, coverage_scope_id);
CREATE UNIQUE INDEX uq_coverage_scope
ON coverage_scopes(run_id, scope_type, scope_key);
CREATE UNIQUE INDEX uq_attribution_revision
ON attribution_revisions(event_id, revision_no);
CREATE INDEX ix_claim_subject_pred ON claims(subject_ref, predicate, status);
CREATE INDEX ix_behavior_actor_time ON behavior_events(actor_process_key, event_time);
CREATE INDEX ix_behavior_target_time ON behavior_events(target_endpoint_id, event_time);
```

SQLite 的 `NULL` 唯一键行为：身份字段应编码为规范的非空字符串/字节再进 unique index。Claim 幂等键中的 `coverage_scope_id` 必须非空，或改用 `claim_key`（规范化内容哈希）作为唯一键；不要依赖含 `NULL` 的唯一索引。`entity_aliases` 必须禁止 alias 链环，并处理旧 ID 曾误合并多个真实资产的歧义——此时 `AMBIGUOUS`，不自动迁移到单一 entity。

`scan_generations` 记录 `BUILDING / PUBLISHED / FAILED`、规则集摘要、输入事件 watermarks、各源 Coverage 摘要；`asset_snapshots` 按 `(entity_id, generation_id)` 唯一。聚合器完成验证后在短事务中切换 published generation；晚到事件放到下一代，不修改已发布快照。

### 9.4 存储限流与隐私

- `ProcessRegistry` 在内存维护活动候选和需要归属的进程；**任何被持久化事件引用的进程必须持久化 birth 行**（否则 `actor_process_key` 悬空）；无关系统进程最多短期 TTL。
- 高频采集先聚合窗口；经行为规则命中的 Observation 才长时间保存；Claim 只在实体状态/有效证据变化时生成，禁止“每个 connect 一条 Claim”。
- SQLite 单写者：批量提交、WAL、busy_timeout、有限队列、重试、可观测的 `dropped_count` / backpressure。降载优先丢低价值周期采样，不得隐瞒掉数，丢失必标相应 Coverage PARTIAL。
- ingest 先脱敏再落盘；敏感字段需要可比较性时使用键控 HMAC 或受限摘要，避免对可猜字段做裸 SHA。HMAC 密钥的存放、轮换、轮换后旧值是否可比必须定义；不可变的是**规范化脱敏 Observation**，而非原始密钥/命令行。
- `normalizer_version` 随 Observation 落库；规则重放时同时校验规则 digest 与归一化版本，避免“规则没变但事实解释变了”被静默忽略。
- `AssetSnapshot` 的 `supporting_claim_ids[]`、`relation_ids[]`、`component_claims[]` 可能很大；快照行只存计数/摘要，明细走子表或详情 API。

---

## 10. 迁移：P0 必须完成 identity compatibility

采用 expand → backfill → verify → switch → contract，任何阶段均可回滚到旧读模式。

1. **Expand**：新增 `identity_version`、`entities`、`entity_keys`、`entity_aliases`、Actor/Target/Process/Endpoint 字段；旧写入路径不动。
2. **Backfill**：从存量 `assets` / `agent_assets` / `applications` 生成新 Entity 和可核验 identity anchors；若旧 ID 曾代表多个实体或原始证据不足，标 `AMBIGUOUS`，不要自动定向。**已被旧逻辑硬删除的行无法重建，迁移是 best effort。**
3. **Verify**：用 golden fixtures 检查一个逻辑实体只映射一个 canonical entity；历史 `behavior_events.asset_id` 能走 alias 找到原实体或明确 `unresolved`。
4. **Switch**：新写入走 canonical EntityKey；旧 ID 只读兼容、读 API 先 alias resolution；旧事件原记录保留，呈现使用 canonical view。保留旧列一段过渡时间。
5. **Contract（P1 以后）**：观察旧路径无写入并稳定验收后再清退旧读法。旧行不物理删除、不直接批量重写历史 actor 指向。

**P0-D 前置开关**：

- P0-A 只做 shadow write：新 Entity/Key/alias 写入，但读路径仍走旧表；P0-D 才切换读路径。
- 当前 `discovery/scanner/inventory.py:_verify_stale` 在容器消失、深扫未见、venv/依赖卸载时**硬删除**资产。P0-B 必须提供 `AGENT_DETECTOR_LEGACY_DELETE=off`（默认关闭）并让旧删除逻辑在非 legacy 模式不执行；否则新架构上线前旧路径仍会清历史。
- P0 包含 Compose 单→多成员身份固定；旧 container ID 在强证据证明同一部署的前提下写 alias；但 `docker run` 仅重建无稳定标签、或 project root 同名却换了项目时，禁止自动 alias。

**旧枚举兼容**：`AssetState`、`ProtectionStatus` 由 projection adapter 映射（§7.6）；在 P1 正交快照上线前，API 同时输出旧字段与新 `agent_status` / `hook_state`，console 不需要即时改版。

---

## 11. P0 开发顺序、对应现有文件与退出条件

| 顺序 | 任务 | 主要旧文件 | 新职责 | 验收 |
| --- | --- | --- | --- | --- |
| P0-A | Identity foundation：Host/Engine、`scope_key`、boot/ns/birth、实体键与 alias、Tetragon matching 规格 | `core/identity.py`, `monitoring/detection/process_graph.py`, `storage/*` | `identity/host.py`, `identity/process.py`, `identity/entity.py` | PID 复用、重启、远程 engine、单/多 Compose 黄金用例通过；只 shadow write |
| P0-B（可并行） | Coverage DAG + 逐谓词状态 + 目标性复核 + 关闭旧硬删除 | `scanner/scan.py`, `inventory.py`, `docker_agents.py`, `fingerprints/loader.py` | `coverage.py`, `lifecycle.py`, `reconfirmers/*` | 预算截断/深扫失败/规则失败零误删；`LEGACY_DELETE=off` 生效 |
| P0-C | Actor/Target 双向归属 + Endpoint + DockerPortResolver | `monitoring/services/monitor.py`, `ingest.py`, `attribution.py`, `discovery/probes/http.py` | `correlation/attribution.py`, `correlation/docker_ports.py`, `correlation/endpoints.py` | docker-proxy/DNAT/多候选 → 正确 target/null；反向代理第一跳正确或 null |
| P0-D | Canonicalization 与历史迁移闭环 + 读路径切换 | `storage/asset_repository.py`, `agent_repository.py`, `console/api/agent_view.py` | `entity_aliases`, `entity_projection.py` | 历史事件/详情无断链，歧义身份不得静默合并 |
| P1 | Evidence ledger / PredicateRegistry / StatusProjection / 正交详情 / 原子发布 | `core/models.py`, `storage/*`, `discovery/sources/frameworks.py` | `evidence/*`, `aggregation/*` | 4 值状态派生正确；静态与动态状态严格区分；冲突可解释 |
| P2 | Node 宿主解析/MCP/受控 instrumentation | `discovery/scanner/resolver.py`, `monitoring/*` | 扩展适配 | 新信号不降级已有身份正确性 |

**任务依赖**：

- P0-A 是 P0-C 和 P0-D 的前置；
- P0-B 可并行，但必须先冻结“P0-B 使用 legacy `asset_id` 还是新 `entity_id`”的接口；最终出站必须同一 generation / identity contract；
- P0-C 依赖 P0-A 的 ProcessRegistry；P0-C 前可以先做 schema 双字段兼容；
- P0-D 是任何新 canonical ID 读路径上线的前置条件；P0-A 的写入必须保持 shadow；
- 正式的 `REMOVED`/归档行为必须在 P0-B 已上线且 `LEGACY_DELETE=off` 后开启。

---

## 12. Golden fixtures / 接口契约验收

必备 fixture（采集源 JSON/事件序列 + 预期 Entities/Relations/Coverage/Snapshots/Status）：

1. 同 PID 不同 start_ticks；跨 boot 同 PID；exec_id 改变但进程 birth 不变；无 boot id 的跨源事件不强归属。
2. Windows ProcessGuid 正常与缺失；同一 PID + 粗粒度 CreateTime 冲突退回 candidate。
3. 本机 Docker、远程 `DOCKER_HOST`、daemon ID 改变、engine→host 映射未验证，保证不串宿主；远程 engine 的实例键使用 `scope_key=engine_key`。
4. Docker published port：userland-proxy、iptables DNAT、容器直连、Nginx→Dify（P0 只验第一跳或 null）、多产品同容器、两个同名 Dify，保证 target 不越权归属。
5. Compose 1→N→1→0、容器重建、无 working_dir/config_files、project 名冲突；已证实身份保持，不足则候选。
6. 40/200 项目截断、200/200 容器无终止证明、rule YAML 错误、deep scan FAILED；完整枚举但目标复核 AccessDenied，不产生 CONFIRMED_ABSENT。
7. 已安装包删除但配置保留（→ `CONFIGURED`，`installed=false`）、项目路径删除再用不同程序重建、共享 venv 两应用、monorepo 双 entry。
8. Hook 配置存在/桥进程启动/真实工具事件/受控阻断回执，E2/E4/E5/ENFORCEMENT 独立。
9. 同一 TCP socket 多次轮询不重复统计为多次推理请求；两个真实独立连接不被一个旧 `flow_id` 吞掉；多源同一操作有全部 Evidence。
10. `agent_status` 派生：运行中 / 已配置 / 已安装 / 未知；仅配置、仅声明、仅名称匹配、覆盖 PARTIAL、实例未验证各自落到正确值；已确认不存在不进入 4 值。
11. Migration：旧 `asset_id`、新 `entity_id`、历史事件关联、歧义 alias、重复执行 backfill 幂等。
12. 旧硬删除开关：`LEGACY_DELETE=off` 时容器/项目/依赖消失不删除；`on` 时保持旧行为（仅兼容用）。

P0 **退出条件**：

- `wrong_actor_count = 0`、`wrong_target_count = 0`、`wrong_auto_merge_count = 0`、`unsafe_removed_count = 0`；
- `status_confusion_count = 0`（安装/配置/运行/未知的派生错误）；
- 重复 Observation / Claim 计数为 0（同一重放输入）；
- 所有 identity/candidate 不足场景明示 `unknown/candidate`；
- 旧单测全绿 + 真实 Linux/Tetragon/Docker、Windows/Sysmon 双平台冒烟测试通过后再打开新行为。

这是 **fixture 内**可计算的质量门禁，不宣称真实世界全量零误报。

---

## 13. 推进前须冻结的产品口径

1. **Agent 状态只有 4 值**：`RUNNING / CONFIGURED / INSTALLED / UNKNOWN`。已移除/归档不是状态，是 `removal_verdict`；能力、保护、覆盖、安装/配置/进程细节都是详情维度，不进入状态列。
2. 自建应用默认以 **`scope_key + canonical application root`** 为主，用户仅为进程/安装归属属性；同一 repo 的多用户进程汇聚到同一应用，monorepo 明确多入口时再拆。安全隔离需求另按用户维度查实例，不强行分叉应用实体。
3. Framework/SDK 默认是 Component，只有独立服务/部署边界才成为 Entity；同一软件可在不同上下文扮演两种角色。
4. 不把 TCP 连接、包安装或普通 `exec` 自动升级为“Agent 自主执行”。本期主要验证 **识别/关联/运行态观察**，不是模型意图鉴定。
5. 不完整覆盖只能增加正证据，不能产生缺席裁决；归档必须经过目标性权威复核。
6. 旧主键不是业务身份的真理；identity 语义冲突时优先安全地断链并标候选，不静默合并。
7. `agent_status` 只由 `StatusProjection` 派生；任何采集器/检测器直接写状态都视为契约违规。

---

## 14. 风险与开放问题

| 风险 | 影响 | 处理 |
| --- | --- | --- |
| P0 范围仍偏大（A/B/C/D 四线） | 交付周期不可控 | P0-A 先 shadow；P0-B 可并行；P0-C 收窄为直接监听/published/proxy/DNAT/null；反向代理第二跳放 P1 |
| 远程引擎 host 映射未验证 | 容器资产可能挂到错误宿主 | `scope_key=engine_key`、`host_key=null`；只有验证后才 bridging |
| Windows 无 Sysmon | ProcessGuid 缺失，粗粒度 CreateTime 碰撞 | 退回 `windows_live_v1` + candidate；不做跨源强合并 |
| Docker userland-proxy / DNAT 分支 | 宿主 listener 不是容器进程 | DockerPortResolver 先查端口绑定；无闭包 → target null |
| 反向代理第二跳 | Dify 证据可能挂到 nginx | P0 只认第一跳或 null；`ROUTES_TO` 需要代理配置/trace |
| Tetragon 时钟域未校准 | 跨源归属不可比 | P0-A 交付 matching 规格；未校准只 candidate |
| SQLite 写放大 | 高频事件 + Claim 拖慢单写者 | 窗口聚合、Claim 仅状态变化、批量提交、背压/丢弃计数 |
| 旧硬删除已清历史 | 迁移无法补全 | P0-B 关闭旧删除；迁移声明 best effort |

## 15. 官方语义参考

- Linux `/proc/<pid>/stat` 第 22 字段 `starttime` 为自开机以来的 clock ticks：https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html
- Linux boot_id：https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html
- Docker 端口映射及 `NetworkSettings.Ports`：https://docs.docker.com/engine/network/port-publishing/
- Docker Compose 项目身份和 project 名覆写机制：https://docs.docker.com/compose/intro/compose-application-model/
- Windows ProcessGuid / Sysmon 事件：https://learn.microsoft.com/sysinternals/downloads/sysmon
- SQLite partial index / WAL：https://www.sqlite.org/partialindex.html 、https://www.sqlite.org/wal.html