# configs/

本目录只放**必须由外部工具消费的配置文件**，例如交给 Sysmon 的 XML。

Agent Detector 自身的默认配置随包发布（沿用与检测规则相同的“内置默认 + 外部覆盖”约定）：

| 配置 | 内置默认（随包发布） | 外部覆盖方式 |
| --- | --- | --- |
| Agent 支持矩阵 | `agent_detector/discovery/data/agents.yaml` | `AGENT_DETECTOR_AGENTS_FILE=/path/to/agents.yaml` |
| 安全策略规则 | `agent_detector/policy/rules/policies.yaml` | `AGENT_DETECTOR_POLICY_DIR=/path/to/dir`（同名文件整体替换） |
| 检测规则（资产发现） | `agent_detector/discovery/fingerprints/rules/*.yaml` | `AGENT_DETECTOR_RULES_DIR=/path/to/dir`（按 id 覆盖） |
| 行为规则 | `agent_detector/detection/rules/behaviors.yaml` | `AGENT_DETECTOR_BEHAVIOR_RULES_DIR=/path/to/dir` |
| LLM 情报名单 | `agent_detector/detection/rules/llm_apis.yaml` | 同上 |

- [sysmon.xml](sysmon.xml)：Windows Sysmon 采集配置模板（进程创建 / 网络连接 / 文件创建与删除）。
  安装与合并步骤见文件头部注释与 [docs/windows.md](../docs/windows.md)。
- 策略与行为规则的字段说明见 [docs/policy.md](../docs/policy.md) 与 [docs/rules.md](../docs/rules.md)。

外部覆盖目录里的文件**按文件名替换内置同名文件**，因此可以在保留其他内置规则的前提下只改一份。