import type {
  AgentStatus,
  Decision,
  ExecutionStatus,
  HookState,
  ProtectionSummary,
  RiskLevel,
} from "../api/types";

export const AGENT_STATUS: Record<AgentStatus, { label: string; tone: string }> = {
  RUNNING: { label: "运行中", tone: "success" },
  CONFIGURED: { label: "已配置", tone: "info" },
  INSTALLED: { label: "已安装", tone: "neutral" },
  UNKNOWN: { label: "未知", tone: "neutral" },
};

export const PROTECTION: Record<ProtectionSummary, { label: string; tone: string; hint: string }> = {
  PROTECTED: { label: "已验证阻断", tone: "success", hint: "有真实前置阻断证据" },
  MONITOR_ONLY: { label: "仅监测", tone: "info", hint: "可观察，未验证执行前阻断" },
  UNPROTECTED: { label: "未保护", tone: "danger", hint: "无 Hook 也无采集覆盖" },
  UNKNOWN: { label: "未知", tone: "neutral", hint: "保护状态无法确认" },
};

export const HOOK_STATE: Record<HookState, { label: string; tone: string }> = {
  NOT_CONFIGURED: { label: "未配置", tone: "neutral" },
  PARTIAL: { label: "部分接入", tone: "warning" },
  CONFLICT: { label: "配置冲突", tone: "danger" },
  CONFIGURED: { label: "已配置（未验证）", tone: "info" },
  HOOK_OBSERVED: { label: "已观测触发", tone: "info" },
  ENFORCEMENT_VERIFIED: { label: "已验证阻断", tone: "success" },
  UNKNOWN: { label: "未知", tone: "neutral" },
};

export const RISK: Record<RiskLevel, { label: string; tone: string }> = {
  low: { label: "低", tone: "neutral" },
  medium: { label: "中", tone: "info" },
  high: { label: "高", tone: "warning" },
  critical: { label: "严重", tone: "danger" },
};

export const DECISION: Record<Decision, { label: string; tone: string }> = {
  allow: { label: "放行", tone: "success" },
  ask: { label: "需确认", tone: "warning" },
  deny: { label: "已阻断", tone: "danger" },
  audit: { label: "仅审计", tone: "info" },
  error: { label: "决策失败", tone: "danger" },
};

export const EXECUTION: Record<ExecutionStatus, { label: string; tone: string }> = {
  pending: { label: "待执行", tone: "neutral" },
  allowed: { label: "已放行（未确认结果）", tone: "neutral" },
  blocked_by_hook: { label: "被 Hook 阻断", tone: "danger" },
  succeeded: { label: "执行成功", tone: "success" },
  failed: { label: "执行失败", tone: "danger" },
  unknown: { label: "执行结果未知", tone: "neutral" },
};

export const INSTANCE_STATUS: Record<string, { label: string; tone: string }> = {
  running: { label: "运行中", tone: "success" },
  stopped: { label: "已停止", tone: "neutral" },
  unverified: { label: "未复核", tone: "neutral" },
};

export const ALERT_STATUS: Record<string, { label: string; tone: string }> = {
  open: { label: "未处理", tone: "warning" },
  acknowledged: { label: "已确认", tone: "info" },
  resolved: { label: "已解决", tone: "success" },
};

export const CHANNEL_STATE: Record<string, { label: string; tone: string }> = {
  OK: { label: "正常", tone: "success" },
  DEGRADED: { label: "降级", tone: "warning" },
  DOWN: { label: "停止", tone: "danger" },
  UNAVAILABLE: { label: "不可用", tone: "neutral" },
  UNKNOWN: { label: "未知", tone: "neutral" },
};

export const HEALTH_STATE: Record<string, { label: string; tone: string }> = {
  OK: { label: "采集正常", tone: "success" },
  DEGRADED: { label: "部分通道异常", tone: "warning" },
  NOT_RUNNING: { label: "未开启采集", tone: "neutral" },
  UNKNOWN: { label: "状态未知", tone: "neutral" },
};

export const ENTITY_KIND: Record<string, string> = {
  PRODUCT_INSTALL: "产品安装",
  SELF_BUILT_APPLICATION: "自建应用",
  COMPOSE_DEPLOYMENT: "Compose 部署",
  CONTAINER_DEPLOYMENT: "容器部署",
  SERVICE: "服务",
  ENVIRONMENT: "环境",
  UNKNOWN: "其他",
};

export const SOURCE_LABEL: Record<string, string> = {
  native_hook: "Agent Hook",
  sysmon: "Sysmon",
  auditd: "auditd",
  tetragon: "eBPF",
  poll: "进程采样",
  netmon: "网络调用",
  scan: "扫描",
};

export const PREDICATE_LABEL: Record<string, string> = {
  running: "运行",
  service_running: "服务运行",
  configured: "已配置",
  installed: "已安装",
  product_identity: "产品身份",
  component_identity: "组件身份",
  agent_capability: "Agent 能力",
  component_configured: "组件配置",
  framework_installed: "框架安装",
};

export const COVERAGE_SCOPE_LABEL: Record<string, string> = {
  host_process_enumeration: "主机进程枚举",
  product_rule: "产品规则范围",
  project_candidate_universe: "项目候选范围",
  container_deep_scan: "容器深扫",
  docker_engine_enumeration: "Docker 引擎枚举",
};

export function text(value: unknown, fallback = "—"): string {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

export function number(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return new Intl.NumberFormat("zh-CN").format(value);
}

export function percent(value: number, total: number): string {
  if (!total) return "—";
  return `${Math.round((value / total) * 100)}%`;
}

export function time(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function clock(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleTimeString("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function relative(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  const seconds = Math.round((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return "刚刚";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`;
  if (seconds < 86400 * 30) return `${Math.floor(seconds / 86400)} 天前`;
  return time(iso);
}

export function shortId(value: string | null | undefined, length = 12): string {
  if (!value) return "—";
  return value.length > length ? `${value.slice(0, length)}…` : value;
}

export function toneForRisk(value: string | null | undefined): string {
  return (RISK[value as RiskLevel] || RISK.medium).tone;
}

export function labelForRisk(value: string | null | undefined): string {
  return (RISK[value as RiskLevel] || RISK.medium).label;
}