// Formatting helpers: labels, times and colour mappings used by every view.
// All product vocabulary (已启用 / 仅审计 / 待适配…) lives here so the console
// never invents a status the backend did not report.

export const PROTECTION = {
  PROTECTED: { label: '已启用拦截', cls: 'success', hint: 'Hook 已接入，工具调用前可阻断' },
  MONITOR_ONLY: { label: '仅监测', cls: 'info', hint: '可观察行为，无法在执行前阻断' },
  DEGRADED: { label: '保护降级', cls: 'warning', hint: 'Hook 配置不完整或已被移除' },
  UNPROTECTED: { label: '未保护', cls: 'danger', hint: '既无 Hook 也无采集通道' },
  UNKNOWN: { label: '未知', cls: 'outline', hint: '尚无足够信息判断保护状态' },
};

export const HOOK_STATE = {
  INSTALLED: { label: '已安装', cls: 'success' },
  PARTIAL: { label: '部分接入', cls: 'warning' },
  NOT_INSTALLED: { label: '未安装', cls: 'outline' },
  CONFLICT: { label: '配置冲突', cls: 'danger' },
  UNSUPPORTED: { label: '不支持', cls: 'outline' },
  UNKNOWN: { label: '未知', cls: 'outline' },
};

export const RISK = {
  low: { label: '低', cls: 'outline' },
  medium: { label: '中', cls: 'info' },
  high: { label: '高', cls: 'warning' },
  critical: { label: '严重', cls: 'critical' },
};

export const DECISION = {
  allow: { label: '放行', cls: 'success' },
  ask: { label: '需确认', cls: 'warning' },
  deny: { label: '已阻断', cls: 'danger' },
  audit: { label: '仅审计', cls: 'info' },
  error: { label: '错误', cls: 'danger' },
};

export const SOURCE = {
  native_hook: { label: 'Agent Hook', icon: 'shield' },
  sysmon: { label: 'Sysmon', icon: 'activity' },
  auditd: { label: 'auditd', icon: 'terminal' },
  tetragon: { label: 'eBPF', icon: 'activity' },
  poll: { label: '进程采样', icon: 'activity' },
  netmon: { label: '网络调用', icon: 'globe' },
  scan: { label: '扫描', icon: 'search' },
};

export const SUPPORT = {
  P0: { label: 'P0', cls: 'info' },
  P1: { label: 'P1', cls: 'outline' },
  P2: { label: 'P2', cls: 'outline' },
  PLANNED: { label: '待适配', cls: 'warning' },
  UNVERIFIED: { label: '待验证', cls: 'warning' },
};

export function supportLabel(level) {
  const item = SUPPORT[level];
  return item ? item.label : level || '—';
}

export function badgeSpec(map, key, fallback = 'outline') {
  return map[key] || { label: key || '—', cls: fallback };
}

export function time(iso) {
  if (!iso) return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString('zh-CN', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

export function clock(iso) {
  if (!iso) return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleTimeString('zh-CN', { hour12: false });
}

export function relative(iso) {
  if (!iso) return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  const seconds = Math.round((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return `${Math.max(seconds, 0)} 秒前`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`;
  if (seconds < 86400 * 30) return `${Math.floor(seconds / 86400)} 天前`;
  return time(iso);
}

export function truncate(text, length = 120) {
  if (!text) return '—';
  return text.length > length ? `${text.slice(0, length)}…` : text;
}

export function count(value) {
  return typeof value === 'number' ? value.toLocaleString('zh-CN') : '—';
}

export function yesNo(value) {
  return value ? '是' : '否';
}

// JSON-safe short text for a tool call target / command.
export function commandText(target) {
  if (!target) return '—';
  return target.replace(/\s+/g, ' ').trim();
}