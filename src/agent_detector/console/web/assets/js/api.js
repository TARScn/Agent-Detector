// Thin API client. Every call goes through here so error handling, base path
// and JSON decoding stay in one place.

const BASE = '';

async function request(path, { method = 'GET', body, signal } = {}) {
  const response = await fetch(BASE + path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
    signal,
  });
  const text = await response.text();
  let payload = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = { detail: text };
  }
  if (!response.ok) {
    const detail = payload && payload.detail
      ? (typeof payload.detail === 'string' ? payload.detail : JSON.stringify(payload.detail))
      : `HTTP ${response.status}`;
    const error = new Error(detail);
    error.status = response.status;
    throw error;
  }
  return payload;
}

export const api = {
  overview: () => request('/api/v1/overview'),
  system: () => request('/api/v1/system'),
  capabilities: () => request('/api/v1/capabilities'),

  agents: () => request('/api/v1/agents'),
  agent: (id) => request(`/api/v1/agents/${encodeURIComponent(id)}`),
  agentMcp: (id) => request(`/api/v1/agents/${encodeURIComponent(id)}/mcp`),

  scan: (active = false) => request('/api/v1/discovery/scan', {
    method: 'POST', body: { active },
  }),
  scans: () => request('/api/v1/discovery/scans'),
  components: () => request('/api/v1/discovery/assets'),
  applications: () => request('/api/v1/discovery/applications'),

  events: (params = {}) => request(`/api/v1/events?${query(params)}`),
  eventStats: (params = {}) => request(`/api/v1/events/stats?${query(params)}`),

  policies: () => request('/api/v1/policies'),
  updatePolicy: (id, patch) => request(`/api/v1/policies/${encodeURIComponent(id)}`, {
    method: 'PUT', body: patch,
  }),
  reloadPolicies: () => request('/api/v1/policies/reload', { method: 'POST' }),

  alerts: (params = {}) => request(`/api/v1/alerts?${query(params)}`),
  updateAlert: (id, status) => request(`/api/v1/alerts/${id}`, {
    method: 'PATCH', body: { status },
  }),

  telemetry: () => request('/api/v1/telemetry/status'),
  startMonitor: (body = {}) => request('/api/v1/telemetry/monitor/start', {
    method: 'POST', body,
  }),
  stopMonitor: () => request('/api/v1/telemetry/monitor/stop', { method: 'POST' }),
  startBehavior: (body = {}) => request('/api/v1/telemetry/behavior/start', {
    method: 'POST', body,
  }),
  stopBehavior: () => request('/api/v1/telemetry/behavior/stop', { method: 'POST' }),
  auditRules: (watchDir) => request(`/api/v1/telemetry/audit-rules${
    watchDir ? `?watch_dir=${encodeURIComponent(watchDir)}` : ''}`),

  hooks: () => request('/api/v1/hooks'),
  hookPlan: (agent) => request(`/api/v1/hooks/${agent}/plan`, { method: 'POST', body: {} }),
  hookInstall: (agent, apply = false) => request(`/api/v1/hooks/${agent}/install`, {
    method: 'POST', body: { apply },
  }),
  hookUninstall: (agent, apply = false) => request(`/api/v1/hooks/${agent}/uninstall`, {
    method: 'POST', body: { apply },
  }),
  hookSnippet: (agent) => request(`/api/v1/hooks/${agent}/snippet`),
};

export function eventStreamUrl(params = {}) {
  return `/api/v1/events/stream?${query({ initial: 15, ...params })}`;
}

function query(params) {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') search.set(key, value);
  });
  return search.toString();
}