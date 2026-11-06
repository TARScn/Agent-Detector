import type {
  AgentDetail,
  AgentRow,
  AlertView,
  CapabilitiesView,
  ClaimsResponse,
  CoverageView,
  EventView,
  HookPlanResponse,
  HooksResponse,
  McpResponse,
  OverviewView,
  PolicyView,
  RelationsResponse,
  ScanResult,
  ScanStatus,
  SystemView,
  TelemetryView,
  TimeseriesView,
} from "./types";

const BASE = "/api/v1";

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

function query(params: object = {}): string {
  const search = new URLSearchParams();
  Object.entries(params as Record<string, unknown>).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") {
      search.set(key, String(value));
    }
  });
  const text = search.toString();
  return text ? `?${text}` : "";
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(BASE + path, {
    ...init,
    headers: {
      ...(init.body ? { "Content-Type": "application/json" } : {}),
      ...(init.headers || {}),
    },
  });
  const text = await response.text();
  let payload: unknown = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = { detail: text };
  }
  if (!response.ok) {
    const detail =
      payload && typeof payload === "object" && "detail" in payload
        ? (payload as { detail: unknown }).detail
        : null;
    const message =
      typeof detail === "string"
        ? detail
        : detail
          ? JSON.stringify(detail)
          : `HTTP ${response.status}`;
    throw new ApiError(message, response.status);
  }
  return payload as T;
}

export interface AgentFilters {
  q?: string;
  agent_type?: string;
  agent_status?: string;
  protection?: string;
  alias_status?: string;
  origin?: string;
  limit?: number;
  offset?: number;
}

export interface EventFilters {
  source?: string;
  risk_level?: string;
  decision?: string;
  execution_status?: string;
  agent_label?: string;
  entity_id?: string;
  limit?: number;
  before_id?: number;
  after_id?: number;
}

export const api = {
  overview: () => request<OverviewView>("/overview"),
  timeseries: (window = "24h", bucket = "hour") =>
    request<TimeseriesView>(`/events/timeseries${query({ window, bucket })}`),

  agents: (filters: AgentFilters = {}) =>
    request<{ items: AgentRow[]; total: number; limit: number; offset: number }>(
      `/agents${query(filters)}`,
    ),
  agent: (entityId: string) =>
    request<AgentDetail>(`/agents/${encodeURIComponent(entityId)}`),
  agentClaims: (entityId: string, includeObservations = true) =>
    request<ClaimsResponse>(
      `/agents/${encodeURIComponent(entityId)}/claims${query({
        include_observations: includeObservations,
        limit: 100,
      })}`,
    ),
  agentCoverage: (entityId: string) =>
    request<CoverageView>(`/agents/${encodeURIComponent(entityId)}/coverage`),
  agentRelations: (entityId: string) =>
    request<RelationsResponse>(`/agents/${encodeURIComponent(entityId)}/relations`),
  agentMcp: (entityId: string) =>
    request<McpResponse>(`/agents/${encodeURIComponent(entityId)}/mcp`),

  events: (filters: EventFilters = {}) =>
    request<{ items: EventView[]; total: number; next_before_id: number | null }>(
      `/events${query(filters)}`,
    ),
  event: (eventId: number) => request<EventView>(`/events/${eventId}`),

  alerts: (params: { status?: string; risk_level?: string; limit?: number } = {}) =>
    request<{ items: AlertView[]; total: number; stats: Record<string, unknown> }>(
      `/alerts${query({ limit: 200, ...params })}`,
    ),
  alert: (alertId: number) => request<AlertView>(`/alerts/${alertId}`),
  updateAlert: (alertId: number, status: string) =>
    request<AlertView>(`/alerts/${alertId}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),

  policies: () =>
    request<{
      items: PolicyView[];
      total: number;
      decision_engine: string;
      failure_mode: string;
      status: Record<string, unknown>;
    }>("/policies"),
  updatePolicy: (policyId: string, patch: { enabled?: boolean; decision?: string }) =>
    request<PolicyView>(`/policies/${encodeURIComponent(policyId)}`, {
      method: "PUT",
      body: JSON.stringify(patch),
    }),
  reloadPolicies: () =>
    request<{ status: Record<string, unknown> }>("/policies/reload", { method: "POST" }),

  telemetry: () => request<TelemetryView>("/telemetry/status"),
  hooks: () => request<HooksResponse>("/hooks"),
  hookPlan: (agentType: string, body: Record<string, unknown> = {}) =>
    request<HookPlanResponse>(`/hooks/${encodeURIComponent(agentType)}/plan`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  hookInstall: (agentType: string, apply: boolean, body: Record<string, unknown> = {}) =>
    request<HookPlanResponse>(`/hooks/${encodeURIComponent(agentType)}/install`, {
      method: "POST",
      body: JSON.stringify({ ...body, apply }),
    }),
  hookUninstall: (agentType: string, apply: boolean) =>
    request<HookPlanResponse>(`/hooks/${encodeURIComponent(agentType)}/uninstall`, {
      method: "POST",
      body: JSON.stringify({ apply }),
    }),

  system: () => request<SystemView>("/system"),
  capabilities: () => request<CapabilitiesView>("/capabilities"),
  scan: (active = false, docker = true) =>
    request<ScanResult>("/discovery/scan", {
      method: "POST",
      body: JSON.stringify({ active, docker }),
    }),
  scanStatus: () => request<ScanStatus>("/discovery/scan/status"),
};