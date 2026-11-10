export type AgentStatus = "RUNNING" | "CONFIGURED" | "INSTALLED" | "UNKNOWN";
export type Presence = "PRESENT" | "ABSENT" | "UNKNOWN";
export type Verification =
  | "VERIFIED"
  | "PARTIAL"
  | "FAILED"
  | "NOT_CHECKED"
  | "STALE";
export type Lifecycle = "ACTIVE" | "WATCH" | "ARCHIVED";
export type ProtectionSummary =
  | "PROTECTED"
  | "MONITOR_ONLY"
  | "UNPROTECTED"
  | "UNKNOWN";
export type HookState =
  | "NOT_CONFIGURED"
  | "PARTIAL"
  | "CONFLICT"
  | "CONFIGURED"
  | "HOOK_OBSERVED"
  | "ENFORCEMENT_VERIFIED"
  | "UNKNOWN";
export type AliasStatus = "OK" | "AMBIGUOUS" | "CONFLICT" | "MISSING";
export type Decision = "allow" | "ask" | "deny" | "audit" | "error";
export type ExecutionStatus =
  | "pending"
  | "allowed"
  | "blocked_by_hook"
  | "succeeded"
  | "failed"
  | "unknown";
export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface StatusBasis {
  basis_version?: number;
  installed?: boolean | null;
  configured?: boolean | null;
  running?: boolean | null;
  conflicts?: string[];
  claim_ids?: Record<string, string[]>;
  presence?: Presence;
  verification?: Verification;
  lifecycle?: Lifecycle;
  reason_code?: string;
  reason?: string;
  last_known_status?: AgentStatus;
  verified?: boolean;
  unverified_reason?: string;
  unverified_code?: string;
  stale?: boolean;
  last_generation_id?: number;
  scope_checks?: Array<{
    scope_type: string;
    scope_key: string;
    predicate: string;
    status: string;
  }>;
}

export interface ProtectionView {
  summary: ProtectionSummary;
  hook_state: HookState;
  basis: {
    enforcement_verified: boolean;
    hook_observed_at: string | null;
    telemetry_running: boolean;
    telemetry_scope: "asset" | "global" | "none";
    reason: string;
  };
}

export interface AgentRow {
  entity_id: string;
  entity_alias_status: AliasStatus;
  entity_kind: string;
  name: string;
  agent_type: string;
  vendor: string | null;
  version: string;
  version_source: string;
  agent_status: AgentStatus | null;
  presence: Presence;
  verification: Verification;
  lifecycle: Lifecycle;
  reason_code: string;
  reason: string;
  last_known_status: AgentStatus;
  status_basis: StatusBasis;
  removal_verdict: "NONE" | "CANDIDATE" | "CONFIRMED" | null;
  snapshot_generation_id: number | null;
  snapshot_current: boolean;
  snapshot_projected_at: string | null;
  snapshot_hook_state: HookState;
  verified_scopes: Array<{
    scope_type: string;
    scope_key: string;
    predicate: string;
    status: string;
  }>;
  owner_scope: { scope_type: string; scope_key: string } | null;
  capability_tags: string[];
  protection: ProtectionView;
  instance_count: number;
  session_count: number;
  component_count: number;
  origin: "host" | "docker";
  first_seen_at: string;
  last_seen_at: string;
  executable: string | null;
  config_paths: string[];
  mcp_servers: string[];
  llm_endpoints: Array<Record<string, string>>;
  notes: string[];
  capabilities: Record<string, unknown>;
}

export interface InstanceView {
  instance_id: string;
  entity_id: string;
  agent_type: string;
  pid: number;
  ppid: number | null;
  process_guid: string | null;
  process_name: string;
  executable: string | null;
  cmdline: string | null;
  cwd: string | null;
  parent_chain: string[];
  origin: "host" | "docker";
  container_id: string | null;
  status: "running" | "stopped" | "unverified";
  evidence: string[];
  started_at: string | null;
  last_seen_at: string;
}

export interface SessionView {
  session_id: string;
  entity_id: string;
  agent_type: string;
  instance_id: string | null;
  source: string;
  cwd: string | null;
  last_tool: string | null;
  event_count: number;
  started_at: string | null;
  last_event_at: string | null;
  ended_at: string | null;
}

export interface ComponentView {
  component_key: string;
  name: string;
  kind: string;
  version: string;
  version_source: string;
  relation_type: string;
  status: "confirmed" | "candidate" | "expired";
  evidence_claim_id: string | null;
}

export interface RelationView {
  relation_type: string;
  status: "confirmed" | "candidate" | "expired";
  from_ref: string;
  to_ref: string;
  label: string;
  version: string | null;
  version_source: string | null;
  evidence_claim_id: string | null;
  valid_from: string | null;
  valid_to: string | null;
}

export interface EndpointView {
  endpoint_id: string;
  protocol: string;
  address: string;
  binding_status: "confirmed" | "candidate" | "expired";
}


export interface LocationView {
  root_path: string;
  environment_path: string | null;
  runtime: string;
  entrypoint: string | null;
  entry_kind: string;
  status: string;
  first_seen_at: string;
  last_seen_at: string;
}

export interface ClaimsSummary {
  available: boolean;
  completeness: "support_only" | "bidirectional";
  claim_count: number;
  conflicts: string[];
  by_predicate: Record<string, number>;
}

export interface AgentDetail extends AgentRow {
  instances: InstanceView[];
  sessions: SessionView[];
  events: EventView[];
  components: ComponentView[];
  relations: RelationView[];
  claims_summary: ClaimsSummary;
  coverage: CoverageView;
  location: LocationView | null;
}

export interface EventActor {
  entity_id: string | null;
  instance_id: string | null;
  label: string;
  alias_status: AliasStatus;
  attribution_state: "verified" | "candidate" | "unattributed";
}

export interface EventTarget {
  entity_id: string | null;
  endpoint_id: string | null;
  instance_id: string | null;
  label: string | null;
  alias_status: AliasStatus;
}

export interface EventView {
  id: number;
  observed_at: string;
  source: string;
  event_type: string | null;
  operation: string | null;
  protocol: string | null;
  tool: string | null;
  target: string | null;
  result: string | null;
  risk_level: RiskLevel | null;
  decision: Decision | null;
  execution_status: ExecutionStatus | null;
  policy_id: string | null;
  session_id: string | null;
  instance_id: string | null;
  process_name: string | null;
  pid: number | null;
  ppid: number | null;
  mcp_server: string | null;
  model: string | null;
  http_status: number | null;
  actor: EventActor;
  target_ref: EventTarget;
  evidence: string[];
  agent_label?: string;
  entity_id?: string | null;
  target_entity_id?: string | null;
  attribution_state?: string;
}

export interface ObservationView {
  observation_id: string;
  source: string;
  source_event_uid: string;
  observed_at: string;
  fact_type: string;
  summary: string;
  payload: Record<string, unknown>;
  payload_digest: string;
  retention_class: string;
}

export interface ClaimView {
  claim_id: string;
  predicate: string;
  object_ref: string;
  polarity: "support" | "refute";
  evidence_class: string;
  verification_method: string;
  rule: { id: string; digest: string; source_path: string | null };
  coverage_scope_id: number | null;
  observed_at: string;
  valid_from: string;
  valid_to: string | null;
  status: string;
  is_current: boolean;
  supersedes_claim_id: string | null;
  observations?: ObservationView[];
}

export interface ClaimsResponse {
  available: boolean;
  entity_id: string | null;
  completeness: "support_only" | "bidirectional";
  reason?: string | null;
  items: ClaimView[];
  claim_count?: number;
  by_predicate?: Record<string, number>;
  conflicts: string[];
  notes: string[];
}

export interface CoverageScopeView {
  scope_type: string;
  scope_key: string;
  own_status: string;
  effective_status: string;
  truncated: boolean;
  predicates: Array<{ predicate: string; status: string }>;
}

export interface CoverageView {
  available: boolean;
  reason: string | null;
  scan_id: number | null;
  generation_id: number | null;
  scope: "scan" | "entity";
  summary: {
    scopes: number;
    truncated: number;
    COMPLETE: number;
    PARTIAL: number;
    FAILED: number;
    NOT_RUN: number;
  };
  scopes: CoverageScopeView[];
  notes: string[];
}

export interface McpServerView {
  name: string;
  transport: string;
  agent_type: string;
  source: string;
}

export interface McpResponse {
  items: McpServerView[];
  notes: string[];
}

export interface RelationsResponse {
  items: RelationView[];
  groups: {
    components: ComponentView[];
    instances: InstanceView[];
    endpoints: EndpointView[];
  };
  notes: string[];
}

export interface AlertView {
  id: number;
  created_at: string;
  entity_id: string | null;
  agent_type: string | null;
  agent_label: string;
  session_id: string | null;
  event_id: number | null;
  policy_id: string | null;
  risk_level: RiskLevel;
  decision: Decision;
  status: "open" | "acknowledged" | "resolved";
  title: string;
  reason: string;
  detail: Record<string, unknown>;
  resolved_at: string | null;
}

export interface PolicyView {
  policy_id: string;
  name: string;
  scope: string;
  decision: "allow" | "ask" | "deny" | "audit";
  risk_level: RiskLevel;
  enabled: boolean;
  priority: number;
  conditions: Record<string, unknown>;
  reason: string;
  updated_at: string;
}

export interface ChannelView {
  id: string;
  name: string;
  available: boolean;
  running: boolean;
  /** RUNNING/STANDBY 仅行为通道互斥组会出现：同一时刻只运行一个。 */
  state: "RUNNING" | "STANDBY" | "STOPPED" | "UNAVAILABLE" | "DOWN" | "UNKNOWN";
  detail: string;
  control: "monitor" | "behavior" | null;
  platform: "Windows" | "Linux" | "all";
  last_event_at: string | null;
  status_age_seconds: number | null;
  reason: string | null;
}

export interface TelemetryView {
  host_platform: string;
  health: {
    state: "OK" | "DEGRADED" | "NOT_RUNNING" | "UNKNOWN";
    basis: string[];
    last_event_at: string | null;
    last_event_age_seconds: number | null;
  };
  channels: ChannelView[];
  behavior: Record<string, unknown>;
  monitor: Record<string, unknown>;
}

export interface HookInstallation {
  agent_type: string;
  display_name: string;
  config_path: string;
  state: string;
  support: string;
  schema_verified: boolean;
  entries: number;
  notes: string[];
  spec_notes: string[];
  events?: string[];
  docs_url?: string;
}

export interface HooksResponse {
  items: HookInstallation[];
  failure_mode: string;
  notes: string[];
}

export interface HookPlanResponse {
  agent_type: string;
  config_path: string;
  command: string;
  events: string[];
  fail_closed: boolean;
  existing: Record<string, unknown>;
  merged: Record<string, unknown>;
  changed: boolean;
  written: boolean;
  backup: string | null;
  /** uninstall 结果：本次移除的本工具条目数 */
  removed?: number;
  status?: HookInstallation[];
}


export interface OverviewView {
  agents: {
    total: number;
    inventory_total: number;
    current_detected: number;
    confirmed_present: number;
    running: number;
    running_count: number;
    running_confirmed: number;
    running_unconfirmed: number;
    needs_verification: number;
    archived_total: number;
    running_basis: "agent_status" | "mixed" | "unavailable";
    new_24h: number;
    unknown_status: number;
    by_entity_kind: Record<string, number>;
    by_type: Record<string, number>;
    protection: Record<string, number>;
    protection_summary: Record<ProtectionSummary, number>;
    hook_states: Partial<Record<HookState, number>>;
  };
  behavior: {
    events_today: number;
    blocked_today: number;
    by_source: Record<string, number>;
    last_event_at: string | null;
  };
  components: { total: number; by_type: Record<string, number> };
  alerts: {
    alert_count: number;
    by_status: Record<string, number>;
    by_risk: Record<string, number>;
    open_high: number;
  };
  recent_events: EventView[];
  recent_alerts: AlertView[];
  latest_scan_id: number | null;
  disclaimer: string[];
}

export interface TimeseriesPoint {
  start: string;
  end: string;
  events: number;
  blocked: number;
}

export interface TimeseriesView {
  bucket: string;
  timezone: string;
  points: TimeseriesPoint[];
}

export interface SystemView {
  version: string;
  platform: { system: string; release: string; python: string; node: string };
  server: { host: string; port: number; listen: string };
  database: { path: string; url: string };
  policy: Record<string, unknown>;
  hooks: Record<string, unknown>;
  channels: Record<string, unknown>;
  behavior: Record<string, unknown>;
  detection_rules: Record<string, unknown>;
  agent_matrix: Record<string, unknown>;
  scope_notes: string[];
}

export interface CapabilitiesView {
  version: string;
  modes: Record<string, unknown>;
}

export interface ScanResult {
  scan_id: number;
  mode: string;
  status: string;
  entities: number;
  components: number;
  errors: Array<{ detector: string; error: string }>;
}

export interface ScanStatus {
  running: boolean;
  started_at: string | null;
  mode: string | null;
}