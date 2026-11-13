import { useEffect, useRef, useSyncExternalStore } from "react";
import {
  keepPreviousData,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { api, type AgentFilters, type EventFilters } from "./client";
import { beginGlobalProgress, endGlobalProgress } from "../lib/progress";
import {
  beginScanRequest,
  endScanRequest,
  isScanRequested,
  subscribeScanRequest,
} from "../lib/scanRequest";
import type { ScanStatus } from "./types";

export function useOverview() {
  return useQuery({
    queryKey: ["overview"],
    queryFn: api.overview,
    staleTime: 10_000,
    refetchInterval: 15_000,
  });
}


export function useTimeseries(window = "24h", bucket = "hour") {
  return useQuery({
    queryKey: ["timeseries", window, bucket],
    queryFn: () => api.timeseries(window, bucket),
    staleTime: 30_000,
  });
}

export function useAgents(filters: AgentFilters) {
  return useQuery({
    queryKey: ["agents", filters],
    queryFn: () => api.agents(filters),
    staleTime: 15_000,
  });
}

export function useAgent(entityId: string | undefined) {
  return useQuery({
    queryKey: ["agent", entityId],
    queryFn: () => api.agent(entityId as string),
    enabled: Boolean(entityId),
    staleTime: 15_000,
  });
}

export function useAgentClaims(entityId: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ["agent", entityId, "claims"],
    queryFn: () => api.agentClaims(entityId as string, true),
    enabled: Boolean(entityId) && enabled,
    staleTime: 30_000,
  });
}

export function useAgentCoverage(entityId: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ["agent", entityId, "coverage"],
    queryFn: () => api.agentCoverage(entityId as string),
    enabled: Boolean(entityId) && enabled,
    staleTime: 30_000,
  });
}

export function useAgentMcp(entityId: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ["agent", entityId, "mcp"],
    queryFn: () => api.agentMcp(entityId as string),
    enabled: Boolean(entityId) && enabled,
    staleTime: 60_000,
  });
}

export function useAgentRelations(entityId: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ["agent", entityId, "relations"],
    queryFn: () => api.agentRelations(entityId as string),
    enabled: Boolean(entityId) && enabled,
    staleTime: 30_000,
  });
}

export function useEvents(filters: EventFilters) {
  return useQuery({
    queryKey: ["events", filters],
    queryFn: () => api.events(filters),
    staleTime: 5_000,
    placeholderData: keepPreviousData,
  });
}

export function useEvent(eventId: number | null | undefined) {
  return useQuery({
    queryKey: ["event", eventId],
    queryFn: () => api.event(eventId as number),
    enabled: Boolean(eventId),
    staleTime: 60_000,
  });
}

export function useAlerts(params: { status?: string; risk_level?: string }) {
  return useQuery({
    queryKey: ["alerts", params],
    queryFn: () => api.alerts({ ...params, limit: 200 }),
    staleTime: 10_000,
    refetchInterval: 15_000,
  });
}

export function usePolicies() {
  return useQuery({
    queryKey: ["policies"],
    queryFn: api.policies,
    staleTime: 30_000,
  });
}

export function useTelemetry() {
  return useQuery({
    queryKey: ["telemetry"],
    queryFn: api.telemetry,
    staleTime: 10_000,
    refetchInterval: 15_000,
  });
}

export function useChannelControl() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({
      control,
      id,
      action,
    }: {
      control: "monitor" | "behavior";
      id: string;
      action: "start" | "stop";
    }) =>
      control === "monitor"
        ? api.monitorControl(action)
        : api.behaviorControl(action, action === "start" ? id : undefined),
    onSuccess: () => client.invalidateQueries({ queryKey: ["telemetry"] }),
  });
}

export function useHooks() {
  return useQuery({
    queryKey: ["hooks"],
    queryFn: api.hooks,
    staleTime: 30_000,
  });
}

export function useSystem() {
  return useQuery({
    queryKey: ["system"],
    queryFn: api.system,
    staleTime: 300_000,
  });
}

export function useCapabilities() {
  return useQuery({
    queryKey: ["capabilities"],
    queryFn: api.capabilities,
    staleTime: 300_000,
  });
}

export function useUpdateAlert() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status }: { id: number; status: string }) =>
      api.updateAlert(id, status),
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ["alerts"] });
      client.invalidateQueries({ queryKey: ["overview"] });
    },
  });
}

export function useUpdatePolicy() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: { enabled?: boolean; decision?: string } }) =>
      api.updatePolicy(id, patch),
    onSuccess: () => client.invalidateQueries({ queryKey: ["policies"] }),
  });
}

export function useReloadPolicies() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: api.reloadPolicies,
    onSuccess: () => client.invalidateQueries({ queryKey: ["policies"] }),
  });
}

export function useScan() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: () => api.scan(false, true),
    onMutate: () => {
      beginScanRequest();
      beginGlobalProgress();
      client.setQueryData<ScanStatus>(["scan-status"], {
        running: true,
        started_at: new Date().toISOString(),
        mode: "agent",
      });
    },
    onSuccess: async () => {
      await Promise.all([
        client.invalidateQueries({ queryKey: ["overview"] }),
        client.invalidateQueries({ queryKey: ["agents"] }),
        client.invalidateQueries({ queryKey: ["telemetry"] }),
      ]);
    },
    onSettled: () => {
      endScanRequest();
      endGlobalProgress();
      client.invalidateQueries({ queryKey: ["scan-status"] });
    },
  });
}

/** Server-side scan activity: survives navigation and page reloads. */
export function useScanStatus() {
  return useQuery({
    queryKey: ["scan-status"],
    queryFn: api.scanStatus,
    refetchInterval: (query) => (query.state.data?.running ? 1500 : 5000),
  });
}

/**
 * One "扫描中" answer for every page: a locally requested scan (shared across
 * routes, immune to the status poll racing the POST) or a scan the server
 * reports as running (page reload, another tab).
 */
export function useScanning() {
  const requested = useSyncExternalStore(subscribeScanRequest, isScanRequested);
  const status = useScanStatus();
  return requested || status.data?.running === true;
}

/**
 * True while a scan runs anywhere in this console process, plus refresh of the
 * affected views when it finishes. Used once by the shell so the loading bar
 * and the "扫描中" label also appear after a reload mid-scan.
 */
export function useScanActivity() {
  const client = useQueryClient();
  const status = useScanStatus();
  const running = status.data?.running ?? false;
  const wasRunning = useRef(false);
  useEffect(() => {
    if (running) {
      wasRunning.current = true;
      return;
    }
    if (!wasRunning.current) return;
    wasRunning.current = false;
    void Promise.all([
      client.invalidateQueries({ queryKey: ["overview"] }),
      client.invalidateQueries({ queryKey: ["agents"] }),
      client.invalidateQueries({ queryKey: ["telemetry"] }),
    ]);
  }, [running, client]);
  return running;
}

export function useHookPlan() {
  return useMutation({
    mutationFn: (agentType: string) => api.hookPlan(agentType),
  });
}

export function useHookInstall() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ agentType, apply }: { agentType: string; apply: boolean }) =>
      api.hookInstall(agentType, apply),
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ["hooks"] });
      client.invalidateQueries({ queryKey: ["agents"] });
      client.invalidateQueries({ queryKey: ["overview"] });
    },
  });
}

export function useHookUninstall() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ agentType, apply }: { agentType: string; apply: boolean }) =>
      api.hookUninstall(agentType, apply),
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ["hooks"] });
      client.invalidateQueries({ queryKey: ["agents"] });
      client.invalidateQueries({ queryKey: ["overview"] });
    },
  });
}
export function useRetention() {
  return useQuery({
    queryKey: ["retention"],
    queryFn: api.retention,
    staleTime: 30_000,
  });
}

export function useUpdateRetention() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (retentionDays: number) => api.updateRetention(retentionDays),
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ["retention"] });
      client.invalidateQueries({ queryKey: ["system"] });
    },
  });
}
