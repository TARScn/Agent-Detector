import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { CloseIcon, PlayCircleIcon, SearchIcon, StopCircleIcon } from "tdesign-icons-react";
import { useEvents } from "../api/queries";
import type { EventView } from "../api/types";
import { EventTable } from "../components/EventTable";
import {
  EmptyState,
  ErrorState,
  KeyValue,
  LoadingBlock,
  PageHeader,
  Tag,
} from "../components/ui";
import {
  DECISION,
  EXECUTION,
  RISK,
  SOURCE_LABEL,
  clock,
  shortId,
  text,
  time,
} from "../lib/format";

export function EventsPage() {
  const [params, setParams] = useSearchParams();
  const [selected, setSelected] = useState<EventView | null>(null);
  const [live, setLive] = useState(false);
  const [liveEvents, setLiveEvents] = useState<EventView[]>([]);
  const [q, setQ] = useState(params.get("agent_label") || "");

  const filters = useMemo(
    () => ({
      source: params.get("source") || undefined,
      risk_level: params.get("risk") || undefined,
      decision: params.get("decision") || undefined,
      execution_status: params.get("execution") || undefined,
      agent_label: params.get("agent_label") || undefined,
      entity_id: params.get("entity_id") || undefined,
      limit: 200,
    }),
    [params],
  );
  const events = useEvents(filters);

  useEffect(() => {
    if (!live) return undefined;
    const source = filters.source ? `?source=${encodeURIComponent(filters.source)}` : "";
    const stream = new EventSource(`/api/v1/events/stream${source}`);
    stream.addEventListener("event", (message) => {
      try {
        const item = JSON.parse((message as MessageEvent).data) as EventView;
        if (!matchesFilters(item, filters)) return;
        setLiveEvents((current) => {
          if (current.some((event) => event.id === item.id)) return current;
          return [item, ...current].slice(0, 100);
        });
      } catch {
        // Ignore malformed frames; the REST feed remains authoritative.
      }
    });
    stream.addEventListener("gap", () => {
      events.refetch();
    });
    return () => stream.close();
  }, [live, filters]);

  useEffect(() => {
    setLiveEvents([]);
  }, [params]);

  const combined = useMemo(() => {
    const byId = new Map<number, EventView>();
    [...liveEvents, ...(events.data?.items || [])].forEach((event) => {
      if (!byId.has(event.id)) byId.set(event.id, event);
    });
    return Array.from(byId.values()).sort((a, b) => b.id - a.id);
  }, [liveEvents, events.data]);

  const applySearch = (event: React.FormEvent) => {
    event.preventDefault();
    const next = new URLSearchParams(params);
    if (q.trim()) next.set("agent_label", q.trim());
    else next.delete("agent_label");
    setParams(next);
  };

  const setFilter = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next);
  };

  return (
    <div className="page">
      <PageHeader
        eyebrow="监测 / 事件"
        title="行为事件"
        actions={
          <button
            type="button"
            className={`btn ${live ? "btn-danger-ghost" : "btn-secondary"}`}
            onClick={() => setLive((value) => !value)}
          >
            {live ? <StopCircleIcon size="16px" /> : <PlayCircleIcon size="16px" />}
            {live ? "暂停实时" : "开启实时"}
          </button>
        }
      />

      <form className="filter-bar" onSubmit={applySearch}>
        <label className="field search-field">
          <SearchIcon size="15px" />
          <input
            value={q}
            onChange={(event) => setQ(event.target.value)}
            placeholder="Agent 名称"
          />
        </label>
        <label className="field">
          <span>来源</span>
          <select value={filters.source || ""} onChange={(event) => setFilter("source", event.target.value)}>
            <option value="">全部</option>
            <option value="native_hook">Agent Hook</option>
            <option value="sysmon">Sysmon</option>
            <option value="auditd">auditd</option>
            <option value="tetragon">eBPF</option>
            <option value="poll">进程采样</option>
            <option value="netmon">网络调用</option>
          </select>
        </label>
        <label className="field">
          <span>风险</span>
          <select value={filters.risk_level || ""} onChange={(event) => setFilter("risk", event.target.value)}>
            <option value="">全部</option>
            <option value="high">高</option>
            <option value="critical">严重</option>
            <option value="medium">中</option>
            <option value="low">低</option>
          </select>
        </label>
        <label className="field">
          <span>决策</span>
          <select value={filters.decision || ""} onChange={(event) => setFilter("decision", event.target.value)}>
            <option value="">全部</option>
            <option value="allow">放行</option>
            <option value="ask">需确认</option>
            <option value="deny">已阻断</option>
            <option value="audit">仅审计</option>
          </select>
        </label>
        <label className="field">
          <span>执行</span>
          <select value={filters.execution_status || ""} onChange={(event) => setFilter("execution", event.target.value)}>
            <option value="">全部</option>
            <option value="blocked_by_hook">被 Hook 阻断</option>
            <option value="succeeded">执行成功</option>
            <option value="failed">执行失败</option>
            <option value="pending">待执行</option>
            <option value="unknown">未知</option>
          </select>
        </label>
        <button type="submit" className="btn btn-primary">
          筛选
        </button>
        <span className="filter-summary">
          {live ? <Tag tone="success">实时已开启</Tag> : null} 共 {combined.length} 条
        </span>
      </form>

      {events.isLoading ? (
        <LoadingBlock label="读取事件…" />
      ) : events.isError ? (
        <ErrorState message={(events.error as Error).message} onRetry={() => events.refetch()} />
      ) : combined.length ? (
        <section className="card card-flush">
          <EventTable events={combined} onSelect={setSelected} />
        </section>
      ) : (
        <EmptyState title="暂无事件" />
      )}

      {selected ? (
        <EventDrawer event={selected} onClose={() => setSelected(null)} />
      ) : null}
    </div>
  );
}

function matchesFilters(
  event: EventView,
  filters: {
    risk_level?: string;
    decision?: string;
    execution_status?: string;
    agent_label?: string;
    entity_id?: string;
  },
): boolean {
  if (filters.risk_level && event.risk_level !== filters.risk_level) return false;
  if (filters.decision && event.decision !== filters.decision) return false;
  if (filters.execution_status && event.execution_status !== filters.execution_status) return false;
  if (filters.entity_id && event.actor?.entity_id !== filters.entity_id) return false;
  if (filters.agent_label) {
    const haystack = (event.actor?.label || event.agent_label || "").toLowerCase();
    if (!haystack.includes(filters.agent_label.toLowerCase())) return false;
  }
  return true;
}

function EventDrawer({ event, onClose }: { event: EventView; onClose: () => void }) {
  const decision = event.decision ? DECISION[event.decision] : null;
  const execution = event.execution_status ? EXECUTION[event.execution_status] : null;
  const risk = event.risk_level ? RISK[event.risk_level] : null;
  return (
    <div className="drawer-layer" role="dialog" aria-modal="true">
      <button type="button" className="drawer-backdrop" aria-label="关闭" onClick={onClose} />
      <aside className="drawer">
        <header className="drawer-head">
          <div>
            <div className="eyebrow">事件 #{event.id}</div>
            <h2>{event.operation || event.event_type || "行为事件"}</h2>
            <div className="secondary-line">{time(event.observed_at)}</div>
          </div>
          <button type="button" className="icon-button" onClick={onClose} aria-label="关闭">
            <CloseIcon size="18px" />
          </button>
        </header>
        <div className="drawer-body">
          <div className="drawer-tags">
            {risk ? <Tag tone={risk.tone}>{risk.label}</Tag> : null}
            {decision ? <Tag tone={decision.tone}>{decision.label}</Tag> : null}
            {execution ? <Tag tone={execution.tone}>{execution.label}</Tag> : null}
            <Tag tone="neutral">{SOURCE_LABEL[event.source] || event.source}</Tag>
          </div>

          <h3>Actor 与 Target</h3>
          <KeyValue
            columns={1}
            items={[
              {
                label: "Actor",
                value: (
                  <span>
                    {event.actor?.label || "未归属"}
                    {event.actor?.entity_id ? (
                      <span className="mono muted"> · {shortId(event.actor.entity_id, 16)}</span>
                    ) : null}
                  </span>
                ),
              },
              {
                label: "归属状态",
                value: event.actor?.attribution_state || event.attribution_state || "unattributed",
              },
              {
                label: "Target",
                value: event.target_ref?.label || event.target || "未归属目标",
              },
              { label: "目标实体", value: shortId(event.target_ref?.entity_id, 18) },
            ]}
          />

          <h3>执行与策略</h3>
          <KeyValue
            columns={1}
            items={[
              { label: "决策", value: decision?.label || "—" },
              { label: "执行状态", value: execution?.label || "—" },
              { label: "策略", value: event.policy_id || "—" },
              { label: "风险", value: risk?.label || "—" },
              { label: "会话", value: event.session_id || "—" },
              { label: "进程", value: `${event.process_name || "—"} (pid ${event.pid ?? "—"})` },
            ]}
          />

          <h3>证据</h3>
          {event.evidence?.length ? (
            <ul className="evidence-list">
              {event.evidence.map((item) => (
                <li key={item} className="mono">
                  {item}
                </li>
              ))}
            </ul>
          ) : (
            <p className="note-text">没有附带证据标签。</p>
          )}
        </div>
        <footer className="drawer-foot">
          <span className="muted">事件时间 {clock(event.observed_at)}</span>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            关闭
          </button>
        </footer>
      </aside>
    </div>
  );
}