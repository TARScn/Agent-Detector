import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  ChevronLeftIcon,
  ChevronRightIcon,
  CloseIcon,
  PlayCircleIcon,
  StopCircleIcon,
} from "tdesign-icons-react";
import { useAgents, useEvents } from "../api/queries";
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

const PAGE_SIZE = 30;

export function EventsPage() {
  const [params, setParams] = useSearchParams();
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<EventView | null>(null);
  const [live, setLive] = useState(false);
  const [liveEvents, setLiveEvents] = useState<EventView[]>([]);

  const agents = useAgents({ limit: 500 });

  // 筛选条件全部走后端；分页为位置分页（limit/offset）。
  const filters = useMemo(
    () => ({
      source: params.get("source") || undefined,
      risk_level: params.get("risk") || undefined,
      decision: params.get("decision") || undefined,
      execution_status: params.get("execution") || undefined,
      entity_id: params.get("entity_id") || undefined,
    }),
    [params],
  );
  const query = useMemo(
    () => ({ ...filters, limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE }),
    [filters, page],
  );
  const events = useEvents(query);

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
    setPage(1);
  }, [params]);

  const items = events.data?.items || [];
  // 实时事件只并入第一页，避免污染后续页的位置分页。
  const pageItems = useMemo(() => {
    if (page !== 1 || !liveEvents.length) return items;
    const byId = new Map<number, EventView>();
    [...liveEvents, ...items].forEach((event) => {
      if (!byId.has(event.id)) byId.set(event.id, event);
    });
    return Array.from(byId.values())
      .sort((a, b) => b.id - a.id)
      .slice(0, PAGE_SIZE);
  }, [liveEvents, items, page]);

  const total = events.data?.total_matches ?? items.length;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const current = Math.min(page, pages);
  useEffect(() => {
    if (page > pages) setPage(pages);
  }, [page, pages]);

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

      <div className="filter-bar">
        <label className="field">
          <span>Agent</span>
          <select
            value={filters.entity_id || ""}
            onChange={(event) => setFilter("entity_id", event.target.value)}
          >
            <option value="">全部</option>
            {(agents.data?.items || []).map((agent) => (
              <option key={agent.entity_id} value={agent.entity_id}>
                {agent.name}
              </option>
            ))}
          </select>
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
        <span className="filter-summary">
          {live ? <Tag tone="success">实时已开启</Tag> : null} 共 {total} 条
        </span>
      </div>

      {events.isLoading ? (
        <LoadingBlock label="读取事件…" />
      ) : events.isError ? (
        <ErrorState message={(events.error as Error).message} onRetry={() => events.refetch()} />
      ) : pageItems.length ? (
        <section className="card card-flush">
          <EventTable events={pageItems} onSelect={setSelected} />
          <div className="pagination">
            <span className="muted">
              第 {current} / {pages} 页
            </span>
            <div className="pagination-buttons">
              <button
                type="button"
                className="icon-button"
                disabled={current <= 1 || events.isFetching}
                onClick={() => setPage(Math.max(1, current - 1))}
              >
                <ChevronLeftIcon size="16px" />
              </button>
              <button
                type="button"
                className="icon-button"
                disabled={current >= pages || events.isFetching}
                onClick={() => setPage(Math.min(pages, current + 1))}
              >
                <ChevronRightIcon size="16px" />
              </button>
            </div>
          </div>
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
    entity_id?: string;
  },
): boolean {
  if (filters.risk_level && event.risk_level !== filters.risk_level) return false;
  if (filters.decision && event.decision !== filters.decision) return false;
  if (filters.execution_status && event.execution_status !== filters.execution_status) return false;
  if (filters.entity_id && event.actor?.entity_id !== filters.entity_id) return false;
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
