import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { MessagePlugin } from "tdesign-react";
import {
  ChevronLeftIcon,
  ChevronRightIcon,
  RefreshIcon,
  SearchIcon,
} from "tdesign-icons-react";
import { useAgents, useScan, useScanning } from "../api/queries";
import type { AgentRow } from "../api/types";
import { EmptyState, ErrorState, LoadingBlock, PageHeader, Tag } from "../components/ui";
import {
  AGENT_STATUS,
  ENTITY_KIND,
  PROTECTION,
  number,
  relative,
} from "../lib/format";

const PAGE_SIZE = 15;

export function AssetsPage() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [page, setPage] = useState(1);
  const [q, setQ] = useState(params.get("q") || "");
  const [status, setStatus] = useState(params.get("agent_status") || "");
  const [protection, setProtection] = useState(params.get("protection") || "");
  const [alias, setAlias] = useState(params.get("alias_status") || "");

  const query = useMemo(
    () => ({
      q: params.get("q") || undefined,
      agent_status: params.get("agent_status") || undefined,
      protection: params.get("protection") || undefined,
      alias_status: params.get("alias_status") || undefined,
      limit: 500,
      offset: 0,
    }),
    [params],
  );
  const agents = useAgents(query);
  const scan = useScan();
  const scanRunning = useScanning();
  const scanning = scan.isPending || scanRunning;

  useEffect(() => {
    setPage(1);
  }, [params]);

  const runScan = async () => {
    try {
      const result = await scan.mutateAsync();
      MessagePlugin.success(`扫描完成：${result.entities} 个资产`);
    } catch (error) {
      MessagePlugin.error((error as Error).message);
    }
  };

  const apply = (event: React.FormEvent) => {
    event.preventDefault();
    const next = new URLSearchParams();
    if (q.trim()) next.set("q", q.trim());
    if (status) next.set("agent_status", status);
    if (protection) next.set("protection", protection);
    if (alias) next.set("alias_status", alias);
    setPage(1);
    setParams(next);
  };

  const reset = () => {
    setQ("");
    setStatus("");
    setProtection("");
    setAlias("");
    setPage(1);
    setParams({});
  };

  const items = agents.data?.items || [];
  const total = agents.data?.total ?? items.length;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const pageItems = items.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  return (
    <div className="page">
      <PageHeader
        eyebrow="监测 / 资产"
        title="资产"
        actions={
          <button
            type="button"
            className="btn btn-primary"
            onClick={runScan}
            disabled={scanning}
          >
            <RefreshIcon size="16px" />
            {scanning ? "扫描中…" : "立即扫描"}
          </button>
        }
      />

      <form className="filter-bar" onSubmit={apply}>
        <label className="field search-field">
          <SearchIcon size="15px" />
          <input
            value={q}
            onChange={(event) => setQ(event.target.value)}
            placeholder="名称 / 类型 / 厂商"
          />
        </label>
        <label className="field">
          <span>状态</span>
          <select value={status} onChange={(event) => setStatus(event.target.value)}>
            <option value="">全部</option>
            <option value="RUNNING">运行中</option>
            <option value="CONFIGURED">已配置</option>
            <option value="INSTALLED">已安装</option>
            <option value="UNKNOWN">未知</option>
          </select>
        </label>
        <label className="field">
          <span>保护</span>
          <select value={protection} onChange={(event) => setProtection(event.target.value)}>
            <option value="">全部</option>
            <option value="PROTECTED">已验证阻断</option>
            <option value="MONITOR_ONLY">仅监测</option>
            <option value="UNPROTECTED">未保护</option>
            <option value="UNKNOWN">未知</option>
          </select>
        </label>
        <label className="field">
          <span>身份</span>
          <select value={alias} onChange={(event) => setAlias(event.target.value)}>
            <option value="">全部</option>
            <option value="OK">已确认</option>
            <option value="AMBIGUOUS">待复核</option>
            <option value="CONFLICT">身份冲突</option>
            <option value="MISSING">未映射</option>
          </select>
        </label>
        <button type="submit" className="btn btn-primary">
          筛选
        </button>
        <button type="button" className="btn btn-ghost" onClick={reset}>
          重置
        </button>
        <span className="filter-summary">共 {number(total)} 个实体</span>
      </form>

      {agents.isLoading ? (
        <LoadingBlock label="读取资产清单…" />
      ) : agents.isError ? (
        <ErrorState message={(agents.error as Error).message} onRetry={() => agents.refetch()} />
      ) : total === 0 ? (
        <EmptyState title="没有匹配的资产" />
      ) : (
        <section className="card card-flush">
          <table className="data-table">
            <thead>
              <tr>
                <th>Agent / 应用</th>
                <th>状态</th>
                <th>保护</th>
                <th>版本</th>
                <th className="num">实例 / 会话</th>
                <th>最近确认</th>
                <th>关注项</th>
              </tr>
            </thead>
            <tbody>
              {pageItems.map((agent) => (
                <AssetRow
                  key={agent.entity_id}
                  agent={agent}
                  onClick={() => navigate(`/assets/${encodeURIComponent(agent.entity_id)}`)}
                />
              ))}
            </tbody>
          </table>
          <div className="pagination">
            <span className="muted">
              第 {page} / {pages} 页
            </span>
            <div className="pagination-buttons">
              <button
                type="button"
                className="icon-button"
                disabled={page <= 1}
                onClick={() => setPage((value) => Math.max(1, value - 1))}
              >
                <ChevronLeftIcon size="16px" />
              </button>
              <button
                type="button"
                className="icon-button"
                disabled={page >= pages}
                onClick={() => setPage((value) => Math.min(pages, value + 1))}
              >
                <ChevronRightIcon size="16px" />
              </button>
            </div>
          </div>
        </section>
      )}
    </div>
  );
}

function AssetRow({ agent, onClick }: { agent: AgentRow; onClick: () => void }) {
  const status = agent.agent_status ? AGENT_STATUS[agent.agent_status] : null;
  const protection = PROTECTION[agent.protection.summary];
  const attention: string[] = [];
  if (agent.entity_alias_status !== "OK") attention.push("身份待复核");
  if ((agent.status_basis.conflicts || []).length) attention.push("证据冲突");
  if (agent.component_count) attention.push(`组件 ${agent.component_count}`);

  return (
    <tr className="clickable" onClick={onClick}>
      <td>
        <div className="primary-cell">{agent.name}</div>
        <div className="secondary-line">
          {agent.agent_type}
          {agent.entity_kind ? ` · ${ENTITY_KIND[agent.entity_kind] || agent.entity_kind}` : ""}
          {agent.origin === "docker" ? " · 容器" : ""}
        </div>
      </td>
      <td>
        {status ? (
          <Tag tone={status.tone}>{status.label}</Tag>
        ) : (
          <Tag tone="neutral">状态待确认</Tag>
        )}
      </td>
      <td>
        <Tag tone={protection.tone} title={agent.protection.basis.reason}>
          {protection.label}
        </Tag>
      </td>
      <td className="mono">{agent.version || "UNKNOWN"}</td>
      <td className="num">
        {number(agent.instance_count)} / {number(agent.session_count)}
      </td>
      <td className="muted">{relative(agent.last_seen_at)}</td>
      <td>
        <div className="attention-tags">
          {attention.length ? (
            attention.slice(0, 3).map((item) => (
              <span className="mini-flag" key={item}>
                {item}
              </span>
            ))
          ) : (
            <span className="muted">—</span>
          )}
        </div>
      </td>
    </tr>
  );
}