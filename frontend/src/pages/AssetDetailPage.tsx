import { useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import {
  ArrowLeftIcon,
  ArrowRightIcon,
  ChevronDownIcon,
  RefreshIcon,
} from "tdesign-icons-react";
import {
  useAgent,
  useAgentClaims,
  useAgentCoverage,
  useAgentMcp,
  useAgentRelations,
} from "../api/queries";
import type { ClaimView, CoverageView } from "../api/types";
import { EventTable } from "../components/EventTable";
import {
  EmptyState,
  ErrorState,
  KeyValue,
  LoadingBlock,
  PageHeader,
  SectionCard,
  Tag,
} from "../components/ui";
import {
  AGENT_STATUS,
  COVERAGE_SCOPE_LABEL,
  ENTITY_KIND,
  HOOK_STATE,
  INSTANCE_STATUS,
  LIFECYCLE,
  PRESENCE,
  PREDICATE_LABEL,
  PROTECTION,
  VERIFICATION,
  number,
  relative,
  shortId,
  text,
  time,
  unverifiedSuffix,
} from "../lib/format";

const TABS = [
  { id: "overview", label: "概览" },
  { id: "behavior", label: "行为" },
  { id: "relations", label: "关系" },
  { id: "evidence", label: "证据" },
] as const;

export function AssetDetailPage() {
  const { entityId = "" } = useParams();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") || "overview") as (typeof TABS)[number]["id"];
  const agent = useAgent(entityId);
  const claims = useAgentClaims(entityId, tab === "evidence");
  const coverage = useAgentCoverage(entityId, tab === "evidence");
  const relations = useAgentRelations(entityId, tab === "relations");
  const mcp = useAgentMcp(entityId, tab === "relations");
  const [claimOpen, setClaimOpen] = useState<string | null>(null);

  if (agent.isLoading) return <LoadingBlock label="读取资产详情…" />;
  if (agent.isError) {
    return (
      <ErrorState
        message={(agent.error as Error).message}
        onRetry={() => agent.refetch()}
      />
    );
  }
  const data = agent.data!;
  const status = data.agent_status ? AGENT_STATUS[data.agent_status] : null;
  const protection = PROTECTION[data.protection.summary];
  const hook = HOOK_STATE[data.protection.hook_state];
  const verification = VERIFICATION[data.verification] || VERIFICATION.STALE;
  const presence = PRESENCE[data.presence] || PRESENCE.UNKNOWN;
  const lifecycle = LIFECYCLE[data.lifecycle] || LIFECYCLE.ACTIVE;
  const suffix = unverifiedSuffix(data.verification);
  const relationComponents = relations.data?.groups.components || [];
  const componentKeys = new Set(
    relationComponents.map((item) => item.component_key),
  );
  const otherRelations = (relations.data?.items || []).filter(
    (item) =>
      !(componentKeys.has(item.to_ref) &&
        ["DEPENDS_ON", "DECLARES"].includes(item.relation_type)),
  );

  const setTab = (id: string) => {
    const next = new URLSearchParams(params);
    next.set("tab", id);
    setParams(next, { replace: true });
  };

  return (
    <div className="page">
      <button type="button" className="back-link" onClick={() => navigate("/assets")}>
        <ArrowLeftIcon size="14px" /> 返回资产
      </button>
      <PageHeader
        eyebrow={text(data.agent_type)}
        title={data.name}
        actions={
          <>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => agent.refetch()}
            >
              <RefreshIcon size="16px" /> 刷新
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => navigate(`/events?entity_id=${encodeURIComponent(data.entity_id)}`)}
            >
              查看事件 <ArrowRightIcon size="14px" />
            </button>
          </>
        }
      />
      <div className="detail-tags">
        {status ? (
          <Tag tone={status.tone} title={verification.label}>
            {status.label}
            {suffix}
          </Tag>
        ) : (
          <Tag tone="neutral">状态待确认</Tag>
        )}
        <Tag tone={protection.tone} title={data.protection.basis.reason}>
          {protection.label}
        </Tag>
        <Tag tone={hook.tone}>{hook.label}</Tag>
        <Tag tone={presence.tone}>{presence.label}</Tag>
        {data.lifecycle !== "ACTIVE" ? (
          <Tag tone={lifecycle.tone}>{lifecycle.label}</Tag>
        ) : null}
        {data.entity_alias_status !== "OK" ? (
          <Tag tone="warning">身份待复核</Tag>
        ) : null}
      </div>

      <div className="detail-summary">
        <SummaryStat label="运行实例" value={number(data.instance_count)} />
        <SummaryStat label="会话" value={number(data.session_count)} />
        <SummaryStat label="Claim" value={number(data.claims_summary.claim_count)} />
        <SummaryStat
          label="覆盖范围"
          value={data.coverage.available ? number(data.coverage.summary.scopes) : "—"}
        />
      </div>

      <div className="tabs" role="tablist">
        {TABS.map((item) => (
          <button
            type="button"
            role="tab"
            aria-selected={tab === item.id}
            className={`tab ${tab === item.id ? "active" : ""}`}
            key={item.id}
            onClick={() => setTab(item.id)}
          >
            {item.label}
          </button>
        ))}
      </div>

      {tab === "overview" ? (
        <div className="stack">
          <div className="grid grid-3">
            <SectionCard title="身份与状态">
              <KeyValue
                items={[
                  { label: "Agent 状态", value: `${status ? status.label : "状态待确认"}${suffix}` },
                  { label: "存在性", value: presence.label },
                  { label: "本轮复核", value: verification.label },
                  { label: "判定依据", value: data.reason || data.reason_code || "—" },
                  { label: "资产类别", value: ENTITY_KIND[data.entity_kind || "UNKNOWN"] || "未知" },
                  { label: "Entity ID", value: <span className="mono">{shortId(data.entity_id, 18)}</span> },
                  { label: "身份别名", value: data.entity_alias_status },
                  { label: "上次快照", value: relative(data.snapshot_projected_at) },
                ]}
              />
              {(data.status_basis.conflicts || []).length ? (
                <div className="inline-warning">
                  证据冲突：{(data.status_basis.conflicts || []).join("、")}
                </div>
              ) : null}
            </SectionCard>
            <SectionCard title="保护">
              <KeyValue
                items={[
                  { label: "保护摘要", value: protection.label },
                  { label: "Hook 状态", value: hook.label },
                  { label: "遥测范围", value: data.protection.basis.telemetry_scope },
                  { label: "强制验证", value: data.protection.basis.enforcement_verified ? "是" : "否" },
                ]}
              />
              <p className="note-text">{data.protection.basis.reason}</p>
            </SectionCard>
            <SectionCard title="版本与来源">
              <KeyValue
                items={[
                  { label: "版本", value: data.version || "UNKNOWN" },
                  { label: "版本来源", value: data.version_source || "unknown" },
                  { label: "宿主", value: data.origin === "docker" ? "Docker" : "本机" },
                  { label: "首次发现", value: time(data.first_seen_at) },
                  { label: "最近确认", value: time(data.last_seen_at) },
                ]}
              />
            </SectionCard>
          </div>

          <SectionCard title="运行实例" flush>
            {data.instances.length ? (
              <table className="data-table compact">
                <thead>
                  <tr>
                    <th>PID</th>
                    <th>进程</th>
                    <th>来源</th>
                    <th>启动时间</th>
                    <th>状态</th>
                  </tr>
                </thead>
                <tbody>
                  {data.instances.map((instance) => (
                    <tr key={instance.instance_id}>
                      <td className="mono">{instance.pid}</td>
                      <td>
                        <div className="primary-cell">{instance.process_name || "—"}</div>
                        <div className="secondary-line mono">{shortId(instance.instance_id, 18)}</div>
                      </td>
                      <td className="muted">{instance.origin}</td>
                      <td className="muted">{time(instance.started_at)}</td>
                      <td>
                        <Tag tone={INSTANCE_STATUS[instance.status]?.tone || "neutral"}>
                          {INSTANCE_STATUS[instance.status]?.label || instance.status}
                        </Tag>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <EmptyState title="没有运行实例" />
            )}
          </SectionCard>

          {data.components?.length ? (
            <SectionCard title="组件依赖">
              <div className="chips">
                {data.components.map((component) => (
                  <span className="chip" key={component.component_key}>
                    {component.name} <span className="mono">{component.version}</span>
                  </span>
                ))}
              </div>
            </SectionCard>
          ) : null}
        </div>
      ) : null}

      {tab === "behavior" ? (
        <SectionCard
          title="最近行为"
          extra={
            <button
              type="button"
              className="link-button"
              onClick={() => navigate(`/events?entity_id=${encodeURIComponent(data.entity_id)}`)}
            >
              查看全部 <ArrowRightIcon size="14px" />
            </button>
          }
          flush
        >
          {data.events.length ? (
            <EventTable events={data.events} />
          ) : (
            <EmptyState title="暂无行为事件" />
          )}
        </SectionCard>
      ) : null}

      {tab === "relations" ? (
        relations.isLoading ? (
          <LoadingBlock label="读取关系…" />
        ) : relations.isError ? (
          <ErrorState message={(relations.error as Error).message} />
        ) : (
          <div className="stack">
            <SectionCard title="组件依赖" flush>
              {relations.data?.groups.components.length ? (
                <table className="data-table compact">
                  <thead>
                    <tr>
                      <th>组件</th>
                      <th>类型</th>
                      <th>版本</th>
                      <th>关系</th>
                      <th>状态</th>
                    </tr>
                  </thead>
                  <tbody>
                    {relations.data.groups.components.map((component) => (
                      <tr key={`${component.component_key}-${component.relation_type}`}>
                        <td className="primary-cell">{component.name}</td>
                        <td className="muted">{component.kind}</td>
                        <td className="mono">{component.version}</td>
                        <td className="muted">{component.relation_type}</td>
                        <td>
                          <Tag tone={component.status === "confirmed" ? "success" : "warning"}>
                            {component.status === "confirmed" ? "已确认" : "待关联"}
                          </Tag>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <EmptyState title="暂无组件关系" />
              )}
            </SectionCard>
            <SectionCard title="端点" flush>
              {relations.data?.groups.endpoints.length ? (
                <table className="data-table compact">
                  <thead>
                    <tr>
                      <th>协议</th>
                      <th>地址</th>
                      <th>状态</th>
                    </tr>
                  </thead>
                  <tbody>
                    {relations.data.groups.endpoints.map((endpoint) => (
                      <tr key={endpoint.endpoint_id}>
                        <td className="mono">{endpoint.protocol}</td>
                        <td className="mono">{endpoint.address}</td>
                        <td>
                          <Tag tone={endpoint.binding_status === "confirmed" ? "success" : "warning"}>
                            {endpoint.binding_status === "confirmed" ? "已确认" : "待关联"}
                          </Tag>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <EmptyState title="暂无可归属端点" />
              )}
            </SectionCard>
            <SectionCard title="MCP 服务" flush>
              {mcp.data?.items.length ? (
                <table className="data-table compact">
                  <thead>
                    <tr>
                      <th>名称</th>
                      <th>传输</th>
                      <th>来源</th>
                    </tr>
                  </thead>
                  <tbody>
                    {mcp.data.items.map((server) => (
                      <tr key={`${server.name}-${server.source}`}>
                        <td className="primary-cell">{server.name}</td>
                        <td className="muted">{server.transport}</td>
                        <td className="muted mono truncate" title={server.source}>
                          {server.source}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <EmptyState title="暂无 MCP 服务" />
              )}
            </SectionCard>

            {otherRelations.length ? (
              <SectionCard title="其他关系" flush>
                <table className="data-table compact">
                  <thead>
                    <tr>
                      <th>关系</th>
                      <th>对象</th>
                      <th>状态</th>
                    </tr>
                  </thead>
                  <tbody>
                    {otherRelations.map((item) => (
                      <tr key={`${item.relation_type}-${item.from_ref}-${item.to_ref}`}>
                        <td>{item.relation_type}</td>
                        <td className="mono">{item.label}</td>
                        <td>
                          <Tag tone={item.status === "confirmed" ? "success" : "warning"}>
                            {item.status === "confirmed" ? "已确认" : "待关联"}
                          </Tag>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </SectionCard>
            ) : null}
          </div>
        )
      ) : null}

      {tab === "evidence" ? (
        claims.isLoading || coverage.isLoading ? (
          <LoadingBlock label="读取证据…" />
        ) : (
          <div className="stack">
            <SectionCard
              title="状态依据"
              extra={
                <Tag tone={claims.data?.completeness === "support_only" ? "info" : "success"}>
                  {claims.data?.completeness === "support_only" ? "仅支持性 Claim" : "支持 / 反驳"}
                </Tag>
              }
            >
              {claims.data?.conflicts.length ? (
                <div className="inline-warning">
                  冲突 predicate：{claims.data.conflicts.join("、")}
                </div>
              ) : null}
              {claims.data?.items.length ? (
                <div className="claim-list">
                  {claims.data.items.map((claim) => (
                    <ClaimCard
                      key={claim.claim_id}
                      claim={claim}
                      open={claimOpen === claim.claim_id}
                      onToggle={() =>
                        setClaimOpen(claimOpen === claim.claim_id ? null : claim.claim_id)
                      }
                    />
                  ))}
                </div>
              ) : (
                <EmptyState title="暂无 Claim" />
              )}
            </SectionCard>

            <CoverageCard coverage={coverage.data} />
          </div>
        )
      ) : null}
    </div>
  );
}

function SummaryStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="summary-stat">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function ClaimCard({
  claim,
  open,
  onToggle,
}: {
  claim: ClaimView;
  open: boolean;
  onToggle: () => void;
}) {
  return (
    <div className={`claim-card ${open ? "open" : ""}`}>
      <button type="button" className="claim-head" onClick={onToggle}>
        <span className="claim-predicate">
          {PREDICATE_LABEL[claim.predicate] || claim.predicate}
        </span>
        <span className="claim-object mono">{claim.object_ref || "—"}</span>
        <Tag tone={claim.polarity === "support" ? "success" : "danger"}>
          {claim.polarity === "support" ? "支持" : "反驳"}
        </Tag>
        <Tag tone="info">{claim.evidence_class}</Tag>
        <span className="claim-method">{claim.verification_method}</span>
        <span className="claim-time">{relative(claim.observed_at)}</span>
        <ChevronDownIcon size="14px" className={open ? "rotate" : ""} />
      </button>
      {open ? (
        <div className="claim-body">
          <KeyValue
            items={[
              { label: "规则", value: claim.rule.id || "—" },
              { label: "规则摘要", value: shortId(claim.rule.digest, 20) },
              { label: "有效期", value: `${time(claim.valid_from)} → ${claim.valid_to ? time(claim.valid_to) : "当前"}` },
              { label: "Coverage Scope", value: claim.coverage_scope_id ? String(claim.coverage_scope_id) : "—" },
            ]}
          />
          {claim.observations?.length ? (
            <div className="observation-list">
              {claim.observations.map((observation) => (
                <div className="observation-row" key={observation.observation_id}>
                  <span className="mono">{observation.source}</span>
                  <span>{observation.summary}</span>
                  <span className="muted">{time(observation.observed_at)}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="note-text">没有内联 Observation。</p>
          )}
        </div>
      ) : null}
    </div>
  );
}

function CoverageCard({ coverage }: { coverage?: CoverageView }) {
  if (!coverage) return null;
  if (!coverage.available) {
    return (
      <SectionCard title="覆盖范围">
        <EmptyState title="暂无覆盖数据" />
      </SectionCard>
    );
  }
  return (
    <SectionCard title="覆盖范围" subtitle={`扫描 #${coverage.scan_id}`}>
      <div className="coverage-grid">
        {(["COMPLETE", "PARTIAL", "FAILED", "NOT_RUN"] as const).map((key) => (
          <div className={`coverage-tile coverage-${key.toLowerCase()}`} key={key}>
            <span>{key === "NOT_RUN" ? "未运行" : key === "COMPLETE" ? "完整" : key === "PARTIAL" ? "不足" : "失败"}</span>
            <strong>{coverage.summary[key]}</strong>
          </div>
        ))}
      </div>
      {coverage.scopes.length ? (
        <table className="data-table compact">
          <thead>
            <tr>
              <th>范围</th>
              <th>自身状态</th>
              <th>有效状态</th>
              <th>截断</th>
            </tr>
          </thead>
          <tbody>
            {coverage.scopes.map((scope) => (
              <tr key={`${scope.scope_type}-${scope.scope_key}`}>
                <td>
                  <div className="primary-cell">
                    {COVERAGE_SCOPE_LABEL[scope.scope_type] || scope.scope_type}
                  </div>
                  <div className="secondary-line mono">{scope.scope_key}</div>
                </td>
                <td>{scope.own_status}</td>
                <td>{scope.effective_status}</td>
                <td>{scope.truncated ? "是" : "否"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </SectionCard>
  );
}