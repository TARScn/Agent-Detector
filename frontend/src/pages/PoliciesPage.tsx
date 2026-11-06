import { useState } from "react";
import { MessagePlugin } from "tdesign-react";
import { CloseIcon, LockOnIcon, RefreshIcon } from "tdesign-icons-react";
import { usePolicies, useReloadPolicies, useUpdatePolicy } from "../api/queries";
import type { PolicyView } from "../api/types";
import {
  EmptyState,
  ErrorState,
  KeyValue,
  LoadingBlock,
  PageHeader,
  Tag,
} from "../components/ui";
import { DECISION, RISK, number, time } from "../lib/format";

export function PoliciesPage() {
  const policies = usePolicies();
  const update = useUpdatePolicy();
  const reload = useReloadPolicies();
  const [selected, setSelected] = useState<PolicyView | null>(null);
  const [decision, setDecision] = useState("");

  const open = (policy: PolicyView) => {
    setSelected(policy);
    setDecision(policy.decision);
  };

  const save = async (enabled: boolean, nextDecision: string) => {
    if (!selected) return;
    try {
      await update.mutateAsync({
        id: selected.policy_id,
        patch: { enabled, decision: nextDecision },
      });
      MessagePlugin.success("策略已更新");
      setSelected(null);
    } catch (error) {
      MessagePlugin.error((error as Error).message);
    }
  };

  const reloadRules = async () => {
    try {
      await reload.mutateAsync();
      MessagePlugin.success("策略已重新加载");
    } catch (error) {
      MessagePlugin.error((error as Error).message);
    }
  };

  return (
    <div className="page">
      <PageHeader
        eyebrow="治理 / 安全策略"
        title="安全策略"
        actions={
          <button
            type="button"
            className="btn btn-secondary"
            onClick={reloadRules}
            disabled={reload.isPending}
          >
            <RefreshIcon size="16px" /> 重新加载
          </button>
        }
      />

      <div className="policy-summary">
        <span>
          共 <b>{number(policies.data?.total || 0)}</b> 条规则
        </span>
        <span>
          决策引擎 <b>{policies.data?.decision_engine || "deterministic"}</b>
        </span>
        <span>
          失败模式 <b>{policies.data?.failure_mode || "—"}</b>
        </span>
        {policies.data?.status?.errors &&
        Array.isArray(policies.data.status.errors) &&
        policies.data.status.errors.length ? (
          <Tag tone="danger">规则加载有错误</Tag>
        ) : (
          <Tag tone="success">规则已加载</Tag>
        )}
      </div>

      {policies.isLoading ? (
        <LoadingBlock label="读取策略…" />
      ) : policies.isError ? (
        <ErrorState message={(policies.error as Error).message} onRetry={() => policies.refetch()} />
      ) : policies.data?.items.length ? (
        <section className="card card-flush">
          <table className="data-table">
            <thead>
              <tr>
                <th>策略</th>
                <th>优先级</th>
                <th>决策</th>
                <th>风险</th>
                <th>启用</th>
                <th>更新时间</th>
              </tr>
            </thead>
            <tbody>
              {policies.data.items.map((policy) => {
                const decisionSpec = DECISION[policy.decision] || DECISION.audit;
                const riskSpec = RISK[policy.risk_level] || RISK.medium;
                return (
                  <tr key={policy.policy_id} className="clickable" onClick={() => open(policy)}>
                    <td>
                      <div className="primary-cell">{policy.name}</div>
                      <div className="secondary-line mono">{policy.policy_id}</div>
                    </td>
                    <td className="num">{policy.priority}</td>
                    <td>
                      <Tag tone={decisionSpec.tone}>{decisionSpec.label}</Tag>
                    </td>
                    <td>
                      <Tag tone={riskSpec.tone}>{riskSpec.label}</Tag>
                    </td>
                    <td>
                      <Tag tone={policy.enabled ? "success" : "neutral"}>
                        {policy.enabled ? "启用" : "停用"}
                      </Tag>
                    </td>
                    <td className="muted">{time(policy.updated_at)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>
      ) : (
        <EmptyState icon={<LockOnIcon size="28px" />} title="暂无策略" />
      )}

      {selected ? (
        <div className="drawer-layer" role="dialog" aria-modal="true">
          <button type="button" className="drawer-backdrop" aria-label="关闭" onClick={() => setSelected(null)} />
          <aside className="drawer">
            <header className="drawer-head">
              <div>
                <div className="eyebrow">策略</div>
                <h2>{selected.name}</h2>
                <div className="secondary-line mono">{selected.policy_id}</div>
              </div>
              <button type="button" className="icon-button" onClick={() => setSelected(null)} aria-label="关闭">
                <CloseIcon size="18px" />
              </button>
            </header>
            <div className="drawer-body">
              <KeyValue
                columns={1}
                items={[
                  { label: "作用域", value: selected.scope },
                  { label: "风险", value: (RISK[selected.risk_level] || RISK.medium).label },
                  { label: "优先级", value: selected.priority },
                  { label: "说明", value: selected.reason || "—" },
                  { label: "更新时间", value: time(selected.updated_at) },
                ]}
              />
              <h3>决策</h3>
              <select
                className="text-select"
                value={decision}
                onChange={(event) => setDecision(event.target.value)}
              >
                <option value="allow">放行</option>
                <option value="ask">需确认</option>
                <option value="deny">阻断</option>
                <option value="audit">仅审计</option>
              </select>
              <h3>匹配条件</h3>
              <pre className="code-block">{JSON.stringify(selected.conditions, null, 2)}</pre>
            </div>
            <footer className="drawer-foot">
              <div className="drawer-actions">
                <button
                  type="button"
                  className="btn btn-secondary"
                  disabled={update.isPending}
                  onClick={() => save(!selected.enabled, decision)}
                >
                  {selected.enabled ? "停用" : "启用"}
                </button>
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={update.isPending}
                  onClick={() => save(selected.enabled, decision)}
                >
                  保存决策
                </button>
              </div>
            </footer>
          </aside>
        </div>
      ) : null}
    </div>
  );
}