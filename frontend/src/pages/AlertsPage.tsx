import { useState } from "react";
import { MessagePlugin } from "tdesign-react";
import { CloseIcon, NotificationIcon } from "tdesign-icons-react";
import { useAlerts, useEvent, useUpdateAlert } from "../api/queries";
import type { AlertView } from "../api/types";
import {
  EmptyState,
  ErrorState,
  KeyValue,
  LoadingBlock,
  PageHeader,
  Tag,
} from "../components/ui";
import {
  ALERT_STATUS,
  DECISION,
  EXECUTION,
  RISK,
  clock,
  number,
  time,
} from "../lib/format";

export function AlertsPage() {
  const [status, setStatus] = useState("open");
  const [risk, setRisk] = useState("");
  const [selected, setSelected] = useState<AlertView | null>(null);
  const alerts = useAlerts({ status: status || undefined, risk_level: risk || undefined });
  const update = useUpdateAlert();
  const items = alerts.data?.items || [];
  const stats = (alerts.data?.stats || {}) as {
    alert_count?: number;
    open_high?: number;
    by_status?: Record<string, number>;
  };

  const changeStatus = async (alert: AlertView, next: string) => {
    try {
      await update.mutateAsync({ id: alert.id, status: next });
      MessagePlugin.success(next === "resolved" ? "告警已解决" : "告警已确认");
      setSelected(null);
    } catch (error) {
      MessagePlugin.error((error as Error).message);
    }
  };

  return (
    <div className="page">
      <PageHeader
        eyebrow="治理 / 告警"
        title="风险告警"
      />

      <div className="grid grid-3">
        <div className="mini-stat">
          <span>未处理高风险</span>
          <strong className="text-danger">{number(stats.open_high || 0)}</strong>
        </div>
        <div className="mini-stat">
          <span>告警总数</span>
          <strong>{number(stats.alert_count || 0)}</strong>
        </div>
        <div className="mini-stat">
          <span>已解决</span>
          <strong>{number(stats.by_status?.resolved || 0)}</strong>
        </div>
      </div>

      <div className="filter-bar">
        <label className="field">
          <span>状态</span>
          <select value={status} onChange={(event) => setStatus(event.target.value)}>
            <option value="open">未处理</option>
            <option value="acknowledged">已确认</option>
            <option value="resolved">已解决</option>
            <option value="">全部</option>
          </select>
        </label>
        <label className="field">
          <span>风险</span>
          <select value={risk} onChange={(event) => setRisk(event.target.value)}>
            <option value="">全部</option>
            <option value="critical">严重</option>
            <option value="high">高</option>
            <option value="medium">中</option>
            <option value="low">低</option>
          </select>
        </label>
        <span className="filter-summary">共 {items.length} 条</span>
      </div>

      {alerts.isLoading ? (
        <LoadingBlock label="读取告警…" />
      ) : alerts.isError ? (
        <ErrorState message={(alerts.error as Error).message} onRetry={() => alerts.refetch()} />
      ) : items.length ? (
        <section className="card card-flush">
          <table className="data-table">
            <thead>
              <tr>
                <th>时间</th>
                <th>告警</th>
                <th>Agent</th>
                <th>风险</th>
                <th>决策</th>
                <th>状态</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {items.map((alert) => {
                const riskSpec = RISK[alert.risk_level] || RISK.medium;
                const statusSpec = ALERT_STATUS[alert.status] || ALERT_STATUS.open;
                return (
                  <tr key={alert.id} className="clickable" onClick={() => setSelected(alert)}>
                    <td className="muted mono">{clock(alert.created_at)}</td>
                    <td>
                      <div className="primary-cell">{alert.title}</div>
                      <div className="secondary-line">{alert.reason || "—"}</div>
                    </td>
                    <td>{alert.agent_label || "未归属"}</td>
                    <td>
                      <Tag tone={riskSpec.tone}>{riskSpec.label}</Tag>
                    </td>
                    <td>
                      <Tag tone={(DECISION[alert.decision] || DECISION.audit).tone}>
                        {(DECISION[alert.decision] || DECISION.audit).label}
                      </Tag>
                    </td>
                    <td>
                      <Tag tone={statusSpec.tone}>{statusSpec.label}</Tag>
                    </td>
                    <td>
                      {alert.status === "open" ? (
                        <button
                          type="button"
                          className="link-button"
                          onClick={(event) => {
                            event.stopPropagation();
                            changeStatus(alert, "acknowledged");
                          }}
                        >
                          确认
                        </button>
                      ) : null}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>
      ) : (
        <EmptyState icon={<NotificationIcon size="28px" />} title="暂无告警" />
      )}

      {selected ? (
        <AlertDrawer
          alert={selected}
          onClose={() => setSelected(null)}
          onAcknowledge={() => changeStatus(selected, "acknowledged")}
          onResolve={() => changeStatus(selected, "resolved")}
          busy={update.isPending}
        />
      ) : null}
    </div>
  );
}

function AlertDrawer({
  alert,
  onClose,
  onAcknowledge,
  onResolve,
  busy,
}: {
  alert: AlertView;
  onClose: () => void;
  onAcknowledge: () => void;
  onResolve: () => void;
  busy: boolean;
}) {
  const linked = useEvent(alert.event_id);
  const risk = RISK[alert.risk_level] || RISK.medium;
  const status = ALERT_STATUS[alert.status] || ALERT_STATUS.open;
  const decision = DECISION[alert.decision] || DECISION.audit;
  const execution = linked.data?.execution_status
    ? EXECUTION[linked.data.execution_status]
    : null;
  return (
    <div className="drawer-layer" role="dialog" aria-modal="true">
      <button type="button" className="drawer-backdrop" aria-label="关闭" onClick={onClose} />
      <aside className="drawer">
        <header className="drawer-head">
          <div>
            <div className="eyebrow">告警 #{alert.id}</div>
            <h2>{alert.title}</h2>
            <div className="secondary-line">{time(alert.created_at)}</div>
          </div>
          <button type="button" className="icon-button" onClick={onClose} aria-label="关闭">
            <CloseIcon size="18px" />
          </button>
        </header>
        <div className="drawer-body">
          <div className="drawer-tags">
            <Tag tone={risk.tone}>{risk.label}</Tag>
            <Tag tone={decision.tone}>{decision.label}</Tag>
            <Tag tone={status.tone}>{status.label}</Tag>
          </div>
          <KeyValue
            columns={1}
            items={[
              { label: "Agent", value: alert.agent_label || "未归属" },
              { label: "策略", value: alert.policy_id || "—" },
              { label: "原因", value: alert.reason || "—" },
              { label: "关联事件", value: alert.event_id ? `#${alert.event_id}` : "—" },
            ]}
          />

          <h3>关联事件</h3>
          {linked.isLoading ? (
            <p className="note-text">读取中…</p>
          ) : linked.data ? (
            <div className="linked-event">
              <div className="linked-event-head">
                <strong>{linked.data.operation || linked.data.event_type || "事件"}</strong>
                <span className="mono">{time(linked.data.observed_at)}</span>
              </div>
              <div className="drawer-tags">
                {linked.data.decision ? (
                  <Tag tone={(DECISION[linked.data.decision] || DECISION.audit).tone}>
                    {(DECISION[linked.data.decision] || DECISION.audit).label}
                  </Tag>
                ) : null}
                {execution ? <Tag tone={execution.tone}>{execution.label}</Tag> : null}
              </div>
              <p className="note-text mono">
                Actor: {linked.data.actor?.label || "未归属"} · Target:{" "}
                {linked.data.target_ref?.label || linked.data.target || "未归属目标"}
              </p>
            </div>
          ) : (
            <p className="note-text">没有关联事件。</p>
          )}

          <details className="raw-details">
            <summary>告警元数据</summary>
            <pre>{JSON.stringify(alert.detail, null, 2)}</pre>
          </details>
        </div>
        <footer className="drawer-foot">
          <div className="drawer-actions">
            {alert.status === "open" ? (
              <button type="button" className="btn btn-secondary" onClick={onAcknowledge} disabled={busy}>
                确认
              </button>
            ) : null}
            {alert.status !== "resolved" ? (
              <button type="button" className="btn btn-primary" onClick={onResolve} disabled={busy}>
                解决
              </button>
            ) : null}
          </div>
        </footer>
      </aside>
    </div>
  );
}