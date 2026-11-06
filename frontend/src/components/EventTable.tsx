import type { EventView } from "../api/types";
import { DECISION, EXECUTION, RISK, SOURCE_LABEL, clock, text } from "../lib/format";
import { Tag } from "./ui";

export function EventTable({
  events,
  onSelect,
  compact = false,
}: {
  events: EventView[];
  onSelect?: (event: EventView) => void;
  compact?: boolean;
}) {
  return (
    <table className={`data-table ${compact ? "compact" : ""}`}>
      <thead>
        <tr>
          <th>时间</th>
          <th>Agent / 归属</th>
          <th>动作</th>
          <th>目标</th>
          {compact ? null : <th>来源</th>}
          <th>风险</th>
          <th>决策</th>
          <th>执行</th>
        </tr>
      </thead>
      <tbody>
        {events.map((event) => {
          const decision = event.decision ? DECISION[event.decision] : null;
          const execution = event.execution_status ? EXECUTION[event.execution_status] : null;
          const risk = event.risk_level ? RISK[event.risk_level] : null;
          const actor = event.actor?.label || event.agent_label || "未归属";
          const unattributed =
            (event.actor?.attribution_state || event.attribution_state) === "unattributed";
          return (
            <tr
              key={event.id}
              className={onSelect ? "clickable" : ""}
              onClick={() => onSelect?.(event)}
            >
              <td className="muted mono">{clock(event.observed_at)}</td>
              <td>
                <div className="agent-cell">
                  <span className={`agent-dot ${unattributed ? "agent-dot-muted" : ""}`} />
                  <span>{actor}</span>
                  {unattributed ? <span className="mini-flag">归属待确认</span> : null}
                </div>
                {event.actor?.alias_status === "AMBIGUOUS" ? (
                  <div className="secondary-line">身份待复核</div>
                ) : null}
              </td>
              <td>
                <div className="primary-cell">{event.operation || event.event_type || "—"}</div>
                {event.tool ? <div className="secondary-line mono">{event.tool}</div> : null}
              </td>
              <td className="mono truncate" title={text(event.target || event.target_ref?.label, "")}>
                {text(event.target || event.target_ref?.label, "—")}
              </td>
              {compact ? null : (
                <td className="muted">{SOURCE_LABEL[event.source] || event.source}</td>
              )}
              <td>{risk ? <Tag tone={risk.tone}>{risk.label}</Tag> : <span className="muted">—</span>}</td>
              <td>{decision ? <Tag tone={decision.tone}>{decision.label}</Tag> : <span className="muted">—</span>}</td>
              <td>
                {execution ? (
                  <Tag tone={execution.tone}>{execution.label}</Tag>
                ) : (
                  <span className="muted">—</span>
                )}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}