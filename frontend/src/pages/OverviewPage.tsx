import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { MessagePlugin } from "tdesign-react";
import type { EChartsCoreOption } from "echarts/core";
import {
  ArrowRightIcon,
  LockOnIcon,
  NotificationIcon,
  PlayCircleIcon,
  RefreshIcon,
  ViewModuleIcon,
} from "tdesign-icons-react";
import { useOverview, useScan, useScanning, useTimeseries } from "../api/queries";
import type { EventView } from "../api/types";
import { Chart } from "../components/Chart";
import {
  EmptyState,
  ErrorState,
  KpiCard,
  LoadingBlock,
  PageHeader,
  SectionCard,
  Tag,
} from "../components/ui";
import {
  DECISION,
  EXECUTION,
  ENTITY_KIND,
  PROTECTION,
  RISK,
  clock,
  number,
  percent,
} from "../lib/format";

const KIND_COLORS = ["#0052d9", "#7b61ff", "#00a870", "#ed7b2f", "#e34d59", "#0594fa", "#a1a7b3"];

export function OverviewPage() {
  const navigate = useNavigate();
  const overview = useOverview();
  const timeseries = useTimeseries("24h", "hour");
  const scan = useScan();
  const scanRunning = useScanning();
  const scanning = scan.isPending || scanRunning;

  const trendOption = useMemo<EChartsCoreOption>(() => {
    const points = timeseries.data?.points || [];
    return {
      color: ["#0052d9", "#e34d59"],
      grid: { left: 38, right: 16, top: 20, bottom: 28 },
      tooltip: { trigger: "axis" },
      legend: {
        right: 0,
        top: 0,
        itemWidth: 8,
        itemHeight: 8,
        textStyle: { color: "#6b7785", fontSize: 12 },
      },
      xAxis: {
        type: "category",
        boundaryGap: false,
        data: points.map((point) => clock(point.start)),
        axisLine: { lineStyle: { color: "#e6e8eb" } },
        axisTick: { show: false },
        axisLabel: { color: "#86909c", fontSize: 11, interval: 3 },
      },
      yAxis: {
        type: "value",
        splitLine: { lineStyle: { color: "#f0f1f3" } },
        axisLabel: { color: "#86909c", fontSize: 11 },
      },
      series: [
        {
          name: "事件",
          type: "line",
          smooth: true,
          symbol: "none",
          areaStyle: {
            color: {
              type: "linear",
              x: 0,
              y: 0,
              x2: 0,
              y2: 1,
              colorStops: [
                { offset: 0, color: "rgba(0,82,217,.16)" },
                { offset: 1, color: "rgba(0,82,217,.02)" },
              ],
            },
          },
          data: points.map((point) => point.events),
        },
        {
          name: "阻断",
          type: "line",
          smooth: true,
          symbol: "none",
          data: points.map((point) => point.blocked),
        },
      ],
    };
  }, [timeseries.data]);

  const kindOption = useMemo<EChartsCoreOption>(() => {
    const data = Object.entries(overview.data?.agents.by_entity_kind || {})
      .filter(([, value]) => value > 0)
      .map(([key, value]) => ({ name: ENTITY_KIND[key] || key, value }));
    return {
      color: KIND_COLORS,
      tooltip: { trigger: "item" },
      legend: {
        orient: "vertical",
        right: 4,
        top: "center",
        itemWidth: 8,
        itemHeight: 8,
        textStyle: { color: "#4e5969", fontSize: 12 },
      },
      series: [
        {
          type: "pie",
          radius: ["52%", "74%"],
          center: ["34%", "50%"],
          avoidLabelOverlap: true,
          itemStyle: { borderColor: "#fff", borderWidth: 3 },
          label: { show: false },
          data,
        },
      ],
      graphic: [
        {
          type: "text",
          left: "27%",
          top: "42%",
          style: {
            text: String(overview.data?.agents.total ?? 0),
            fontSize: 24,
            fontWeight: 600,
            fill: "#1f2329",
            textAlign: "center",
          },
        },
        {
          type: "text",
          left: "29%",
          top: "56%",
          style: { text: "总计", fontSize: 12, fill: "#86909c" },
        },
      ],
    };
  }, [overview.data]);

  if (overview.isLoading) return <LoadingBlock label="正在读取总览…" />;
  if (overview.isError) {
    return (
      <ErrorState
        message={(overview.error as Error).message}
        onRetry={() => overview.refetch()}
      />
    );
  }
  const data = overview.data!;
  const agents = data.agents;
  const protection = agents.protection_summary;
  const openHigh = data.alerts.open_high;

  const runScan = async () => {
    try {
      const result = await scan.mutateAsync();
      MessagePlugin.success(`扫描完成：${result.entities} 个资产`);
    } catch (error) {
      MessagePlugin.error((error as Error).message);
    }
  };

  return (
    <div className="page">
      <PageHeader
        eyebrow="监测 / 总览"
        title="总览"
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

      <div className="grid grid-4 kpi-grid">
        <KpiCard
          icon={<ViewModuleIcon size="22px" />}
          label="发现 Agent"
          value={number(agents.total)}
          meta={
            <span>
              近 24h 新增 <b className="text-success">+{number(agents.new_24h)}</b>
            </span>
          }
          tone="brand"
          onClick={() => navigate("/assets")}
        />
        <KpiCard
          icon={<PlayCircleIcon size="22px" />}
          label="运行中"
          value={number(agents.running_confirmed)}
          meta={
            <span>
              占 {percent(agents.running_confirmed, agents.total)}
              {agents.running_unconfirmed > 0
                ? ` · 待确认 ${agents.running_unconfirmed}`
                : " · 已核验"}
            </span>
          }
          tone="success"
          onClick={() => navigate("/assets?agent_status=RUNNING")}
        />
        <KpiCard
          icon={<NotificationIcon size="22px" />}
          label="未处理高风险告警"
          value={number(openHigh)}
          meta={openHigh > 0 ? "需要处置" : "暂无高风险告警"}
          tone="danger"
          onClick={() => navigate("/alerts")}
        />
        <KpiCard
          icon={<LockOnIcon size="22px" />}
          label="已验证阻断"
          value={number(protection.PROTECTED)}
          meta={
            <span>
              仅监测 {number(protection.MONITOR_ONLY)} · 未保护{" "}
              {number(protection.UNPROTECTED)} · 未知 {number(protection.UNKNOWN)}
            </span>
          }
          tone="warning"
          onClick={() => navigate("/collectors")}
        />
      </div>

      <SectionCard
        className="overview-trend"
        title="事件趋势"
        subtitle="最近 24 小时"
        extra={
          <button type="button" className="link-button" onClick={() => navigate("/events")}>
            查看全部 <ArrowRightIcon size="14px" />
          </button>
        }
      >
        {timeseries.isLoading ? (
          <LoadingBlock label="读取趋势…" />
        ) : timeseries.data?.points.some((point) => point.events > 0) ? (
          <Chart option={trendOption} height={248} />
        ) : (
          <EmptyState title="最近 24 小时暂无事件" />
        )}
      </SectionCard>

      <div className="grid grid-main grid-main-wide">
        <SectionCard title="Agent 资产分布">
          {agents.total ? (
            <Chart option={kindOption} height={238} />
          ) : (
            <EmptyState title="尚未发现 Agent" />
          )}
        </SectionCard>

        <SectionCard
          title="最近事件"
          extra={
            <button type="button" className="link-button" onClick={() => navigate("/events")}>
              查看全部 <ArrowRightIcon size="14px" />
            </button>
          }
          flush
        >
          {data.recent_events.length ? (
            <table className="data-table compact">
              <thead>
                <tr>
                  <th>时间</th>
                  <th>Agent</th>
                  <th>动作</th>
                  <th>决策</th>
                  <th>执行</th>
                </tr>
              </thead>
              <tbody>
                {data.recent_events.slice(0, 5).map((event) => (
                  <EventRow key={event.id} event={event} onClick={() => navigate(`/events?event=${event.id}`)} />
                ))}
              </tbody>
            </table>
          ) : (
            <EmptyState title="暂无事件" />
          )}
        </SectionCard>
      </div>
    </div>
  );
}

function EventRow({ event, onClick }: { event: EventView; onClick: () => void }) {
  const decision = event.decision ? DECISION[event.decision] : null;
  const execution = event.execution_status ? EXECUTION[event.execution_status] : null;
  return (
    <tr className="clickable" onClick={onClick}>
      <td className="muted mono">{clock(event.observed_at)}</td>
      <td>
        <span className="agent-cell">
          <span className="agent-dot" />
          {event.actor?.label || event.agent_label || "未归属"}
        </span>
      </td>
      <td>{event.operation || event.event_type || "—"}</td>
      <td>{decision ? <Tag tone={decision.tone}>{decision.label}</Tag> : "—"}</td>
      <td>
        {execution ? (
          <Tag tone={execution.tone}>{execution.label}</Tag>
        ) : (
          <span className="muted">—</span>
        )}
      </td>
    </tr>
  );
}