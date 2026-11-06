import { useState, useSyncExternalStore } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  ActivityIcon,
  ChevronRightIcon,
  DashboardIcon,
  LockOnIcon,
  NotificationIcon,
  SearchIcon,
  ServerIcon,
  SettingIcon,
  ViewModuleIcon,
} from "tdesign-icons-react";
import { useOverview, useScanActivity, useTelemetry } from "../api/queries";
import { HEALTH_STATE, number } from "../lib/format";
import {
  isGlobalProgressActive,
  subscribeGlobalProgress,
} from "../lib/progress";
import { Tag } from "../components/ui";

const NAV = [
  {
    label: "监测",
    items: [
      { to: "/overview", label: "总览", icon: <DashboardIcon /> },
      { to: "/assets", label: "资产", icon: <ViewModuleIcon /> },
      { to: "/events", label: "事件", icon: <ActivityIcon /> },
    ],
  },
  {
    label: "治理",
    items: [
      { to: "/alerts", label: "告警", icon: <NotificationIcon /> },
      { to: "/policies", label: "安全策略", icon: <LockOnIcon /> },
      { to: "/collectors", label: "采集管理", icon: <ServerIcon /> },
      { to: "/settings", label: "系统设置", icon: <SettingIcon /> },
    ],
  },
];

export function AppShell() {
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const overview = useOverview();
  const telemetry = useTelemetry();
  const health = telemetry.data?.health;
  const healthSpec = HEALTH_STATE[health?.state || "UNKNOWN"];
  const openAlerts = overview.data?.alerts.by_status.open ?? 0;
  const agentTotal = overview.data?.agents.total ?? 0;
  const busyFromStore = useSyncExternalStore(subscribeGlobalProgress, isGlobalProgressActive);
  const scanRunning = useScanActivity();
  const busy = busyFromStore || scanRunning;

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    const value = search.trim();
    navigate(value ? `/assets?q=${encodeURIComponent(value)}` : "/assets");
  };

  return (
    <div className="app-shell">
      {busy ? (
        <div className="global-progress" role="progressbar" aria-label="加载中">
          <span className="global-progress-track" />
        </div>
      ) : null}
      <header className="topbar">
        <div className="brand">
          <span className="brand-name">Agent Detector</span>
        </div>
        <form className="topbar-search" onSubmit={submit}>
          <SearchIcon size="16px" />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="搜索 Agent 名称或类型…"
            aria-label="搜索 Agent"
          />
          <kbd>Enter</kbd>
        </form>
        <div className="topbar-right">
          <NavLink
            to="/collectors"
            className={`health-chip health-${healthSpec.tone}`}
            title={health?.basis?.join("；") || "采集状态"}
          >
            <span className="health-dot" />
            {healthSpec.label}
          </NavLink>
          <NavLink to="/alerts" className="icon-button" title="告警">
            <NotificationIcon size="18px" />
            {openAlerts > 0 ? <span className="badge-count">{openAlerts}</span> : null}
          </NavLink>
          <NavLink to="/settings" className="icon-button" title="系统信息">
            <SettingIcon size="18px" />
          </NavLink>
        </div>
      </header>

      <aside className="sidebar">
        <div className="sidebar-scroll">
          {NAV.map((section) => (
            <div className="nav-section" key={section.label}>
              <div className="nav-label">{section.label}</div>
              {section.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
                >
                  <span className="nav-icon">{item.icon}</span>
                  <span className="nav-text">{item.label}</span>
                  {item.to === "/assets" ? (
                    <span className="nav-count">{number(agentTotal)}</span>
                  ) : null}
                  {item.to === "/alerts" && openAlerts > 0 ? (
                    <span className="nav-count nav-count-alert">{openAlerts}</span>
                  ) : null}
                  <ChevronRightIcon className="nav-chevron" size="14px" />
                </NavLink>
              ))}
            </div>
          ))}
        </div>
        <div className="sidebar-foot">
          <Tag tone="neutral" dot={false}>
            仅本机
          </Tag>
          <span>127.0.0.1 · 本地控制台</span>
        </div>
      </aside>

      <main className="main">
        <Outlet />
      </main>
    </div>
  );
}