import type { ReactNode } from "react";
import { Loading } from "tdesign-react";
import { ErrorCircleIcon, InfoCircleIcon } from "tdesign-icons-react";

export type Tone =
  | "success"
  | "info"
  | "warning"
  | "danger"
  | "critical"
  | "neutral";

export function Tag({
  tone = "neutral",
  children,
  dot = true,
  title,
}: {
  tone?: Tone | string;
  children: ReactNode;
  dot?: boolean;
  title?: string;
}) {
  return (
    <span className={`tag tag-${tone}`} title={title}>
      {dot ? <span className="tag-dot" /> : null}
      <span>{children}</span>
    </span>
  );
}

export function PageHeader({
  title,
  actions,
  eyebrow,
}: {
  title: string;
  actions?: ReactNode;
  eyebrow?: string;
}) {
  return (
    <header className="page-head">
      <div>
        {eyebrow ? <div className="eyebrow">{eyebrow}</div> : null}
        <h1>{title}</h1>
      </div>
      {actions ? <div className="page-actions">{actions}</div> : null}
    </header>
  );
}

export function KpiCard({
  icon,
  label,
  value,
  meta,
  tone = "brand",
  onClick,
}: {
  icon: ReactNode;
  label: string;
  value: ReactNode;
  meta?: ReactNode;
  tone?: "brand" | "success" | "warning" | "danger";
  onClick?: () => void;
}) {
  return (
    <button
      type="button"
      className={`kpi-card kpi-${tone} ${onClick ? "kpi-clickable" : ""}`}
      onClick={onClick}
    >
      <span className="kpi-icon">{icon}</span>
      <span className="kpi-body">
        <span className="kpi-label">{label}</span>
        <span className="kpi-value">{value}</span>
        {meta ? <span className="kpi-meta">{meta}</span> : null}
      </span>
    </button>
  );
}

export function SectionCard({
  title,
  subtitle,
  extra,
  children,
  className = "",
  flush = false,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  extra?: ReactNode;
  children: ReactNode;
  className?: string;
  flush?: boolean;
}) {
  return (
    <section className={`card ${flush ? "card-flush" : ""} ${className}`}>
      {title ? (
        <div className="card-head">
          <div>
            <h2>{title}</h2>
            {subtitle ? <div className="card-subtitle">{subtitle}</div> : null}
          </div>
          {extra ? <div className="card-extra">{extra}</div> : null}
        </div>
      ) : null}
      <div className={flush ? "card-body card-body-flush" : "card-body"}>
        {children}
      </div>
    </section>
  );
}

export function EmptyState({
  title,
  icon,
  action,
}: {
  title: string;
  icon?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="state-block">
      <div className="state-icon">{icon || <InfoCircleIcon size="28px" />}</div>
      <h3>{title}</h3>
      {action}
    </div>
  );
}

export function ErrorState({
  title = "读取失败",
  message,
  onRetry,
}: {
  title?: string;
  message?: string;
  onRetry?: () => void;
}) {
  return (
    <div className="state-block state-error">
      <div className="state-icon">
        <ErrorCircleIcon size="28px" />
      </div>
      <h3>{title}</h3>
      {message ? <p>{message}</p> : null}
      {onRetry ? (
        <button type="button" className="btn btn-secondary" onClick={onRetry}>
          重试
        </button>
      ) : null}
    </div>
  );
}

export function LoadingBlock({ label = "读取中…" }: { label?: string }) {
  return (
    <div className="state-block">
      <Loading size="24px" />
      <p>{label}</p>
    </div>
  );
}

export function KeyValue({
  items,
  columns = 2,
}: {
  items: Array<{ label: string; value: ReactNode }>;
  columns?: 1 | 2 | 3;
}) {
  return (
    <div className={`kv-grid kv-${columns}`}>
      {items.map((item) => (
        <div className="kv-item" key={item.label}>
          <span className="kv-label">{item.label}</span>
          <span className="kv-value">{item.value}</span>
        </div>
      ))}
    </div>
  );
}