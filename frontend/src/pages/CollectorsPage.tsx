import { useState } from "react";
import { DialogPlugin, MessagePlugin } from "tdesign-react";
import { CloseIcon, PlayCircleIcon, RefreshIcon, ServerIcon } from "tdesign-icons-react";
import { useChannelControl, useHookInstall, useHookPlan, useHookUninstall, useHooks, useTelemetry } from "../api/queries";
import type { ChannelView, HookInstallation, HookPlanResponse } from "../api/types";
import {
  EmptyState,
  ErrorState,
  LoadingBlock,
  PageHeader,
  SectionCard,
  Tag,
} from "../components/ui";
import { CHANNEL_STATE, HEALTH_STATE, relative, time } from "../lib/format";

const INSTALL_STATE: Record<string, { label: string; tone: string }> = {
  INSTALLED: { label: "已安装", tone: "success" },
  PARTIAL: { label: "部分接入", tone: "warning" },
  CONFLICT: { label: "配置冲突", tone: "danger" },
  NOT_INSTALLED: { label: "未安装", tone: "neutral" },
  UNSUPPORTED: { label: "不支持", tone: "neutral" },
  UNKNOWN: { label: "未知", tone: "neutral" },
};

export function CollectorsPage() {
  const telemetry = useTelemetry();
  const hooks = useHooks();
  const plan = useHookPlan();
  const install = useHookInstall();
  const uninstall = useHookUninstall();
  const control = useChannelControl();
  const [preview, setPreview] = useState<HookPlanResponse | null>(null);
  const [previewMode, setPreviewMode] = useState<"install" | "uninstall">("install");

  const health = telemetry.data?.health;
  const healthSpec = HEALTH_STATE[health?.state || "UNKNOWN"];

  const activeBehavior = (telemetry.data?.channels || []).find(
    (channel) => channel.control === "behavior" && channel.state === "RUNNING",
  );

  const startChannel = (channel: ChannelView) => {
    const controlKind = channel.control as "monitor" | "behavior";
    const doStart = () =>
      control.mutate(
        { control: controlKind, id: channel.id, action: "start" },
        {
          onSuccess: () =>
            MessagePlugin.success(
              activeBehavior && activeBehavior.id !== channel.id && controlKind === "behavior"
                ? `已切换至 ${channel.name}`
                : "已启动",
            ),
          onError: (error) => MessagePlugin.error((error as Error).message),
        },
      );
    if (controlKind === "behavior" && activeBehavior && activeBehavior.id !== channel.id) {
      const dialog = DialogPlugin.confirm({
        header: "切换行为通道",
        body: `行为通道同时只能运行一个：启动 ${channel.name} 将先停止 ${activeBehavior.name}。`,
        confirmBtn: "切换",
        cancelBtn: "取消",
        onConfirm: () => {
          dialog.hide();
          doStart();
        },
        onCancel: () => dialog.hide(),
        onClose: () => dialog.hide(),
      });
      return;
    }
    doStart();
  };

  const stopChannel = (channel: ChannelView) => {
    control.mutate(
      { control: channel.control as "monitor" | "behavior", id: channel.id, action: "stop" },
      {
        onSuccess: () => MessagePlugin.success("已停止"),
        onError: (error) => MessagePlugin.error((error as Error).message),
      },
    );
  };

  const showPlan = async (hook: HookInstallation) => {
    try {
      const result = await plan.mutateAsync(hook.agent_type);
      setPreviewMode("install");
      setPreview(result);
    } catch (error) {
      MessagePlugin.error((error as Error).message);
    }
  };

  const applyInstall = (hook: HookInstallation) => {
    const dialog = DialogPlugin.confirm({
      header: "确认安装 Hook",
      body: `将向 ${hook.config_path} 写入 Agent Detector 条目，并在写入前备份。是否继续？`,
      confirmBtn: "安装",
      cancelBtn: "取消",
      onConfirm: async () => {
        try {
          const result = await install.mutateAsync({ agentType: hook.agent_type, apply: true });
          setPreviewMode("install");
          setPreview(result);
          MessagePlugin.success(result.written ? "Hook 已安装" : "配置没有变化，未写入");
        } catch (error) {
          MessagePlugin.error((error as Error).message);
        } finally {
          dialog.hide();
        }
      },
      onCancel: () => dialog.hide(),
      onClose: () => dialog.hide(),
    });
  };

  const applyUninstall = (hook: HookInstallation) => {
    const dialog = DialogPlugin.confirm({
      header: "确认卸载 Hook",
      theme: "warning",
      body: hook.entries
        ? `将从 ${hook.config_path} 移除 Agent Detector 写入的 ${hook.entries} 个条目，写入前先备份。是否继续？`
        : `没有检测到 Agent Detector 写入的条目，卸载不会修改 ${hook.config_path}。是否继续？`,
      confirmBtn: "卸载",
      cancelBtn: "取消",
      onConfirm: async () => {
        try {
          const result = await uninstall.mutateAsync({ agentType: hook.agent_type, apply: true });
          setPreviewMode("uninstall");
          setPreview(result);
          MessagePlugin.success(
            result.written
              ? `Hook 已卸载（移除 ${result.removed ?? 0} 个条目）`
              : "没有本工具写入的条目，未修改配置",
          );
        } catch (error) {
          MessagePlugin.error((error as Error).message);
        } finally {
          dialog.hide();
        }
      },
      onCancel: () => dialog.hide(),
      onClose: () => dialog.hide(),
    });
  };

  if (telemetry.isLoading || hooks.isLoading) return <LoadingBlock label="读取采集状态…" />;
  if (telemetry.isError || hooks.isError) {
    return (
      <ErrorState
        message={((telemetry.error || hooks.error) as Error).message}
        onRetry={() => {
          telemetry.refetch();
          hooks.refetch();
        }}
      />
    );
  }

  return (
    <div className="page">
      <PageHeader
        eyebrow="治理 / 采集管理"
        title="采集管理"
        actions={
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => {
              telemetry.refetch();
              hooks.refetch();
            }}
          >
            <RefreshIcon size="16px" /> 刷新
          </button>
        }
      />

      <div className={`health-banner health-banner-${healthSpec.tone}`}>
        <span className="health-banner-icon">
          <ServerIcon size="20px" />
        </span>
        <div>
          <strong>{healthSpec.label}</strong>
          <span>{health?.basis?.join("；") || "尚未读取到采集状态"}</span>
        </div>
        <span className="muted">
          最近事件 {relative(health?.last_event_at)}
          {health?.last_event_age_seconds
            ? ` · ${health.last_event_age_seconds}s 前`
            : ""}
        </span>
      </div>

      <SectionCard title="行为通道" flush>
        {telemetry.data?.channels.length ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>通道</th>
                <th>平台</th>
                <th>状态</th>
                <th>说明</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {telemetry.data.channels.map((channel) => {
                const spec = CHANNEL_STATE[channel.state] || CHANNEL_STATE.UNKNOWN;
                return (
                  <tr key={channel.id}>
                    <td>
                      <div className="primary-cell">{channel.name}</div>
                      <div className="secondary-line mono">{channel.id}</div>
                    </td>
                    <td className="muted">{channel.platform}</td>
                    <td>
                      <Tag tone={spec.tone}>{spec.label}</Tag>
                    </td>
                    <td className="muted truncate" title={channel.detail}>
                      {channel.detail}
                    </td>
                    <td>
                      {channel.control ? (
                        <button
                          type="button"
                          className="link-button"
                          disabled={control.isPending}
                          onClick={() =>
                            channel.state === "RUNNING"
                              ? stopChannel(channel)
                              : startChannel(channel)
                          }
                        >
                          {channel.state === "RUNNING" ? "停止" : "启动"}
                        </button>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : (
          <EmptyState title="没有通道数据" />
        )}
      </SectionCard>

      <SectionCard title="Agent 原生 Hook" flush>
        {hooks.data?.items.length ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Agent</th>
                <th>安装状态</th>
                <th>条目</th>
                <th>Schema</th>
                <th>配置文件</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {hooks.data.items.map((hook) => {
                const spec = INSTALL_STATE[hook.state] || INSTALL_STATE.UNKNOWN;
                return (
                  <tr key={hook.agent_type}>
                    <td>
                      <div className="primary-cell">{hook.display_name}</div>
                      <div className="secondary-line mono">{hook.agent_type}</div>
                    </td>
                    <td>
                      <Tag tone={spec.tone}>{spec.label}</Tag>
                    </td>
                    <td className="num">{hook.entries}</td>
                    <td>
                      <Tag tone={hook.schema_verified ? "success" : "warning"}>
                        {hook.schema_verified ? "已验证" : "待验证"}
                      </Tag>
                    </td>
                    <td className="mono truncate" title={hook.config_path}>
                      {hook.config_path}
                    </td>
                    <td>
                      <div className="row-actions">
                        <button
                          type="button"
                          className="link-button"
                          onClick={() => showPlan(hook)}
                        >
                          预览
                        </button>
                        <button
                          type="button"
                          className="link-button"
                          onClick={() => applyInstall(hook)}
                        >
                          安装
                        </button>
                        <button
                          type="button"
                          className="link-button link-button-danger"
                          onClick={() => applyUninstall(hook)}
                        >
                          卸载
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : (
          <EmptyState
            icon={<PlayCircleIcon size="28px" />}
            title="没有可用的 Hook 适配器"
          />
        )}
      </SectionCard>

      {preview ? (
        <div className="drawer-layer" role="dialog" aria-modal="true">
          <button type="button" className="drawer-backdrop" aria-label="关闭" onClick={() => setPreview(null)} />
          <aside className="drawer">
            <header className="drawer-head">
              <div>
                <div className="eyebrow">
                  {previewMode === "uninstall" ? "Hook 卸载结果" : "Hook 配置预览"}
                </div>
                <h2>{preview.agent_type}</h2>
                <div className="secondary-line mono">{preview.config_path}</div>
              </div>
              <button type="button" className="icon-button" onClick={() => setPreview(null)} aria-label="关闭">
                <CloseIcon size="18px" />
              </button>
            </header>
            <div className="drawer-body">
              <div className="drawer-tags">
                <Tag tone={preview.written ? "success" : "info"}>
                  {previewMode === "uninstall"
                    ? preview.written
                      ? "已卸载"
                      : "未修改"
                    : preview.written
                      ? "已写入"
                      : "仅预览"}
                </Tag>
                <Tag tone={preview.changed ? "warning" : "neutral"}>
                  {preview.changed ? "有变更" : "无变更"}
                </Tag>
                {previewMode === "uninstall" && preview.removed !== undefined ? (
                  <Tag tone="warning">移除 {preview.removed} 个条目</Tag>
                ) : null}
                {preview.backup ? <Tag tone="neutral">已备份</Tag> : null}
              </div>
              {preview.command ? <p className="note-text mono">{preview.command}</p> : null}
              {preview.backup ? (
                <p className="note-text">备份文件：{preview.backup}</p>
              ) : null}
              <h3>{previewMode === "uninstall" ? "剩余配置" : "合并后的配置"}</h3>
              <pre className="code-block">{JSON.stringify(preview.merged, null, 2)}</pre>
            </div>
            <footer className="drawer-foot">
              <span className="muted">{time(new Date().toISOString())}</span>
              <button type="button" className="btn btn-secondary" onClick={() => setPreview(null)}>
                关闭
              </button>
            </footer>
          </aside>
        </div>
      ) : null}
    </div>
  );
}