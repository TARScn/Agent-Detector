import { useCapabilities, useSystem } from "../api/queries";
import {
  ErrorState,
  KeyValue,
  LoadingBlock,
  PageHeader,
  SectionCard,
  Tag,
} from "../components/ui";

export function SettingsPage() {
  const system = useSystem();
  const capabilities = useCapabilities();

  if (system.isLoading) return <LoadingBlock label="读取系统信息…" />;
  if (system.isError) {
    return (
      <ErrorState
        message={(system.error as Error).message}
        onRetry={() => system.refetch()}
      />
    );
  }
  const data = system.data!;
  const modes = capabilities.data?.modes || {};

  return (
    <div className="page">
      <PageHeader
        eyebrow="治理 / 系统设置"
        title="系统设置"
        actions={
          <Tag tone="info" dot={false}>
            {data.version}
          </Tag>
        }
      />

      <div className="grid grid-2">
        <SectionCard title="运行环境">
          <KeyValue
            items={[
              { label: "版本", value: data.version },
              { label: "平台", value: `${data.platform.system} ${data.platform.release}` },
              { label: "Python", value: data.platform.python },
              { label: "主机名", value: data.platform.node },
              { label: "监听地址", value: data.server.listen },
              { label: "数据库", value: data.database.path },
            ]}
          />
        </SectionCard>
        <SectionCard title="安全边界">
          <ul className="scope-list">
            {data.scope_notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </SectionCard>
      </div>

      <SectionCard title="能力清单">
        <div className="capability-grid">
          {Object.entries(modes).map(([key, value]) => {
            const implemented =
              typeof value === "object" &&
              value !== null &&
              "implemented" in value &&
              Boolean((value as { implemented: unknown }).implemented);
            return (
              <div className="capability-card" key={key}>
                <div className="capability-head">
                  <strong>{key}</strong>
                  <Tag tone={implemented ? "success" : "neutral"}>
                    {implemented ? "已实现" : "未实现"}
                  </Tag>
                </div>
                <pre className="code-block small">
                  {JSON.stringify(value, null, 2)}
                </pre>
              </div>
            );
          })}
          {!Object.keys(modes).length ? (
            <p className="note-text">未读取到能力清单。</p>
          ) : null}
        </div>
      </SectionCard>

      <SectionCard title="检测规则与支持矩阵">
        <KeyValue
          items={[
            {
              label: "客户端规则",
              value: String(
                (data.detection_rules.client_rules as unknown[] | undefined)?.length ?? 0,
              ),
            },
            {
              label: "框架规则",
              value: String(data.detection_rules.framework_rules ?? "—"),
            },
            {
              label: "规则错误",
              value: String(
                (data.detection_rules.errors as unknown[] | undefined)?.length ?? 0,
              ),
            },
            {
              label: "矩阵来源",
              value: String(data.agent_matrix.source ?? "—"),
            },
          ]}
        />
      </SectionCard>
    </div>
  );
}