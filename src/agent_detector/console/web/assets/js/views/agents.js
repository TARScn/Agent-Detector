// Agent 资产：list + detail. The detail drawer shows exactly what the backend
// knows — instances, sessions, MCP names, capability matrix, hook state and the
// evidence behind each claim — and offers the Hook install/uninstall actions.
import { api } from '../api.js';
import {
  badgeSpec, count, DECISION, HOOK_STATE, PROTECTION, relative, RISK, SOURCE,
  supportLabel, time,
} from '../format.js';
import {
  badge, button, card, drawer, el, empty, fragment, note, pageHead, sectionTitle, table, toast,
} from '../ui.js';

export async function render(ctx) {
  if (ctx.params.assetId) return detailPage(ctx, ctx.params.assetId);
  return listPage(ctx);
}

async function listPage(ctx) {
  const payload = await api.agents();
  const agents = payload.items || [];
  const wrapper = el('div', { class: 'page' }, [
    pageHead({
      title: 'Agent 资产',
      description: '已发现的 Agent 与保护状态',
      actions: [
        button('重新扫描', { kind: 'primary', iconName: 'search', onClick: async () => {
          try {
            await api.scan(false);
            toast('扫描完成', { kind: 'success' });
            await ctx.refresh();
            await render(ctx);
          } catch (error) { toast(error.message, { kind: 'error' }); }
        } }),
      ],
    }),
  ]);

  if (payload.matrix_errors && payload.matrix_errors.length) {
    wrapper.append(note('Agent 支持矩阵加载失败', 'warning'));
  }

  const running = agents.filter((agent) => agent.instance_count > 0);
  wrapper.append(el('div', { class: 'grid grid-4' }, [
    statRow('Agent 资产', count(agents.length), '与 PID 无关'),
    statRow('运行中', count(running.length), '有运行实例'),
    statRow('已启用拦截', count(agents.filter((a) => a.protection_status === 'PROTECTED').length),
      'Hook 已接入'),
    statRow('待处理', count(agents.filter((a) => a.protection_status !== 'PROTECTED').length),
      '仅监测 / 降级'),
  ]));

  wrapper.append(card('资产清单', agents.length ? table([
    { label: 'Agent', render: (row) => el('div', {}, [
      el('div', { class: 'primary-cell', text: row.name }),
      el('div', { class: 'muted', text: row.agent_type }),
    ]) },
    { label: '状态', width: '140px', render: (row) => fragment(statesBadges(row.states)
      .concat(row.status === 'inactive' ? [badge({ label: '未活跃', cls: 'outline' })] : [])) },
    { label: '版本', width: '130px', render: (row) => el('span', { class: 'mono',
      text: row.version || 'UNKNOWN' }) },
    { label: '保护', width: '130px', render: (row) => badge(badgeSpec(PROTECTION, row.protection_status)) },
    { label: 'Hook', width: '110px', render: (row) => badge(badgeSpec(HOOK_STATE, row.hook_state)) },
    { label: '实例 / 会话', width: '110px', class: 'num',
      render: (row) => `${row.instance_count} / ${row.session_count}` },
    { label: 'MCP', width: '80px', class: 'num',
      render: (row) => (row.mcp_servers || []).length || '—' },
    { label: '最近活动', width: '130px', render: (row) => el('span', { class: 'muted',
      text: relative(row.last_seen_at) }) },
  ], agents, { onRowClick: (row) => ctx.navigate(`#/agents/${encodeURIComponent(row.asset_id)}`) })
    : empty({ title: '尚未发现 Agent', message: '点击“重新扫描”开始发现',
      iconName: 'agent' }), { flush: true }));

  return wrapper;
}

function statRow(label, value, meta) {
  return el('div', { class: 'card stat' }, [
    el('div', { class: 'label', text: label }),
    el('div', { class: 'value', text: value }),
    el('div', { class: 'meta', text: meta }),
  ]);
}

export function statesBadges(states = []) {
  const map = {
    INSTALLED: { label: '已安装', cls: 'outline' },
    CONFIGURED: { label: '已配置', cls: 'info' },
    RUNNING: { label: '运行中', cls: 'success' },
    BEHAVIOR_SUSPECTED: { label: '行为可疑', cls: 'warning' },
    EXECUTION_CONFIRMED: { label: '执行已确认', cls: 'success' },
    UNKNOWN: { label: '未知', cls: 'outline' },
  };
  return states.map((state) => badge(badgeSpec(map, state)));
}

async function detailPage(ctx, assetId) {
  const [detail, mcp] = await Promise.all([
    api.agent(assetId),
    api.agentMcp(assetId).catch(() => ({ items: [] })),
  ]);
  const protection = badgeSpec(PROTECTION, detail.protection_status);
  const notes = detail.notes || [];

  const wrapper = el('div', { class: 'page' }, [
    pageHead({
      breadcrumb: [{ label: 'Agent 资产', href: '#/agents' }, { label: detail.name }],
      title: detail.name,
      description: `${detail.agent_type}${detail.vendor ? ` · ${detail.vendor}` : ''}`,
      actions: [button('行为时间线', { kind: 'primary', iconName: 'activity',
        onClick: () => ctx.navigate('#/behavior') })],
    }),
  ]);

  // Three cards of equal height: identity / protection & capability / MCP.
  const facts = [
    ['状态', fragment(statesBadges(detail.states)), { stack: true }],
    ['版本', mono(detail.version || 'UNKNOWN')],
    ['版本来源', detail.version_source],
    ['可执行文件', mono(detail.executable || '—')],
    ['首次发现', time(detail.first_seen_at)],
    ['最近活动', time(detail.last_seen_at)],
    ['资产 ID', mono(detail.asset_id)],
    ['置信度', String(detail.confidence)],
  ];
  const capabilities = Object.entries(detail.capabilities || {}).map(([key, value]) => [
    { discovery: '资产发现', monitor: '行为监测', protect: '前置拦截' }[key] || key,
    badge({ label: supportLabel(value), cls: value === 'P0' ? 'info' : 'outline' }),
  ]);

  wrapper.append(el('div', { class: 'grid grid-3' }, [
    card('基本信息', factList(facts), { hint: `发现于 ${relative(detail.first_seen_at)}` }),
    card('保护与能力', [
      factList([
        ['保护状态', badge(protection), { stack: true }],
        ['Hook', badge(badgeSpec(HOOK_STATE, detail.hook_state))],
        ...capabilities,
      ]),
      el('p', { class: 'muted', style: { color: 'var(--text-muted)', fontSize: '12px',
        margin: '10px 0 0' }, text: protection.hint || '' }),
    ], {
      footer: notes.length ? notes.join(' ') : null,
      actions: [button('安装 Hook', { kind: 'subtle', size: 'small', iconName: 'shield',
        onClick: () => openHookDrawer(detail.agent_type, () => render(ctx)) })],
    }),
    card('MCP 配置', mcp.items?.length ? table([
      { label: '服务名', render: (row) => el('span', { class: 'primary-cell', text: row.name }) },
      { label: '传输', width: '90px', render: (row) => badge({ label: row.transport, cls: 'outline' }) },
    ], mcp.items)
      // Same row rhythm as the neighbouring cards instead of a centred empty
      // block, which left a large blank area in an equal-height card.
      : factList([['MCP 服务', '0'], ['读取范围', '仅服务名与传输类型']]),
    { flush: Boolean(mcp.items?.length),
      hint: mcp.items?.length ? `${mcp.items.length} 个` : '' }),
  ]));

  // 项目与依赖：自建框架资产由进程→项目解析产生，这里展示它归属的应用与
  // AI 依赖组件（包名/版本/来源），全部来自依赖元数据，不读取项目源码。
  const application = detail.application;
  if (application) {
    const sourceMap = {
      'package-metadata': { label: '已安装', cls: 'success' },
      locked: { label: '锁定', cls: 'info' },
      declared: { label: '声明', cls: 'outline' },
      unknown: { label: '未知', cls: 'outline' },
    };
    const components = application.components || [];
    wrapper.append(sectionTitle('项目与依赖'));
    wrapper.append(card(null, [
      factList([
        ['项目目录', mono(application.root_path || '—')],
        ['运行时', application.runtime || '—'],
        ['虚拟环境', mono(application.environment_path || '系统环境')],
        ['入口', `${application.entrypoint || '—'}（${application.entry_kind || 'cwd'}）`],
      ]),
      el('div', { style: { height: '12px' } }),
      components.length ? table([
        { label: '组件', render: (row) => el('span', { class: 'primary-cell mono', text: row.name }) },
        { label: '版本', width: '130px', render: (row) => el('span', { class: 'mono',
          text: row.version || 'UNKNOWN' }) },
        { label: '版本来源', width: '110px',
          render: (row) => badge(badgeSpec(sourceMap, row.version_source)) },
        { label: '来源文件', render: (row) => el('span', { class: 'muted mono ellipsis-cell',
          title: row.source_path || '', text: row.source_path || '—' }) },
      ], components) : empty({ title: '未记录 AI 依赖组件', iconName: 'agent' }),
    ], { flush: components.length > 0,
      hint: `发现于 ${relative(application.first_seen_at)}` }));
  }

  // LLM 底座：从各 Agent 自己的配置文件里提取的模型与供应商端点。
  // 只读模型名与 URL —— 密钥、会话级环境变量永不读取（与 MCP 卡同一口径）。
  const endpoints = detail.llm_endpoints || [];
  wrapper.append(sectionTitle('LLM 底座'));
  wrapper.append(card(null, endpoints.length ? table([
    { label: '模型', render: (row) => el('span', { class: 'primary-cell mono',
      text: row.model || '—' }) },
    { label: '供应商', width: '200px', render: (row) => el('span', {
      text: row.provider || row.provider_id || '未知' }) },
    { label: '端点', render: (row) => el('span', { class: 'muted mono ellipsis-cell',
      title: row.base_url || '', text: row.base_url || '—' }) },
    { label: '来源', width: '280px', render: (row) => el('span',
      { class: 'muted mono ellipsis-cell', title: row.source || '', text: row.source || '—' }) },
  ], endpoints)
    : empty({ title: '配置中未发现模型 / 端点覆盖',
      message: '仅读取配置文件里的模型名与端点 URL；会话级环境变量与密钥类内容永不读取。',
      iconName: 'agent' }), { flush: Boolean(endpoints.length) }));

  wrapper.append(sectionTitle('运行实例'));
  wrapper.append(card(null, detail.instances?.length ? table([
    { label: 'PID', width: '80px', class: 'num', render: (row) => String(row.pid) },
    { label: '进程', render: (row) => el('div', {}, [
      el('div', { class: 'primary-cell', text: row.process_name || '—' }),
      el('div', { class: 'muted mono ellipsis-cell', text: row.cmdline || row.executable || '',
        title: row.cmdline || row.executable || '' }),
    ]) },
    { label: '父进程链', render: (row) => el('span', { class: 'muted mono ellipsis-cell',
      title: (row.parent_chain || []).join(' ← '),
      text: (row.parent_chain || []).join(' ← ') || '—' }) },
    { label: '启动时间', width: '150px', render: (row) => el('span', { class: 'muted',
      text: time(row.started_at) }) },
    { label: '状态', width: '90px', render: (row) => badge({
      label: row.status === 'running' ? '运行中' : '已退出',
      cls: row.status === 'running' ? 'success' : 'outline' }) },
  ], detail.instances) : empty({ title: '无运行实例', iconName: 'agent' }), { flush: true }));

  wrapper.append(sectionTitle('会话'));
  wrapper.append(card(null, detail.sessions?.length ? table([
    { label: '会话', render: (row) => el('span', { class: 'mono ellipsis-cell',
      title: row.session_id, text: row.session_id }) },
    { label: '工作目录', render: (row) => el('span', { class: 'mono ellipsis-cell',
      title: row.cwd || '', text: row.cwd || '—' }) },
    { label: '最近工具', width: '140px', render: (row) => row.last_tool || '—' },
    { label: '事件数', width: '80px', class: 'num', render: (row) => String(row.event_count) },
    { label: '最近事件', width: '150px', render: (row) => el('span', { class: 'muted',
      text: time(row.last_event_at) }) },
  ], detail.sessions) : empty({ title: '暂无会话', message: '安装 Hook 后产生',
    iconName: 'shield' }), { flush: true }));

  wrapper.append(sectionTitle('最近事件'));
  wrapper.append(card(null, detail.events?.length ? table([
    { label: '时间', width: '150px', render: (row) => el('span', { class: 'muted',
      text: time(row.observed_at) }) },
    { label: '来源', width: '110px', render: (row) => badge(badgeSpec(SOURCE, row.source)) },
    { label: '操作', width: '150px', render: (row) => row.operation || row.event_type },
    { label: '目标', render: (row) => el('span', { class: 'mono ellipsis-cell',
      title: row.target || row.endpoint || '',
      text: row.target || row.endpoint || '—' }) },
    { label: '风险', width: '80px', render: (row) => row.risk_level
      ? badge(badgeSpec(RISK, row.risk_level)) : '—' },
    { label: '决策', width: '90px', render: (row) => row.decision
      ? badge(badgeSpec(DECISION, row.decision)) : '—' },
  ], detail.events) : empty({ title: '暂无事件', iconName: 'activity' }), { flush: true }));

  return wrapper;
}

function mono(text) {
  return el('span', { class: 'mono ellipsis', title: text, text });
}

/** Dense label/value rows that stay one line tall (see .fact-row). */
function factList(rows) {
  const list = el('dl', { class: 'fact-list' });
  rows.forEach(([label, value, options]) => {
    if (value === undefined || value === null || value === '') return;
    list.append(el('div', { class: `fact-row ${options?.stack ? 'stack-value' : ''}`.trim() }, [
      el('dt', { text: label }),
      el('dd', {}, [value instanceof Node ? value : document.createTextNode(String(value))]),
    ]));
  });
  return list;
}

export async function openHookDrawer(agentType, onDone) {
  const snippet = await api.hookSnippet(agentType).catch(() => null);
  const plan = await api.hookPlan(agentType).catch((error) => ({ error }));
  const body = [note('写入前会备份，且只增删本工具自己的条目。', 'info', 'info')];
  if (plan.error) {
    body.push(note(`无法生成安装计划：${plan.error.message}`, 'danger', 'warning'));
  } else {
    body.push(card('将写入的配置片段', [
      el('div', { class: 'code', text: JSON.stringify(plan.merged?.hooks || {}, null, 2) }),
    ], { hint: plan.config_path }));
  }
  if (snippet) {
    body.push(card('手工粘贴片段', [
      el('div', { class: 'code', text: JSON.stringify(snippet.events || {}, null, 2) }),
    ], { hint: snippet.config_path }));
  }
  drawer({
    title: '安装 Hook',
    subtitle: agentType,
    body,
    actions: [button('安装（备份后写入）', { kind: 'primary', iconName: 'check', onClick: async () => {
      try {
        const result = await api.hookInstall(agentType, true);
        toast(`已写入 ${result.config_path}${result.backup ? '（已备份）' : ''}`,
          { kind: 'success', title: 'Hook 已安装' });
        if (onDone) onDone();
      } catch (error) { toast(error.message, { kind: 'error', title: '安装失败' }); }
    } })],
  });
}