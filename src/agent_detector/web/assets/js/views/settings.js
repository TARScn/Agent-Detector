// 设置：channels, hook installation, policy engine, detection rules and the
// honest list of what this build does not do yet.
import { api } from '../api.js';
import { badgeSpec, HOOK_STATE, supportLabel } from '../format.js';
import {
  badge, button, card, drawer, el, fragment, keyValues, note, pageHead, table, toast, todo,
} from '../ui.js';

export async function render(ctx) {
  const [system, telemetry, hooks] = await Promise.all([
    api.system(), api.telemetry(), api.hooks(),
  ]);
  const wrapper = el('div', { class: 'page' }, [
    pageHead({
      title: '设置',
      description: '环境、采集通道与 Hook 安装',
      actions: [button('刷新', { iconName: 'refresh', onClick: () => render(ctx) })],
    }),
  ]);

  wrapper.append(el('div', { class: 'grid grid-side' }, [
    card('系统信息', keyValues([
      ['版本', system.version],
      ['平台', `${system.platform.system} ${system.platform.release}`],
      ['主机名', system.platform.node],
      ['Python', system.platform.python],
      ['服务监听', `${system.server.host}:${system.server.port}`],
      ['数据库', el('span', { class: 'mono', text: system.database.path })],
      ['Hook 决策接口', el('span', { class: 'mono', text: system.hooks.url })],
      ['Hook 失败处置', system.hooks.failure_mode === 'block'
        ? '故障关闭（拒绝调用）' : '审计放行'],
      ['数据保留', `${system.behavior.retention_days} 天`],
      ['告警风险阈值', system.behavior.alert_risk_level],
      ['路径策略', system.behavior.path_policy],
    ])),
    el('div', { class: 'stack' }, [
      card('采集通道', (telemetry.channels || []).map((channel) => el('div', {
        style: { display: 'flex', gap: '10px', padding: '7px 0',
          borderBottom: '1px solid var(--divider)' },
      }, [
        badge({ label: channel.available ? '可用' : '不可用',
          cls: channel.available ? 'success' : 'outline', dot: true }),
        el('div', {}, [
          el('div', { style: { fontWeight: 600, fontSize: '13px' }, text: channel.name }),
          el('div', { style: { fontSize: '12px', color: 'var(--text-muted)' }, text: channel.detail }),
        ]),
      ]))),
      card('边界', el('ul', { class: 'plain-list tight' },
        (system.scope_notes || []).map((text) => el('li', { text })))),
    ]),
  ]));

  wrapper.append(el('div', { class: 'section-title' }, [
    el('h2', { text: 'Hook 安装' }),
    el('span', { class: 'hint', text: '默认 dry-run，需 --apply 才写入' }),
  ]));

  const hookHost = el('div');
  wrapper.append(hookHost);
  paintHooks(hookHost, hooks);

  wrapper.append(el('div', { class: 'section-title' }, [
    el('h2', { text: '系统行为采集' }),
    el('span', { class: 'hint', text: 'Sysmon / auditd / 采样' }),
  ]));

  const collectorHost = el('div');
  wrapper.append(collectorHost);
  paintCollectors(collectorHost, telemetry);

  wrapper.append(el('div', { class: 'section-title' }, [
    el('h2', { text: '网络观察' }),
    el('span', { class: 'hint', text: '连接级证据，不读内容' }),
  ]));
  const monitorHost = el('div');
  wrapper.append(monitorHost);
  paintMonitor(monitorHost, telemetry);

  wrapper.append(el('div', { class: 'grid grid-2' }, [
    card('检测规则（资产发现）', [
      table([
        { label: '规则', render: (row) => el('span', { class: 'primary-cell', text: row.name }) },
        { label: 'ID', render: (row) => el('span', { class: 'mono', text: row.id }) },
        { label: '类型', width: '150px', render: (row) => row.asset_type },
        { label: '版本', width: '70px', class: 'num', render: (row) => String(row.revision) },
      ], system.detection_rules.client_rules || []),
      el('div', { style: { marginTop: '10px' } }, [
        el('p', { class: 'muted', style: { color: 'var(--text-muted)', fontSize: '12px' },
          text: `另有 ${system.detection_rules.signature_rules} 条签名规则；新增目标只需加 YAML。` }),
        system.detection_rules.errors?.length
          ? note(`规则文件存在错误：${JSON.stringify(system.detection_rules.errors)}`, 'danger', 'warning')
          : null,
      ]),
    ], { hint: 'fingerprints/rules' }),
    card('Agent 支持矩阵', [
      table([
        { label: 'Agent', render: (row) => el('div', {}, [
          el('div', { class: 'primary-cell', text: row.name }),
          el('div', { class: 'muted', text: row.vendor || '未知厂商' }),
        ]) },
        { label: '发现', width: '70px', render: (row) => support(row.capabilities.discovery) },
        { label: '监测', width: '70px', render: (row) => support(row.capabilities.monitor) },
        { label: '拦截', width: '80px', render: (row) => support(row.capabilities.protect) },
        { label: '适配器', width: '110px', render: (row) => row.hook || '—' },
      ], system.agent_matrix.agents || []),
      el('div', { style: { marginTop: '10px' } },
        note('P0 / P1 为计划优先级，不代表已完成。', 'warning', 'warning')),
    ], { hint: system.agent_matrix.source ? '来源：' + system.agent_matrix.source : '' }),
  ]));

  wrapper.append(el('div', { class: 'section-title' }, [el('h2', { text: '待开发' })]));
  wrapper.append(card(null, el('ul', { class: 'plain-list' }, [
    el('li', {}, ['Codex / Cursor 响应 Schema 核对 ', todo('待验证')]),
    el('li', {}, ['Named Pipe + 用户 SID 决策通道（现为 loopback HTTP + Token） ', todo('待开发')]),
    el('li', {}, ['策略可视化编辑与签名、企业托管下发 ', todo('待开发')]),
    el('li', {}, ['WSL2 内部采集 ', todo('待开发')]),
    el('li', {}, ['eBPF / ETW 通道与容器内 Agent 发现 ', todo('待开发')]),
    el('li', {}, ['告警通知、报表导出、多用户与权限 ', todo('待开发')]),
  ]), { flush: false }));

  function support(level) {
    return badge({ label: supportLabel(level), cls: level === 'P0' ? 'info' : 'outline' });
  }

  function paintHooks(host, payload) {
    host.replaceChildren(card(null, table([
      { label: 'Agent', render: (row) => el('div', {}, [
        el('div', { class: 'primary-cell', text: row.display_name }),
        el('div', { class: 'muted mono', text: row.config_path }),
      ]) },
      { label: '状态', width: '120px', render: (row) => badge(badgeSpec(HOOK_STATE, row.state)) },
      { label: '事件', width: '110px', render: (row) => (row.events || []).join(', ') || '—' },
      { label: 'Schema', width: '110px', render: (row) => badge({
        label: row.schema_verified ? '已核对' : '待验证',
        cls: row.schema_verified ? 'success' : 'warning' }) },
      { label: '操作', width: '230px', render: (row) => fragment([
        row.state === 'INSTALLED' || row.state === 'PARTIAL'
          ? button('卸载', { size: 'small', onClick: () => act('uninstall', row) })
          : null,
        button(row.state === 'INSTALLED' ? '重装' : '安装（dry-run）', {
          size: 'small', kind: 'primary', onClick: () => act('install', row),
        }),
      ]) },
    ], payload.items || []), {
      flush: true,
      hint: payload.failure_mode === 'block'
        ? 'Hook 失败时按“故障关闭”处理' : 'Hook 失败时按“审计放行”处理',
      actions: [button('全部 dry-run', { size: 'small', onClick: () => act('plan', {
        agent_type: (payload.items || [])[0]?.agent_type,
        display_name: '全部 Agent',
        state: 'NOT_INSTALLED',
      }) })],
    }));
  }

  async function act(action, row) {
    try {
      if (action === 'plan') {
        const result = await api.hookPlan(row.agent_type);
        drawer({
          title: `${row.display_name} · 安装计划`,
          subtitle: result.config_path,
          body: [
            note('dry-run：不会写入文件。', 'info', 'info'),
            card('合并后的 hooks 配置', [
              el('div', { class: 'code', text: JSON.stringify(result.merged?.hooks || {}, null, 2) }),
            ]),
            card('调用命令', [el('div', { class: 'code', text: result.command })]),
          ],
          actions: [button('安装（写入并备份）', { kind: 'primary', onClick: async () => {
            const written = await api.hookInstall(row.agent_type, true);
            toast(`已写入 ${written.config_path}${written.backup ? '，已备份原配置' : ''}`,
              { kind: 'success', title: '安装完成' });
            await render(ctx);
          } })],
        });
        return;
      }
      if (action === 'install') {
        const result = await api.hookInstall(row.agent_type, false);
        toast(result.changed ? '配置有变化，可查看详情后写入' : '配置已是最新',
          { title: 'dry-run 结果' });
        await act('plan', row);
        return;
      }
      const result = await api.hookUninstall(row.agent_type, true);
      toast(`已移除 ${result.removed} 条本工具写入的条目`, { kind: 'success' });
      await render(ctx);
    } catch (error) {
      toast(error.message, { kind: 'error', title: '操作失败' });
    }
  }

  function paintCollectors(host, payload) {
    const behavior = payload.behavior || {};
    host.replaceChildren(el('div', { class: 'grid grid-2' }, [
      card('采集器状态', keyValues([
        ['模式', behavior.mode],
        ['运行中', behavior.running ? '是' : '否'],
        ['采集批次', String(behavior.batches ?? 0)],
        ['已存事件', String(behavior.events ?? 0)],
        ['Sysmon 通道', behavior.sysmon_channel || '—'],
        ['间隔', `${behavior.interval}s`],
        ['抑制窗口', `${behavior.suppress_seconds}s`],
        ['保留天数', `${behavior.retention_days} 天`],
      ]), { actions: [
        behavior.running
          ? button('停止采集', { size: 'small', onClick: () => control('behavior/stop') })
          : button('启动采集', { size: 'small', kind: 'primary', onClick: () => control('behavior/start',
            { mode: behavior.mode }) }),
      ] }),
      card('auditd 规则生成器（Linux）', auditGenerator()),
    ]));
  }

  function auditGenerator() {
    const input = el('input', {
      type: 'text', placeholder: '/home/user/agent-lab', style: { flex: '1' },
    });
    return [
      el('p', { class: 'muted', style: { color: 'var(--text-muted)', fontSize: '13px' },
        text: '输入审计目录，生成 root 安装命令（不自动提权）。' }),
      el('div', { class: 'toolbar', style: { marginTop: '10px' } }, [
        input,
        button('生成命令', { onClick: async () => {
          try {
            const result = await api.auditRules(input.value.trim() || undefined);
            drawer({
              title: 'auditd 规则与安装命令',
              subtitle: '需要 root 执行',
              body: [
                card('规则', [el('div', { class: 'code', text: (result.rules || []).join('\n') })]),
                card('安装', [el('div', { class: 'code', text: (result.install || []).join('\n') })]),
                card('卸载', [el('div', { class: 'code', text: (result.uninstall || []).join('\n') })]),
                el('ul', { class: 'plain-list tight' },
                  (result.notes || []).map((text) => el('li', { text }))),
              ],
            });
          } catch (error) { toast(error.message, { kind: 'error' }); }
        } }),
      ]),
    ];
  }

  function paintMonitor(host, payload) {
    const monitor = payload.monitor || {};
    host.replaceChildren(card('出站连接观察', keyValues([
      ['运行中', monitor.running ? '是' : '否'],
      ['轮询间隔', `${monitor.interval}s`],
      ['已知 LLM 域名', String(monitor.known_llm_hosts ?? 0)],
      ['DNS 缓存条目', String(monitor.dns_cache_entries ?? 0)],
      ['观测轮次', String(monitor.iterations ?? 0)],
      ['命中次数', String(monitor.hits ?? 0)],
    ]), { actions: [
      monitor.running
        ? button('停止观察', { size: 'small', onClick: () => control('monitor/stop') })
        : button('启动观察', { size: 'small', kind: 'primary', onClick: () => control('monitor/start') }),
    ], hint: '零合作：无需目标 Agent 配置代理或证书' }));
  }

  async function control(path, body = {}) {
    try {
      await fetch(`/api/v1/telemetry/${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }).then(async (response) => {
        if (!response.ok) throw new Error((await response.json()).detail || response.statusText);
      });
      toast('操作已生效', { kind: 'success' });
      await render(ctx);
    } catch (error) {
      toast(error.message, { kind: 'error' });
    }
  }

  return wrapper;
}