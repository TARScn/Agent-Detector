// 风险告警：what crossed the risk bar, why, and what the operator did about it.
import { api } from '../api.js';
import { badgeSpec, DECISION, RISK, time } from '../format.js';
import {
  badge, button, card, drawer, el, empty, fragment, keyValues, note, pageHead, segmented, table, toast, todo,
} from '../ui.js';

const STATUS_FILTERS = [
  { value: '', label: '全部' },
  { value: 'open', label: '未处理' },
  { value: 'acknowledged', label: '已确认' },
  { value: 'resolved', label: '已解决' },
];

const STATUS_META = {
  open: { label: '未处理', cls: 'danger' },
  acknowledged: { label: '已确认', cls: 'warning' },
  resolved: { label: '已解决', cls: 'success' },
};

export async function render(ctx) {
  const state = { status: '' };
  const summary = el('div', { class: 'grid grid-4' });
  const host = el('div');

  const wrapper = el('div', { class: 'page' }, [
    pageHead({
      title: '风险告警',
      description: '阻断与高风险事件的记录',
      actions: [button('刷新', { iconName: 'refresh', onClick: () => load() })],
    }),
    summary,
    el('div', {}, [host]),
  ]);

  async function load() {
    const payload = await api.alerts({ limit: 200, status: state.status });
    const items = payload.items || [];
    summary.replaceChildren(...[
      tile('告警总数', String(payload.stats.alert_count), '全部状态'),
      tile('未处理高危', String(payload.stats.open_high), 'high / critical'),
      tile('已阻断', String(items.filter((item) => item.decision === 'deny').length),
        'decision=deny'),
      tile('风险分布', Object.entries(payload.stats.by_risk || {})
        .map(([key, value]) => `${badgeSpec(RISK, key).label}${value}`).join(' ') || '—',
        '按等级统计'),
    ]);
    host.replaceChildren(card('告警清单', items.length ? table([
      { label: '时间', width: '150px', render: (row) => el('span', { class: 'muted',
        text: time(row.created_at) }) },
      { label: '等级', width: '80px', render: (row) => badge(badgeSpec(RISK, row.risk_level)) },
      { label: '处置', width: '90px', render: (row) => badge(badgeSpec(DECISION, row.decision)) },
      { label: 'Agent', width: '150px', render: (row) => row.agent_label || row.agent_type || '—' },
      { label: '内容', render: (row) => el('div', {}, [
        el('div', { class: 'primary-cell', text: row.title }),
        el('div', { class: 'muted', text: row.reason }),
      ]) },
      { label: '状态', width: '100px', render: (row) => badge(badgeSpec(STATUS_META, row.status)) },
      { label: '操作', width: '170px', render: (row) => fragment([
        row.status === 'open'
          ? button('确认', { size: 'small', onClick: (event) => {
            event.stopPropagation(); update(row.id, 'acknowledged'); } })
          : null,
        row.status !== 'resolved'
          ? button('解决', { size: 'small', kind: 'subtle', onClick: (event) => {
            event.stopPropagation(); update(row.id, 'resolved'); } })
          : null,
      ]) },
    ], items, { onRowClick: (row) => showAlert(row) }) : empty({
      title: '暂无告警',
      message: '命中策略或风险达阈值时出现',
      iconName: 'alert',
    }), {
      flush: true,
      hint: `当前筛选：${STATUS_FILTERS.find((item) => item.value === state.status)?.label || '全部'}`,
      actions: [segmented(STATUS_FILTERS, state.status, (value) => {
        state.status = value; load();
      })],
    }));
  }

  async function update(id, status) {
    try {
      await api.updateAlert(id, status);
      toast(`告警 #${id} 已标记为${STATUS_META[status].label}`, { kind: 'success' });
      await load();
      await ctx.refresh();
    } catch (error) {
      toast(error.message, { kind: 'error' });
    }
  }

  function showAlert(row) {
    drawer({
      title: row.title,
      subtitle: `告警 #${row.id} · ${time(row.created_at)}`,
      body: [
        card('告警', [
          keyValues([
            ['风险等级', badge(badgeSpec(RISK, row.risk_level))],
            ['决策', badge(badgeSpec(DECISION, row.decision))],
            ['状态', badge(badgeSpec(STATUS_META, row.status))],
            ['Agent', row.agent_label || row.agent_type],
            ['资产', row.asset_id],
            ['会话', row.session_id],
            ['策略', row.policy_id],
            ['关联事件', row.event_id ? `#${row.event_id}` : '—'],
            ['原因', row.reason],
          ]),
        ]),
        card('明细', [el('div', { class: 'code', text: JSON.stringify(row.detail || {}, null, 2) })]),
        note('系统行为类告警仅记录，不阻断调用。', 'info', 'info'),
        el('div', {}, todo('告警抑制与通知渠道')),
      ],
      actions: [button('标记为已解决', { kind: 'primary', onClick: () => {
        update(row.id, 'resolved');
      } })],
    });
  }

  await load();
  return wrapper;
}

function tile(label, value, meta) {
  return el('div', { class: 'card stat' }, [
    el('div', { class: 'label', text: label }),
    el('div', { class: 'value', text: value }),
    el('div', { class: 'meta', text: meta }),
  ]);
}