// 安全策略：deterministic rules, their conditions, and the operator overrides.
// The page makes the decision order visible — the first matching rule wins — so
// "why was this blocked" is answerable without reading YAML.
import { api } from '../api.js';
import { badgeSpec, DECISION, RISK } from '../format.js';
import { icon } from '../icons.js';
import {
  badge, button, card, drawer, el, empty, keyValues, note, pageHead, switchControl, table, toast, todo,
} from '../ui.js';

export async function render(ctx) {
  const payload = await api.policies();
  const items = payload.items || [];
  const wrapper = el('div', { class: 'page' }, [
    pageHead({
      title: '安全策略',
      description: '命中即阻断；未命中仅记录',
      actions: [
        button('重新加载规则', { iconName: 'refresh', onClick: async () => {
          try {
            const result = await api.reloadPolicies();
            toast(`已加载 ${result.status.rules} 条规则（决策引擎：确定性）`, { kind: 'success' });
            await render(ctx);
          } catch (error) { toast(error.message, { kind: 'error' }); }
        } }),
      ],
    }),
  ]);

  wrapper.append(el('div', { class: 'grid grid-4' }, [
    tile('规则总数', String(items.length), '内置 + 外部覆盖'),
    tile('阻断规则', String(items.filter((item) => item.decision === 'deny').length), '命中即拒绝'),
    tile('需确认规则', String(items.filter((item) => item.decision === 'ask').length), '交由用户判断'),
    tile('故障处置', payload.failure_mode === 'block' ? '故障关闭' : '审计放行',
      payload.failure_mode === 'block' ? '服务不可用时阻断' : '服务不可用时放行'),
  ]));

  wrapper.append(el('div', {}, [
    card('策略清单', items.length ? table([
      { label: '顺序', width: '64px', class: 'num', render: (row) => String(row.priority) },
      { label: '规则', render: (row) => el('div', {}, [
        el('div', { class: 'primary-cell', text: row.name }),
        el('div', { class: 'muted mono', text: row.policy_id }),
      ]) },
      { label: '决策', width: '140px', render: (row) => decisionSelect(row) },
      { label: '风险', width: '90px', render: (row) => badge(badgeSpec(RISK, row.risk_level)) },
      { label: '作用域', width: '110px', render: (row) => badge({ label: row.scope, cls: 'outline' }) },
      { label: '条件', render: (row) => conditionSummary(row) },
      { label: '启用', width: '80px', render: (row) => switchControl(row.enabled, async (next) => {
        try {
          await api.updatePolicy(row.policy_id, { enabled: next });
          toast(`${row.name} 已${next ? '启用' : '停用'}`, { kind: 'success' });
        } catch (error) {
          toast(error.message, { kind: 'error' });
          throw error;
        }
      }, { title: '启用 / 停用该策略' }) },
      { label: '', width: '48px', render: (row) => el('button', {
        class: 'icon-btn', type: 'button', title: '查看条件与原因',
        onClick: () => showRule(row),
      }, [icon('chevron', { size: 14 })]) },
    ], items) : empty({
      title: '没有加载到策略规则',
      message: '检查 AGENT_DETECTOR_POLICY_DIR 与内置 policy/rules/policies.yaml。',
      iconName: 'shield',
    }), { flush: true }),
  ]));

  wrapper.append(el('div', { class: 'grid grid-2' }, [
    card('修改方式', [
      el('ul', { class: 'plain-list tight' }, [
        el('li', { text: '规则文件：policy/rules/policies.yaml 或外部覆盖目录。' }),
        el('li', { text: '本页只覆盖“启用状态”与“决策”，不改规则文件。' }),
        el('li', { text: '命令行自测：agent-detector policy test --command "…"' }),
      ]),
    ]),
    card('待开发', [
      el('ul', { class: 'plain-list tight' }, [
        el('li', {}, ['策略可视化编辑 ', todo('待开发')]),
        el('li', {}, ['按目录 / 域名允许列表 ', todo('待开发')]),
        el('li', {}, ['策略签名与托管下发 ', todo('待开发')]),
      ]),
    ]),
  ]));

  function decisionSelect(row) {
    const select = el('select', { title: '运行时可把决策改为更保守或更宽松的值' });
    ['allow', 'ask', 'deny', 'audit'].forEach((value) => {
      select.append(el('option', {
        value, text: badgeSpec(DECISION, value).label,
        selected: row.decision === value,
      }));
    });
    select.addEventListener('change', async () => {
      try {
        await api.updatePolicy(row.policy_id, { decision: select.value });
        toast(`${row.name} 决策已改为 ${badgeSpec(DECISION, select.value).label}`,
          { kind: 'success' });
      } catch (error) {
        toast(error.message, { kind: 'error' });
        select.value = row.decision;
      }
    });
    return select;
  }

  function conditionSummary(row) {
    const conditions = row.conditions || {};
    const parts = Object.entries(conditions).map(([key, value]) => {
      const text = Array.isArray(value) ? value.join(' | ') : String(value);
      return `${key}: ${text}`;
    });
    return el('span', { class: 'muted mono', title: parts.join('\n'),
      text: parts.join(' , ').slice(0, 96) || '—' });
  }

  function showRule(row) {
    const conditions = row.conditions || {};
    const body = [
      card('规则', keyValues([
        ['ID', row.policy_id],
        ['名称', row.name],
        ['优先级', String(row.priority)],
        ['决策', badge(badgeSpec(DECISION, row.decision))],
        ['风险', badge(badgeSpec(RISK, row.risk_level))],
        ['原因', row.reason],
      ])),
    ];
    const conditionCard = card('匹配条件', el('div', {}, Object.entries(conditions).map(([key, value]) => el('div', {
      style: { marginBottom: '8px' },
    }, [
      el('div', { style: { fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }, text: key }),
      el('div', { class: 'code', text: Array.isArray(value) ? value.join('\n') : String(value) }),
    ]))));
    body.push(conditionCard);
    body.push(note('字段间 AND，列表内 OR；path_patterns 支持 * 与 **。', 'info', 'info'));
    drawer({ title: row.name, subtitle: row.policy_id, body });
  }

  return wrapper;
}

function tile(label, value, meta) {
  return el('div', { class: 'card stat' }, [
    el('div', { class: 'label', text: label }),
    el('div', { class: 'value', text: value }),
    el('div', { class: 'meta', text: meta }),
  ]);
}