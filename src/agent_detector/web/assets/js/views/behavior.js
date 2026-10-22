// 行为时间线：one feed for every channel (hook / Sysmon / auditd / poll / netmon),
// with live tailing over SSE and an evidence panel per event.
import { api, eventStreamUrl } from '../api.js';
import { badgeSpec, count, commandText, DECISION, RISK, SOURCE, time } from '../format.js';
import { icon } from '../icons.js';
import {
  badge, button, card, el, empty, fragment, pageHead, segmented,
} from '../ui.js';

const SOURCE_FILTERS = [
  { value: '', label: '全部' },
  { value: 'native_hook', label: 'Agent Hook' },
  { value: 'sysmon', label: 'Sysmon' },
  { value: 'auditd', label: 'auditd' },
  { value: 'poll', label: '进程采样' },
  { value: 'netmon', label: '网络调用' },
];

const RISK_FILTERS = [
  { value: '', label: '全部等级' },
  { value: 'high', label: '高及以上' },
  { value: 'medium', label: '中' },
  { value: 'low', label: '低' },
];

let stream = null;

export function destroy() {
  if (stream) {
    stream.close();
    stream = null;
  }
}

export async function render(ctx) {
  const filters = { source: '', risk: '', eventType: '', agent: ctx.query || '' };
  const live = { on: true };

  const toolbar = el('div', { class: 'toolbar' });
  const feedHost = el('div', { class: 'feed' });
  const wrapper = el('div', { class: 'page' }, [
    pageHead({
      title: '行为时间线',
      description: '所有采集通道的统一事件流',
      actions: [
        button('导出 JSON', { iconName: 'file', onClick: async () => {
          const payload = await api.events({ limit: 500, ...filters });
          const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const anchor = el('a', { href: url, download: 'agent-detector-events.json' });
          anchor.click();
          URL.revokeObjectURL(url);
        } }),
        button('刷新', { iconName: 'refresh', onClick: () => load() }),
      ],
    }),
  ]);

  const summary = el('div', { class: 'grid grid-4' });
  wrapper.append(summary, card('实时事件流', feedHost, {
    flush: true,
    hint: 'SSE 实时推送，等待时保持连接',
    actions: [toolbar],
  }));

  wrapper.append(el('div', {}, [
  ]));

  paintToolbar(toolbar, filters, live, () => load());

  async function load() {
    feedHost.replaceChildren(el('div', { class: 'empty' }, [el('span', { class: 'spinner' })]));
    const [events, stats] = await Promise.all([
      api.events({ limit: 120, ...filters }),
      api.events({ limit: 1, ...filters }).then(() => api.eventStats(
        filters.source ? { source: filters.source } : {})),
    ]);
    summary.replaceChildren(...statTiles(stats, events.items || []));
    feedHost.replaceChildren(...(events.items || []).map((event) => row(event)));
    if (!(events.items || []).length) {
      feedHost.replaceChildren(empty({
        title: '暂无事件',
        message: '启动采集通道或执行一次工具调用',
        iconName: 'activity',
      }));
    }
  }

  function row(event) {
    const detailHost = el('div', { style: { display: 'none' } });
    const row_ = el('div', { class: 'feed-row' }, [
      el('div', { class: 'feed-time' }, [icon((SOURCE[event.source] || { icon: 'activity' }).icon, { size: 13 }),
        ' ', time(event.observed_at)]),
      el('div', { class: 'feed-main' }, [
        el('div', { class: 'feed-title' }, [
          el('strong', { text: event.agent_label || '未归属' }),
          el('span', { text: event.operation || event.event_type || '—' }),
          badge(badgeSpec(SOURCE, event.source)),
          event.confidence ? badge({ label: `置信度 ${event.confidence}`, cls: 'outline' }) : null,
        ]),
        event.target || event.endpoint
          ? el('div', { class: 'feed-target', text: commandText(event.target || event.endpoint) })
          : null,
        detailHost,
      ]),
      el('div', { class: 'feed-meta' }, [
        event.risk_level ? badge(badgeSpec(RISK, event.risk_level)) : null,
        event.decision ? badge(badgeSpec(DECISION, event.decision)) : null,
        event.execution_status ? badge({ label: event.execution_status, cls: 'outline' }) : null,
        el('button', { class: 'icon-btn', type: 'button', title: '查看证据', onClick: () => {
          const open = detailHost.style.display === 'block';
          detailHost.style.display = open ? 'none' : 'block';
          if (!open && !detailHost.childElementCount) detailHost.append(evidence(event));
        } }, [icon('chevron', { size: 14 })]),
      ]),
    ]);
    return row_;
  }

  function evidence(event) {
    const pairs = [
      ['事件 ID', `#${event.id}`],
      ['来源', (SOURCE[event.source] || { label: event.source }).label],
      ['事件类型', event.event_type],
      ['操作', event.operation],
      ['进程', event.process_name ? `${event.process_name} (pid ${event.pid || '—'})` : '—'],
      ['父进程 PID', event.ppid],
      ['会话', event.session_id],
      ['实例', event.instance_id],
      ['资产', event.asset_id],
      ['策略', event.policy_id],
      ['执行状态', event.execution_status],
      ['结果', event.result],
    ].filter(([, value]) => value !== undefined && value !== null && value !== '');
    return fragment([
      el('div', { class: 'feed-detail' }, [
        ...pairs.map(([key, value]) => el('div', {}, [
          el('strong', { text: `${key}: ` }), String(value),
        ])),
        el('div', { style: { marginTop: '6px' } }, [
          el('strong', { text: '证据标签: ' }),
          (event.evidence || []).join(' · ') || '—',
        ]),
      ]),
    ]);
  }

  function paintToolbar(host, state_, liveState, reload) {
    const typeInput = el('input', { type: 'text', placeholder: '事件类型，如 proc.exec',
      value: state_.eventType, style: { width: '190px' } });
    const agentInput = el('input', { type: 'text', placeholder: 'Agent 名称',
      value: state_.agent || '', style: { width: '150px' } });
    typeInput.addEventListener('change', () => { state_.eventType = typeInput.value.trim(); reload(); });
    agentInput.addEventListener('change', () => { state_.agent = agentInput.value.trim(); reload(); });
    host.replaceChildren(
      segmented(SOURCE_FILTERS, state_.source, (value) => {
        state_.source = value; paintToolbar(host, state_, liveState, reload); reload(); startStream();
      }),
      segmented(RISK_FILTERS, state_.risk, (value) => {
        state_.risk = value; paintToolbar(host, state_, liveState, reload); reload();
      }),
      typeInput,
      agentInput,
      el('span', { class: 'spacer' }),
      liveButton(liveState, startStream),
    );
  }

  function liveButton(liveState, restart) {
    return button(liveState.on ? '实时已开启' : '实时已暂停', {
      kind: liveState.on ? 'primary' : 'secondary', size: 'small',
      iconName: liveState.on ? 'stop' : 'play',
      onClick: () => {
        liveState.on = !liveState.on;
        restart();
        paintToolbar(toolbar, filters, liveState, load);
      },
    });
  }

  function startStream() {
    if (stream) { stream.close(); stream = null; }
    if (!live.on) return;
    stream = new EventSource(eventStreamUrl(filters.source ? { source: filters.source } : {}));
    stream.addEventListener('event', (message) => {
      try {
        const event = JSON.parse(message.data);
        if (filters.risk && !matchesRisk(event.risk_level, filters.risk)) return;
        if (filters.eventType && event.event_type !== filters.eventType) return;
        if (filters.agent && !(event.agent_label || '').toLowerCase().includes(filters.agent.toLowerCase())) return;
        feedHost.prepend(row(event));
        while (feedHost.childElementCount > 200) feedHost.lastElementChild.remove();
      } catch (error) { console.warn(error); }
    });
    stream.onerror = () => { /* EventSource reconnects on its own */ };
  }

  await load();
  startStream();
  return wrapper;
}

function matchesRisk(risk, filter) {
  const order = { low: 0, medium: 1, high: 2, critical: 3 };
  if (!risk) return false;
  if (filter === 'high') return order[risk] >= 2;
  return risk === filter;
}

function statTiles(stats, items) {
  const blocked = items.filter((item) => item.decision === 'deny').length;
  const bySource = Object.entries(stats.by_source || {})
    .map(([key, value]) => `${(SOURCE[key] || { label: key }).label} ${value}`)
    .join(' · ') || '暂无来源数据';
  return [
    tile('事件总数', count(stats.event_count), bySource),
    tile('已阻断', count(blocked), 'decision=deny'),
    tile('Agent Hook 事件', count((stats.by_source || {}).native_hook || 0),
      'Agent 主动上报'),
    tile('高风险事件', count(highRiskCount(stats)), '风险分级与策略命中'),
  ];
}

function highRiskCount(stats) {
  const byRisk = stats.by_risk || {};
  return (byRisk.high || 0) + (byRisk.critical || 0);
}

function tile(label, value, meta) {
  return el('div', { class: 'card stat' }, [
    el('div', { class: 'label', text: label }),
    el('div', { class: 'value', text: value }),
    el('div', { class: 'meta', text: meta }),
  ]);
}