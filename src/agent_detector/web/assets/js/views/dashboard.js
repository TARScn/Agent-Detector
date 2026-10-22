// 总览：The four numbers the product promises (design section 1.3) plus the
// channel health that explains how much of them can be trusted.
import { api } from '../api.js';
import { badgeSpec, count, DECISION, PROTECTION, RISK, SOURCE, time } from '../format.js';
import { icon } from '../icons.js';
import {
  badge, bar, button, card, el, empty, note, pageHead, statTile, table, toast,
} from '../ui.js';

// Feed window: one page is fetched at a time (cursor paging, newest first) and
// the DOM holds at most WINDOW_MAX rows, so a long history costs the same as a
// short one. Trimming happens with the scroll position compensated, otherwise
// the list would visibly jump while the user reads it.
const FEED_PAGE_SIZE = 15;
const WINDOW_MAX = 60;

let timer = null;
let feedWindow = null;

export function destroy() {
  if (timer) clearInterval(timer);
  timer = null;
  document.querySelectorAll('.feed-card').forEach((node) => {
    if (node.__heightObserver) node.__heightObserver.disconnect();
  });
  feedWindow = null;
}

export async function render(ctx) {
  const [overview, telemetry] = await Promise.all([
    api.overview().catch((error) => ({ error })),
    api.telemetry().catch(() => null),
  ]);

  const scanning = { busy: false };
  const scanButton = button('立即扫描', {
    kind: 'primary', iconName: 'search',
    onClick: async () => {
      if (scanning.busy) return;
      scanning.busy = true;
      scanButton.disabled = true;
      scanButton.replaceChildren(el('span', { class: 'spinner' }), '扫描中…');
      try {
        const result = await api.scan(false);
        toast(`扫描完成：发现 ${result.assets} 个组件资产，`
          + `${result.agent_assets.length} 个 Agent 资产`, { kind: 'success', title: '扫描完成' });
        await ctx.refresh();
        await render(ctx);
      } catch (error) {
        toast(error.message, { kind: 'error', title: '扫描失败' });
      } finally {
        scanning.busy = false;
      }
    },
  });

  const wrapper = el('div', { class: 'page' }, [
    pageHead({
      title: 'Agent Detector',
      description: '本机 Agent 资产、行为与拦截状态',
      actions: [scanButton, button('刷新', { iconName: 'refresh', onClick: () => render(ctx) })],
    }),
  ]);

  if (overview.error) {
    wrapper.append(card('无法读取总览', [note(`服务返回错误：${overview.error.message}`, 'danger')]));
    return wrapper;
  }

  const agents = overview.agents || {};
  const behavior = overview.behavior || {};
  const protection = agents.protection || {};
  const unprotected = (agents.total || 0) - (protection.PROTECTED || 0);

  wrapper.append(el('div', { class: 'grid grid-4' }, [
    statTile({
      label: '发现 Agent 资产', value: count(agents.total),
      meta: `运行中 ${count(agents.running)}`, tone: 'emphasis',
    }),
    statTile({
      label: '今日行为事件', value: count(behavior.events_today),
      meta: behavior.last_event_at ? `最近 ${time(behavior.last_event_at)}` : '今日暂无',
    }),
    statTile({
      label: '今日已阻断', value: count(behavior.blocked_today),
      meta: behavior.blocked_today ? 'Hook 阻断' : '无阻断',
      tone: behavior.blocked_today ? 'warn' : '',
    }),
    statTile({
      label: '未启用拦截的 Agent', value: count(unprotected),
      meta: protection.PROTECTED ? `已启用 ${protection.PROTECTED}` : '未接入 Hook',
      tone: unprotected ? 'warn' : '',
    }),
  ]));

  // align-row: the right column decides the row height, the feed card fills it
  // and scrolls internally instead of growing with the number of events.
  wrapper.append(el('div', { class: 'grid grid-side align-row' }, [
    behaviorCard(overview, ctx),
    el('div', { class: 'stack', id: 'overview-side' }, [
      protectionCard(agents, protection),
      channelsCard(overview, telemetry),
    ]),
  ]));

  // Full width: the alerts table no longer shares its row with a second card.
  // (The capability-boundary card was removed here — the same caveats are
  // already stated on the protection card above and on the settings page.)
  wrapper.append(alertsCard(overview, ctx));

  timer = setInterval(async () => {
    try {
      const fresh = await api.overview();
      if (feedWindow) feedWindow.prepend(fresh.recent_events || []);
    } catch { /* keep the last good render */ }
  }, 15000);

  return wrapper;
}

function behaviorCard(overview, ctx) {
  const bySource = overview.behavior?.by_source || {};
  const sourceText = Object.entries(bySource)
    .map(([key, value]) => `${(SOURCE[key] || { label: key }).label} ${value}`)
    .join(' · ') || '暂无来源数据';

  const viewport = el('div', { class: 'feed compact feed-viewport', id: 'overview-feed' });
  const footLabel = el('span', { text: '加载中…' });
  const footAction = el('span');
  const feedCard = card('最近行为事件', viewport, {
    hint: sourceText,
    className: 'feed-card',
    actions: [button('全部时间线', { kind: 'subtle', size: 'small',
      onClick: () => ctx.navigate('#/behavior') })],
    footer: el('div', { class: 'feed-window-foot' }, [
      footLabel,
      el('span', { class: 'spacer' }),
      footAction,
    ]),
  });

  feedWindow = createFeedWindow({ viewport, footLabel, footAction, ctx,
    seed: overview.recent_events || [] });
  return feedCard;
}

/**
 * Runs after the page node is in the document (see app.js): sizes the feed to
 * the right column and pulls pages until the window can actually scroll.
 */
export async function mount() {
  const feedCard = document.querySelector('.feed-card');
  const side = document.getElementById('overview-side');
  if (feedCard && side && typeof ResizeObserver === 'function') {
    // Height follows the right column (the grid row stretches); the cap keeps
    // the feed from ever driving the row height with its own content.
    const fit = () => {
      const height = Math.round(side.getBoundingClientRect().height);
      if (height > 0) feedCard.style.maxHeight = `${Math.max(height, 240)}px`;
    };
    fit();
    const observer = new ResizeObserver(fit);
    observer.observe(side);
    feedCard.__heightObserver = observer;
  }
  if (feedWindow) await feedWindow.ensureScrollable();
}

/**
 * Bounded, cursor-paged event feed.
 *
 * - one page per fetch (`before_id` = oldest id held), never the whole table
 * - scrolling to the bottom loads the next page
 * - the DOM is trimmed to WINDOW_MAX rows with scrollTop compensation, so the
 *   reading position survives both trimming and live prepends
 */
function createFeedWindow({ viewport, footLabel, footAction, ctx, seed }) {
  const state = { ids: new Set(), oldest: null, loading: false, exhausted: false,
    pages: 0 };

  function add(event, position) {
    if (state.ids.has(event.id)) return null;
    const node = feedRow(event, ctx);
    state.ids.add(event.id);
    if (position === 'top') viewport.prepend(node); else viewport.append(node);
    state.oldest = state.oldest === null ? event.id : Math.min(state.oldest, event.id);
    return node;
  }

  function trim() {
    const nodes = Array.from(viewport.children);
    const excess = nodes.length - WINDOW_MAX;
    if (excess <= 0) return;
    const heightBefore = viewport.scrollHeight;
    nodes.slice(0, excess).forEach((node) => {
      state.ids.delete(Number(node.dataset.eventId));
      node.remove();
    });
    viewport.scrollTop = Math.max(0, viewport.scrollTop - (heightBefore - viewport.scrollHeight));
  }

  function updateFooter() {
    if (state.loading) footLabel.textContent = '加载中…';
    else if (state.exhausted) footLabel.textContent = `${state.ids.size} 条 · 已到最早`;
    else footLabel.textContent = `${state.ids.size} 条`;
    // Explicit affordance: a window that fits without a scrollbar still has to
    // offer a way to load older events.
    footAction.replaceChildren(state.exhausted || state.loading ? '' :
      button('加载更早', { kind: 'subtle', size: 'small',
        onClick: () => loadMore() }));
  }

  async function loadMore() {
    if (state.loading || state.exhausted || state.oldest === null) return;
    state.loading = true;
    updateFooter();
    try {
      const page = await api.events({ limit: FEED_PAGE_SIZE, before_id: state.oldest });
      const items = (page.items || []).filter((item) => item.id < state.oldest);
      items.sort((a, b) => a.id - b.id).forEach((item) => add(item, 'bottom'));
      state.pages += 1;
      // The server tells us whether history continues (next_before_id is null
      // when the page was short) — never infer it from what we happen to render.
      state.exhausted = !page.next_before_id && items.length < FEED_PAGE_SIZE;
    } catch (error) {
      footLabel.textContent = `加载失败：${error.message}`;
      state.loading = false;
      return;
    }
    state.loading = false;
    trim();
    updateFooter();
  }

  /** Newest events (from the 15s overview poll) go on top of the window. */
  function prepend(events) {
    const fresh = events.filter((event) => !state.ids.has(event.id))
      .sort((a, b) => a.id - b.id);
    if (!fresh.length) return;
    const atTop = viewport.scrollTop < 8;
    const heightBefore = viewport.scrollHeight;
    fresh.forEach((event) => add(event, 'top'));
    if (!atTop) viewport.scrollTop += viewport.scrollHeight - heightBefore;
    trim();
    updateFooter();
  }

  async function fill(events) {
    if (!events.length) {
      viewport.append(empty({ title: '暂无事件', message: '启动采集通道后显示',
        iconName: 'activity' }));
      state.exhausted = true;
      updateFooter();
      return;
    }
    // Newest first: history is read downwards, and older pages are appended at
    // the bottom by loadMore().
    [...events].sort((a, b) => b.id - a.id).forEach((event) => add(event, 'bottom'));
    updateFooter();
  }

  /**
   * The seed is a fixed slice from the dashboard summary, not a paged read, so
   * top the window up until it can scroll (or history ends). Must run after
   * mount: a detached viewport reports 0 for every size.
   */
  async function ensureScrollable() {
    let guard = 0;
    while (!state.exhausted && guard < 10
           && viewport.scrollHeight <= viewport.clientHeight + 8) {
      guard += 1;
      await loadMore();
    }
  }

  viewport.addEventListener('scroll', () => {
    const nearBottom = viewport.scrollTop + viewport.clientHeight
      >= viewport.scrollHeight - 48;
    if (nearBottom) loadMore();
  }, { passive: true });

  fill(seed);
  return { prepend, ensureScrollable, get size() { return state.ids.size; }, viewport };
}

function feedRow(event, ctx) {
  const target = event.target || event.endpoint || '';
  return el('div', {
    class: 'feed-row', dataset: { eventId: event.id }, title: target,
    onClick: () => ctx.navigate('#/behavior'),
  }, [
    el('div', { class: 'feed-time' }, [
      icon((SOURCE[event.source] || { icon: 'activity' }).icon, { size: 13 }),
      ' ',
      time(event.observed_at),
    ]),
    el('div', { class: 'feed-main' }, [
      el('div', { class: 'feed-title' }, [
        el('strong', { text: event.agent_label || '未归属' }),
        el('span', { class: 'muted', text: '·' }),
        el('span', { text: event.operation || event.event_type }),
        badge(badgeSpec(SOURCE, event.source)),
      ]),
      target ? el('div', { class: 'feed-target', text: target }) : null,
    ]),
    el('div', { class: 'feed-meta' }, [
      event.risk_level ? badge(badgeSpec(RISK, event.risk_level)) : null,
      event.decision ? badge(badgeSpec(DECISION, event.decision)) : null,
    ]),
  ]);
}

function protectionCard(agents, protection) {
  const colors = {
    PROTECTED: '#107c10', MONITOR_ONLY: '#0f6cbd', DEGRADED: '#f7630c',
    UNPROTECTED: '#d13438', UNKNOWN: '#a19f9d',
  };
  const segments = ['PROTECTED', 'MONITOR_ONLY', 'DEGRADED', 'UNPROTECTED', 'UNKNOWN']
    .filter((key) => protection[key])
    .map((key) => ({ label: PROTECTION[key].label, value: protection[key], color: colors[key] }));
  const locked = !(protection.PROTECTED);
  return card('保护状态分布', [
    segments.length ? bar(segments) : empty({ title: '暂无 Agent 资产', iconName: 'agent' }),
    el('div', { style: { marginTop: '12px' } }, [
      note(locked ? '未接入 Hook：只能观察，无法在执行前阻断。'
        : `${protection.PROTECTED} 个 Agent 已启用拦截。`,
      locked ? 'warning' : 'info',
      locked ? 'warning' : 'shield'),
    ]),
  ], { hint: `${count(agents.total)} 个 Agent` });
}

function channelsCard(overview, telemetry) {
  const channels = overview.channels || [];
  return card('采集通道', channels.map((channel) => el('div', {
    class: 'channel-row', title: channel.detail,
  }, [
    el('span', { class: 'channel-name', text: channel.name }),
    badge({ label: channel.running ? '运行中' : '未运行',
      cls: channel.running ? 'success' : 'outline', dot: true }),
  ])), { hint: telemetry ? telemetry.host_platform : '' });
}

function alertsCard(overview, ctx) {
  const alerts = overview.recent_alerts || [];
  const stats = overview.alerts || {};
  return card('风险告警', alerts.length
    ? table([
      { label: '时间', width: '150px', render: (row) => el('span', { class: 'muted', text: time(row.created_at) }) },
      { label: '等级', width: '70px', render: (row) => badge(badgeSpec(RISK, row.risk_level)) },
      { label: '处置', width: '80px', render: (row) => badge(badgeSpec(DECISION, row.decision)) },
      { label: '内容', render: (row) => el('span', { text: row.title }) },
      { label: '状态', width: '90px', render: (row) => badge({ label: row.status, cls: 'outline' }) },
    ], alerts, { onRowClick: () => ctx.navigate('#/alerts') })
    : empty({ title: '暂无告警', message: '命中策略或风险达阈值时出现',
      iconName: 'alert' }), {
    hint: `未处理高危 ${stats.open_high || 0} / ${stats.alert_count || 0}`,
    flush: true,
    actions: [button('全部告警', { kind: 'subtle', size: 'small',
      onClick: () => ctx.navigate('#/alerts') })],
  });
}