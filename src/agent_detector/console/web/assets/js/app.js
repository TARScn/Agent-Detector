// Console shell: top command bar, grouped navigation, route outlet.
//
// The navigation shows live system state (channel health, open alerts) so the
// user can see at a glance what is actually running — the console never shows a
// green light for a channel the backend reports as unavailable.
import { api } from './api.js';
import { badgeSpec, count, PROTECTION } from './format.js';
import { icon } from './icons.js';
import { currentRoute, navigate, onRouteChange } from './router.js';
import { badge, button, el, toast } from './ui.js';
import * as dashboard from './views/dashboard.js';
import * as agents from './views/agents.js';
import * as behavior from './views/behavior.js';
import * as policies from './views/policies.js';
import * as alerts from './views/alerts.js';
import * as settings from './views/settings.js';

const VIEWS = { dashboard, agents, behavior, policies, alerts, settings };

const NAV_SECTIONS = [
  {
    label: '监测',
    items: [
      { id: 'dashboard', label: '总览', icon: 'grid', href: '#/overview' },
      { id: 'agents', label: 'Agent 资产', icon: 'agent', href: '#/agents', countKey: 'agents' },
      { id: 'behavior', label: '行为时间线', icon: 'activity', href: '#/behavior' },
    ],
  },
  {
    label: '治理',
    items: [
      { id: 'policies', label: '安全策略', icon: 'shield', href: '#/policies', countKey: 'policies' },
      { id: 'alerts', label: '风险告警', icon: 'alert', href: '#/alerts', countKey: 'alerts' },
      { id: 'settings', label: '设置', icon: 'settings', href: '#/settings' },
    ],
  },
];

const state = {
  overview: null,
  activeView: null,
  query: '',
};

export function boot() {
  const root = document.getElementById('root');
  root.className = 'app';

  const searchInput = el('input', {
    type: 'search', placeholder: '搜索 Agent、事件或命令…', 'aria-label': '搜索',
  });
  const topbar = el('header', { class: 'topbar' }, [
    el('div', { class: 'brand' }, [
      el('span', { class: 'brand-mark' }, [icon('shield', { size: 16 })]),
      el('span', {}, ['Agent Detector ', el('span', { class: 'brand-sub', text: 'V0.2' })]),
    ]),
    el('div', { class: 'topbar-search' }, [icon('search', { size: 16 }), searchInput]),
    el('div', { class: 'topbar-right' }, [
      el('span', { class: 'chip', id: 'chip-mode' }, [el('span', { class: 'dot' }), '读取中…']),
      el('div', { class: 'avatar', text: '本机' }),
    ]),
  ]);

  const nav = el('nav', { class: 'nav', id: 'nav' });
  const main = el('main', { class: 'main' });
  root.append(topbar, nav, main);
  buildNav();

  searchInput.addEventListener('input', () => { state.query = searchInput.value.trim().toLowerCase(); });
  searchInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && state.query) navigate('#/behavior');
  });

  onRouteChange(render);
  refreshChrome();
  setInterval(refreshChrome, 30000);
  render();
}

async function refreshChrome() {
  try {
    const overview = await api.overview();
    state.overview = overview;
    paintTopbar(overview);
    updateNav(overview);
  } catch (error) {
    const chip = document.getElementById('chip-mode');
    if (chip) {
      chip.className = 'chip off';
      chip.replaceChildren(el('span', { class: 'dot' }), '服务不可用');
    }
    console.error(error);
  }
}

function paintTopbar(overview) {
  const chip = document.getElementById('chip-mode');
  if (!chip) return;
  const channels = overview.channels || [];
  const live = channels.filter((item) => item.running).length;
  const hook = channels.find((item) => item.id === 'native_hook');
  const protectedCount = overview.agents?.protection?.PROTECTED || 0;
  chip.className = `chip ${protectedCount ? 'live' : 'off'}`;
  const detail = hook && !protectedCount
    ? '拦截未启用'
    : `${live} 个通道在运行`;
  chip.replaceChildren(el('span', { class: 'dot' }), detail);
  chip.title = (channels.map((item) => `${item.name}: ${item.detail}`) || []).join('\n');
}

const NAV_ITEM_BY_ID = Object.fromEntries(
  NAV_SECTIONS.flatMap((section) => section.items).map((item) => [item.id, item]));

/** Navigation DOM is created once; later updates only touch classes and text. */
function buildNav() {
  const nav = document.getElementById('nav');
  if (!nav) return;
  const items = NAV_SECTIONS.flatMap((section) => [
    el('div', { class: 'nav-group', text: section.label }),
    ...section.items.map((item) => el('a', {
      class: 'nav-item', href: item.href, dataset: { view: item.id },
    }, [
      icon(item.icon, { size: 18 }),
      el('span', { text: item.label }),
    ])),
  ]);
  nav.replaceChildren(...items, el('div', { class: 'nav-status', id: 'nav-status' }));
  updateNav(state.overview);
}

/** Refresh the active marker, the count badges and the channel status box. */
function updateNav(overview) {
  const route = currentRoute();
  const counts = {
    agents: overview?.agents?.total,
    alerts: overview?.alerts?.open_high,
    policies: overview?.policy_rules,
  };
  document.querySelectorAll('.nav-item').forEach((node) => {
    node.classList.toggle('active', node.dataset.view === route.view);
    const item = NAV_ITEM_BY_ID[node.dataset.view];
    const value = item?.countKey ? counts[item.countKey] : null;
    const existing = node.querySelector('.count');
    if (value) {
      if (existing) existing.textContent = count(value);
      else node.append(el('span', { class: 'count', text: count(value) }));
    } else if (existing) {
      existing.remove();
    }
  });
  paintNavStatus(overview);
}

function paintNavStatus(overview) {
  const box = document.getElementById('nav-status');
  if (!box) return;
  const channels = overview?.channels || [];
  const rows = [el('h4', { text: '采集通道' })];
  if (!channels.length) {
    rows.push(el('div', { class: 'row' }, ['状态未知']));
  } else {
    channels.forEach((channel) => {
      // The hook channel is not a process that "runs": it is installed per Agent,
      // so the label reflects installation, not liveness.
      const label = channel.id === 'native_hook'
        ? (channel.running ? '已接入' : '未安装')
        : (channel.running ? '运行中' : '未运行');
      rows.push(el('div', { class: 'row', title: channel.detail }, [
        el('span', { text: channel.name }),
        badge({ label, cls: channel.running ? 'success' : 'outline' }),
      ]));
    });
    rows.push(el('div', { class: 'row', title: '本工具不会声称提供它没有的保护能力' }, [
      el('span', { text: '拦截' }),
      badge(badgeSpec(PROTECTION,
        (overview?.agents?.protection?.PROTECTED ? 'PROTECTED' : 'MONITOR_ONLY'))),
    ]));
  }
  box.replaceChildren(...rows);
}

async function render() {
  const route = currentRoute();
  const main = document.querySelector('.main');
  if (!main) return;
  updateNav(state.overview);
  const view = VIEWS[route.view] || dashboard;
  if (state.activeView && state.activeView.destroy) {
    try { state.activeView.destroy(); } catch (error) { console.warn(error); }
  }
  main.replaceChildren();
  const context = {
    params: route.params,
    query: state.query,
    navigate,
    toast,
    refresh: refreshChrome,
    overview: state.overview,
  };
  state.activeView = view;
  try {
    const node = await view.render(context);
    main.replaceChildren(node);
    main.scrollTop = 0;
    // Views that must measure or scroll something need the node in the document
    // first; before that every offset/client size is 0.
    if (typeof view.mount === 'function') await view.mount(context);
  } catch (error) {
    console.error(error);
    main.replaceChildren(el('div', { class: 'card' }, el('div', { class: 'card-body' }, [
      el('h2', { text: '页面加载失败' }),
      el('p', { text: String(error.message || error) }),
      el('div', { style: { marginTop: '12px' } }, [button('重试', {
        kind: 'primary', onClick: () => render(),
      })]),
    ])));
  }
}

export function statusBadge(map, key) {
  return badge(badgeSpec(map, key));
}