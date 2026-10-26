// Minimal hash router: hash routes keep the console deployable as plain static
// files behind any path, with no server rewrite rules.

const routes = [
  { pattern: /^#\/overview$/, view: 'dashboard', title: '总览' },
  { pattern: /^#\/agents$/, view: 'agents', title: 'Agent 资产' },
  { pattern: /^#\/agents\/(.+)$/, view: 'agents', title: 'Agent 详情', params: ['assetId'] },
  { pattern: /^#\/behavior$/, view: 'behavior', title: '行为时间线' },
  { pattern: /^#\/policies$/, view: 'policies', title: '安全策略' },
  { pattern: /^#\/alerts$/, view: 'alerts', title: '风险告警' },
  { pattern: /^#\/settings$/, view: 'settings', title: '设置' },
];

export function currentRoute() {
  const hash = window.location.hash || '#/overview';
  for (const route of routes) {
    const match = route.pattern.exec(hash);
    if (!match) continue;
    const params = {};
    (route.params || []).forEach((name, index) => { params[name] = decodeURIComponent(match[index + 1]); });
    return { view: route.view, title: route.title, params, hash };
  }
  return { view: 'dashboard', title: '总览', params: {}, hash: '#/overview' };
}

export function navigate(hash) {
  if (window.location.hash === hash) {
    window.dispatchEvent(new HashChangeEvent('hashchange'));
    return;
  }
  window.location.hash = hash;
}

export function onRouteChange(handler) {
  window.addEventListener('hashchange', handler);
}