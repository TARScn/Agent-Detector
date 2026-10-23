// Small DOM component helpers shared by all views. No framework: `el()` builds
// nodes, everything else is composition, which keeps the console build-free.
import { icon } from './icons.js';

export function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  Object.entries(props).forEach(([key, value]) => {
    if (value === undefined || value === null || value === false) return;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key === 'html') node.innerHTML = value;
    else if (key === 'style') Object.assign(node.style, value);
    else if (key.startsWith('on') && typeof value === 'function') {
      node.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (key === 'dataset') Object.assign(node.dataset, value);
    else node.setAttribute(key, value === true ? '' : value);
  });
  const list = Array.isArray(children) ? children : [children];
  list.flat().forEach((child) => {
    if (child === null || child === undefined || child === false) return;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  });
  return node;
}

export function fragment(children) {
  const node = document.createDocumentFragment();
  (Array.isArray(children) ? children : [children]).flat().forEach((child) => {
    if (child === null || child === undefined || child === false) return;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  });
  return node;
}

export function badge(spec, extra = '') {
  return el('span', { class: `badge ${spec.cls || ''} ${extra}`.trim() },
    [spec.dot ? el('span', { class: 'dot' }) : null, spec.label]);
}

export function card(title, body, { actions = [], hint = '', flush = false, footer,
  className = '' } = {}) {
  const head = title === null ? null : el('div', { class: 'card-head' }, [
    el('h2', { text: title }),
    hint ? el('span', { class: 'hint', text: hint }) : null,
    actions.length ? el('div', { class: 'card-head-actions' }, actions) : null,
  ]);
  return el('section', { class: `card ${className}`.trim() }, [
    head,
    el('div', { class: `card-body ${flush ? 'flush' : ''}`.trim() }, body),
    footer ? el('div', { class: 'card-foot' }, footer) : null,
  ]);
}

export function statTile({ label, value, meta, tone = '' }) {
  return el('div', { class: `card stat ${tone}`.trim() }, [
    el('div', { class: 'label', text: label }),
    el('div', { class: 'value', text: value }),
    meta ? el('div', { class: 'meta' }, meta) : null,
  ]);
}

export function button(label, { onClick, kind = 'secondary', size = '', iconName, disabled,
  title } = {}) {
  const node = el('button', {
    class: `btn ${kind} ${size}`.trim(), type: 'button', onClick, disabled, title,
  }, [iconName ? icon(iconName, { size: 16 }) : null, label]);
  return node;
}

export function iconButton(name, { onClick, title } = {}) {
  return el('button', { class: 'icon-btn', type: 'button', onClick, title }, [icon(name, { size: 16 })]);
}

export function switchControl(checked, onChange, { title } = {}) {
  const node = el('button', {
    class: 'switch', type: 'button', role: 'switch', title,
    'aria-checked': String(Boolean(checked)),
    onClick: async () => {
      const next = node.getAttribute('aria-checked') !== 'true';
      node.setAttribute('aria-checked', String(next));
      try {
        await onChange(next);
      } catch (error) {
        node.setAttribute('aria-checked', String(!next));
        throw error;
      }
    },
  });
  return node;
}

export function segmented(options, current, onSelect) {
  return el('div', { class: 'segmented', role: 'group' },
    options.map((option) => el('button', {
      type: 'button',
      'aria-pressed': String(option.value === current),
      text: option.label,
      onClick: () => onSelect(option.value),
    })));
}

export function empty({ title, message, iconName = 'info' } = {}) {
  return el('div', { class: 'empty' }, [
    icon(iconName, { size: 24 }),
    el('h3', { text: title || '暂无数据' }),
    message ? el('p', { text: message }) : null,
  ]);
}

export function note(text, tone = 'info', iconName = 'info') {
  return el('div', { class: `note ${tone}`.trim() }, [icon(iconName, { size: 16 }), el('span', { text })]);
}

export function todo(text) {
  return el('span', { class: 'todo', text });
}

export function keyValues(pairs) {
  const list = el('dl', { class: 'kv' });
  pairs.forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return;
    list.append(el('dt', { text: key }));
    list.append(el('dd', {}, [value instanceof Node ? value : document.createTextNode(String(value))]));
  });
  return list;
}

export function table(columns, rows, { onRowClick, emptyState } = {}) {
  if (!rows.length) return emptyState || empty({});
  const head = el('thead', {}, [
    el('tr', {}, columns.map((column) => el('th', {
      text: column.label,
      style: column.width ? { width: column.width } : undefined,
    }))),
  ]);
  const body = el('tbody', {}, rows.map((row) => el('tr', {
    class: onRowClick ? 'clickable' : '',
    onClick: onRowClick ? () => onRowClick(row) : undefined,
  }, columns.map((column) => {
    const value = column.render ? column.render(row) : row[column.key];
    const cell = value instanceof Node ? value : document.createTextNode(
      value === undefined || value === null || value === '' ? '—' : String(value));
    return el('td', { class: column.class || '' }, [cell]);
  }))));
  return el('div', { class: 'table-wrap' }, [el('table', { class: 'table' }, [head, body])]);
}

export function bar(segments, total) {
  const sum = total || segments.reduce((acc, item) => acc + item.value, 0) || 1;
  const node = el('div', { class: 'bar' }, segments.map((item) => el('span', {
    style: { width: `${(item.value / sum) * 100}%`, background: item.color },
    title: `${item.label}: ${item.value}`,
  })));
  const legend = el('div', { class: 'legend' }, segments.map((item) => el('span', {}, [
    el('i', { style: { background: item.color } }),
    `${item.label} ${item.value}`,
  ])));
  return fragment([node, legend]);
}

export function toast(message, { title = '', kind = '' } = {}) {
  let host = document.querySelector('.toast-host');
  if (!host) {
    host = el('div', { class: 'toast-host' });
    document.body.append(host);
  }
  const node = el('div', { class: `toast ${kind}`.trim() }, [
    title ? el('div', { class: 'title', text: title }) : null,
    el('div', { text: message }),
  ]);
  host.append(node);
  setTimeout(() => node.remove(), kind === 'error' ? 7000 : 4000);
}

export function loading(text = '加载中…') {
  return el('div', { class: 'empty' }, [el('span', { class: 'spinner' }), el('p', { text })]);
}

export function drawer({ title, subtitle, body, onClose, actions = [] }) {
  const overlay = el('div', { class: 'overlay', onClick: (event) => {
    if (event.target === overlay) onClose();
  } });
  const panel = el('aside', { class: 'drawer' }, [
    el('div', { class: 'drawer-head' }, [
      el('div', {}, [el('h2', { text: title }), subtitle ? el('div', { class: 'sub', text: subtitle }) : null]),
      el('div', { style: { marginLeft: 'auto', display: 'flex', gap: '8px' } }, [
        ...actions, iconButton('close', { title: '关闭', onClick: onClose }),
      ]),
    ]),
    el('div', { class: 'drawer-body' }, body),
  ]);
  overlay.append(panel);
  document.body.append(overlay);
  const onKey = (event) => {
    if (event.key === 'Escape') {
      overlay.remove();
      document.removeEventListener('keydown', onKey);
    }
  };
  document.addEventListener('keydown', onKey);
  return {
    close() { overlay.remove(); document.removeEventListener('keydown', onKey); },
    element: overlay,
  };
}

export function pageHead({ title, description, actions = [], breadcrumb = [] }) {
  return fragment([
    breadcrumb.length ? el('div', { class: 'breadcrumb' }, breadcrumb.flatMap((item, index) => [
      index ? el('span', { text: '/' }) : null,
      item.href ? el('a', { href: item.href, text: item.label }) : el('span', { text: item.label }),
    ])) : null,
    el('div', { class: 'page-head' }, [
      el('div', {}, [el('h1', { text: title }), description ? el('p', { text: description }) : null]),
      actions.length ? el('div', { class: 'page-actions' }, actions) : null,
    ]),
  ]);
}

export function sectionTitle(title, hint, actions = []) {
  return el('div', { class: 'section-title' }, [
    el('h2', { text: title }),
    hint ? el('span', { class: 'hint', text: hint }) : null,
    actions.length ? el('div', { style: { marginLeft: 'auto', display: 'flex', gap: '8px' } }, actions) : null,
  ]);
}