// Fluent-style icons (20px grid, stroke based). Inline SVG only: the console
// must work fully offline, so no icon font or CDN is used.

const PATHS = {
  grid: ['<rect x="3" y="3" width="6" height="6" rx="1.5"/>',
         '<rect x="11" y="3" width="6" height="6" rx="1.5"/>',
         '<rect x="3" y="11" width="6" height="6" rx="1.5"/>',
         '<rect x="11" y="11" width="6" height="6" rx="1.5"/>'],
  agent: ['<rect x="3.5" y="6.5" width="13" height="9" rx="2.5"/>',
          '<path d="M10 3v3.5"/><circle cx="10" cy="2.6" r="1.1"/>',
          '<path d="M7.5 10.5v1.5M12.5 10.5v1.5"/>'],
  activity: ['<path d="M2.5 10h3l2-4.5 3 9 2-4.5h5"/>'],
  shield: ['<path d="M10 2.5 16.5 5v5.2c0 3.6-2.7 6.5-6.5 7.3-3.8-.8-6.5-3.7-6.5-7.3V5L10 2.5Z"/>',
           '<path d="m7.4 10 1.9 1.9 3.4-3.6"/>'],
  alert: ['<path d="M10 3.2 17.4 16H2.6L10 3.2Z"/><path d="M10 8v3.4"/>',
          '<path d="M10 13.6h.01"/>'],
  settings: ['<circle cx="10" cy="10" r="2.6"/>',
             '<path d="M10 2.6v2.1M10 15.3v2.1M2.6 10h2.1M15.3 10h2.1'
             + 'M4.8 4.8l1.5 1.5M13.7 13.7l1.5 1.5M15.2 4.8l-1.5 1.5M6.3 13.7l-1.5 1.5"/>'],
  search: ['<circle cx="9" cy="9" r="5.2"/><path d="m13 13 3.8 3.8"/>'],
  refresh: ['<path d="M16.4 9.2A6.5 6.5 0 1 0 15 14.6"/><path d="M16.9 4.6v4.8h-4.8"/>'],
  play: ['<path d="M6.5 4.6 15 10l-8.5 5.4V4.6Z"/>'],
  stop: ['<rect x="5.5" y="5.5" width="9" height="9" rx="1.6"/>'],
  chevron: ['<path d="m8 5.5 4.5 4.5L8 14.5"/>'],
  external: ['<path d="M11.5 4.5H16v4.5"/><path d="M16 4.5 9.5 11"/>',
             '<path d="M14.5 12v3.2a1.3 1.3 0 0 1-1.3 1.3H5.3A1.3 1.3 0 0 1 4 15.2V7.3'
             + 'A1.3 1.3 0 0 1 5.3 6H8.5"/>'],
  check: ['<path d="m4.5 10.5 3.6 3.6L15.5 6.6"/>'],
  close: ['<path d="m5.5 5.5 9 9M14.5 5.5l-9 9"/>'],
  info: ['<circle cx="10" cy="10" r="7.2"/><path d="M10 9v4.4"/>',
         '<path d="M10 6.6h.01"/>'],
  warning: ['<path d="M10 3.2 17.4 16H2.6L10 3.2Z"/><path d="M10 8v3.4"/>',
            '<path d="M10 13.6h.01"/>'],
  terminal: ['<rect x="2.8" y="4" width="14.4" height="12" rx="2"/>',
             '<path d="m6 8 2.4 2.4L6 12.8M10.6 13.2h3.6"/>'],
  clock: ['<circle cx="10" cy="10" r="7.2"/><path d="M10 5.8V10l3 2"/>'],
  lock: ['<rect x="4.5" y="8.6" width="11" height="7.4" rx="2"/>',
         '<path d="M7 8.6V6.8a3 3 0 0 1 6 0v1.8"/>'],
  link: ['<path d="M8.4 11.6a3.2 3.2 0 0 1 0-4.5l2.2-2.2a3.2 3.2 0 0 1 4.5 4.5l-1 1"/>',
         '<path d="M11.6 8.4a3.2 3.2 0 0 1 0 4.5l-2.2 2.2a3.2 3.2 0 0 1-4.5-4.5l1-1"/>'],
  file: ['<path d="M11.5 2.8H6.4A1.4 1.4 0 0 0 5 4.2v11.6a1.4 1.4 0 0 0 1.4 1.4h7.2'
         + 'a1.4 1.4 0 0 0 1.4-1.4V6.5l-3.5-3.7Z"/>',
         '<path d="M11.4 2.9v3.7h3.5"/>'],
  layers: ['<path d="m10 3 6.5 3.4L10 9.8 3.5 6.4 10 3Z"/>',
           '<path d="m3.5 10.4 6.5 3.4 6.5-3.4"/>',
           '<path d="m3.5 13.7 6.5 3.4 6.5-3.4"/>'],
  key: ['<circle cx="7" cy="8" r="3.2"/><path d="m9.4 10.2 6.4 6.4M13 13l1.6-1.6"/>'],
  globe: ['<circle cx="10" cy="10" r="7.2"/><path d="M2.8 10h14.4"/>',
          '<path d="M10 2.8c2 2 3 4.6 3 7.2s-1 5.2-3 7.2c-2-2-3-4.6-3-7.2s1-5.2 3-7.2Z"/>'],
  plus: ['<path d="M10 4.6v10.8M4.6 10h10.8"/>'],
  filter: ['<path d="M3.4 4.8h13.2l-5 5.6v4.6l-3.2 1.6v-6.2l-5-5.6Z"/>'],
};

export function icon(name, { size = 18, cls = '' } = {}) {
  const parts = PATHS[name] || PATHS.info;
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 20 20');
  svg.setAttribute('width', size);
  svg.setAttribute('height', size);
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.5');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  if (cls) svg.setAttribute('class', cls);
  svg.innerHTML = parts.join('');
  return svg;
}

export const iconNames = Object.keys(PATHS);