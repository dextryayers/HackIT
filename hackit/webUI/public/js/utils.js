export const $ = (sel, ctx = document) => ctx.querySelector(sel);
export const $$ = (sel, ctx = document) => [...ctx.querySelectorAll(sel)];

export function debounce(fn, ms = 300) {
  let timer;
  return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), ms); };
}

export function throttle(fn, ms = 200) {
  let last = 0;
  return (...args) => { const now = Date.now(); if (now - last >= ms) { last = now; fn(...args); } };
}

export function escapeHtml(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

export function timeAgo(date) {
  const sec = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  return `${Math.floor(hr / 24)}d ago`;
}

export function copyToClipboard(text) {
  if (navigator.clipboard) return navigator.clipboard.writeText(text);
  const ta = document.createElement('textarea');
  ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
}

export function plural(n, s) { return n === 1 ? `1 ${s}` : `${n} ${s}s`; }

export function formatDuration(seconds) {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return [h, m, s].map(v => String(v).padStart(2, '0')).join(':');
}

export function formatNumber(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
  return String(n);
}

export function severityColor(severity) {
  const s = (severity || '').toLowerCase();
  if (s.includes('critical') || s.includes('high')) return '#ef4444';
  if (s.includes('medium')) return '#f59e0b';
  if (s.includes('low')) return '#3b82f6';
  return '#6b7280';
}

export function statusBadge(status) {
  const s = (status || '').toLowerCase();
  const colors = {
    completed: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
    running: 'bg-sky-500/10 text-sky-400 border-sky-500/20 animate-pulse',
    error: 'bg-red-500/10 text-red-400 border-red-500/20',
    pending: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  };
  const cls = colors[s] || 'bg-gray-500/10 text-gray-400 border-gray-500/20';
  return `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${cls}">${status}</span>`;
}

export function createSpinner(size = 20) {
  const div = document.createElement('div');
  div.className = 'animate-spin rounded-full border-2 border-sf-border border-t-sf-tabActive';
  div.style.width = size + 'px';
  div.style.height = size + 'px';
  return div;
}

export function showToast(message, type = 'info', duration = 3000) {
  const colors = { info: 'bg-sf-tabActive/10 border-sf-tabActive/30 text-sf-tabActive', success: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400', error: 'bg-red-500/10 border-red-500/30 text-red-400', warning: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400' };
  const toast = document.createElement('div');
  toast.className = `fixed top-4 right-4 z-[9999] px-4 py-2.5 rounded-lg border text-sm font-medium shadow-2xl backdrop-blur-sm transition-all duration-500 translate-x-0 opacity-0 ${colors[type] || colors.info}`;
  toast.textContent = message;
  document.body.appendChild(toast);
  requestAnimationFrame(() => { toast.style.opacity = '1'; toast.style.transform = 'translateX(0)'; });
  setTimeout(() => { toast.style.opacity = '0'; toast.style.transform = 'translateX(100%)'; setTimeout(() => toast.remove(), 500); }, duration);
}

export function createElement(tag, attrs = {}, children = []) {
  const el = document.createElement(tag);
  Object.entries(attrs).forEach(([k, v]) => {
    if (k === 'className') el.className = v;
    else if (k === 'innerHTML') el.innerHTML = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else el.setAttribute(k, v);
  });
  children.forEach(c => { if (typeof c === 'string') el.appendChild(document.createTextNode(c)); else if (c instanceof Node) el.appendChild(c); });
  return el;
}

export function renderChart(canvasId, type, labels, data, options = {}) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || typeof Chart === 'undefined') return null;
  const ctx = canvas.getContext('2d');
  const isDark = document.documentElement.classList.contains('dark') || !document.documentElement.classList.contains('light');
  const textColor = isDark ? '#888888' : '#64748b';
  const gridColor = isDark ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.05)';
  return new Chart(ctx, {
    type,
    data: { labels, datasets: data.datasets || [{
      data,
      backgroundColor: options.color || '#38bdf8',
      borderRadius: 4,
    }] },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: options.showLegend !== false, labels: { color: textColor, font: { size: 10 } } } },
      scales: {
        x: { grid: { color: gridColor }, ticks: { color: textColor, font: { size: 9 }, maxRotation: 45 } },
        y: { beginAtZero: true, grid: { color: gridColor }, ticks: { color: textColor, font: { size: 9 } } },
      },
      ...options.chartOptions,
    },
  });
}
