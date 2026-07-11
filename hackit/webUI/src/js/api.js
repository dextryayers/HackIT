const API_BASE = 'http://127.0.0.1:8000';

export async function api(path, opts = {}) {
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...opts.headers },
    ...opts,
  });
  if (!res.ok) throw new Error(`API ${res.status}: ${res.statusText}`);
  return res.json();
}

export const scans = {
  start: (target, type, settings) =>
    api('/api/scan/start', { method: 'POST', body: JSON.stringify({ target, type, settings }) }),
  status: (scanId) => api(`/api/scan/${scanId}`),
  results: (scanId) => api(`/api/scan/${scanId}/results`),
  list: () => api('/api/scans'),
  cancel: (scanId) => api(`/api/scan/${scanId}/cancel`, { method: 'POST' }),
};

export const settings = {
  get: () => api('/api/settings'),
  save: (data) => api('/api/settings', { method: 'POST', body: JSON.stringify(data) }),
  apiKeys: () => api('/api/settings/api-keys'),
};

export const tools = {
  subdomains: (domain) => api(`/api/tools/subdomains?target=${encodeURIComponent(domain)}`),
  ports: (host) => api(`/api/tools/ports?target=${encodeURIComponent(host)}`),
  dns: (domain) => api(`/api/tools/dns?target=${encodeURIComponent(domain)}`),
  whois: (domain) => api(`/api/tools/whois?target=${encodeURIComponent(domain)}`),
  ssl: (domain) => api(`/api/tools/ssl?target=${encodeURIComponent(domain)}`),
};
