/**
 * HackIT webUI API client.
 * Same-origin by default so it works behind the FastAPI backend (port 8080),
 * the Astro dev server, or any reverse proxy. Endpoints match python/main.py.
 */

const API_BASE = (typeof window !== 'undefined' && window.__HACKIT_API_BASE) || '';

export async function api(path, opts = {}) {
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  if (!res.ok) throw new Error(`API ${res.status}: ${res.statusText}`);
  return res.json();
}

function qs(params) {
  return Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
}

export const scans = {
  start: (target, settings = {}) =>
    api(`/api/scan?${qs({ target, ...settings })}`),
  status: (jobId) => api(`/api/status?job_id=${encodeURIComponent(jobId)}`),
  byTarget: (target) => api(`/api/job-by-target?target=${encodeURIComponent(target)}`),
  list: () => api('/api/jobs'),
};

export const tools = {
  portscan: (target, range) =>
    api(`/api/portscan?${qs({ target, range })}`),
  subdomains: (domain) => api(`/api/subdomains?domain=${encodeURIComponent(domain)}`),
  sqli: (url) => api(`/api/sqli?url=${encodeURIComponent(url)}`),
  dns: (domain) => api(`/api/dns/lookup?domain=${encodeURIComponent(domain)}`),
  emailSecurity: (domain) => api(`/api/dns/email-security?domain=${encodeURIComponent(domain)}`),
  headers: (url) => api(`/api/http/headers?url=${encodeURIComponent(url)}`),
  ssl: (hostname, port = 443) => api(`/api/ssl/certificate?${qs({ hostname, port })}`),
  whois: (domain) => api(`/api/whois/domain?domain=${encodeURIComponent(domain)}`),
  geo: (ip) => api(`/api/ip/geolocate?ip=${encodeURIComponent(ip)}`),
  emails: (domain) => api(`/api/domain/emails?domain=${encodeURIComponent(domain)}`),
  comprehensive: (domain) => api(`/api/domain/comprehensive?domain=${encodeURIComponent(domain)}`),
  ping: () => api('/api/ping'),
};

export const settings = {
  apiKeys: () => api('/api/settings/api-keys'),
  saveApiKeys: (keys) =>
    api('/api/settings/api-keys', { method: 'POST', body: JSON.stringify(keys) }),
  scan: () => api('/api/settings/scan'),
  saveScan: (data) =>
    api('/api/settings/scan', { method: 'POST', body: JSON.stringify(data) }),
};
