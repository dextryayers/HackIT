const API_BASE = 'http://127.0.0.1:8000';

export class ScanClient {
  constructor(base = API_BASE) {
    this.base = base;
    this.controller = null;
  }

  async fetch(path, opts = {}) {
    const url = `${this.base}${path}`;
    const headers = { 'Content-Type': 'application/json', ...opts.headers };
    const res = await fetch(url, { ...opts, headers, signal: opts.signal || null });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`API ${res.status}: ${res.statusText}${body ? ` — ${body.slice(0, 200)}` : ''}`);
    }
    return res.json();
  }

  withCancel() {
    this.controller = new AbortController();
    return this.controller.signal;
  }

  cancel() { this.controller?.abort(); }

  async retry(path, opts = {}, retries = 3, delay = 1000) {
    for (let i = 0; i < retries; i++) {
      try { return await this.fetch(path, opts); }
      catch (e) { if (i === retries - 1) throw e; await new Promise(r => setTimeout(r, delay * (i + 1))); }
    }
  }

  async startScan(target, options = {}) {
    let url = `/api/scan?target=${encodeURIComponent(target)}`;
    if (options.depth) url += `&depth=${options.depth}`;
    if (options.sniperRatio) url += `&sniper_ratio=${options.sniperRatio}`;
    if (options.timeout) url += `&timeout=${options.timeout}`;
    if (options.verbose !== undefined) url += `&verbose=${options.verbose}`;
    if (options.maxFindings) url += `&max_findings=${options.maxFindings}`;
    if (options.format) url += `&format=${options.format}`;
    if (options.modules) url += `&modules=${Array.isArray(options.modules) ? options.modules.join(',') : options.modules}`;
    if (options.toggles) {
      Object.entries(options.toggles).forEach(([k, v]) => { url += `&${k}=${v ? '1' : '0'}`; });
    }
    return this.fetch(url, { signal: this.withCancel() });
  }

  getScanStatus(jobId) { return this.fetch(`/api/status?job_id=${jobId}`); }
  listJobs() { return this.fetch('/api/jobs'); }
  getJobByTarget(target) { return this.fetch(`/api/job-by-target?target=${encodeURIComponent(target)}`); }

  getDNS(domain) { return this.fetch(`/api/dns/${encodeURIComponent(domain)}`); }
  getHTTP(domain) { return this.fetch(`/api/http/${encodeURIComponent(domain)}`); }
  getSSL(domain) { return this.fetch(`/api/ssl/${encodeURIComponent(domain)}`); }
  getWhois(domain) { return this.fetch(`/api/whois/${encodeURIComponent(domain)}`); }
  getIPGeolocation(ip) { return this.fetch(`/api/ip/geolocate?ip=${encodeURIComponent(ip)}`); }
  getSubdomains(domain) { return this.fetch(`/api/domain/subdomains?domain=${encodeURIComponent(domain)}`); }
  getEmails(domain) { return this.fetch(`/api/domain/emails?domain=${encodeURIComponent(domain)}`); }
  getComprehensive(domain) { return this.fetch(`/api/domain/comprehensive?domain=${encodeURIComponent(domain)}`); }
  portScan(host) { return this.fetch(`/api/port/scan?host=${encodeURIComponent(host)}`); }
  testSQLi(url) { return this.fetch(`/api/sqli?url=${encodeURIComponent(url)}`); }

  getSettings() { return this.fetch('/api/settings'); }
  saveSettings(data) { return this.fetch('/api/settings', { method: 'POST', body: JSON.stringify(data) }); }
  getApiKeys() { return this.fetch('/api/settings/api-keys'); }
  saveApiKeys(data) { return this.fetch('/api/settings/api-keys', { method: 'POST', body: JSON.stringify(data) }); }

  getPing() { return this.fetch('/api/ping'); }
}

export const api = new ScanClient();
export default api;
