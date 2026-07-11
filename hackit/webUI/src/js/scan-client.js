import { api } from './api.js';
import { ws } from './ws.js';

export class ScanSession {
  constructor(target) {
    this.target = target;
    this.jobId = null;
    this.findings = [];
    this.progress = {};
    this.onUpdate = null;
    this.onComplete = null;
    this.onError = null;
    this.onLog = null;
  }

  async start() {
    const saved = localStorage.getItem('hackit_scan_settings');
    let options = {};
    if (saved) {
      try { options = JSON.parse(saved); } catch {}
    }
    const data = await api.startScan(this.target, options);
    if (data.job_id) {
      this.jobId = data.job_id;
      this._connectWS();
      return data;
    }
    throw new Error(data.error || 'No job_id returned');
  }

  _connectWS() {
    ws.on('*', (type, msg) => this._handleMessage(type, msg));
    ws.on('progress', (msg) => this._handleProgress(msg));
    ws.on('connected', () => console.log('[ScanSession] WS connected'));
    ws.on('disconnected', () => console.log('[ScanSession] WS disconnected'));
    ws.connect(this.jobId);
  }

  _handleProgress(msg) {
    this.progress[msg.module || msg.type] = msg;
    if (this.onLog) this.onLog(`[${msg.module}] ${msg.status}`);
  }

  _handleMessage(type, msg) {
    if (type === 'finding') {
      this.findings.push(msg);
      if (this.onUpdate) this.onUpdate(msg);
    }
    if (type === 'complete') {
      if (this.onComplete) this.onComplete(msg);
      ws.disconnect();
    }
    if (type === 'error') {
      if (this.onError) this.onError(msg);
    }
  }

  async poll() {
    while (true) {
      const status = await api.getScanStatus(this.jobId);
      if (status.status === 'Completed' || status.status === 'Error') {
        if (this.onComplete) this.onComplete(status);
        break;
      }
      await new Promise(r => setTimeout(r, 1000));
    }
  }

  cancel() {
    api.cancel();
    ws.disconnect();
  }
}

window.ScanSession = ScanSession;
