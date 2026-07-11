const WS_URL = 'ws://127.0.0.1:8000/ws';

export class WSClient {
  constructor(url = WS_URL) {
    this.url = url;
    this.ws = null;
    this.listeners = new Map();
    this.reconnectTimer = null;
    this.pingTimer = null;
    this.messageQueue = [];
    this.reconnectDelay = 1000;
    this.maxReconnectDelay = 30000;
    this.connected = false;
    this.scanId = null;
  }

  connect(scanId) {
    this.scanId = scanId;
    if (this.ws?.readyState === WebSocket.OPEN) return;
    const wsUrl = scanId ? `${this.url}?scan_id=${scanId}` : this.url;
    this.ws = new WebSocket(wsUrl);

    this.ws.onopen = () => {
      this.connected = true;
      this.reconnectDelay = 1000;
      this._emit('connected', { scanId });
      this._startHeartbeat();
      this._flushQueue();
    };

    this.ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        this._emit(msg.type || 'message', msg);
        this._emit('*', msg.type, msg);
      } catch {
        this._emit('raw', event.data);
      }
    };

    this.ws.onclose = (event) => {
      this.connected = false;
      this._stopHeartbeat();
      this._emit('disconnected', { code: event.code, reason: event.reason });
      this._scheduleReconnect();
    };

    this.ws.onerror = () => {
      this._emit('error', { message: 'WebSocket error' });
    };
  }

  disconnect() {
    this._stopHeartbeat();
    this._clearReconnect();
    if (this.ws) {
      this.ws.onclose = null;
      this.ws.close(1000, 'Client disconnect');
      this.ws = null;
    }
    this.connected = false;
  }

  send(data) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data));
      return true;
    }
    this.messageQueue.push(data);
    return false;
  }

  on(event, fn) {
    if (!this.listeners.has(event)) this.listeners.set(event, []);
    this.listeners.get(event).push(fn);
    return () => this.off(event, fn);
  }

  off(event, fn) {
    const arr = this.listeners.get(event);
    if (arr) this.listeners.set(event, arr.filter(f => f !== fn));
  }

  _emit(event, ...args) {
    (this.listeners.get(event) || []).forEach(fn => { try { fn(...args); } catch (e) { console.warn('[WS] listener error:', e); } });
  }

  _startHeartbeat() {
    this._stopHeartbeat();
    this.pingTimer = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ type: 'ping', ts: Date.now() }));
      }
    }, 15000);
  }

  _stopHeartbeat() {
    if (this.pingTimer) { clearInterval(this.pingTimer); this.pingTimer = null; }
  }

  _scheduleReconnect() {
    this._clearReconnect();
    console.log(`[WS] Reconnecting in ${this.reconnectDelay}ms...`);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectDelay = Math.min(this.reconnectDelay * 1.5, this.maxReconnectDelay);
      if (this.scanId) this.connect(this.scanId);
    }, this.reconnectDelay);
  }

  _clearReconnect() {
    if (this.reconnectTimer) { clearTimeout(this.reconnectTimer); this.reconnectTimer = null; }
  }

  _flushQueue() {
    while (this.messageQueue.length > 0) {
      const msg = this.messageQueue.shift();
      this.send(msg);
    }
  }
}

export const ws = new WSClient();
export default ws;
