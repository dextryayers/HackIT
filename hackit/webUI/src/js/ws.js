/**
 * HackIT live scan WebSocket client.
 * Connects same-origin to /ws?scan_id=... served by python/main.py.
 * Server messages: scan_start, scan_done, scan_error, pong.
 */

function wsUrl(scanId) {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${window.location.host}/ws?scan_id=${encodeURIComponent(scanId)}`;
}

let ws = null;
let reconnectTimer = null;
const listeners = new Map();

export function connect(scanId) {
  if (typeof window === 'undefined' || typeof WebSocket === 'undefined') return;
  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;
  try {
    ws = new WebSocket(wsUrl(scanId));
  } catch (err) {
    emit('error', err);
    return;
  }

  ws.onopen = () => {
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
    emit('connected', { scanId });
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      emit(msg.type || 'message', msg);
    } catch {
      emit('raw', event.data);
    }
  };

  const schedule = () => {
    emit('disconnected', {});
    if (!reconnectTimer) reconnectTimer = setTimeout(() => { reconnectTimer = null; connect(scanId); }, 3000);
  };
  ws.onclose = schedule;

  ws.onerror = (err) => {
    emit('error', err);
  };
}

export function disconnect() {
  if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
  if (ws) { try { ws.close(); } catch { /* already closed */ } ws = null; }
}

export function send(data) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data));
}

export function on(event, fn) {
  if (!listeners.has(event)) listeners.set(event, []);
  listeners.get(event).push(fn);
  return () => off(event, fn);
}

export function off(event, fn) {
  const arr = listeners.get(event);
  if (arr) listeners.set(event, arr.filter((f) => f !== fn));
}

function emit(event, data) {
  (listeners.get(event) || []).forEach((fn) => fn(data));
  (listeners.get('*') || []).forEach((fn) => fn(event, data));
}
