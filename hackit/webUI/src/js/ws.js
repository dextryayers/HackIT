const WS_URL = 'ws://127.0.0.1:8000/ws';

let ws = null;
let reconnectTimer = null;
const listeners = new Map();

export function connect(scanId) {
  if (ws?.readyState === WebSocket.OPEN) return;
  ws = new WebSocket(`${WS_URL}?scan_id=${scanId}`);

  ws.onopen = () => {
    console.log('[WS] Connected');
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
    emit('connected', { scanId });
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      emit(msg.type || 'message', msg);
    } catch { emit('raw', event.data); }
  };

  ws.onclose = () => {
    console.log('[WS] Disconnected, reconnecting in 3s...');
    emit('disconnected', {});
    reconnectTimer = setTimeout(() => connect(scanId), 3000);
  };

  ws.onerror = (err) => {
    console.error('[WS] Error:', err);
    emit('error', err);
  };
}

export function disconnect() {
  if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
  if (ws) { ws.close(); ws = null; }
}

export function send(data) {
  if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data));
}

export function on(event, fn) {
  if (!listeners.has(event)) listeners.set(event, []);
  listeners.get(event).push(fn);
  return () => off(event, fn);
}

export function off(event, fn) {
  const arr = listeners.get(event);
  if (arr) listeners.set(event, arr.filter(f => f !== fn));
}

function emit(event, data) {
  (listeners.get(event) || []).forEach(fn => fn(data));
  (listeners.get('*') || []).forEach(fn => fn(event, data));
}
