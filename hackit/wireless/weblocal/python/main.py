import os, sys, json, asyncio, subprocess, time, io, inspect
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from dataclasses import asdict
from rich.console import Console

BASE = Path(__file__).resolve().parent.parent  # weblocal/
WIRELESS = BASE.parent  # wireless/
HACKIT = WIRELESS.parent  # hackit/
PROJECT_ROOT = HACKIT.parent  # project root
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(HACKIT))
sys.path.insert(0, str(WIRELESS))

HackITWirelessExecutor = None
EXECUTOR = None
BRIDGE = None
ENGINE_HEALTH = {"initializing": True}

# ── Try to import engine executor ──
try:
    import importlib
    _mod_exec = importlib.import_module("hackit.wireless.executor")
    HackITWirelessExecutor = _mod_exec.HackITWirelessExecutor
    EXECUTOR = HackITWirelessExecutor()
    from hackit.wireless.engine_bridge import EngineBridge
    BRIDGE = EXECUTOR.bridge
    ENGINE_HEALTH = BRIDGE.engine_health()
except Exception as e:
    ENGINE_HEALTH = {"error": str(e)}

ATTACKS = {
    "deauth": {
        "label": "Deauth Attack",
        "desc": "Send 802.11 deauthentication frames to disconnect clients from an AP",
        "icon": "zap",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "bssid", "label": "BSSID", "type": "text", "placeholder": "AA:BB:CC:DD:EE:FF"},
            {"name": "station", "label": "Station MAC", "type": "text", "optional": True, "placeholder": "FF:FF:FF:FF:FF:FF"},
            {"name": "count", "label": "Packet count", "type": "number", "default": "10", "optional": True},
            {"name": "reason", "label": "Reason code", "type": "number", "default": "7", "optional": True},
        ],
    },
    "beacon-flood": {
        "label": "Beacon Flood",
        "desc": "Flood the airwaves with fake beacon frames to confuse clients",
        "icon": "radio",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "ssid", "label": "SSID name", "type": "text", "default": "FreeWiFi"},
            {"name": "count", "label": "Frame count", "type": "number", "default": "500", "optional": True},
            {"name": "wpa2", "label": "WPA2 flag", "type": "checkbox", "optional": True},
        ],
    },
    "probe-flood": {
        "label": "Probe Flood",
        "desc": "Flood probe requests to overwhelm APs and monitoring tools",
        "icon": "activity",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "count", "label": "Frame count", "type": "number", "default": "1000", "optional": True},
            {"name": "random-mac", "label": "Random source MAC", "type": "checkbox", "optional": True},
        ],
    },
    "eviltwin": {
        "label": "Evil Twin",
        "desc": "Clone a legitimate SSID and broadcast a rogue AP with captive portal",
        "icon": "copy",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "ssid", "label": "Target SSID to clone", "type": "text"},
            {"name": "channel", "label": "Channel", "type": "number", "default": "6", "optional": True},
            {"name": "captive", "label": "Captive portal", "type": "checkbox", "optional": True},
        ],
    },
    "handshake": {
        "label": "Handshake Capture",
        "desc": "Capture WPA/WPA2 4-way handshake by deauthenticating a client",
        "icon": "shield",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "bssid", "label": "BSSID", "type": "text", "placeholder": "AA:BB:CC:DD:EE:FF"},
            {"name": "timeout", "label": "Timeout (sec)", "type": "number", "default": "60", "optional": True},
            {"name": "deauth", "label": "Deauth trigger", "type": "checkbox", "optional": True},
        ],
    },
    "pmkid": {
        "label": "PMKID Capture",
        "desc": "Capture PMKID hash from WPA2/WPA3 APs for offline cracking",
        "icon": "key",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "bssid", "label": "BSSID (optional)", "type": "text", "optional": True},
            {"name": "timeout", "label": "Timeout (sec)", "type": "number", "default": "30", "optional": True},
        ],
    },
    "wps-pixie": {
        "label": "WPS PixieDust",
        "desc": "PixieDust attack against WPS-enabled AP to recover PIN",
        "icon": "unlock",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "bssid", "label": "BSSID", "type": "text", "placeholder": "AA:BB:CC:DD:EE:FF"},
            {"name": "timeout", "label": "Timeout (sec)", "type": "number", "default": "180", "optional": True},
        ],
    },
    "wep-arp": {
        "label": "WEP ARP Replay",
        "desc": "Capture ARP packets and replay to generate WEP IVs",
        "icon": "repeat",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "bssid", "label": "BSSID", "type": "text", "placeholder": "AA:BB:CC:DD:EE:FF"},
            {"name": "count", "label": "Packet count", "type": "number", "default": "5000", "optional": True},
        ],
    },
    "crack": {
        "label": "WPA Cracking",
        "desc": "Dictionary attack against captured handshake/PMKID hash",
        "icon": "terminal",
        "params": [
            {"name": "hashfile", "label": "Hash file (.hc22000)", "type": "text"},
            {"name": "wordlist", "label": "Wordlist path", "type": "text"},
            {"name": "rules", "label": "Rules file", "type": "text", "optional": True},
        ],
    },
    "crawl": {
        "label": "AP Scan",
        "desc": "Scan all access points in range with detailed info",
        "icon": "search",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "timeout", "label": "Timeout (sec)", "type": "number", "default": "15", "optional": True},
        ],
    },
    "client-hunt": {
        "label": "Client Hunt",
        "desc": "Enumerate clients connected to a target AP",
        "icon": "users",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "bssid", "label": "BSSID", "type": "text", "placeholder": "AA:BB:CC:DD:EE:FF"},
            {"name": "timeout", "label": "Timeout (sec)", "type": "number", "default": "30", "optional": True},
        ],
    },
    "rogue": {
        "label": "Rogue AP",
        "desc": "Broadcast a fake access point with custom SSID",
        "icon": "wifi",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "ssid", "label": "SSID name", "type": "text", "default": "FreeWiFi"},
            {"name": "channel", "label": "Channel", "type": "number", "default": "6", "optional": True},
        ],
    },
    "arp-spoof": {
        "label": "ARP Spoof",
        "desc": "Poison ARP cache of target and gateway to intercept traffic",
        "icon": "share-2",
        "params": [
            {"name": "target", "label": "Target IP", "type": "text", "placeholder": "192.168.1.100"},
            {"name": "gateway", "label": "Gateway IP", "type": "text", "placeholder": "192.168.1.1"},
            {"name": "timeout", "label": "Timeout (sec)", "type": "number", "default": "120", "optional": True},
        ],
    },
}

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        log_dir = Path("/tmp/hackit")
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"web_{os.getpid()}.log"
        log_file.write_text(f"[{time.strftime('%H:%M:%S')}] HackIT Wireless Web started\n")
    except (OSError, PermissionError):
        pass
    yield

app = FastAPI(title="HackIT Wireless Web", version="3.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

PORT = int(os.environ.get("HACKIT_WEB_PORT", 8081))


# ── Engine helpers ────────────────────────────────────────────────

def _coerce_types(method, data: dict) -> dict:
    """Convert form string values to match method param types."""
    sig = inspect.signature(method)
    coerced = {}
    for k, v in data.items():
        if k in sig.parameters:
            param = sig.parameters[k]
            if param.annotation is int or (isinstance(param.annotation, type) and issubclass(param.annotation, int)):
                try: coerced[k] = int(v)
                except (ValueError, TypeError): coerced[k] = v
            elif param.annotation is float:
                try: coerced[k] = float(v)
                except (ValueError, TypeError): coerced[k] = v
            elif param.annotation is bool:
                coerced[k] = v in ("true", "True", "1", "on", True, 1) if not isinstance(v, bool) else v
            else:
                coerced[k] = v
        else:
            coerced[k] = v
    return coerced


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes and Rich control chars for JSON safety."""
    import re
    text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', text)
    return text.strip() or "OK"


def _exec_captured(method, data: dict, timeout: int = 120) -> dict:
    """Run a method, capturing console output, with timeout."""
    import hackit.wireless.executor as exec_mod
    import hackit.wireless.ui_renderer as ui_mod
    import threading

    buf = io.StringIO()
    captured_console = Console(file=buf, width=100, no_color=True, force_terminal=False)
    orig_exec_console = exec_mod._console
    orig_ui_console = ui_mod.console

    result_container = []
    error_container = []

    def target():
        try:
            exec_mod._console = captured_console
            ui_mod.console = captured_console
            coerced = _coerce_types(method, data)
            r = method(**coerced)
            result_container.append(r)
        except Exception as e:
            error_container.append(e)
        finally:
            exec_mod._console = orig_exec_console
            ui_mod.console = orig_ui_console

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        exec_mod._console = orig_exec_console
        ui_mod.console = orig_ui_console
        return {"stdout": "", "stderr": "Attack timed out", "code": 1}

    if error_container:
        return {"stdout": _strip_ansi(buf.getvalue()), "stderr": str(error_container[0]), "code": 1}

    output = _strip_ansi(buf.getvalue())
    return {"stdout": output, "stderr": "", "code": 0}


ATTACK_MAP = {
    "deauth": "do_deauth",
    "beacon-flood": "do_beacon_flood",
    "probe-flood": "do_probe_flood",
    "eviltwin": "do_eviltwin",
    "rogue": "do_rogue_ap",
    "arp-spoof": "do_arp_spoof",
    "handshake": "do_handshake_capture",
    "pmkid": "do_pmkid_capture",
    "wps-pixie": "do_wps_pixie",
    "wep-arp": "do_wep_arp_replay",
    "crawl": "do_crawl",
    "client-hunt": "do_client_hunt",
}


def _exec_attack(name: str, data: dict) -> dict:
    """Execute an attack using the real HackITWirelessExecutor."""
    if EXECUTOR is None:
        return {"stdout": "", "stderr": "Engine executor not available", "code": 1}
    method_name = ATTACK_MAP.get(name)
    if not method_name:
        return {"stdout": "", "stderr": f"No handler for {name}", "code": 1}
    method = getattr(EXECUTOR, method_name, None)
    if not method:
        return {"stdout": "", "stderr": f"Method {method_name} not found", "code": 1}
    return _exec_captured(method, data)


def _exec_crack(data: dict) -> dict:
    if EXECUTOR is None:
        return {"stdout": "", "stderr": "Executor not available", "code": 1}
    return _exec_captured(EXECUTOR.do_crack, data, timeout=600)


def _exec_recon(attack_type: str, data: dict) -> dict:
    return _exec_attack(attack_type, data)


def _exec_plugin(data: dict) -> dict:
    if EXECUTOR is None:
        return {"stdout": "", "stderr": "Executor not available", "code": 1}
    engine = data.get("engine", "lua")
    script = data.get("script", "")
    if engine == "lua":
        method = EXECUTOR.do_plugin_lua
        coerced = {"script": script}
    elif engine == "ruby":
        method = EXECUTOR.do_plugin_ruby
        coerced = {"script": script}
    else:
        return {"stdout": "", "stderr": f"Unknown engine: {engine}", "code": 1}
    return _exec_captured(method, coerced, timeout=300)


# ── API Routes ────────────────────────────────────────────────────

@app.get("/api/ping")
def ping():
    health = ENGINE_HEALTH if BRIDGE else {"error": "no bridge"}
    return {"status": "ok", "version": "3.0", "engines": health}


@app.get("/api/engines")
def engines():
    if BRIDGE:
        return {"engines": BRIDGE.engine_health()}
    return {"engines": ENGINE_HEALTH}


@app.get("/api/attacks")
def list_attacks():
    return {"attacks": {k: {"label": v["label"], "desc": v["desc"], "icon": v["icon"],
                            "params": v["params"]} for k, v in ATTACKS.items()}}


@app.post("/api/attack/{name}")
async def run_attack(name: str, data: dict):
    if name not in ATTACKS:
        raise HTTPException(404, f"Unknown attack: {name}")
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, lambda: _exec_attack(name, data))
    return result


@app.post("/api/attack/{name}/stream")
async def stream_attack(name: str, data: dict):
    if name not in ATTACKS:
        raise HTTPException(404, f"Unknown attack: {name}")

    async def generate():
        yield "data: Starting attack...\n\n"
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, lambda: _exec_attack(name, data))
        if result["stdout"]:
            yield f"data: {result['stdout']}\n\n"
        if result["stderr"]:
            yield f"data: [ERROR] {result['stderr']}\n\n"
        yield f"data: [DONE] exit code: {result['code']}\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream")


@app.post("/api/quick-scan")
async def quick_scan(data: dict = {}):
    """Multi-engine quick scan via go_support module (Python + Go + Rust)."""
    try:
        from go_support import quick_scan as gs_scan
        return await gs_scan(data.get("iface", "wlan0"), bridge=BRIDGE)
    except Exception as e:
        return {"aps": [], "count": 0, "engines": [], "engine_outputs": {},
                "errors": [str(e)], "status": "error"}


@app.post("/api/go/scan")
async def go_scan(data: dict = {}):
    """Go engine dual-band spectrum scan."""
    try:
        from go_support import GoEngine
        eng = GoEngine()
        iface = data.get("iface", "wlan0")
        scan = await eng.scan_dual_band_async(iface)
        return {
            "channels": [c.__dict__ if hasattr(c, '__dict__') else asdict(c) for c in scan.channels],
            "best_channel": scan.best_channel.__dict__ if scan.best_channel else None,
            "raw": scan.raw_output[:3000],
            "error": scan.error,
        }
    except Exception as e:
        return {"channels": [], "best_channel": None, "raw": "", "error": str(e)}


@app.post("/api/go/status")
async def go_status(data: dict = {}):
    """Go engine interface status."""
    try:
        from go_support import GoEngine
        eng = GoEngine()
        status = eng.get_status(data.get("iface", "wlan0"))
        return {"status": status.__dict__ if hasattr(status, '__dict__') else asdict(status)}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/go/mode")
async def go_mode(data: dict = {}):
    """Switch interface mode via Go engine."""
    try:
        from go_support import GoEngine
        eng = GoEngine()
        ok, msg = eng.set_mode(data.get("iface", "wlan0"), data.get("mode", "monitor"))
        return {"ok": ok, "message": msg}
    except Exception as e:
        return {"ok": False, "message": str(e)}


@app.post("/api/go/channel")
async def go_channel(data: dict = {}):
    """Set interface channel via Go engine."""
    try:
        from go_support import GoEngine
        eng = GoEngine()
        ok, msg = eng.set_channel(data.get("iface", "wlan0"), int(data.get("channel", 6)))
        return {"ok": ok, "message": msg}
    except Exception as e:
        return {"ok": False, "message": str(e)}


@app.post("/api/go/txpower")
async def go_txpower(data: dict = {}):
    try:
        from go_support import GoEngine
        eng = GoEngine()
        ok, msg = eng.set_txpower(data.get("iface", "wlan0"), int(data.get("power", 20)))
        return {"ok": ok, "message": msg}
    except Exception as e:
        return {"ok": False, "message": str(e)}


@app.post("/api/go/mac")
async def go_mac(data: dict = {}):
    try:
        from go_support import GoEngine
        eng = GoEngine()
        ok, msg = eng.set_mac(data.get("iface", "wlan0"), data.get("action", "random"))
        return {"ok": ok, "message": msg}
    except Exception as e:
        return {"ok": False, "message": str(e)}


@app.post("/api/go/wps-pin")
async def go_wps_pin(data: dict = {}):
    try:
        from go_support import GoEngine
        eng = GoEngine()
        result = eng.wps_pin(data.get("bssid", ""))
        return {"pin": result.pin, "candidates": result.candidates, "error": result.error}
    except Exception as e:
        return {"pin": "", "candidates": [], "error": str(e)}


@app.post("/api/go/packet-gen")
async def go_packet_gen(data: dict = {}):
    try:
        from go_support import GoEngine
        eng = GoEngine()
        ok, msg = eng.packet_gen(
            data.get("iface", "wlan0"),
            data.get("frame_type", "auth"),
            data.get("ssid", "HackIT")
        )
        return {"ok": ok, "message": msg}
    except Exception as e:
        return {"ok": False, "message": str(e)}


@app.get("/api/go/sessions")
async def go_sessions():
    try:
        from go_support import GoEngine
        eng = GoEngine()
        sessions = eng.list_sessions()
        return {"sessions": [s.__dict__ if hasattr(s, '__dict__') else asdict(s) for s in sessions]}
    except Exception as e:
        return {"sessions": [], "error": str(e)}


# ── Go Web Server Management ────────────────────────────────────────

GO_WEB_PROCESS: subprocess.Popen | None = None
GO_WEB_PORT_ENV = 8200


@app.get("/api/go-web/status")
def go_web_status():
    """Check if Go web server is running."""
    global GO_WEB_PROCESS
    running = GO_WEB_PROCESS is not None and GO_WEB_PROCESS.poll() is None
    port = int(os.environ.get("GO_WEB_PORT", GO_WEB_PORT_ENV))
    pid = GO_WEB_PROCESS.pid if running and GO_WEB_PROCESS else None

    go_web_dir = BASE / "go_web"
    binary = go_web_dir / "go-web-server"
    binary_ready = binary.is_file()

    return {
        "running": running,
        "port": port,
        "pid": pid,
        "binary": str(binary) if binary_ready else None,
        "binary_ready": binary_ready,
        "url": f"http://127.0.0.1:{port}",
    }


@app.post("/api/go-web/start")
async def go_web_start():
    """Start the Go web server."""
    global GO_WEB_PROCESS
    if GO_WEB_PROCESS is not None and GO_WEB_PROCESS.poll() is None:
        return {"ok": True, "message": "Already running", "pid": GO_WEB_PROCESS.pid}

    go_web_dir = BASE / "go_web"
    binary = go_web_dir / "go-web-server"
    if not binary.is_file():
        return {"ok": False, "message": "Binary not found. Build with: go build -o go-web-server ."}

    port = int(os.environ.get("GO_WEB_PORT", GO_WEB_PORT_ENV))
    env = os.environ.copy()
    env["GO_WEB_PORT"] = str(port)

    try:
        GO_WEB_PROCESS = subprocess.Popen(
            [str(binary)],
            cwd=str(go_web_dir),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Wait briefly to check it started
        import time
        time.sleep(0.5)
        if GO_WEB_PROCESS.poll() is not None:
            return {"ok": False, "message": f"Process exited immediately (code {GO_WEB_PROCESS.returncode})"}
        return {"ok": True, "message": f"Started on port {port}", "pid": GO_WEB_PROCESS.pid}
    except Exception as e:
        return {"ok": False, "message": str(e)}


@app.post("/api/go-web/stop")
async def go_web_stop():
    """Stop the Go web server."""
    global GO_WEB_PROCESS
    if GO_WEB_PROCESS is None or GO_WEB_PROCESS.poll() is not None:
        GO_WEB_PROCESS = None
        return {"ok": True, "message": "Not running"}

    try:
        GO_WEB_PROCESS.terminate()
        try:
            GO_WEB_PROCESS.wait(timeout=3)
        except subprocess.TimeoutExpired:
            GO_WEB_PROCESS.kill()
            GO_WEB_PROCESS.wait()
        GO_WEB_PROCESS = None
        return {"ok": True, "message": "Stopped"}
    except Exception as e:
        return {"ok": False, "message": str(e)}


@app.post("/api/go-web/build")
async def go_web_build():
    """Build the Go web server binary."""
    go_web_dir = BASE / "go_web"
    if not (go_web_dir / "main.go").is_file():
        return {"ok": False, "message": "main.go not found"}

    try:
        result = subprocess.run(
            ["go", "build", "-o", "go-web-server", "."],
            cwd=str(go_web_dir),
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            return {"ok": True, "message": "Build successful"}
        else:
            return {"ok": False, "message": result.stderr or result.stdout}
    except subprocess.TimeoutExpired:
        return {"ok": False, "message": "Build timed out"}
    except FileNotFoundError:
        return {"ok": False, "message": "Go compiler not found"}
    except Exception as e:
        return {"ok": False, "message": str(e)}


@app.get("/api/adapters")
def adapters():
    if EXECUTOR:
        try:
            return {"adapters": EXECUTOR.detect_wireless_adapters()}
        except Exception:
            pass
    return {"adapters": []}


@app.get("/api/plugins")
def plugins(typ: str = ""):
    if EXECUTOR:
        try:
            all_plugins = EXECUTOR.do_plugin_list()
            lua = [s for s in all_plugins.get("lua", [])]
            ruby = [s for s in all_plugins.get("ruby", [])]
            return {"lua": lua, "ruby": ruby}
        except Exception:
            pass
    return {"lua": [], "ruby": []}


@app.post("/api/plugin/run")
async def plugin_run(data: dict):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, lambda: _exec_plugin(data))
    return result


@app.post("/api/crack/run")
async def crack_run(data: dict):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, lambda: _exec_crack(data))
    return result


@app.get("/api/wordlists")
def wordlists():
    paths = ["/usr/share/wordlists", "/usr/share/dict", "/usr/share/seclists/Passwords"]
    results = []
    for p in paths:
        pp = Path(p)
        if pp.is_dir():
            for f in sorted(pp.rglob("*"))[:50]:
                if f.is_file() and f.stat().st_size > 1000:
                    results.append({"name": str(f.relative_to(pp.parent)),
                                    "size": _fmt_size(f.stat().st_size)})
    return {"wordlists": results}


def _fmt_size(b: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if b < 1024:
            return f"{b:.1f}{unit}"
        b /= 1024
    return f"{b:.1f}TB"


@app.post("/api/recon/{attack_type}")
async def recon_run(attack_type: str, data: dict):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, lambda: _exec_recon(attack_type, data))
    return result


@app.get("/api/sessions")
def sessions():
    sess_file = WIRELESS / "go_workers" / "sessions.json"
    if sess_file.exists():
        try:
            return json.loads(sess_file.read_text())
        except Exception:
            pass
    return {"sessions": []}


@app.get("/api/workspaces")
def workspaces():
    ws_dir = WIRELESS / "workspaces"
    if ws_dir.is_dir():
        return {"workspaces": sorted(d.name for d in ws_dir.iterdir() if d.is_dir())}
    return {"workspaces": []}


@app.get("/api/logs")
def logs(tail: int = 50):
    log_file = Path("/tmp/hackit_wireless_web.log")
    lines = []
    if log_file.exists():
        lines = log_file.read_text().splitlines()
    return {"logs": lines[-tail:]}


# ── Serve static frontend ─────────────────────────────────────────

FRONTEND = BASE / "dist"


@app.get("/{path:path}")
def serve_frontend(path: str):
    file_path = FRONTEND / path
    if file_path.exists():
        if file_path.is_file():
            return FileResponse(str(file_path))
        index = file_path / "index.html"
        if index.exists():
            return FileResponse(str(index))
    index = FRONTEND / "index.html"
    if index.exists():
        return FileResponse(str(index))
    raise HTTPException(404)



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
