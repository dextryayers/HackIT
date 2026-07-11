import subprocess, json, os, asyncio, sys
from dataclasses import dataclass, field
from typing import Optional, List, Callable

ENGINE_DIR = os.path.join(os.path.dirname(__file__), "modules", "rust_engine", "target")
ENGINE_PATH = next(
    (os.path.join(ENGINE_DIR, d, "hackit_engine") for d in ("release", "debug")
     if os.path.exists(os.path.join(ENGINE_DIR, d, "hackit_engine"))),
    None
)
if ENGINE_PATH and "debug" in ENGINE_PATH and os.path.exists(ENGINE_PATH.replace("debug", "release")):
    ENGINE_PATH = ENGINE_PATH.replace("debug", "release")

SCAN_TIMEOUTS = {
    "subdomain": 45, "ports": 60, "dns": 20, "email": 20, "webtech": 20,
    "crawl": 30, "sensitive": 30, "secret": 30, "waf": 20, "social": 20,
    "crtsh": 30, "vuln": 60, "cloud": 30, "all": 120,
}

@dataclass
class EngineResult:
    success: bool = False
    error: Optional[str] = None
    raw: dict = field(default_factory=dict)
    data: any = None
    progress_events: List[dict] = field(default_factory=list)

    @property
    def is_error(self) -> bool:
        return not self.success or "error" in self.raw

def parse_result(raw: dict, key: str = None) -> EngineResult:
    r = EngineResult(raw=raw)
    if not raw:
        r.error = "Empty response"
        return r
    if "error" in raw:
        r.error = raw["error"]
        return r
    r.success = True
    r.data = raw.get(key) if key else raw
    return r

async def run_engine(command: str, target: str, timeout: int = None,
                     progress_callback: Callable[[dict], None] = None) -> dict:
    if not ENGINE_PATH or not os.path.exists(ENGINE_PATH):
        return {"error": f"Engine not found at {ENGINE_PATH}"}
    timeout = timeout or SCAN_TIMEOUTS.get(command, 30)
    try:
        proc = await asyncio.get_event_loop().run_in_executor(
            None, lambda: subprocess.Popen(
                [ENGINE_PATH, "--progress", command, target],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1,
            )
        )

        result_data = None
        progress_events = []

        async def read_stdout():
            nonlocal result_data
            loop = asyncio.get_event_loop()
            while True:
                line = await loop.run_in_executor(None, proc.stdout.readline)
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    event = obj.get("event")
                    if event == "progress":
                        progress_events.append(obj)
                        if progress_callback:
                            progress_callback(obj)
                    elif event == "result":
                        progress_events.append(obj)
                    elif event == "complete":
                        result_data = obj.get("data", obj)
                    else:
                        result_data = obj
                except json.JSONDecodeError:
                    continue

        await asyncio.wait_for(read_stdout(), timeout=timeout)
        proc.wait(timeout=5)

        stderr = proc.stderr.read().strip()
        if result_data:
            return result_data
        if stderr:
            return {"error": stderr}
        if proc.returncode and proc.returncode != 0:
            return {"error": f"Exit code {proc.returncode}"}
        return {"error": "No output"}

    except asyncio.TimeoutError:
        return {"error": "Engine timed out"}
    except Exception as e:
        return {"error": str(e)}

async def scan_subdomains(domain: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("subdomain", domain, progress_callback=cb))

async def scan_ports(host: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("ports", host, progress_callback=cb))

async def scan_dns(domain: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("dns", domain, progress_callback=cb))

async def scan_emails(domain: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("email", domain, progress_callback=cb))

async def scan_webtech(url: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("webtech", url, progress_callback=cb))

async def scan_crawl(url: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("crawl", url, progress_callback=cb))

async def scan_sensitive(url: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("sensitive", url, progress_callback=cb))

async def scan_secret(url: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("secret", url, progress_callback=cb))

async def scan_waf(url: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("waf", url, progress_callback=cb))

async def scan_social(username: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("social", username, progress_callback=cb))

async def scan_crtsh(domain: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("crtsh", domain, progress_callback=cb))

async def scan_vuln(target: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("vuln", target, 60, progress_callback=cb))

async def scan_cloud(target: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("cloud", target, 30, progress_callback=cb))

async def scan_all(target: str, cb=None) -> EngineResult:
    raw = await run_engine("all", target, 120, progress_callback=cb)
    r = parse_result(raw)
    if r.success and "duration_ms" in raw:
        print(f"[rust_bridge] All scan completed in {raw['duration_ms']}ms")
    return r

SCAN_FUNCTIONS = {
    "subdomain": scan_subdomains, "ports": scan_ports, "dns": scan_dns,
    "email": scan_emails, "webtech": scan_webtech, "crawl": scan_crawl,
    "sensitive": scan_sensitive, "secret": scan_secret, "waf": scan_waf,
    "social": scan_social, "crtsh": scan_crtsh, "vuln": scan_vuln,
    "cloud": scan_cloud, "all": scan_all,
}
