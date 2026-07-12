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
    "crtsh": 30, "vuln": 60, "cloud": 30,
    "whois": 15, "ssl_tls": 20, "http_headers": 15, "cve_search": 15,
    "breach_check": 15, "subdomain_takeover": 30, "tech_fingerprint": 20,
    "api_discovery": 30, "cloud_buckets": 20, "social_search": 30,
    "paste_scan": 15, "git_discovery": 15, "dns_zone_transfer": 15,
    "cors_check": 15, "redirect_trace": 15, "cookie_audit": 15,
    "email_security": 15, "asn_network": 15, "js_analysis": 20,
    "dir_enum": 45, "social_media_check": 20, "email_intel": 20,
    "dns_intel": 20, "darkweb_search": 20, "ssl_intel": 20,
    "web_intel": 30, "google_dorks": 30,
    "link_extractor": 30, "web_form_discovery": 20, "http_method_fuzzer": 30,
    "web_backup_scanner": 40, "domain_permutation": 30, "http_archive_scanner": 25,
    "all": 180,
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
                     progress_callback: Callable[[dict], None] = None,
                     config: dict = None) -> dict:
    if not ENGINE_PATH or not os.path.exists(ENGINE_PATH):
        return {"error": f"Engine not found at {ENGINE_PATH}"}
    timeout = timeout or SCAN_TIMEOUTS.get(command, 30)
    cmd = [ENGINE_PATH, "--progress", command, target]
    if config:
        cmd += ["--config", json.dumps(config)]
    try:
        proc = await asyncio.get_event_loop().run_in_executor(
            None, lambda: subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
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


# ── Individual module scan functions ──
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

# ── New module scan functions ──
async def scan_whois(domain: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("whois", domain, progress_callback=cb))
async def scan_ssl_tls(hostname: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("ssl_tls", hostname, progress_callback=cb))
async def scan_http_headers(url: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("http_headers", url, progress_callback=cb))
async def scan_cve_search(target: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("cve_search", target, progress_callback=cb))
async def scan_breach_check(target: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("breach_check", target, progress_callback=cb))
async def scan_subdomain_takeover(target: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("subdomain_takeover", target, progress_callback=cb))
async def scan_tech_fingerprint(url: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("tech_fingerprint", url, progress_callback=cb))
async def scan_api_discovery(url: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("api_discovery", url, progress_callback=cb))
async def scan_cloud_buckets(target: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("cloud_buckets", target, progress_callback=cb))
async def scan_social_search(username: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("social_search", username, progress_callback=cb))
async def scan_paste_scan(target: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("paste_scan", target, progress_callback=cb))
async def scan_git_discovery(url: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("git_discovery", url, progress_callback=cb))
async def scan_dns_zone_transfer(domain: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("dns_zone_transfer", domain, progress_callback=cb))
async def scan_cors_check(url: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("cors_check", url, progress_callback=cb))
async def scan_redirect_trace(url: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("redirect_trace", url, progress_callback=cb))
async def scan_cookie_audit(url: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("cookie_audit", url, progress_callback=cb))
async def scan_email_security(domain: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("email_security", domain, progress_callback=cb))
async def scan_asn_network(target: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("asn_network", target, progress_callback=cb))
async def scan_js_analysis(url: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("js_analysis", url, progress_callback=cb))
async def scan_dir_enum(url: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("dir_enum", url, progress_callback=cb))

# ── New power module scan functions ──
async def scan_social_media_check(username: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("social_media_check", username, progress_callback=cb))
async def scan_email_intel(domain: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("email_intel", domain, progress_callback=cb))
async def scan_dns_intel(domain: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("dns_intel", domain, progress_callback=cb))
async def scan_darkweb_search(query: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("darkweb_search", query, progress_callback=cb))
async def scan_ssl_intel(hostname: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("ssl_intel", hostname, progress_callback=cb))
async def scan_web_intel(domain: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("web_intel", domain, progress_callback=cb))
async def scan_google_dorks(domain: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("google_dorks", domain, progress_callback=cb))

async def scan_link_extractor(target: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("link_extractor", target, progress_callback=cb))
async def scan_web_form_discovery(target: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("web_form_discovery", target, progress_callback=cb))
async def scan_http_method_fuzzer(target: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("http_method_fuzzer", target, 30, progress_callback=cb))
async def scan_web_backup_scanner(target: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("web_backup_scanner", target, 40, progress_callback=cb))
async def scan_domain_permutation(target: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("domain_permutation", target, progress_callback=cb))
async def scan_http_archive_scanner(target: str, cb=None) -> EngineResult:
    return parse_result(await run_engine("http_archive_scanner", target, 25, progress_callback=cb))

async def scan_all(target: str, cb=None, config: dict = None) -> EngineResult:
    raw = await run_engine("all", target, 180, progress_callback=cb, config=config)
    r = parse_result(raw)
    if r.success and "duration_ms" in raw:
        print(f"[rust_bridge] All scan completed in {raw['duration_ms']}ms")
    return r

SCAN_FUNCTIONS = {
    "subdomain": scan_subdomains, "ports": scan_ports, "dns": scan_dns,
    "email": scan_emails, "webtech": scan_webtech, "crawl": scan_crawl,
    "sensitive": scan_sensitive, "secret": scan_secret, "waf": scan_waf,
    "social": scan_social, "crtsh": scan_crtsh, "vuln": scan_vuln,
    "cloud": scan_cloud,
    "whois": scan_whois, "ssl_tls": scan_ssl_tls, "http_headers": scan_http_headers,
    "cve_search": scan_cve_search, "breach_check": scan_breach_check,
    "subdomain_takeover": scan_subdomain_takeover, "tech_fingerprint": scan_tech_fingerprint,
    "api_discovery": scan_api_discovery, "cloud_buckets": scan_cloud_buckets,
    "social_search": scan_social_search, "paste_scan": scan_paste_scan,
    "git_discovery": scan_git_discovery, "dns_zone_transfer": scan_dns_zone_transfer,
    "cors_check": scan_cors_check, "redirect_trace": scan_redirect_trace,
    "cookie_audit": scan_cookie_audit, "email_security": scan_email_security,
    "asn_network": scan_asn_network, "js_analysis": scan_js_analysis,
    "dir_enum": scan_dir_enum,
    "social_media_check": scan_social_media_check, "email_intel": scan_email_intel,
    "dns_intel": scan_dns_intel, "darkweb_search": scan_darkweb_search,
    "ssl_intel": scan_ssl_intel, "web_intel": scan_web_intel,
    "google_dorks": scan_google_dorks,
    "link_extractor": scan_link_extractor, "web_form_discovery": scan_web_form_discovery,
    "http_method_fuzzer": scan_http_method_fuzzer, "web_backup_scanner": scan_web_backup_scanner,
    "domain_permutation": scan_domain_permutation, "http_archive_scanner": scan_http_archive_scanner,
    "all": scan_all,
}
