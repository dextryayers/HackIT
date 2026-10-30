"""External reconnaissance helpers for the HackIt agent pipeline.

The module prefers real security tools when they are installed on the host
(nmap, httpx, ...) and falls back to pure-Python implementations so the
pipeline is powerful even on a clean machine.  Every result is deduplicated
before it reaches the workflow state.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import threading
import time
from typing import Any, Dict, List, Set


COMMON_SUBDOMAINS = [
    "www", "api", "app", "admin", "portal", "dev", "staging", "test",
    "mail", "smtp", "vpn", "auth", "login", "dashboard", "docs", "blog",
    "cdn", "static", "assets", "media", "shop", "store", "support", "help",
    "status", "monitor", "grafana", "kibana", "jenkins", "gitlab", "jira",
    "confluence", "wiki", "backup", "db", "database", "mysql", "redis",
    "elastic", "search", "api-v1", "api-v2", "v1", "v2", "beta", "alpha",
    "demo", "sandbox", "qa", "uat", "prod", "internal", "intranet",
]

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465,
    587, 993, 995, 1433, 1521, 2049, 2181, 3000, 3306, 3389, 4369,
    5000, 5432, 5601, 5900, 6379, 7001, 8000, 8080, 8081, 8443, 8888,
    9000, 9090, 9200, 9300, 11211, 27017,
]

COMMON_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/.git/config", "/.env",
    "/admin", "/login", "/api", "/api/v1", "/swagger.json", "/openapi.json",
    "/graphql", "/health", "/status", "/metrics", "/backup", "/config",
    "/phpinfo.php", "/.well-known/security.txt", "/server-status",
]


def available_tools() -> Dict[str, str]:
    result: Dict[str, str] = {}
    for name in ("nmap", "httpx", "subfinder", "amass", "katana", "nuclei",
                 "ffuf", "gospider", "dnsx", "naabu"):
        path = shutil.which(name)
        if path:
            result[name] = path
    return result


def _run(cmd: List[str], timeout: int = 120) -> str:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return (proc.stdout or "") + (proc.stderr or "")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def nmap_scan(host: str, ports: List[int] | None = None) -> List[Dict[str, Any]]:
    ports = ports or COMMON_PORTS
    tool = shutil.which("nmap")
    if not tool:
        return _python_port_scan(host, ports)
    port_spec = ",".join(str(p) for p in ports)
    out = _run([tool, "-T4", "-sV", "-Pn", "-p", port_spec, host], timeout=180)
    results: List[Dict[str, Any]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or "/" not in line:
            continue
        # e.g. "80/tcp open  http    Apache httpd 2.4.41"
        parts = line.split()
        if len(parts) < 2 or "open" not in parts:
            continue
        port_proto = parts[0]
        if "/" not in port_proto:
            continue
        port_str, proto = port_proto.split("/", 1)
        try:
            port_num = int(port_str)
        except ValueError:
            continue
        service = parts[3] if len(parts) > 3 else ""
        version = " ".join(parts[4:]) if len(parts) > 4 else ""
        results.append({
            "port": port_num,
            "protocol": proto,
            "state": "open",
            "service": service,
            "version": version,
        })
    if not results:
        return _python_port_scan(host, ports)
    return _dedup_ports(results)


def _python_port_scan(host: str, ports: List[int]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    lock = threading.Lock()

    def check(port: int) -> None:
        try:
            with socket.create_connection((host, port), timeout=2):
                with lock:
                    results.append({"port": port, "protocol": "tcp",
                                   "state": "open", "service": "", "version": ""})
        except (OSError, socket.timeout):
            pass

    threads = []
    for port in ports:
        t = threading.Thread(target=check, args=(port,), daemon=True)
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=4)
    return _dedup_ports(results)


def _dedup_ports(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Set[int] = set()
    out: List[Dict[str, Any]] = []
    for item in items:
        port = item.get("port")
        if port in seen:
            continue
        seen.add(port)
        out.append(item)
    return sorted(out, key=lambda x: x.get("port", 0))


def httpx_probe(urls: List[str], timeout: int = 10) -> List[Dict[str, Any]]:
    # The host may ship python-httpx (different CLI), so prefer the reliable
    # pure-Python probe.  A real projectdiscovery httpx binary is still used
    # when its help advertises the expected flags.
    tool = shutil.which("httpx")
    if tool:
        help_text = _run([tool, "-h"], timeout=5)
        if "-silent" in help_text and "-json" in help_text and "tech-detect" in help_text:
            try:
                proc = subprocess.run(
                    [tool, "-silent", "-json", "-status-code", "-title",
                     "-tech-detect", "-follow-redirects"],
                    input="\n".join(urls), capture_output=True, text=True,
                    timeout=timeout + 30,
                )
                out = (proc.stdout or "") + (proc.stderr or "")
                results: List[Dict[str, Any]] = []
                for line in out.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    results.append({
                        "url": obj.get("url") or obj.get("input"),
                        "status_code": obj.get("status_code"),
                        "title": obj.get("title"),
                        "tech": obj.get("tech") or obj.get("technologies") or [],
                        "content_length": obj.get("content_length"),
                    })
                if results:
                    return _dedup_http(results)
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
    return _python_http_probe(urls, timeout)


def _python_http_probe(urls: List[str], timeout: int) -> List[Dict[str, Any]]:
    import urllib.request
    import urllib.error

    results: List[Dict[str, Any]] = []
    lock = threading.Lock()

    def probe(url: str) -> None:
        try:
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", "HackIt-Recon/1.0")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(4096).decode("utf-8", "replace")
                title = ""
                import re
                m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                if m:
                    title = m.group(1).strip()[:120]
                with lock:
                    results.append({
                        "url": url,
                        "status_code": resp.status,
                        "title": title,
                        "tech": [],
                        "content_length": len(body),
                    })
        except urllib.error.HTTPError as exc:
            with lock:
                results.append({
                    "url": url,
                    "status_code": exc.code,
                    "title": "",
                    "tech": [],
                    "content_length": 0,
                })
        except Exception:
            pass

    threads = []
    for url in urls:
        t = threading.Thread(target=probe, args=(url,), daemon=True)
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=timeout + 2)
    return _dedup_http(results)


def _dedup_http(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Set[str] = set()
    out: List[Dict[str, Any]] = []
    for item in items:
        key = f"{item.get('url')}|{item.get('status_code')}"
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def subdomain_enum(host: str) -> List[str]:
    if _is_ip(host):
        return []
    tool = shutil.which("subfinder") or shutil.which("amass")
    if tool:
        if "subfinder" in tool:
            out = _run([tool, "-d", host, "-silent"], timeout=180)
        else:
            out = _run([tool, "enum", "-passive", "-d", host], timeout=180)
        names = []
        for line in out.splitlines():
            line = line.strip().lower()
            if line and host in line:
                names.append(line)
        if names:
            return _dedup_str(names)
    return _python_subdomain_enum(host)


def _python_subdomain_enum(host: str) -> List[str]:
    found: List[str] = []
    lock = threading.Lock()

    def check(name: str) -> None:
        fqdn = f"{name}.{host}"
        try:
            socket.gethostbyname(fqdn)
            with lock:
                found.append(fqdn)
        except socket.gaierror:
            pass

    threads = []
    for prefix in COMMON_SUBDOMAINS:
        t = threading.Thread(target=check, args=(prefix,), daemon=True)
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=5)
    return _dedup_str(found)


def _dedup_str(items: List[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for item in items:
        key = str(item).strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(key)
    return sorted(out)


def _is_ip(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except (OSError, socket.error):
        try:
            import ipaddress
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False


def aggregate_recon(host: str, base_url: str) -> Dict[str, Any]:
    """Run all available recon techniques and return deduped data."""
    subdomains = subdomain_enum(host)
    ports = nmap_scan(host)
    probe_urls = [base_url]
    for sub in subdomains[:20]:
        probe_urls.append(f"https://{sub}")
        probe_urls.append(f"http://{sub}")
    probe_urls = _dedup_str(probe_urls)
    http_results = httpx_probe(probe_urls)
    endpoints: List[str] = []
    for result in http_results:
        url = result.get("url")
        if url:
            endpoints.append(url)
    endpoints = _dedup_str(endpoints)
    return {
        "subdomains": subdomains,
        "ports": ports,
        "http_probe": http_results,
        "endpoints": endpoints,
        "tools": available_tools(),
    }