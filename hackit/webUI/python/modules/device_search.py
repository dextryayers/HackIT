import httpx
import asyncio
import json
import re
from datetime import datetime
from typing import List, Optional
from urllib.parse import urlparse
from models import IntelligenceFinding

DEVICE_API_SOURCES = [
    ("shodan", "https://api.shodan.io/shodan/host/{}"),
    ("censys", "https://search.censys.io/api/v2/hosts/{}"),
    ("fofa", "https://fofa.info/api/v1/search/all?qbase64={}"),
    ("zoomeye", "https://api.zoomeye.org/host/search/{}"),
]

async def device_fingerprint(ip: str, client: httpx.AsyncClient) -> dict:
    results = {}
    for name, url_tmpl in DEVICE_API_SOURCES:
        try:
            url = url_tmpl.format(ip)
            resp = await client.get(url, timeout=10.0,
                headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                try:
                    results[name] = resp.json()
                except:
                    results[name] = {"raw": resp.text[:500]}
        except:
            pass
    return results

IOT_KEYWORDS = ["camera", "router", "switch", "printer", "scanner", "iot", "smart",
    "sensor", "thermostat", "doorbell", "lock", "light", "plug", "hub", "bridge",
    "gateway", "arm", "mcu", "esp", "arduino", "raspberry", "nvr", "dvr"]

INDUSTRIAL_KEYWORDS = ["plc", "scada", "hmi", "rtu", "modbus", "s7", "bacnet",
    "dnp3", "hart", "profibus", "industrial", "cnc", "robot", "controller"]

async def classify_device(banner: str, headers: dict) -> list:
    types = []
    bl = banner.lower() if banner else ""
    for kw in IOT_KEYWORDS:
        if kw in bl:
            types.append(f"IoT/{kw}")
            break
    for kw in INDUSTRIAL_KEYWORDS:
        if kw in bl:
            types.append(f"Industrial/{kw}")
            break
    for key, val in headers.items():
        kl = key.lower()
        vl = val.lower()
        if "server" in kl:
            if "apache" in vl: types.append("Web Server/Apache")
            elif "nginx" in vl: types.append("Web Server/Nginx")
            elif "iis" in vl: types.append("Web Server/IIS")
            elif "lighttpd" in vl: types.append("Web Server/Lighttpd")
            elif "caddy" in vl: types.append("Web Server/Caddy")
        if "x-powered-by" in kl:
            types.append(f"Platform/{val}")
    return list(set(types))

async def response_headers(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        for scheme in ("https", "http"):
            try:
                resp = await client.get(f"{scheme}://{ip}", timeout=5.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code:
                    return {
                        "headers": dict(resp.headers),
                        "status": resp.status_code,
                        "body_preview": resp.text[:500],
                        "scheme": scheme,
                    }
            except:
                pass
    except:
        pass
    return {}

VULNERABILITY_HEADERS = {
    "X-Powered-By": ["PHP", "ASP.NET", "Express", "Django"],
    "X-AspNet-Version": [r"\d+\.\d+"],
    "X-AspNetMvc-Version": [r"\d+\.\d+"],
    "X-Generator": ["Drupal", "WordPress"],
    "X-Drupal-Cache": [r"\d+"],
    "X-Varnish": [r"\d+"],
    "X-Cache": ["HIT", "MISS"],
}

FRAMEWORK_PATTERNS = {
    "PHP": [r"\.php", r"PHPSESSID", r"X-Powered-By: PHP"],
    "ASP.NET": [r"\.aspx", r"\.ashx", r"ASP.NET", r"ViewState"],
    "Java": [r"\.jsp", r"\.do", r"JSESSIONID", r"Servlet"],
    "Python": [r"wsgi", r"flask", r"django", r"python"],
    "Node.js": [r"node", r"express", r"koa", r"next\.js"],
    "Ruby": [r"ruby", r"rails", r"rack"],
    "Go": [r"gin", r"echo", r"fiber", r"go"],
    "Rust": [r"rocket", r"actix", r"warp"],
}

CPE_PATTERNS = {
    "Apache": [r"apache", r"httpd"],
    "Nginx": [r"nginx"],
    "IIS": [r"iis", r"microsoft-iis"],
    "Tomcat": [r"tomcat", r"catalina"],
    "Jetty": [r"jetty"],
    "Node.js": [r"node\.js", r"nodejs"],
    "Python": [r"python", r"gunicorn", r"uwsgi"],
    "Ruby": [r"ruby", r"passenger", r"puma"],
    "OpenSSL": [r"openssl"],
    "OpenSSH": [r"openssh", r"ssh"],
}

async def detect_fingerprint_version(server_header: str) -> list:
    findings = []
    server_lower = server_header.lower()
    version_patterns = [
        (r"(apache|httpd)/([\d.]+)", "Apache HTTP Server"),
        (r"nginx/([\d.]+)", "Nginx"),
        (r"(iis|microsoft-iis)/([\d.]+)", "IIS"),
        (r"tomcat/([\d.]+)", "Apache Tomcat"),
        (r"jetty/([\d.]+)", "Jetty"),
        (r"node\.js/([\d.]+)", "Node.js"),
        (r"(gunicorn|uwsgi)/([\d.]+)", "Python WSGI"),
        (r"openresty/([\d.]+)", "OpenResty"),
        (r"caddy/([\d.]+)", "Caddy"),
    ]
    for pat, name in version_patterns:
        m = re.search(pat, server_lower)
        if m:
            ver = m.group(2) if m.lastindex >= 2 else m.group(1)
            findings.append(IntelligenceFinding(
                entity=f"Versioned: {name} {ver}",
                type="Device Search: Software Version",
                source="DeviceSearch",
                confidence="High",
                color="slate",
                status="Versioned",
                tags=["device", "version", name.lower().replace(" ", "-")]
            ))
    return findings

async def check_vulnerability_headers(headers: dict) -> list:
    findings = []
    for hdr, patterns in VULNERABILITY_HEADERS.items():
        val = headers.get(hdr, "")
        if val:
            findings.append(IntelligenceFinding(
                entity=f"Info leak header: {hdr}: {val}",
                type="Device Search: Information Disclosure",
                source="DeviceSearch",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                status="Disclosed",
                tags=["device", "info-leak", hdr.lower().replace("-", "_")]
            ))
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    ip = target.strip().lower()
    if ip.startswith("http"):
        ip = urlparse(ip).netloc

    try:
        import socket
        socket.inet_aton(ip)
    except:
        findings.append(IntelligenceFinding(
            entity="Invalid IP address for device search",
            type="Device Search: Invalid Input",
            source="DeviceSearch",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Error",
            resolution=ip,
            tags=["device", "error"]
        ))
        return findings

    headers = await response_headers(ip, client)
    if headers:
        findings.append(IntelligenceFinding(
            entity=f"HTTP {headers.get('scheme', 'http')}://{ip} - Status: {headers.get('status', 0)}",
            type="Device Search: HTTP Response",
            source="DeviceSearch",
            confidence="Medium",
            color="slate",
            status="Responding",
            resolution=ip,
            tags=["device", "http"]
        ))

        device_types = await classify_device(
            headers.get("body_preview", ""),
            headers.get("headers", {})
        )
        for dt in device_types:
            findings.append(IntelligenceFinding(
                entity=f"Device Type: {dt}",
                type="Device Search: Device Classification",
                source="DeviceSearch",
                confidence="Medium",
                color="slate",
                status="Identified",
                resolution=ip,
                tags=["device", "classification"]
            ))

        srv = headers.get("headers", {}).get("Server", "")
        if srv:
            findings.append(IntelligenceFinding(
                entity=f"Server: {srv}",
                type="Device Search: Server Fingerprint",
                source="DeviceSearch",
                confidence="High",
                color="slate",
                status="Fingerprinted",
                resolution=ip,
                tags=["device", "server", "fingerprint"]
            ))
            version_results = await detect_fingerprint_version(srv)
            for vr in version_results:
                vr.resolution = ip
                findings.append(vr)

        vuln_results = await check_vulnerability_headers(headers.get("headers", {}))
        for vr in vuln_results:
            vr.resolution = ip
            findings.append(vr)

    api_results = await device_fingerprint(ip, client)
    for source, data in api_results.items():
        if data:
            findings.append(IntelligenceFinding(
                entity=f"Device data from {source}",
                type=f"Device Search: {source.title()}",
                source=source,
                confidence="Medium",
                color="slate",
                status="Retrieved",
                resolution=ip,
                tags=["device", source]
            ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity="No device information found",
            type="Device Search: Complete",
            source="DeviceSearch",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Not Found",
            resolution=ip,
            tags=["device", "empty"]
        ))

    return findings
