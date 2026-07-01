import httpx
import re
from urllib.parse import urlparse
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

PROXY_HEADERS = [
    "x-forwarded-for", "x-real-ip", "x-forwarded-proto", "x-forwarded-host",
    "x-forwarded-server", "x-original-url", "x-rewrite-url", "x-original-host",
    "x-original-proto", "x-forwarded-ssl", "x-url-scheme", "x-proxy-user",
    "x-proxy-remote-ip", "x-authenticated-user", "x-is-authenticated",
    "x-remote-ip", "x-remote-addr", "x-client-ip", "x-cluster-client-ip",
    "x-request-uri", "x-request-path", "x-backend-host", "x-backend-server",
    "x-backend-status", "x-cache-hits", "x-cache-status", "x-varnish",
]

PROXY_SOFTWARE_SIGNATURES = {
    "nginx": [r"nginx/?[\d.]*", r"x-nginx-proxy"],
    "Apache": [r"Apache/?[\d.]*", r"mod_proxy"],
    "HAProxy": [r"HAProxy", r"x-haproxy"],
    "Varnish": [r"Varnish", r"x-varnish"],
    "Squid": [r"Squid", r"x-squid"],
    "Traffic Server": [r"Traffic Server", r"ApacheTrafficServer"],
    "Envoy": [r"Envoy", r"x-envoy"],
    "Traefik": [r"Traefik", r"x-traefik"],
    "Caddy": [r"Caddy", r"caddy"],
    "IIS ARR": [r"IIS", r"ARR", r"Application Request Routing"],
    "ATS": [r"ApacheTrafficServer", r"trafficserver"],
    "Pound": [r"Pound"],
    "Polaris": [r"Polaris"],
    "Tengine": [r"Tengine"],
    "OpenResty": [r"OpenResty"],
    "Kong": [r"Kong"],
    "Apache APISIX": [r"APISIX"],
    "Souin": [r"Souin"],
    "Fly.io": [r"fly.io", r"x-fly"],
}

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    detected_proxies = set()

    for proto in ["https", "http"]:
        try:
            resp = await client.get(f"{proto}://{domain}", timeout=10.0, follow_redirects=True, headers={"User-Agent": UA})
            headers = {k.lower(): v for k, v in dict(resp.headers).items()}
            full_headers = dict(resp.headers)
            status = resp.status_code

            findings.append(IntelligenceFinding(
                entity=f"Initial response: HTTP {status} ({len(resp.content)} bytes)",
                type="Proxy: Initial Response",
                source="ReverseProxyDetector",
                confidence="High",
                color="slate",
                threat_level="Informational",
                tags=["proxy", "initial"]
            ))

            found_proxy_headers = []
            for ph in PROXY_HEADERS:
                if ph in headers:
                    found_proxy_headers.append((ph, headers[ph]))
                    findings.append(IntelligenceFinding(
                        entity=f"Proxy header found: {ph}: {headers[ph][:60]}",
                        type="Proxy: Proxy Header",
                        source="ReverseProxyDetector",
                        confidence="High",
                        color="blue",
                        threat_level="Informational",
                        raw_data=f"header={ph}, value={headers[ph][:200]}",
                        tags=["proxy", "header"]
                    ))

            if not found_proxy_headers:
                findings.append(IntelligenceFinding(
                    entity="No reverse proxy headers detected",
                    type="Proxy: No Proxy Headers",
                    source="ReverseProxyDetector",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    tags=["proxy", "no-headers"]
                ))

            for hdr_name, hdr_val in headers.items():
                for sw_name, patterns in PROXY_SOFTWARE_SIGNATURES.items():
                    for pattern in patterns:
                        if re.search(pattern, hdr_val, re.I) or re.search(pattern, hdr_name, re.I):
                            if sw_name not in detected_proxies:
                                detected_proxies.add(sw_name)
                                findings.append(IntelligenceFinding(
                                    entity=f"Reverse proxy software detected: {sw_name} (via {hdr_name}: {hdr_val[:60]})",
                                    type="Proxy: Software Detection",
                                    source="ReverseProxyDetector",
                                    confidence="High",
                                    color="purple",
                                    threat_level="Informational",
                                    raw_data=f"software={sw_name}, header={hdr_name}, value={hdr_val[:200]}",
                                    tags=["proxy", "software", sw_name.lower().replace(" ", "-")]
                                ))

            server_header = headers.get("server", "")
            if server_header:
                for sw_name, patterns in PROXY_SOFTWARE_SIGNATURES.items():
                    for pattern in patterns:
                        if re.search(pattern, server_header, re.I):
                            if sw_name not in detected_proxies:
                                detected_proxies.add(sw_name)
                                findings.append(IntelligenceFinding(
                                    entity=f"Reverse proxy: {sw_name} (via Server header: {server_header})",
                                    type="Proxy: Software from Server Header",
                                    source="ReverseProxyDetector",
                                    confidence="Medium",
                                    color="purple",
                                    threat_level="Informational",
                                    raw_data=f"software={sw_name}, server={server_header}",
                                    tags=["proxy", "software", sw_name.lower().replace(" ", "-")]
                                ))

            test_paths = ["/", "/admin", "/api", "/static", "/images", "/test"]
            for path in test_paths:
                try:
                    r = await client.get(f"{proto}://{domain}{path}", timeout=5.0, follow_redirects=False, headers={"User-Agent": UA})
                    if r.status_code != status:
                        findings.append(IntelligenceFinding(
                            entity=f"Path-based routing: {path} -> HTTP {r.status_code} (different from root {status})",
                            type="Proxy: Path Routing",
                            source="ReverseProxyDetector",
                            confidence="Medium",
                            color="yellow",
                            threat_level="Informational",
                            raw_data=f"path={path}, status={r.status_code}, root_status={status}",
                            tags=["proxy", "path-routing"]
                        ))
                except Exception:
                    continue

            resp2 = await client.get(f"{proto}://{domain}", timeout=10.0, follow_redirects=False, headers={"User-Agent": UA, "X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1", "X-Original-URL": "/admin", "X-Rewrite-URL": "/admin"})
            headers2 = dict(resp2.headers)

            if headers2 != full_headers:
                findings.append(IntelligenceFinding(
                    entity="Server behavior changes with proxy headers (e.g., X-Forwarded-For, X-Original-URL)",
                    type="Proxy: Header Injection Response",
                    source="ReverseProxyDetector",
                    confidence="Medium",
                    color="orange",
                    threat_level="Elevated Risk",
                    raw_data="Server responded differently when proxy headers were sent",
                    tags=["proxy", "header-injection", "risk"]
                ))

            break
        except Exception:
            continue

    if not detected_proxies:
        findings.append(IntelligenceFinding(
            entity=f"No reverse proxy software detected for {domain}",
            type="Proxy: No Proxy Detected",
            source="ReverseProxyDetector",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            tags=["proxy", "none"]
        ))
    else:
        findings.append(IntelligenceFinding(
            entity=f"Reverse Proxy Assessment: {', '.join(detected_proxies)} ({len(detected_proxies)} software(s))",
            type="Proxy: Assessment",
            source="ReverseProxyDetector",
            confidence="High",
            color="purple",
            threat_level="Informational",
            raw_data=f"software={', '.join(detected_proxies)}",
            tags=["proxy", "assessment"]
        ))

    return findings
