import re
import json
from datetime import datetime
from urllib.parse import urlparse
from module_common import safe_fetch, safe_fetch_json, make_finding

SECURITY_HEADERS = {
    "content-security-policy": "CSP",
    "strict-transport-security": "HSTS",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "x-xss-protection": "X-XSS-Protection",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "access-control-allow-origin": "CORS",
    "access-control-allow-methods": "CORS Methods",
    "access-control-allow-headers": "CORS Headers",
    "access-control-expose-headers": "CORS Expose",
    "cross-origin-opener-policy": "COOP",
    "cross-origin-embedder-policy": "COEP",
    "cross-origin-resource-policy": "CORP",
}

COOKIE_ATTRS = ["Secure", "HttpOnly", "SameSite", "Domain", "Path", "Expires", "Max-Age"]

SERVER_FINGERPRINT = {
    "nginx": "Nginx", "apache": "Apache", "iis": "IIS",
    "cloudflare": "Cloudflare", "akamai": "Akamai",
    "gunicorn": "Gunicorn", "uvicorn": "Uvicorn",
    "kestrel": "Kestrel (.NET)", "caddy": "Caddy",
    "openresty": "OpenResty", "lighttpd": "Lighttpd",
    "fastly": "Fastly", "varnish": "Varnish",
    "node": "Node.js", "express": "Express.js",
}

async def _analyze_archive_headers(domain: str, client) -> list:
    findings = []
    data = await safe_fetch_json(client,
        f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original,timestamp,statuscode&limit=15&filter=statuscode:200&collapse=urlkey",
        timeout=20.0,
        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
    if data:
        server_history = {}
        for row in data[1:15]:
            if isinstance(row, list) and len(row) >= 2:
                orig = row[0]
                ts = row[1]
                snap = await safe_fetch(client,
                    f"http://web.archive.org/web/{ts}if_/{orig}",
                    timeout=10.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if snap and snap.status_code == 200:
                    hdrs = snap.headers
                    server = hdrs.get("server", "")
                    powered = hdrs.get("x-powered-by", "")
                    set_cookie = hdrs.get("set-cookie", "")
                    csp = hdrs.get("content-security-policy", "")
                    location = hdrs.get("location", "")
                    vary = hdrs.get("vary", "")
                    content_type = hdrs.get("content-type", "")
                    xfo = hdrs.get("x-frame-options", "")
                    hsts = hdrs.get("strict-transport-security", "")
                    xcto = hdrs.get("x-content-type-options", "")

                    date_val = ts[:8]

                    if server:
                        date_key = f"{server}|{date_val}"
                        server_history[date_key] = server_history.get(date_key, 0) + 1
                        for sig, label in SERVER_FINGERPRINT.items():
                            if sig in server.lower():
                                findings.append(make_finding(
                                    entity=f"{label} [{date_val}]",
                                    ftype="Forensic HTTP - Server Fingerprint",
                                    source="Wayback Machine",
                                    confidence="High", color="orange",
                                    status="Historical",
                                    raw_data=f"Server: {server} on {date_val}",
                                    tags=["forensic", "http", "server"]
                                ))
                                break
                        else:
                            findings.append(make_finding(
                                entity=f"Server: {server} [{date_val}]",
                                ftype="Forensic HTTP - Custom Server Header",
                                source="Wayback Machine",
                                confidence="High", color="slate",
                                status="Historical",
                                tags=["forensic", "http", "server"]
                            ))

                    if powered:
                        findings.append(make_finding(
                            entity=f"X-Powered-By: {powered} [{date_val}]",
                            ftype="Forensic HTTP - Platform Header",
                            source="Wayback Machine",
                            confidence="High", color="slate",
                            status="Historical",
                            tags=["forensic", "http", "platform"]
                        ))

                    if set_cookie:
                        found_attrs = []
                        for attr in COOKIE_ATTRS:
                            if attr.lower() in set_cookie.lower():
                                found_attrs.append(attr)
                        findings.append(make_finding(
                            entity=f"Cookie attributes: {', '.join(found_attrs)} [{date_val}]",
                            ftype="Forensic HTTP - Cookie Security Attributes",
                            source="Wayback Machine",
                            confidence="High",
                            color="emerald" if "Secure" in found_attrs and "HttpOnly" in found_attrs else "orange",
                            threat_level="Informational" if "Secure" in found_attrs else "Elevated Risk",
                            status="Historical",
                            raw_data=f"Set-Cookie: {set_cookie[:300]}",
                            tags=["forensic", "http", "cookie"]
                        ))
                        if "Secure" not in set_cookie:
                            findings.append(make_finding(
                                entity=f"Cookie missing Secure flag [{date_val}]",
                                ftype="Forensic HTTP - Insecure Cookie",
                                source="Wayback Machine",
                                confidence="High", color="red",
                                threat_level="Elevated Risk",
                                tags=["forensic", "http", "insecure-cookie"]
                            ))

                    if location:
                        findings.append(make_finding(
                            entity=f"Redirect to: {location} [{date_val}]",
                            ftype="Forensic HTTP - Redirect Target",
                            source="Wayback Machine",
                            confidence="High", color="slate",
                            status="Historical",
                            tags=["forensic", "http", "redirect"]
                        ))

                    if csp:
                        if "unsafe-inline" in csp or "unsafe-eval" in csp:
                            findings.append(make_finding(
                                entity=f"CSP allows unsafe directives [{date_val}]",
                                ftype="Forensic HTTP - CSP Weakness",
                                source="Wayback Machine",
                                confidence="High", color="red",
                                threat_level="Elevated Risk",
                                raw_data=f"CSP: {csp[:200]}",
                                tags=["forensic", "http", "csp"]
                            ))

                    if xfo:
                        findings.append(make_finding(
                            entity=f"X-Frame-Options: {xfo} [{date_val}]",
                            ftype="Forensic HTTP - Clickjacking Protection",
                            source="Wayback Machine",
                            confidence="High", color="emerald",
                            status="Historical",
                            tags=["forensic", "http", "x-frame-options"]
                        ))
                    else:
                        findings.append(make_finding(
                            entity=f"Missing X-Frame-Options [{date_val}]",
                            ftype="Forensic HTTP - Missing Clickjacking Protection",
                            source="Wayback Machine",
                            confidence="High", color="orange",
                            threat_level="Standard Target",
                            tags=["forensic", "http", "missing-header"]
                        ))

                    if hsts:
                        hsts_attrs = hsts.split(";")
                        for attr in hsts_attrs:
                            attr = attr.strip()
                            if attr.startswith("max-age="):
                                try:
                                    max_age = int(attr.split("=")[1])
                                    findings.append(make_finding(
                                        entity=f"HSTS max-age={max_age}s ({max_age//86400}d) [{date_val}]",
                                        ftype="Forensic HTTP - HSTS Duration",
                                        source="Wayback Machine",
                                        confidence="High",
                                        color="emerald" if max_age >= 31536000 else "orange",
                                        status="Historical",
                                        tags=["forensic", "http", "hsts"]
                                    ))
                                except Exception:
                                    pass
                    else:
                        findings.append(make_finding(
                            entity=f"Missing HSTS [{date_val}]",
                            ftype="Forensic HTTP - Missing HSTS",
                            source="Wayback Machine",
                            confidence="High", color="orange",
                            threat_level="Standard Target",
                            tags=["forensic", "http", "missing-header"]
                        ))

                    if xcto:
                        findings.append(make_finding(
                            entity=f"X-Content-Type-Options: {xcto} [{date_val}]",
                            ftype="Forensic HTTP - MIME Sniffing Protection",
                            source="Wayback Machine",
                            confidence="High", color="emerald",
                            status="Historical",
                            tags=["forensic", "http", "x-content-type-options"]
                        ))

                    if vary:
                        findings.append(make_finding(
                            entity=f"Vary: {vary} [{date_val}]",
                            ftype="Forensic HTTP - Caching Behavior",
                            source="Wayback Machine",
                            confidence="High", color="slate",
                            tags=["forensic", "http", "cache"]
                        ))

                    if content_type:
                        findings.append(make_finding(
                            entity=f"Content-Type: {content_type} [{date_val}]",
                            ftype="Forensic HTTP - Content Type",
                            source="Wayback Machine",
                            confidence="High", color="slate",
                            tags=["forensic", "http", "content-type"]
                        ))

        if server_history:
            server_versions = set()
            for key in server_history:
                server_versions.add(key.split("|")[0])
            if len(server_versions) > 1:
                findings.append(make_finding(
                    entity=f"Server software changed {len(server_versions)} times in history",
                    ftype="Forensic HTTP - Server Version History",
                    source="Wayback Machine",
                    confidence="High", color="orange",
                    status="Changes Detected",
                    raw_data=f"Different servers seen: {', '.join(server_versions)}",
                    tags=["forensic", "http", "server-history"]
                ))

    return findings

async def _check_security_headers_summary(findings_sofar: list) -> list:
    findings = []
    headers_seen = set()
    missing_critical = []
    for f in findings_sofar:
        if "Forensic HTTP" in f.type:
            for hdr_name in SECURITY_HEADERS:
                if hdr_name.replace("-", " ").lower() in f.entity.lower() or hdr_name.lower() in f.entity.lower():
                    headers_seen.add(hdr_name)
    for hdr in SECURITY_HEADERS:
        if hdr not in headers_seen:
            missing_critical.append(hdr)
    if missing_critical:
        findings.append(make_finding(
            entity=f"Security headers never observed: {', '.join(missing_critical[:8])}",
            ftype="Forensic HTTP - Missing Security Headers (All Time)",
            source="Forensic HTTP Response",
            confidence="High", color="red",
            threat_level="Elevated Risk",
            status="Headers Missing",
            tags=["forensic", "http", "security-headers"]
        ))
    return findings

async def crawl(target: str, client) -> list:
    findings = []
    domain = target.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).netloc

    archive_hdr_findings = await _analyze_archive_headers(domain, client)
    findings.extend(archive_hdr_findings)

    summary_findings = await _check_security_headers_summary(findings)
    findings.extend(summary_findings)

    if findings:
        findings.append(make_finding(
            entity=f"Forensic HTTP Response analysis complete: {len(findings)} findings",
            ftype="Forensic HTTP - Summary",
            source="Forensic HTTP Response",
            confidence="High", color="purple",
            status="Complete",
            tags=["forensic", "http", "summary"]
        ))

    return findings
