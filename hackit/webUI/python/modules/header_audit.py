import httpx
from models import IntelligenceFinding

SECURITY_HEADERS = {
    "Content-Security-Policy": ("CSP", "critical", "Prevents XSS and data injection attacks"),
    "Strict-Transport-Security": ("HSTS", "critical", "Enforces HTTPS connections"),
    "X-Frame-Options": ("X-Frame-Options", "high", "Prevents clickjacking"),
    "X-Content-Type-Options": ("X-Content-Type-Options", "high", "Prevents MIME-type sniffing"),
    "Referrer-Policy": ("Referrer-Policy", "medium", "Controls referrer information"),
    "Permissions-Policy": ("Permissions-Policy", "medium", "Controls browser features"),
    "Cross-Origin-Opener-Policy": ("COOP", "medium", "Isolates cross-origin windows"),
    "Cross-Origin-Resource-Policy": ("CORP", "medium", "Controls resource sharing"),
    "Cross-Origin-Embedder-Policy": ("COEP", "medium", "Requires CORP for cross-origin resources"),
}

CDN_INDICATORS = {
    "cf-ray": "Cloudflare",
    "x-akamai-transformed": "Akamai",
    "x-fastly-request-id": "Fastly",
    "x-amz-cf-id": "AWS CloudFront",
    "x-cdn": "Generic CDN",
    "x-sucuri-id": "Sucuri WAF",
    "x-sucuri-cache": "Sucuri Cache",
    "x-encoded-content-encoding": "Reverse Proxy",
}

INFO_HEADERS = [
    "Server", "X-Powered-By", "X-Generator", "X-AspNet-Version",
    "X-AspNetMvc-Version", "X-Runtime", "X-Version", "Via",
]

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    base_url = f"https://{target}" if not target.startswith("http") else target

    try:
        resp = await client.get(base_url, timeout=15.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        headers = dict(resp.headers)
        status = resp.status_code

        findings.append(IntelligenceFinding(
            entity=str(status),
            type="HTTP Status Code",
            source="HeaderAudit",
            confidence="High",
            color="emerald" if status < 400 else "orange",
            threat_level="Informational" if status < 400 else "Standard Target",
            raw_data=f"Response status: {status}"
        ))

        for header_key, (display, severity, desc) in SECURITY_HEADERS.items():
            val = headers.get(header_key.lower())
            if val:
                color = "emerald" if severity == "critical" else ("blue" if severity == "high" else "slate")
                findings.append(IntelligenceFinding(
                    entity=f"{display}: {val[:80]}{'...' if len(val) > 80 else ''}",
                    type=f"Security Header: {display} (Present)",
                    source="HeaderAudit",
                    confidence="High",
                    color=color,
                    threat_level="Informational",
                    status="Implemented",
                    raw_data=f"{header_key}: {val[:2000]}",
                    tags=[severity]
                ))
            else:
                findings.append(IntelligenceFinding(
                    entity=display,
                    type=f"Missing Security Header: {display}",
                    source="HeaderAudit",
                    confidence="High",
                    color="red" if severity == "critical" else ("orange" if severity == "high" else "yellow"),
                    category="Security & Exposure Analysis",
                    threat_level="High Risk" if severity == "critical" else ("Elevated Risk" if severity == "high" else "Informational"),
                    status="Missing",
                    raw_data=f"Missing: {header_key} - {desc}",
                    tags=[severity]
                ))

        for key, name in CDN_INDICATORS.items():
            if key in headers:
                findings.append(IntelligenceFinding(
                    entity=name,
                    type="CDN / Reverse Proxy",
                    source="HeaderAudit",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    raw_data=f"Detected via {key}: {headers[key]}"
                ))

        server = headers.get("server")
        if server:
            findings.append(IntelligenceFinding(
                entity=server[:200],
                type="Web Server",
                source="HeaderAudit",
                confidence="High",
                color="indigo",
                threat_level="Informational",
                status="Detected",
                raw_data=f"Server: {server}"
            ))

        for info_h in INFO_HEADERS:
            val = headers.get(info_h.lower())
            if val and info_h.lower() != "server":
                findings.append(IntelligenceFinding(
                    entity=val[:200],
                    type=f"Technology: {info_h}",
                    source="HeaderAudit",
                    confidence="High",
                    color="purple",
                    threat_level="Informational",
                    raw_data=f"{info_h}: {val[:500]}"
                ))

        cookies_raw = headers.get("set-cookie", "")
        if cookies_raw:
            for cookie in cookies_raw.split("\n"):
                cookie = cookie.strip()
                if cookie:
                    parts = cookie.split(";")[0]
                    findings.append(IntelligenceFinding(
                        entity=parts[:150],
                        type="Cookie Set",
                        source="HeaderAudit",
                        confidence="Medium",
                        color="yellow",
                        threat_level="Informational",
                        raw_data=cookie[:500]
                    ))

        location = headers.get("location")
        if location:
            findings.append(IntelligenceFinding(
                entity=location[:300],
                type="Redirect Target",
                source="HeaderAudit",
                confidence="High",
                color="slate",
                threat_level="Informational",
                raw_data=f"Redirects to: {location}"
            ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=str(e)[:150],
            type="Header Audit Error",
            source="HeaderAudit",
            confidence="Low",
            color="red",
            threat_level="Informational"
        ))

    return findings
