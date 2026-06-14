import httpx
import ssl
import socket
import asyncio
from models import IntelligenceFinding
from osint_common import get_ssl_cert_info, parse_cert_to_dict

TECH_SIGNATURES = {
    "X-Powered-By": ("Tech Stack", "orange"),
    "X-Generator": ("CMS Detection", "orange"),
    "X-Drupal-Cache": ("CMS: Drupal", "blue"),
    "X-Drupal-Dynamic-Cache": ("CMS: Drupal", "blue"),
    "X-Generator": ("CMS Detection", "orange"),
}

SERVER_SIGNATURES = {
    "nginx": "Web Server: Nginx",
    "apache": "Web Server: Apache",
    "cloudflare": "CDN: Cloudflare",
    "akamai": "CDN: Akamai",
    "iis": "Web Server: IIS",
    "lighttpd": "Web Server: Lighttpd",
    "caddy": "Web Server: Caddy",
    "openresty": "Web Server: OpenResty",
    "gunicorn": "Web Server: Gunicorn",
    "uvicorn": "Web Server: Uvicorn",
    "node": "Tech: Node.js",
    "express": "Tech: Express.js",
    "next.js": "Tech: Next.js",
    "python": "Tech: Python",
    "java": "Tech: Java",
    "tomcat": "Tech: Apache Tomcat",
    "jetty": "Tech: Jetty",
    "netty": "Tech: Netty",
}

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    base_url = f"https://{target}" if not target.startswith("http") else target

    try:
        resp = await client.get(base_url, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        headers = dict(resp.headers)
        html = resp.text[:100000] if hasattr(resp, 'text') else ""

        for header_key, (ftype, color) in TECH_SIGNATURES.items():
            val = headers.get(header_key.lower())
            if val:
                findings.append(IntelligenceFinding(
                    entity=val[:200],
                    type=ftype,
                    source="WebTech",
                    confidence="High",
                    color=color,
                    threat_level="Informational",
                    raw_data=f"{header_key}: {val[:500]}"
                ))

        server = (headers.get("server") or "").lower()
        if server:
            for sig, ftype in SERVER_SIGNATURES.items():
                if sig in server:
                    findings.append(IntelligenceFinding(
                        entity=headers.get("server", "")[:200],
                        type=ftype,
                        source="WebTech",
                        confidence="High",
                        color="orange",
                        threat_level="Informational",
                        raw_data=headers.get("server", "")
                    ))
                    break
            else:
                findings.append(IntelligenceFinding(
                    entity=headers.get("server", "")[:200],
                    type="Web Server",
                    source="WebTech",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                ))

        ct = headers.get("content-type", "")
        if "php" in html.lower() or "php" in ct:
            findings.append(IntelligenceFinding(
                entity="PHP detected",
                type="Tech: PHP",
                source="WebTech",
                confidence="Medium",
                color="orange",
                threat_level="Informational",
            ))

        if "wp-content" in html or "wp-includes" in html or "wordpress" in html.lower():
            findings.append(IntelligenceFinding(
                entity="WordPress CMS",
                type="CMS: WordPress",
                source="WebTech",
                confidence="High",
                color="blue",
                threat_level="Informational",
                raw_data="WordPress indicators found in HTML"
            ))

        if "csrf" in html.lower() or "csrf_token" in html.lower():
            findings.append(IntelligenceFinding(
                entity="CSRF protection detected",
                type="Security: CSRF Protection",
                source="WebTech",
                confidence="Medium",
                color="emerald",
                threat_level="Informational",
            ))

        if "react" in html.lower() or "reactroot" in html.lower() or "_reactroot" in html.lower():
            findings.append(IntelligenceFinding(
                entity="React.js",
                type="JavaScript Framework",
                source="WebTech",
                confidence="Medium",
                color="cyan",
                threat_level="Informational",
            ))

        if "vue" in html.lower() or "vuejs" in html.lower():
            findings.append(IntelligenceFinding(
                entity="Vue.js",
                type="JavaScript Framework",
                source="WebTech",
                confidence="Medium",
                color="cyan",
                threat_level="Informational",
            ))

        if "angular" in html.lower() or "ng-" in html.lower() or "_ngcontent" in html.lower():
            findings.append(IntelligenceFinding(
                entity="Angular",
                type="JavaScript Framework",
                source="WebTech",
                confidence="Medium",
                color="cyan",
                threat_level="Informational",
            ))

        if "jquery" in html.lower():
            findings.append(IntelligenceFinding(
                entity="jQuery",
                type="JavaScript Library",
                source="WebTech",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
            ))

        if "bootstrap" in html.lower():
            findings.append(IntelligenceFinding(
                entity="Bootstrap",
                type="CSS Framework",
                source="WebTech",
                confidence="Medium",
                color="purple",
                threat_level="Informational",
            ))

        if "tailwind" in html.lower():
            findings.append(IntelligenceFinding(
                entity="Tailwind CSS",
                type="CSS Framework",
                source="WebTech",
                confidence="Medium",
                color="purple",
                threat_level="Informational",
            ))

        if "google-analytics" in html or "googletagmanager" in html:
            findings.append(IntelligenceFinding(
                entity="Google Analytics / Tag Manager",
                type="Analytics / Tracking",
                source="WebTech",
                confidence="High",
                color="slate",
                threat_level="Informational",
            ))

        if "facebook" in html.lower() and ("pixel" in html.lower() or "fbq" in html.lower()):
            findings.append(IntelligenceFinding(
                entity="Facebook Pixel",
                type="Analytics / Tracking",
                source="WebTech",
                confidence="High",
                color="slate",
                threat_level="Informational",
            ))

        csp = headers.get("content-security-policy", "")
        if csp:
            directives = [d.strip() for d in csp.split(";") if d.strip()]
            for d in directives:
                if "unsafe-inline" in d or "unsafe-eval" in d:
                    findings.append(IntelligenceFinding(
                        entity=f"CSP allows unsafe: {d[:80]}",
                        type="CSP Weakness",
                        source="WebTech",
                        confidence="High",
                        color="red",
                        threat_level="Elevated Risk",
                        raw_data=d[:500]
                    ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"WebTech HTTP error: {str(e)[:100]}",
            type="WebTech Error",
            source="WebTech",
            confidence="Low",
            color="red",
            threat_level="Informational"
        ))

    try:
        cert_info = await get_ssl_cert_info(target)
        if cert_info and cert_info.get("cert"):
            cert = cert_info["cert"]
            parsed = parse_cert_to_dict(cert)

            if parsed.get("issuer"):
                org = parsed["issuer"].get("organizationName", "Unknown")
                cn = parsed["issuer"].get("commonName", "")
                findings.append(IntelligenceFinding(
                    entity=f"Issuer: {org} ({cn})" if cn else f"Issuer: {org}",
                    type="SSL Certificate Authority",
                    source="WebTech",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    raw_data=f"Issuer: {parsed['issuer']}"
                ))

            if parsed.get("days_remaining") is not None:
                days = parsed["days_remaining"]
                color = "emerald" if days > 30 else ("orange" if days > 7 else "red")
                risk = "Informational" if days > 30 else ("Elevated Risk" if days > 7 else "High Risk")
                findings.append(IntelligenceFinding(
                    entity=f"SSL expires in {days} days ({parsed.get('valid_to', '')})",
                    type="SSL Expiry",
                    source="WebTech",
                    confidence="High",
                    color=color,
                    threat_level=risk,
                    raw_data=f"Valid until: {parsed.get('valid_to')}"
                ))

            if parsed.get("is_expired"):
                findings.append(IntelligenceFinding(
                    entity="SSL Certificate has EXPIRED",
                    type="SSL Expired",
                    source="WebTech",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    raw_data=f"Expired at: {parsed.get('valid_to')}",
                    tags=["security"]
                ))

            if parsed.get("subject_alt_names"):
                sans = parsed["subject_alt_names"]
                for san in sans[:10]:
                    findings.append(IntelligenceFinding(
                        entity=san,
                        type="SSL SAN (Subject Alternative Name)",
                        source="WebTech",
                        confidence="High",
                        color="blue",
                        threat_level="Informational",
                    ))
                if len(sans) > 10:
                    findings.append(IntelligenceFinding(
                        entity=f"... and {len(sans)-10} more SANs",
                        type="SSL SAN Summary",
                        source="WebTech",
                        confidence="High",
                        color="slate",
                        threat_level="Informational",
                    ))

            protocol = cert_info.get("protocol", "")
            if protocol:
                findings.append(IntelligenceFinding(
                    entity=protocol,
                    type="SSL/TLS Protocol",
                    source="WebTech",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                ))

            cipher = cert_info.get("cipher")
            if cipher:
                cipher_name = cipher[0] if isinstance(cipher, tuple) else str(cipher)
                findings.append(IntelligenceFinding(
                    entity=cipher_name,
                    type="SSL/TLS Cipher",
                    source="WebTech",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                ))

    except Exception as e:
        pass

    return findings
