import httpx
import ssl
import socket
import asyncio
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """Web technology detector — analyzes HTTP headers, security headers, cookies, and SSL certificates."""
    findings = []
    loop = asyncio.get_event_loop()
    
    # 1. HTTP Headers Analysis
    try:
        resp = await client.get(f"https://{target}", follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
        headers = dict(resp.headers)
        
        # Server identification
        if "server" in headers:
            findings.append(IntelligenceFinding(
                entity=headers["server"],
                type="Web Server",
                source="HTTP Headers",
                confidence="High",
                color="orange"
            ))
        
        # X-Powered-By
        if "x-powered-by" in headers:
            findings.append(IntelligenceFinding(
                entity=headers["x-powered-by"],
                type="Tech Stack",
                source="HTTP Headers",
                confidence="High",
                color="orange"
            ))
        
        # Security Headers
        security_headers = {
            "strict-transport-security": "HSTS",
            "content-security-policy": "CSP",
            "x-frame-options": "X-Frame-Options",
            "x-content-type-options": "X-Content-Type-Options",
            "x-xss-protection": "XSS Protection",
            "referrer-policy": "Referrer Policy",
            "permissions-policy": "Permissions Policy",
        }
        
        for header_key, header_name in security_headers.items():
            if header_key in headers:
                findings.append(IntelligenceFinding(
                    entity=f"{header_name}: {headers[header_key][:100]}",
                    type="Security Header",
                    source="HTTP Headers",
                    confidence="High",
                    color="emerald"
                ))
            else:
                findings.append(IntelligenceFinding(
                    entity=f"Missing: {header_name}",
                    type="Missing Security Header",
                    source="HTTP Headers",
                    confidence="High",
                    color="red",
                    threat_level="Elevated Risk"
                ))
        
        # CDN / WAF Detection
        cdn_indicators = {
            "cf-ray": "Cloudflare",
            "x-cdn": "CDN Detected",
            "x-cache": "Cache Layer",
            "x-akamai-transformed": "Akamai CDN",
            "x-fastly-request-id": "Fastly CDN",
            "x-amz-cf-id": "AWS CloudFront",
        }
        for key, name in cdn_indicators.items():
            if key in headers:
                findings.append(IntelligenceFinding(
                    entity=name,
                    type="CDN/WAF",
                    source="HTTP Headers",
                    confidence="High",
                    color="orange"
                ))
        
        # Cookies
        if "set-cookie" in headers:
            findings.append(IntelligenceFinding(
                entity=headers["set-cookie"][:120],
                type="Cookie",
                source="HTTP Headers",
                confidence="Medium",
                color="slate"
            ))
        
    except Exception as e:
        print(f"[WebTech] HTTP analysis error: {e}")
    
    # 2. SSL Certificate Analysis
    try:
        def get_ssl_info():
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
                s.settimeout(10)
                s.connect((target, 443))
                cert = s.getpeercert()
                return cert
        
        cert = await loop.run_in_executor(None, get_ssl_info)
        
        if cert:
            # Issuer
            issuer = dict(x[0] for x in cert.get("issuer", []))
            org = issuer.get("organizationName", "Unknown")
            findings.append(IntelligenceFinding(
                entity=f"Issuer: {org}",
                type="SSL Certificate",
                source="SSL Analysis",
                confidence="High",
                color="emerald"
            ))
            
            # Expiry
            not_after = cert.get("notAfter", "")
            findings.append(IntelligenceFinding(
                entity=f"Expires: {not_after}",
                type="SSL Expiry",
                source="SSL Analysis",
                confidence="High",
                color="slate"
            ))
            
            # Subject Alternative Names (SAN)
            sans = cert.get("subjectAltName", [])
            for san_type, san_value in sans:
                if san_type == "DNS":
                    findings.append(IntelligenceFinding(
                        entity=san_value,
                        type="SSL SAN",
                        source="SSL Analysis",
                        confidence="High",
                        color="blue"
                    ))
    except Exception as e:
        print(f"[WebTech] SSL analysis error: {e}")
    
    return findings
