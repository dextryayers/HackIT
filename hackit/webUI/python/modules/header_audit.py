import httpx
from models import IntelligenceFinding

async def crawl(target, client):
    findings = []
    base_url = f"https://{target}" if not target.startswith("http") else target
    
    try:
        resp = await client.get(base_url, timeout=10.0, follow_redirects=True)
        headers = resp.headers
        
        # Security headers to check
        security_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy"
        ]
        
        for header in security_headers:
            val = headers.get(header)
            if val:
                findings.append(IntelligenceFinding(
                    entity=f"{header}: {val[:50]}...",
                    type="Security Header",
                    source="HeaderAudit",
                    confidence="High",
                    color="emerald",
                    category="Web Technology Detection",
                    threat_level="Informational",
                    status="Implemented",
                    raw_data=f"{header}: {val}"
                ))
            else:
                findings.append(IntelligenceFinding(
                    entity=header,
                    type="Missing Security Header",
                    source="HeaderAudit",
                    confidence="High",
                    color="orange",
                    category="Security & Exposure Analysis",
                    threat_level="Elevated Risk",
                    status="Missing",
                    raw_data=f"{header} not found in response headers"
                ))
                
        # Server Banner
        server = headers.get("Server")
        if server:
             findings.append(IntelligenceFinding(
                entity=server,
                type="Web Server Identification",
                source="HeaderAudit",
                confidence="High",
                color="indigo",
                category="Web Technology Detection",
                threat_level="Informational",
                status="Detected",
                raw_data=server
            ))
            
    except: pass
    
    return findings
