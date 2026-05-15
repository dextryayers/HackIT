import httpx
from models import IntelligenceFinding

async def crawl(target, client):
    findings = []
    base_url = f"https://{target}" if not target.startswith("http") else target
    
    # Common API paths and documentation
    api_endpoints = [
        "/api", "/v1", "/v2", "/api/v1", "/api/v2",
        "/swagger.json", "/swagger-ui.html", "/openapi.json",
        "/redoc", "/graphiql", "/graphql", "/api/docs",
        "/rest-api", "/wp-json/v2", "/api/swagger"
    ]
    
    for endpoint in api_endpoints:
        try:
            url = f"{base_url}{endpoint}"
            resp = await client.get(url, timeout=5.0)
            
            if resp.status_code == 200:
                is_api = False
                content = resp.text.lower()
                
                if "swagger" in content or "openapi" in content or "version" in content:
                    is_api = True
                elif resp.headers.get("Content-Type", "").startswith("application/json"):
                    is_api = True
                
                if is_api:
                    findings.append(IntelligenceFinding(
                        entity=url,
                        type="API Endpoint",
                        source="APIScanner",
                        confidence="High",
                        color="indigo",
                        category="Information Disclosure",
                        threat_level="Informational",
                        status="Live",
                        raw_data=resp.text[:500]
                    ))
        except: continue
            
    return findings
