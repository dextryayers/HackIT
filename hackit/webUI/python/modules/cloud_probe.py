import httpx
from models import IntelligenceFinding

async def crawl(target, client):
    findings = []
    # Clean domain name
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    org_name = domain.split(".")[0]
    
    # Common bucket patterns
    buckets = [
        f"{org_name}-assets", f"{org_name}-public", f"{org_name}-prod",
        f"{org_name}-staging", f"{org_name}-backup", f"{org_name}-data",
        f"{org_name}-files", f"{org_name}-storage"
    ]
    
    platforms = [
        {"name": "AWS S3", "suffix": ".s3.amazonaws.com"},
        {"name": "Azure Blob", "suffix": ".blob.core.windows.net"},
        {"name": "Google Cloud Storage", "suffix": ".storage.googleapis.com"}
    ]
    
    for bucket in buckets:
        for platform in platforms:
            try:
                url = f"https://{bucket}{platform['suffix']}"
                # We check for 200 (Open) or 403 (Protected but exists)
                resp = await client.head(url, timeout=3.0)
                
                if resp.status_code in [200, 403]:
                    status_desc = "Publicly Accessible" if resp.status_code == 200 else "Access Denied (Existing)"
                    findings.append(IntelligenceFinding(
                        entity=url,
                        type="Cloud Bucket",
                        source="CloudProbe",
                        confidence="Medium",
                        color="amber" if resp.status_code == 403 else "red",
                        category="Infrastructure",
                        threat_level="Elevated Risk" if resp.status_code == 403 else "High Risk",
                        status=status_desc,
                        raw_data=f"HTTP {resp.status_code}"
                    ))
            except: continue
            
    return findings
