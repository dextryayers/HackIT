import httpx
from models import IntelligenceFinding

async def crawl(target, client):
    findings = []
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    org_name = domain.split(".")[0]
    
    # Common Cloud Asset Patterns
    cloud_assets = [
        {"name": "AWS S3 Bucket", "url": f"https://{org_name}.s3.amazonaws.com"},
        {"name": "Azure Blob Storage", "url": f"https://{org_name}.blob.core.windows.net"},
        {"name": "Google Cloud Storage", "url": f"https://storage.googleapis.com/{org_name}"},
        {"name": "Kubernetes Dashboard", "url": f"https://k8s.{domain}"},
        {"name": "Docker Registry", "url": f"https://registry.{domain}"}
    ]
    
    async def check_asset(asset):
        try:
            resp = await client.get(asset["url"], timeout=5.0)
            if resp.status_code in [200, 403]: # 403 means it exists but is private
                status = "Public" if resp.status_code == 200 else "Private (Exists)"
                return IntelligenceFinding(
                    entity=asset["url"],
                    type=f"Cloud {asset['name']}",
                    source="CloudRecon",
                    confidence="High",
                    color="blue" if status == "Public" else "slate",
                    threat_level="High Risk" if status == "Public" else "Informational",
                    status=status,
                    raw_data=f"Detected via head request"
                )
        except: pass
        return None

    import asyncio
    results = await asyncio.gather(*[check_asset(a) for a in cloud_assets])
    findings.extend([r for r in results if r])
    
    return findings
