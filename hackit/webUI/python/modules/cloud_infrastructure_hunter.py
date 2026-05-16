import httpx
import asyncio
from models import IntelligenceFinding

async def check_storage(client, url, platform):
    try:
        resp = await client.head(url, timeout=5.0)
        if resp.status_code == 200:
            return IntelligenceFinding(
                entity=url,
                type="Cloud Storage Bucket",
                source=f"{platform} Hunter",
                confidence="High",
                color="cyan",
                category="Cloud / Infrastructure OSINT",
                threat_level="Medium",
                status="Public",
                raw_data=f"Publicly accessible storage bucket found on {platform}. URL: {url}"
            )
        elif resp.status_code == 403:
            return IntelligenceFinding(
                entity=url,
                type="Cloud Storage Bucket",
                source=f"{platform} Hunter",
                confidence="High",
                color="yellow",
                category="Cloud / Infrastructure OSINT",
                threat_level="Low",
                status="Private",
                raw_data=f"Protected storage bucket detected on {platform}. URL: {url}"
            )
    except:
        pass
    return None

async def crawl(target, client):
    findings = []
    base_name = target.split('.')[0] if '.' in target else target
    
    # Logic from sfp_azureblobstorage, sfp_googleobjectstorage, etc.
    storage_checks = [
        # Azure
        (f"https://{base_name}.blob.core.windows.net/", "Azure"),
        (f"https://{base_name}storage.blob.core.windows.net/", "Azure"),
        # GCP
        (f"https://storage.googleapis.com/{base_name}/", "GCP"),
        (f"https://{base_name}.storage.googleapis.com/", "GCP"),
        # AWS (Legacy/Common)
        (f"https://{base_name}.s3.amazonaws.com/", "AWS"),
        # DigitalOcean
        (f"https://{base_name}.digitaloceanspaces.com/", "DigitalOcean")
    ]
    
    tasks = [check_storage(client, url, platform) for url, platform in storage_checks]
    results = await asyncio.gather(*tasks)
    
    for r in results:
        if r: findings.append(r)
        
    return findings
