import httpx
from models import IntelligenceFinding
from datetime import datetime

async def crawl(target, client):
    findings = []
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    # Wayback Machine availability check for the domain
    url = f"https://archive.org/wayback/available?url={domain}"
    try:
        resp = await client.get(url, timeout=5.0)
        data = resp.json()
        
        if "archived_snapshots" in data and "closest" in data["archived_snapshots"]:
            snapshot = data["archived_snapshots"]["closest"]
            findings.append(IntelligenceFinding(
                entity=snapshot["url"],
                type="Historical Snapshot",
                source="Wayback Machine",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Archived",
                resolution=f"Timestamp: {snapshot['timestamp']}",
                raw_data=str(snapshot)
            ))
            
            # Also get a count of total snapshots (using CDX API)
            cdx_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=10"
            cdx_resp = await client.get(cdx_url, timeout=5.0)
            if cdx_resp.status_code == 200:
                history_data = cdx_resp.json()
                if len(history_data) > 1:
                    findings.append(IntelligenceFinding(
                        entity=f"{len(history_data)-1} archived sub-URLs found",
                        type="Archive History",
                        source="Wayback Machine",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        raw_data=str(history_data[:5])
                    ))
                    
    except Exception as e:
        pass
        
    return findings
