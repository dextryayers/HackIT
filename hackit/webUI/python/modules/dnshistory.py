import httpx
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """DNS History — queries completedns.com for historical DNS records."""
    findings = []
    try:
        url = f"https://completedns.com/dns-history/{target}"
        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            import re
            # Extract IP addresses from historical records
            ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', resp.text)
            seen = set()
            for ip in ips:
                if ip not in seen:
                    seen.add(ip)
                    findings.append(IntelligenceFinding(
                        entity=ip,
                        type="Historical IP",
                        source="DNSHistory",
                        confidence="Medium",
                        color="slate",
                        resolution=f"Previously resolved for {target}"
                    ))
    except Exception as e:
        print(f"[DNSHistory] Error: {e}")
    return findings
