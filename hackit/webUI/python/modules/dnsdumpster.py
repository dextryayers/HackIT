import httpx
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """Uses HackerTarget DNS lookup API to get A/MX/NS/TXT/SOA records."""
    findings = []
    try:
        url = f"https://api.hackertarget.com/dnslookup/?q={target}"
        resp = await client.get(url)
        if resp.status_code == 200 and "error" not in resp.text.lower():
            for line in resp.text.strip().splitlines():
                if ':' in line:
                    parts = line.split(':', 1)
                    rtype = parts[0].strip()
                    rdata = parts[1].strip() if len(parts) > 1 else ""
                    findings.append(IntelligenceFinding(
                        entity=f"{target}",
                        type=f"DNS {rtype}",
                        source="DNSDumpster",
                        confidence="High",
                        color="blue",
                        resolution=rdata
                    ))
    except Exception as e:
        print(f"[DNSDumpster] Error: {e}")
    return findings
