import httpx
import re
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """BGP HE.NET — scrapes ASN and network info for the target domain."""
    findings = []
    try:
        url = f"https://bgp.he.net/dns/{target}"
        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            # Extract ASN numbers
            asn_matches = re.findall(r'(AS\d+)', resp.text)
            seen = set()
            for asn in asn_matches:
                if asn not in seen:
                    seen.add(asn)
                    findings.append(IntelligenceFinding(
                        entity=asn,
                        type="ASN",
                        source="BGP HE.NET",
                        confidence="High",
                        color="emerald"
                    ))
            # Extract IP addresses
            ip_matches = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', resp.text)
            ip_seen = set()
            for ip in ip_matches:
                if ip not in ip_seen:
                    ip_seen.add(ip)
                    findings.append(IntelligenceFinding(
                        entity=ip,
                        type="IP Address",
                        source="BGP HE.NET",
                        confidence="High",
                        color="blue"
                    ))
    except Exception as e:
        print(f"[BGP HE.NET] Error: {e}")
    return findings
