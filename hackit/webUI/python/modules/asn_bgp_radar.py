import httpx
import asyncio
from models import IntelligenceFinding

async def crawl(target, client):
    findings = []
    
    # Check if target is an IP or Domain. BGP/ASN requires IP first usually.
    # For now, let's assume we can resolve the IP using HackerTarget or simple API
    try:
        # Step 1: Resolve Domain to IP (if it's a domain)
        resolve_url = f"https://api.hackertarget.com/hostsearch/?q={target}"
        resp = await client.get(resolve_url, timeout=10.0)
        
        target_ip = None
        if resp.status_code == 200 and "error" not in resp.text:
            lines = resp.text.strip().split('\n')
            if len(lines) > 0 and ',' in lines[0]:
                target_ip = lines[0].split(',')[1]
        
        if not target_ip:
            target_ip = target  # Fallback: assume it's already an IP
            
        # Step 2: Query BGPView for ASN and Prefix Info
        bgp_url = f"https://api.bgpview.io/ip/{target_ip}"
        bgp_resp = await client.get(bgp_url, timeout=15.0)
        
        if bgp_resp.status_code == 200:
            data = bgp_resp.json()
            if data.get("status") == "ok" and data.get("data"):
                prefixes = data["data"].get("prefixes", [])
                
                for prefix in prefixes:
                    asn = prefix.get("asn", {}).get("asn")
                    asn_name = prefix.get("asn", {}).get("name")
                    asn_desc = prefix.get("asn", {}).get("description")
                    ip_prefix = prefix.get("prefix")
                    
                    details = f"ASN: AS{asn} | Name: {asn_name} | Desc: {asn_desc}\nPrefix: {ip_prefix}"
                    
                    findings.append(IntelligenceFinding(
                        entity=ip_prefix,
                        type="BGP Route / Subnet",
                        source="BGPView Radar",
                        confidence="Certain",
                        color="indigo",
                        category="Infrastructure",
                        threat_level="Informational",
                        status="Mapped",
                        raw_data=details
                    ))
    except Exception as e:
        pass
        
    return findings
