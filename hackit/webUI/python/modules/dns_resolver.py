import asyncio
import dns.resolver
from models import IntelligenceFinding

RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV']

async def crawl(target: str, client=None):
    """Direct DNS resolution using dnspython — covers A/AAAA/MX/NS/TXT/SOA/CNAME/SRV records."""
    findings = []
    loop = asyncio.get_event_loop()
    
    extended_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'CAA', 'DS', 'TLSA']
    
    for rtype in extended_types:
        try:
            answers = await loop.run_in_executor(None, lambda rt=rtype: dns.resolver.resolve(target, rt))
            for rdata in answers:
                value = str(rdata)
                
                finding_type = f"DNS {rtype} Record"
                threat_level = "Informational"
                color = "blue"
                
                if rtype == "TXT":
                    if "v=spf1" in value:
                        finding_type = "SPF Record"
                        color = "emerald"
                    elif "v=DKIM1" in value:
                        finding_type = "DKIM Record"
                        color = "emerald"
                    elif "v=DMARC1" in value:
                        finding_type = "DMARC Record"
                        color = "emerald"
                
                if rtype == "MX":
                    finding_type = "MX Record"
                    color = "slate"
                elif rtype == "NS":
                    finding_type = "Nameserver"
                    color = "slate"
                
                findings.append(IntelligenceFinding(
                    entity=value,
                    type=finding_type,
                    source="DNS Resolver",
                    confidence="High",
                    color=color,
                    threat_level=threat_level,
                    resolution=f"{rtype} record for {target}",
                    raw_data=value
                ))
        except: pass
    
    # Check for DMARC specifically
    try:
        dmarc = await loop.run_in_executor(None, lambda: dns.resolver.resolve(f"_dmarc.{target}", "TXT"))
        for rdata in dmarc:
            findings.append(IntelligenceFinding(
                entity=str(rdata),
                type="DMARC Record",
                source="DNS Resolver",
                confidence="High",
                color="emerald",
                resolution=f"_dmarc.{target}",
                raw_data=str(rdata)
            ))
    except: pass
    
    # Check common DKIM selectors
    for selector in ['default', 'google', 'mail', 'k1']:
        try:
            dkim = await loop.run_in_executor(None, lambda: dns.resolver.resolve(f"{selector}._domainkey.{target}", "TXT"))
            for rdata in dkim:
                findings.append(IntelligenceFinding(
                    entity=f"{selector}._domainkey",
                    type="DKIM Record",
                    source="DNS Resolver",
                    confidence="High",
                    color="emerald",
                    resolution=str(rdata),
                    raw_data=str(rdata)
                ))
        except: pass

    # Check for wildcard DNS
    try:
        wild = await loop.run_in_executor(None, lambda: dns.resolver.resolve(f"nonexistent-test-{target[:5]}.{target}", "A"))
        if wild:
            findings.append(IntelligenceFinding(
                entity=f"*.{target}",
                type="Wildcard DNS",
                source="DNS Resolver",
                confidence="High",
                color="orange",
                threat_level="Elevated Risk",
                raw_data=str(wild[0])
            ))
    except: pass
    
    return findings
