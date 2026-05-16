import httpx
import asyncio
import dns.resolver
from models import IntelligenceFinding

async def check_zone_transfer(domain):
    # Concept from sfp_dnszonexfer
    findings = []
    try:
        # Get NS records first
        ns_records = dns.resolver.resolve(domain, 'NS')
        for ns in ns_records:
            ns_server = str(ns.target)
            try:
                # Attempt zone transfer
                zone = dns.zone.from_xfr(dns.query.xfr(ns_server, domain))
                if zone:
                    findings.append(IntelligenceFinding(
                        entity=domain,
                        type="DNS Zone Transfer",
                        source="DNS Deep Forensics",
                        confidence="Certain",
                        color="red",
                        category="Vulnerability",
                        threat_level="Critical",
                        status="VULNERABLE",
                        raw_data=f"Zone transfer successful from {ns_server}. This reveals the entire internal DNS structure."
                    ))
            except:
                pass
    except:
        pass
    return findings

async def crawl(target, client):
    findings = []
    
    # DNS Record Analysis (Concept from sfp_dnsraw)
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'SPF', 'SOA', 'SRV']
    
    async def check_record(rtype):
        try:
            answers = await asyncio.get_event_loop().run_in_executor(None, lambda: dns.resolver.resolve(target, rtype))
            recs = []
            for rdata in answers:
                val = str(rdata)
                recs.append(IntelligenceFinding(
                    entity=val,
                    type=f"DNS {rtype} Record",
                    source="DNS Deep Forensics",
                    confidence="High",
                    color="blue",
                    category="1. DOMAIN RECON",
                    threat_level="Informational",
                    status="Active",
                    raw_data=f"Found {rtype} record for {target}: {val}"
                ))
            return recs
        except:
            return []

    tasks = [check_record(rtype) for rtype in record_types]
    results = await asyncio.gather(*tasks)
    
    for rlist in results:
        findings.extend(rlist)
        
    # Check for SPF/DMARC leaks (Concept from sfp_dnsraw/sfp_strangeheaders)
    for f in findings:
        if f.type == "DNS TXT Record" or f.type == "DNS SPF Record":
            if "v=spf1" in f.entity:
                # Check for +all (dangerous)
                if "+all" in f.entity:
                    findings.append(IntelligenceFinding(
                        entity=target,
                        type="DMARC/SPF Configuration Weakness",
                        source="DNS Deep Forensics",
                        confidence="High",
                        color="red",
                        category="Vulnerability",
                        threat_level="High",
                        status="WEAK",
                        raw_data=f"SPF record contains '+all', allowing any server to spoof emails from this domain."
                    ))
                    
    return findings
