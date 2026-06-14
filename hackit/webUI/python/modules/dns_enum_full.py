import asyncio
import dns.resolver
from models import IntelligenceFinding
from datetime import datetime
from osint_common import resolve_dns

RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'CAA', 'DS', 'TLSA', 'NAPTR', 'LOC', 'HINFO', 'RP', 'SSHFP']

async def crawl(target: str, client=None):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    loop = asyncio.get_event_loop()

    for rtype in RECORD_TYPES:
        try:
            answers = await loop.run_in_executor(None, lambda rt=rtype: dns.resolver.resolve(domain, rt))
            for rdata in answers:
                value = str(rdata)
                color = "blue"
                ftype = f"DNS {rtype}"

                if rtype == "A":
                    color = "emerald"
                elif rtype == "AAAA":
                    color = "purple"
                elif rtype == "MX":
                    color = "slate"
                elif rtype == "NS":
                    color = "slate"
                elif rtype == "TXT":
                    color = "orange"
                    if value.startswith("v=spf1"): ftype = "SPF"
                    elif value.startswith("v=DMARC1"): ftype = "DMARC"
                elif rtype == "SOA":
                    color = "indigo"
                elif rtype == "CAA":
                    color = "yellow"
                elif rtype == "DS":
                    color = "emerald"
                    ftype = "DNSSEC DS"
                elif rtype == "TLSA":
                    color = "emerald"
                    ftype = "DANE TLSA"
                elif rtype == "SSHFP":
                    color = "cyan"
                    ftype = "SSH Fingerprint"

                findings.append(IntelligenceFinding(
                    entity=value[:300],
                    type=ftype,
                    source="DNS Full Enumeration",
                    confidence="High",
                    color=color,
                    threat_level="Informational",
                    resolution=f"{rtype} record",
                    raw_data=value[:2000]
                ))
        except: pass

    dmarc_selectors = ["_dmarc"]
    for sel in dmarc_selectors:
        try:
            answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(f"{sel}.{domain}", "TXT"))
            for r in answers:
                findings.append(IntelligenceFinding(
                    entity=str(r)[:300],
                    type="DMARC Policy",
                    source="DNS Full Enumeration",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    raw_data=str(r)[:2000]
                ))
        except: pass

    for selector in ['default', 'google', 'mail', 'k1', 'dkim', 'mx', 'selector1', 'selector2', 's1', 's2']:
        try:
            answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT"))
            for r in answers:
                findings.append(IntelligenceFinding(
                    entity=f"{selector}._domainkey.{domain}",
                    type="DKIM Public Key",
                    source="DNS Full Enumeration",
                    confidence="High",
                    color="emerald",
                    resolution=str(r)[:200],
                    threat_level="Informational",
                    raw_data=str(r)[:2000]
                ))
        except: pass

    try:
        wc_test = f"xwcz-{abs(hash(domain)) % 99999}.{domain}"
        wild = await loop.run_in_executor(None, lambda: dns.resolver.resolve(wc_test, "A"))
        findings.append(IntelligenceFinding(
            entity=f"*.{domain} -> {str(wild[0])}",
            type="Wildcard DNS Detected",
            source="DNS Full Enumeration",
            confidence="High",
            color="red",
            threat_level="Elevated Risk",
            raw_data=f"Wildcard resolves to {str(wild[0])}"
        ))
    except: pass

    try:
        soa = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, "SOA"))
        for r in soa:
            mname = str(r.mname).rstrip('.')
            findings.append(IntelligenceFinding(
                entity=mname,
                type="Primary Nameserver (SOA MNAME)",
                source="DNS Full Enumeration",
                confidence="High",
                color="indigo",
                threat_level="Informational",
                raw_data=f"Primary NS: {mname}"
            ))
    except: pass

    try:
        mx_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, "MX"))
        mx_hosts = [str(r.exchange).rstrip('.') for r in mx_records]
        for mx in mx_hosts:
            for ip_type in ['A', 'AAAA']:
                try:
                    ips = await loop.run_in_executor(None, lambda: dns.resolver.resolve(mx, ip_type))
                    for ip in ips:
                        findings.append(IntelligenceFinding(
                            entity=f"{mx} -> {str(ip)}",
                            type="MX Server IP",
                            source="DNS Full Enumeration",
                            confidence="High",
                            color="slate",
                            threat_level="Informational",
                            raw_data=f"MX {mx} resolves to {str(ip)}"
                        ))
                except: pass
    except: pass

    try:
        ns_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, "NS"))
        ns_hosts = [str(r).rstrip('.') for r in ns_records]
        for ns in ns_hosts:
            for ip_type in ['A', 'AAAA']:
                try:
                    ips = await loop.run_in_executor(None, lambda: dns.resolver.resolve(ns, ip_type))
                    for ip in ips:
                        findings.append(IntelligenceFinding(
                            entity=f"{ns} -> {str(ip)}",
                            type="Nameserver IP",
                            source="DNS Full Enumeration",
                            confidence="High",
                            color="slate",
                            threat_level="Informational",
                            raw_data=f"NS {ns} resolves to {str(ip)}"
                        ))
                except: pass
    except: pass

    return findings
