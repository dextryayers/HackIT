import asyncio
import dns.resolver
import dns.rdatatype
from models import IntelligenceFinding

ALL_RECORD_TYPES = [
    ('A', 'IPv4 Address'),
    ('AAAA', 'IPv6 Address'),
    ('CNAME', 'Canonical Name'),
    ('MX', 'Mail Exchange'),
    ('NS', 'Nameserver'),
    ('TXT', 'Text Record'),
    ('SOA', 'Start of Authority'),
    ('SRV', 'Service Record'),
    ('PTR', 'Pointer Record'),
    ('CAA', 'CA Authorization'),
    ('DS', 'DNSSEC Delegation Signer'),
    ('DNSKEY', 'DNSSEC Public Key'),
    ('NSEC', 'Next Secure (DNSSEC)'),
    ('NSEC3', 'NSEC3 (DNSSEC)'),
    ('NSEC3PARAM', 'NSEC3 Parameters'),
    ('RRSIG', 'RRSIG (DNSSEC)'),
    ('CDS', 'Child DS'),
    ('CDNSKEY', 'Child DNSKEY'),
    ('SPF', 'SPF Record'),
    ('LOC', 'Location Record'),
    ('HINFO', 'Host Information'),
    ('RP', 'Responsible Person'),
    ('NAPTR', 'Naming Authority Pointer'),
    ('CERT', 'Certificate Record'),
    ('SMIMEA', 'S/MIME Cert Association'),
    ('TLSA', 'TLSA (DANE)'),
    ('SSHFP', 'SSH Fingerprint'),
    ('IPSECKEY', 'IPSec Key'),
    ('DKIM', 'DKIM Key'),
    ('DMARC', 'DMARC Record'),
    ('URI', 'URI Record'),
    ('SVCB', 'Service Binding'),
    ('HTTPS', 'HTTPS Service Binding'),
    ('DNAME', 'Delegation Name'),
    ('OPENPGPKEY', 'OpenPGP Key'),
    ('TKEY', 'Transaction Key'),
    ('TSIG', 'Transaction Signature'),
    ('ZONEMD', 'Zone Message Digest'),
    ('WKS', 'Well-Known Service'),
    ('X25', 'X.25 PSDN'),
    ('ISDN', 'ISDN'),
    ('RT', 'Route Through'),
    ('AFSDB', 'AFS Database'),
    ('DHCID', 'DHCP Identifier'),
    ('HIP', 'Host Identity Protocol'),
    ('RKEY', 'Record Key'),
    ('TA', 'DNSSEC Trust Anchor'),
    ('DLV', 'DNSSEC Lookaside Validation'),
    ('CSYNC', 'Child Sync'),
    ('EUI48', 'MAC Address (48-bit)'),
    ('EUI64', 'MAC Address (64-bit)'),
    ('L32', 'Location 32'),
    ('L64', 'Location 64'),
    ('LP', 'Location Point'),
    ('NID', 'Node Identifier'),
    ('NINFO', 'Node Info'),
    ('RTR', 'Router'),
    ('DOA', 'Data Object Authorization'),
]

async def resolve_rtype(domain: str, rtype: str):
    loop = asyncio.get_event_loop()
    try:
        answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, rtype))
        return [str(r) for r in answers]
    except:
        return []

async def crawl(target: str, client=None):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    resolved_types = []
    total_types = len(ALL_RECORD_TYPES)
    rtype_count = 0

    for rtype, rdesc in ALL_RECORD_TYPES:
        records = await resolve_rtype(domain, rtype)
        if records:
            rtype_count += 1
            resolved_types.append(rtype)
            color_map = {
                "A": "blue", "AAAA": "purple", "CNAME": "purple",
                "MX": "slate", "NS": "slate", "TXT": "orange",
                "SOA": "indigo", "CAA": "yellow", "SRV": "cyan",
                "PTR": "blue", "SSHFP": "cyan", "LOC": "orange",
                "HINFO": "orange", "RP": "slate", "NAPTR": "purple",
                "CERT": "orange", "TLSA": "emerald", "SMIMEA": "emerald",
                "URI": "purple", "SVCB": "purple", "HTTPS": "purple",
                "DNAME": "purple", "OPENPGPKEY": "orange", "ZONEMD": "orange",
            }
            color = "emerald" if rtype in ("DNSKEY", "DS", "RRSIG", "NSEC", "NSEC3", "CDS", "CDNSKEY") else color_map.get(rtype, "slate")

            for i, record in enumerate(records[:3]):
                ftype = rtype.upper()
                if rtype == "TXT":
                    lower = record.lower()
                    if lower.startswith("v=spf1"): ftype = "SPF"
                    elif lower.startswith("v=dmarc1"): ftype = "DMARC"
                    elif "dkim" in lower.lower() or "v=dkim1" in lower.lower(): ftype = "DKIM"

                findings.append(IntelligenceFinding(
                    entity=record[:300],
                    type=f"DNS {ftype} Record ({rdesc})",
                    source="DNS All Record Types",
                    confidence="High",
                    color=color,
                    threat_level="Informational",
                    status=f"{rtype.upper()} Resolved",
                    resolution=f"{rtype.upper()} record for {domain}",
                    raw_data=f"Type: {rtype} | Description: {rdesc} | Value: {record[:2000]}",
                    tags=["dns", rtype.lower(), "record"]
                ))

            if len(records) > 3:
                findings.append(IntelligenceFinding(
                    entity=f"{len(records)} total {rtype.upper()} records ({rdesc})",
                    type=f"DNS {rtype.upper()} Record Count",
                    source="DNS All Record Types",
                    confidence="High",
                    color=color,
                    threat_level="Informational",
                    status=f"{len(records)} Records",
                    tags=["dns", rtype.lower(), "count"]
                ))

            for record in records:
                if rtype == "CAA":
                    parts = record.split()
                    if len(parts) >= 3:
                        caa_tag = parts[1].lower()
                        caa_val = parts[2].strip('"')
                        if caa_tag == "issue":
                            findings.append(IntelligenceFinding(
                                entity=f"CAA issue: {caa_val}",
                                type="DNS CAA Issue Permission",
                                source="DNS All Record Types",
                                confidence="High",
                                color="yellow",
                                threat_level="Informational",
                                status="CAA Configured",
                                tags=["dns", "caa", "issue"]
                            ))
                elif rtype == "TLSA":
                    findings.append(IntelligenceFinding(
                        entity=f"DANE TLSA: {record[:100]}",
                        type="DNS DANE TLSA Record",
                        source="DNS All Record Types",
                        confidence="High",
                        color="emerald",
                        threat_level="Informational",
                        status="DANE Active",
                        tags=["dns", "dane", "tlsa"]
                    ))
                elif rtype == "SSHFP":
                    findings.append(IntelligenceFinding(
                        entity=f"SSH Fingerprint: {record[:100]}",
                        type="DNS SSHFP Record",
                        source="DNS All Record Types",
                        confidence="High",
                        color="cyan",
                        threat_level="Informational",
                        status="SSHFP Active",
                        tags=["dns", "sshfp"]
                    ))
                elif rtype == "LOC":
                    findings.append(IntelligenceFinding(
                        entity=f"Location: {record}",
                        type="DNS LOC Record",
                        source="DNS All Record Types",
                        confidence="High",
                        color="orange",
                        threat_level="Informational",
                        status="Location Found",
                        tags=["dns", "loc", "geo"]
                    ))
                elif rtype == "HINFO":
                    findings.append(IntelligenceFinding(
                        entity=f"Host Info: {record}",
                        type="DNS HINFO Record",
                        source="DNS All Record Types",
                        confidence="High",
                        color="orange",
                        threat_level="Standard Target",
                        status="Info Leaked",
                        tags=["dns", "hinfo", "leak"]
                    ))
                elif rtype == "RP":
                    findings.append(IntelligenceFinding(
                        entity=f"Responsible Person: {record}",
                        type="DNS RP Record",
                        source="DNS All Record Types",
                        confidence="High",
                        color="slate",
                        threat_level="Informational",
                        status="RP Found",
                        tags=["dns", "rp"]
                    ))

    dnssec_types = [t for t in resolved_types if t in ("DNSKEY", "DS", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "CDS", "CDNSKEY")]
    if dnssec_types:
        findings.append(IntelligenceFinding(
            entity=f"DNSSEC records: {', '.join(dnssec_types)}",
            type="DNS DNSSEC Record Summary",
            source="DNS All Record Types",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            status="DNSSEC Active",
            tags=["dns", "dnssec"]
        ))

    security_types = [t for t in resolved_types if t in ("CAA", "TLSA", "SSHFP", "SMIMEA", "OPENPGPKEY")]
    if security_types:
        findings.append(IntelligenceFinding(
            entity=f"Security records: {', '.join(security_types)}",
            type="DNS Security Record Summary",
            source="DNS All Record Types",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            status="Security Records",
            tags=["dns", "security"]
        ))

    findings.append(IntelligenceFinding(
        entity=f"Resolved {rtype_count}/{total_types} record types for {domain}",
        type="DNS All Record Types Summary",
        source="DNS All Record Types",
        confidence="High",
        color="blue",
        threat_level="Informational",
        status=f"{rtype_count}/{total_types} Types",
        raw_data=f"Record types found: {', '.join(resolved_types)} | Total: {rtype_count}/{total_types}",
        tags=["dns", "summary", "all-records"]
    ))

    return findings
