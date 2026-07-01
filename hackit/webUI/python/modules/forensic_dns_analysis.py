import httpx
import re
import json
import asyncio
import socket
from datetime import datetime
from urllib.parse import urlparse
from models import IntelligenceFinding

PUBLIC_DNS_RESOLVERS = [
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query",
    "https://dns.quad9.net:5053/dns-query",
    "https://doh.opendns.com/dns-query",
]

WILDCARD_TEST_PREFIXES = [
    "xys7h82k", "a9m3n7q2", "k4p8w1z5", "test-forensic-dns", "nonexistent-12345",
    "jk83hd82", "random-prefix-abc123",
]

async def _check_dnssec_chain(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        ds_resp = await client.get(
            f"https://dns.google/resolve?name={domain}&type=DS",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if ds_resp.status_code == 200:
            ds_data = ds_resp.json()
            ds_answers = ds_data.get("Answer", [])
            ds_records = [a for a in ds_answers if a.get("type") == 43]
            if ds_records:
                findings.append(IntelligenceFinding(
                    entity=f"{len(ds_records)} DS records found - DNSSEC chain exists",
                    type="Forensic DNS - DNSSEC DS Records",
                    source="Google DoH",
                    confidence="High", color="emerald",
                    status="DNSSEC Chain Valid",
                    raw_data=f"DS records: {[a.get('data', '')[:100] for a in ds_records]}",
                    tags=["forensic", "dnssec", "ds"]
                ))
                for rec in ds_records[:5]:
                    findings.append(IntelligenceFinding(
                        entity=rec.get("data", "")[:200],
                        type="Forensic DNS - DS Record Detail",
                        source="Google DoH",
                        confidence="High", color="slate",
                        tags=["forensic", "dnssec", "ds-record"]
                    ))
            else:
                findings.append(IntelligenceFinding(
                    entity="No DS records found - DNSSEC not configured",
                    type="Forensic DNS - Missing DNSSEC",
                    source="Google DoH",
                    confidence="High", color="orange",
                    threat_level="Standard Target",
                    status="No DNSSEC",
                    tags=["forensic", "dnssec", "missing"]
                ))
        dnskey_resp = await client.get(
            f"https://dns.google/resolve?name={domain}&type=DNSKEY",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if dnskey_resp.status_code == 200:
            dk_data = dnskey_resp.json()
            dk_answers = dk_data.get("Answer", [])
            dnskey_records = [a for a in dk_answers if a.get("type") == 48]
            rrsig_records = [a for a in dk_answers if a.get("type") == 46]
            if dnskey_records:
                findings.append(IntelligenceFinding(
                    entity=f"{len(dnskey_records)} DNSKEY records",
                    type="Forensic DNS - DNSKEY Records",
                    source="Google DoH",
                    confidence="High", color="emerald",
                    status="DNSKEY Present",
                    tags=["forensic", "dnssec", "dnskey"]
                ))
                for dk in dnskey_records[:3]:
                    flag = dk.get("data", "").split()[0] if dk.get("data") else ""
                    zone_type = "KSK (Secure Entry Point)" if "257" in str(flag) else "ZSK (Zone Signing)"
                    findings.append(IntelligenceFinding(
                        entity=f"DNSKEY flag={flag} - {zone_type}",
                        type="Forensic DNS - DNSKEY Type",
                        source="Google DoH",
                        confidence="High", color="slate",
                        tags=["forensic", "dnssec", dnskey_records.lower()]
                    ))
            if rrsig_records:
                findings.append(IntelligenceFinding(
                    entity=f"{len(rrsig_records)} RRSIG records - zone is signed",
                    type="Forensic DNS - RRSIG Validation",
                    source="Google DoH",
                    confidence="High", color="emerald",
                    status="Zone Signed",
                    tags=["forensic", "dnssec", "rrsig"]
                ))
    except Exception:
        pass
    return findings

async def _check_wildcard_dns(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        for prefix in WILDCARD_TEST_PREFIXES[:3]:
            try:
                resp = await client.get(
                    f"https://dns.google/resolve?name={prefix}.{domain}&type=A",
                    timeout=10.0,
                    headers={"Accept": "application/json"}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    answers = data.get("Answer", [])
                    a_records = [a for a in answers if a.get("type") == 1]
                    if a_records:
                        findings.append(IntelligenceFinding(
                            entity=f"Wildcard DNS DETECTED: {prefix}.{domain} resolves to {a_records[0].get('data', '')}",
                            type="Forensic DNS - Wildcard Detection",
                            source="Google DoH",
                            confidence="High",
                            color="orange",
                            threat_level="Standard Target",
                            status="Wildcard Present",
                            raw_data=f"Random prefix {prefix}.{domain} returned A record: {a_records[0].get('data', '')}",
                            tags=["forensic", "wildcard", "dns"]
                        ))
                        return findings
            except Exception:
                pass
        findings.append(IntelligenceFinding(
            entity="No wildcard DNS detected",
            type="Forensic DNS - No Wildcard",
            source="Google DoH",
            confidence="High", color="emerald",
            status="No Wildcard",
            tags=["forensic", "wildcard", "clean"]
        ))
    except Exception:
        pass
    return findings

async def _check_nsec_enumeration(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://dns.google/resolve?name={domain}&type=NSEC",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            answers = data.get("Answer", [])
            nsec_records = [a for a in answers if a.get("type") == 47]
            if nsec_records:
                findings.append(IntelligenceFinding(
                    entity=f"NSEC records found - zone might be enumerable via NSEC walking",
                    type="Forensic DNS - NSEC Walking Risk",
                    source="Google DoH",
                    confidence="Medium",
                    color="orange",
                    threat_level="Standard Target",
                    status="NSEC Present",
                    raw_data=f"NSEC records indicate possible zone enumeration",
                    tags=["forensic", "nsec", "enumeration"]
                ))
            else:
                nsec3_resp = await client.get(
                    f"https://dns.google/resolve?name={domain}&type=NSEC3PARAM",
                    timeout=10.0,
                    headers={"Accept": "application/json"}
                )
                if nsec3_resp.status_code == 200:
                    n3_data = nsec3_resp.json()
                    n3_answers = n3_data.get("Answer", [])
                    nsec3param = [a for a in n3_answers if a.get("type") == 61]
                    if nsec3param:
                        findings.append(IntelligenceFinding(
                            entity=f"NSEC3PARAM found - NSEC3 walking possible",
                            type="Forensic DNS - NSEC3 Walking Risk",
                            source="Google DoH",
                            confidence="Medium",
                            color="orange",
                            status="NSEC3 Present",
                            tags=["forensic", "nsec3", "enumeration"]
                        ))
    except Exception:
        pass
    return findings

async def _check_ttl_anomalies(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://dns.google/resolve?name={domain}&type=A",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            answers = data.get("Answer", [])
            ttl_values = []
            for ans in answers:
                if ans.get("type") == 1:
                    ttl_values.append(ans.get("TTL", 0))
            if ttl_values:
                avg_ttl = sum(ttl_values) / len(ttl_values)
                findings.append(IntelligenceFinding(
                    entity=f"TTL analysis: avg={avg_ttl:.0f}s, min={min(ttl_values)}s, max={max(ttl_values)}s",
                    type="Forensic DNS - TTL Analysis",
                    source="Google DoH",
                    confidence="High", color="slate",
                    raw_data=f"TTLs: {ttl_values}",
                    tags=["forensic", "ttl"]
                ))
                if avg_ttl < 60:
                    findings.append(IntelligenceFinding(
                        entity=f"Very low average TTL ({avg_ttl:.0f}s) - possible fast-flux",
                        type="Forensic DNS - Fast-Flux TTL Indicator",
                        source="Google DoH",
                        confidence="High",
                        color="red",
                        threat_level="High Risk",
                        status="Fast-Flux Suspected",
                        tags=["forensic", "fast-flux", "ttl"]
                    ))
    except Exception:
        pass
    return findings

async def _check_cname_chain(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    chain = []
    current = domain
    seen = set()
    for _ in range(10):
        if current in seen:
            break
        seen.add(current)
        try:
            resp = await client.get(
                f"https://dns.google/resolve?name={current}&type=CNAME",
                timeout=10.0,
                headers={"Accept": "application/json"}
            )
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", [])
                cname_target = None
                for ans in answers:
                    if ans.get("type") == 5:
                        cname_target = ans.get("data", "").rstrip(".").lower()
                        break
                if cname_target:
                    chain.append(f"{current} -> {cname_target}")
                    current = cname_target
                else:
                    break
        except Exception:
            break
    if chain:
        findings.append(IntelligenceFinding(
            entity=f"CNAME chain ({len(chain)+1} hops): {' -> '.join([domain] + [c.split(' -> ')[1] for c in chain])}",
            type="Forensic DNS - CNAME Chain Analysis",
            source="Google DoH",
            confidence="High", color="orange",
            status=f"{len(chain)} Redirects",
            raw_data="\n".join(chain),
            tags=["forensic", "cname", "chain"]
        ))
        if len(chain) >= 3:
            findings.append(IntelligenceFinding(
                entity=f"Long CNAME chain ({len(chain)} hops) - possible redirector domain",
                type="Forensic DNS - Long CNAME Chain",
                source="Google DoH",
                confidence="Medium",
                color="red",
                threat_level="Elevated Risk",
                status="Suspicious Chain",
                tags=["forensic", "cname", "redirector"]
            ))
    return findings

async def _compare_dns_views(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    all_answers = {}
    for resolver_url in PUBLIC_DNS_RESOLVERS[:2]:
        try:
            resp = await client.get(
                f"{resolver_url}?name={domain}&type=A",
                timeout=10.0,
                headers={"Accept": "application/json"}
            )
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", [])
                resolver_ips = set()
                for ans in answers:
                    if ans.get("type") == 1:
                        resolver_ips.add(ans.get("data", ""))
                all_answers[resolver_url] = resolver_ips
        except Exception:
            pass
    if len(all_answers) >= 2:
        ipsets = list(all_answers.values())
        if len(ipsets) >= 2:
            if ipsets[0] != ipsets[1]:
                diff1 = ipsets[0] - ipsets[1]
                diff2 = ipsets[1] - ipsets[0]
                findings.append(IntelligenceFinding(
                    entity=f"DNS view discrepancy: {diff1} vs {diff2}",
                    type="Forensic DNS - DNS View Poisoning Check",
                    source="Forensic DNS Analysis",
                    confidence="High",
                    color="red",
                    threat_level="Critical Risk",
                    status="DNS View Mismatch",
                    raw_data=f"Google DoH: {ipsets[0]}, Cloudflare: {ipsets[1]}",
                    tags=["forensic", "dns-poisoning", "view-discrepancy"]
                ))
            else:
                findings.append(IntelligenceFinding(
                    entity="Consistent DNS responses across resolvers",
                    type="Forensic DNS - View Consistency OK",
                    source="Forensic DNS Analysis",
                    confidence="High", color="emerald",
                    status="Consistent",
                    tags=["forensic", "dns-consistency"]
                ))
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).netloc

    dnssec_findings = await _check_dnssec_chain(domain, client)
    findings.extend(dnssec_findings)

    wildcard_findings = await _check_wildcard_dns(domain, client)
    findings.extend(wildcard_findings)

    nsec_findings = await _check_nsec_enumeration(domain, client)
    findings.extend(nsec_findings)

    ttl_findings = await _check_ttl_anomalies(domain, client)
    findings.extend(ttl_findings)

    cname_findings = await _check_cname_chain(domain, client)
    findings.extend(cname_findings)

    view_findings = await _compare_dns_views(domain, client)
    findings.extend(view_findings)

    if findings:
        findings.append(IntelligenceFinding(
            entity=f"Forensic DNS Analysis complete: {len(findings)} findings",
            type="Forensic DNS - Summary",
            source="Forensic DNS Analysis",
            confidence="High", color="purple",
            status="Complete",
            tags=["forensic", "dns", "summary"]
        ))

    return findings
