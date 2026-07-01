import asyncio
import dns.resolver
import re
from collections import defaultdict
from models import IntelligenceFinding

SPF_MECHANISMS = ['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists', 'redirect']
SPF_MODIFIERS = ['redirect', 'exp']

async def get_txt(domain: str):
    loop = asyncio.get_event_loop()
    try:
        answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'TXT'))
        return [str(r) for r in answers]
    except:
        return []

async def crawl(target: str, client=None):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    txt_records = await get_txt(domain)
    spf_records = [r for r in txt_records if r.startswith("v=spf1")]
    if not spf_records:
        findings.append(IntelligenceFinding(
            entity=f"No SPF record for {domain}",
            type="SPF Record Missing",
            source="DNS SPF Validator",
            confidence="High",
            color="red",
            threat_level="High Risk",
            status="No SPF",
            raw_data="Missing SPF allows any server to send email as this domain",
            tags=["spf", "missing", "email-security"]
        ))
        return findings

    for spf in spf_records:
        findings.append(IntelligenceFinding(
            entity=spf[:300],
            type="SPF Record Found",
            source="DNS SPF Validator",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            status="SPF Configured",
            raw_data=spf[:2000],
            tags=["spf", "record"]
        ))

        parsed = parse_spf(spf)
        if parsed:
            mechanisms = parsed.get('mechanisms', {})
            include_count = len(mechanisms.get('include', []))
            dns_lookups = include_count + len(mechanisms.get('a', [])) + len(mechanisms.get('mx', [])) + len(mechanisms.get('ptr', [])) + len(mechanisms.get('exists', []))
            redirect = parsed.get('redirect')
            if redirect:
                dns_lookups += 1

            all_mech = mechanisms.get('all', [])
            if all_mech:
                all_val = all_mech[0]
                all_type = "SoftFail (~all)" if '~all' in all_val else "Fail (-all)" if '-all' in all_val else "Neutral (?all)" if '?all' in all_val else "Pass (+all)"
                all_color = "green" if '-all' in all_val else "orange" if '~all' in all_val else "red" if '+all' in all_val else "slate"
                all_threat = "Informational" if '-all' in all_val else "Standard Target" if '~all' in all_val else "Elevated Risk" if '+all' in all_val else "Standard Target"
                findings.append(IntelligenceFinding(
                    entity=f"SPF 'all' mechanism: {all_val} ({all_type})",
                    type="SPF All Mechanism",
                    source="DNS SPF Validator",
                    confidence="High",
                    color=all_color,
                    threat_level=all_threat,
                    status=all_type,
                    raw_data=f"All mechanism '{all_val}' determines how unauthorized senders are treated",
                    tags=["spf", "all", all_val.strip().replace('+', '')]
                ))

            if dns_lookups > 10:
                findings.append(IntelligenceFinding(
                    entity=f"SPF requires {dns_lookups} DNS lookups (limit is 10) - PERMERROR!",
                    type="SPF DNS Lookup Limit Exceeded",
                    source="DNS SPF Validator",
                    confidence="Certain",
                    color="red",
                    threat_level="High Risk",
                    status="Over Limit",
                    raw_data=f"DNS lookups required: {dns_lookups}/10. SPF will be rejected by receivers.",
                    tags=["spf", "dns-lookup", "error", "permerror"]
                ))
            else:
                findings.append(IntelligenceFinding(
                    entity=f"SPF requires {dns_lookups} DNS lookups (limit: 10)",
                    type="SPF DNS Lookup Count",
                    source="DNS SPF Validator",
                    confidence="High",
                    color="green" if dns_lookups <= 7 else "orange",
                    threat_level="Informational",
                    status=f"{dns_lookups}/10 Lookups",
                    tags=["spf", "dns-lookup"]
                ))

            include_mechs = mechanisms.get('include', [])
            if include_mechs:
                for inc in include_mechs[:10]:
                    findings.append(IntelligenceFinding(
                        entity=f"include:{inc}",
                        type="SPF Include Mechanism",
                        source="DNS SPF Validator",
                        confidence="High",
                        color="blue",
                        threat_level="Informational",
                        status="Included",
                        raw_data=f"SPF includes domain: {inc}",
                        tags=["spf", "include", inc]
                    ))

                findings.append(IntelligenceFinding(
                    entity=f"{len(include_mechs)} include mechanisms (chains to other domains)",
                    type="SPF Include Chain Analysis",
                    source="DNS SPF Validator",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    status=f"{len(include_mechs)} Includes",
                    tags=["spf", "include-chain"]
                ))

            ip4_mechs = mechanisms.get('ip4', [])
            ip6_mechs = mechanisms.get('ip6', [])
            if ip4_mechs or ip6_mechs:
                total_ips = len(ip4_mechs) + len(ip6_mechs)
                findings.append(IntelligenceFinding(
                    entity=f"Authorized IP ranges: {len(ip4_mechs)} IPv4, {len(ip6_mechs)} IPv6",
                    type="SPF Authorized IPs",
                    source="DNS SPF Validator",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    status=f"{total_ips} Ranges",
                    tags=["spf", "ip-ranges"]
                ))
                if ip4_mechs:
                    for ip4 in ip4_mechs[:5]:
                        findings.append(IntelligenceFinding(
                            entity=f"ip4:{ip4}",
                            type="SPF IPv4 Authorization",
                            source="DNS SPF Validator",
                            confidence="High",
                            color="slate",
                            threat_level="Informational",
                            status="Authorized",
                            tags=["spf", "ipv4"]
                        ))
                if ip6_mechs:
                    for ip6 in ip6_mechs[:5]:
                        findings.append(IntelligenceFinding(
                            entity=f"ip6:{ip6}",
                            type="SPF IPv6 Authorization",
                            source="DNS SPF Validator",
                            confidence="High",
                            color="slate",
                            threat_level="Informational",
                            status="Authorized",
                            tags=["spf", "ipv6"]
                        ))

            a_mechs = mechanisms.get('a', [])
            if a_mechs:
                findings.append(IntelligenceFinding(
                    entity="SPF includes 'a' mechanism - domain's A records can send email",
                    type="SPF A Mechanism",
                    source="DNS SPF Validator",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    status="Included",
                    tags=["spf", "a-mechanism"]
                ))

            mx_mechs = mechanisms.get('mx', [])
            if mx_mechs:
                findings.append(IntelligenceFinding(
                    entity="SPF includes 'mx' mechanism - MX hosts can send email",
                    type="SPF MX Mechanism",
                    source="DNS SPF Validator",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    status="Included",
                    tags=["spf", "mx-mechanism"]
                ))

            exists_mechs = mechanisms.get('exists', [])
            if exists_mechs:
                for ex in exists_mechs[:3]:
                    findings.append(IntelligenceFinding(
                        entity=f"exists:{ex}",
                        type="SPF Exists Mechanism",
                        source="DNS SPF Validator",
                        confidence="Medium",
                        color="orange",
                        threat_level="Standard Target",
                        status="Exists Check",
                        raw_data=f"SPF exists:{ex} - performs a DNS lookup to check existence",
                        tags=["spf", "exists"]
                    ))

            if redirect:
                findings.append(IntelligenceFinding(
                    entity=f"SPF redirect={redirect}",
                    type="SPF Redirect Modifier",
                    source="DNS SPF Validator",
                    confidence="High",
                    color="purple",
                    threat_level="Informational",
                    status="Redirect Enabled",
                    raw_data=f"SPF redirects to: {redirect}",
                    tags=["spf", "redirect"]
                ))

            macros_found = re.findall(r'%{[^}]+}', spf)
            if macros_found:
                findings.append(IntelligenceFinding(
                    entity=f"SPF macros used: {', '.join(macros_found[:5])}",
                    type="SPF Macro Usage",
                    source="DNS SPF Validator",
                    confidence="Medium",
                    color="orange",
                    threat_level="Standard Target",
                    status="Macros Detected",
                    tags=["spf", "macros"]
                ))

            void_lookups = 0
            for inc in include_mechs:
                inc_records = await get_txt(inc)
                if not any(r.startswith("v=spf1") for r in inc_records):
                    void_lookups += 1
            if void_lookups > 0:
                findings.append(IntelligenceFinding(
                    entity=f"{void_lookups} void lookup(s) - included domains without SPF",
                    type="SPF Void Lookups",
                    source="DNS SPF Validator",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                    status="Void Lookups",
                    tags=["spf", "void-lookup"]
                ))

            if not all_mech:
                findings.append(IntelligenceFinding(
                    entity="SPF record has NO 'all' mechanism - policy is incomplete!",
                    type="SPF Missing All Mechanism",
                    source="DNS SPF Validator",
                    confidence="High",
                    color="red",
                    threat_level="Elevated Risk",
                    status="Missing All",
                    tags=["spf", "missing-all"]
                ))

            if include_mechs:
                seen_includes = set()
                inc_queue = list(include_mechs)
                depth = 0
                while inc_queue and depth < 10:
                    current = inc_queue.pop(0)
                    if current in seen_includes:
                        continue
                    seen_includes.add(current)
                    inc_txt = await get_txt(current)
                    for r in inc_txt:
                        if r.startswith("v=spf1"):
                            sub_parsed = parse_spf(r)
                            if sub_parsed:
                                sub_includes = sub_parsed['mechanisms'].get('include', [])
                                for si in sub_includes:
                                    if si not in seen_includes:
                                        inc_queue.append(si)
                    depth += 1
                total_chain = len(seen_includes)
                if total_chain > 0:
                    findings.append(IntelligenceFinding(
                        entity=f"SPF include chain depth: {depth}, total unique domains: {total_chain}",
                        type="SPF Include Chain Depth",
                        source="DNS SPF Validator",
                        confidence="High",
                        color="orange" if depth >= 5 else "slate",
                        threat_level="Standard Target" if depth >= 5 else "Informational",
                        status=f"Depth {depth}",
                        tags=["spf", "chain-depth"]
                    ))

    findings.append(IntelligenceFinding(
        entity=f"SPF validation complete for {domain}",
        type="SPF Validation Summary",
        source="DNS SPF Validator",
        confidence="High",
        color="blue",
        threat_level="Informational",
        status="Complete",
        tags=["spf", "summary"]
    ))

    return findings

def parse_spf(spf_str: str):
    try:
        spf_str = spf_str.strip('"').strip("'")
        if not spf_str.startswith("v=spf1"):
            return None
        parts = spf_str.split()
        mechanisms = defaultdict(list)
        redirect = None
        exp = None
        for part in parts[1:]:
            part = part.strip()
            if not part:
                continue
            qualifier = part[0]
            if qualifier in ('+', '-', '~', '?'):
                mechanism_part = part[1:]
            else:
                mechanism_part = part
            if mechanism_part.startswith('include:'):
                mechanisms['include'].append(mechanism_part[8:])
            elif mechanism_part.startswith('ip4:'):
                mechanisms['ip4'].append(mechanism_part[4:])
            elif mechanism_part.startswith('ip6:'):
                mechanisms['ip6'].append(mechanism_part[4:])
            elif mechanism_part.startswith('a'):
                mechanisms['a'].append(mechanism_part[2:] if len(mechanism_part) > 1 else '')
            elif mechanism_part.startswith('mx'):
                mechanisms['mx'].append(mechanism_part[3:] if len(mechanism_part) > 2 else '')
            elif mechanism_part.startswith('ptr'):
                mechanisms['ptr'].append(mechanism_part[4:] if len(mechanism_part) > 3 else '')
            elif mechanism_part.startswith('exists:'):
                mechanisms['exists'].append(mechanism_part[7:])
            elif mechanism_part.startswith('redirect='):
                redirect = mechanism_part[9:]
            elif mechanism_part.startswith('exp='):
                exp = mechanism_part[4:]
            elif mechanism_part in ('all', '+all', '-all', '~all', '?all'):
                mechanisms['all'].append(part)
        return {
            'mechanisms': dict(mechanisms),
            'redirect': redirect,
            'exp': exp
        }
    except:
        return None
