import re
import json
from datetime import datetime
from urllib.parse import urlparse
from ..module_common import safe_fetch, make_finding

PDNS_SOURCES = [
    ("crt.sh", "https://crt.sh/?q=%25.{domain}&output=json"),
    ("SecurityTrails", "https://api.securitytrails.com/v1/domain/{domain}/dns"),
    ("AlienVault OTX", "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"),
    ("HackerTarget", "https://api.hackertarget.com/hostsearch/?q={domain}"),
    ("ViewDNS", "https://viewdns.info/iphistory/?domain={domain}"),
    ("DNSDumpster", "https://dnsdumpster.com/"),
]

FAST_FLUX_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "date", "men", "loan", "download", "review", "bid", "trade", "webcam", "science"}

MALWARE_DOMAINS_DB = {
    "malwarepatrol", "malwaredomains", "abuse.ch", "cybercrime", "phishtank", "openphish", "vxunderground"
}

async def _fetch_ct_logs(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20.0)
        if resp.status_code == 200:
            certs = resp.json() if isinstance(resp.text, str) and resp.text.startswith("[") else []
            timeline = {}
            for cert in certs[:500]:
                name = cert.get("name_value", "").strip().lower()
                nb = str(cert.get("not_before", ""))[:10]
                na = str(cert.get("not_after", ""))[:10]
                for single in name.split("\n"):
                    single = single.strip()
                    if "*" in single or not single.endswith("." + domain):
                        continue
                    if single not in timeline:
                        timeline[single] = {"first": nb, "last": na, "count": 0, "ips": set()}
                    if nb and (nb < timeline[single]["first"] or not timeline[single]["first"]):
                        timeline[single]["first"] = nb
                    if na and (na > timeline[single]["last"] or not timeline[single]["last"]):
                        timeline[single]["last"] = na
                    timeline[single]["count"] += 1
            for name, data in sorted(timeline.items(), key=lambda x: x[1]["first"])[:50]:
                findings.append(make_finding(
                    entity=name,
                    ftype="Passive DNS Timeline - CT Log Entry",
                    source="crt.sh",
                    confidence="High",
                    color="emerald",
                    status="Historical",
                    resolution=f"First seen: {data['first']}",
                    raw_data=f"First: {data['first']}, Last: {data['last']}, Certs: {data['count']}",
                    tags=["pdns", "certificate-transparency", "timeline"]
                ))
            if timeline:
                earliest = min(d["first"] for d in timeline.values() if d["first"])
                latest = max(d["last"] for d in timeline.values() if d["last"])
                findings.append(make_finding(
                    entity=f"CT timeline: {earliest} to {latest} ({len(timeline)} unique hostnames)",
                    ftype="Passive DNS Timeline - CT Summary",
                    source="crt.sh",
                    confidence="High",
                    color="blue",
                    status="Summary",
                    raw_data=f"Timeline span: {earliest} to {latest}",
                    tags=["pdns", "timeline", "summary"]
                ))
    except Exception:
        pass
    return findings

async def _fetch_otx_pdns(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=15.0)
        if resp.status_code == 200:
            data = resp.json()
            pdns_entries = data.get("passive_dns", [])
            ip_changes = {}
            for entry in pdns_entries:
                hostname = entry.get("hostname", "").lower()
                ip = entry.get("address", "")
                first = str(entry.get("first", ""))[:10]
                last = str(entry.get("last", ""))[:10]
                rtype = entry.get("record_type", "")
                if ip and hostname:
                    key = f"{hostname}|{ip}"
                    if key not in ip_changes:
                        ip_changes[key] = {"hostname": hostname, "ip": ip, "first": first, "last": last, "type": rtype, "count": 0}
                    ip_changes[key]["count"] += 1
                    if first and (first < ip_changes[key]["first"] or not ip_changes[key]["first"]):
                        ip_changes[key]["first"] = first
                    if last and (last > ip_changes[key]["last"] or not ip_changes[key]["last"]):
                        ip_changes[key]["last"] = last
            for key, data in sorted(ip_changes.items(), key=lambda x: x[1]["first"])[:40]:
                findings.append(make_finding(
                    entity=f"{data['hostname']} -> {data['ip']}",
                    ftype=f"Passive DNS - {data['type']} Record",
                    source="AlienVault OTX",
                    confidence="High",
                    color="cyan",
                    status="Historical",
                    resolution=f"First: {data['first']}",
                    raw_data=f"Host: {data['hostname']}, IP: {data['ip']}, Type: {data['type']}, First: {data['first']}, Last: {data['last']}",
                    tags=["pdns", "otx", "historical-record"]
                ))
            if len(ip_changes) > 5:
                ip_count = len(set(d["ip"] for d in ip_changes.values()))
                findings.append(make_finding(
                    entity=f"{len(ip_changes)} passive DNS entries, {ip_count} unique IPs across timeline",
                    ftype="Passive DNS - OTX Summary",
                    source="AlienVault OTX",
                    confidence="High",
                    color="slate",
                    status="Summary",
                    raw_data=f"Total entries: {len(ip_changes)}, Unique IPs: {ip_count}",
                    tags=["pdns", "summary"]
                ))
    except Exception:
        pass
    return findings

async def _fetch_viewdns_history(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, f"https://viewdns.info/iphistory/?domain={domain}", timeout=20.0)
        if resp.status_code == 200:
            ip_dates = re.findall(r'>(\d+\.\d+\.\d+\.\d+)</td><td>(\d{4}-\d{2}-\d{2})', resp.text)
            unique_ips = list(set(ip_dates))
            if unique_ips:
                findings.append(make_finding(
                    entity=f"{len(unique_ips)} historical IP changes from ViewDNS",
                    ftype="Passive DNS Timeline - IP History Summary",
                    source="ViewDNS",
                    confidence="Medium",
                    color="blue",
                    status="Historical",
                    raw_data=f"Historical IPs found: {len(unique_ips)}",
                    tags=["pdns", "ip-history", "viewdns"]
                ))
                ip_freq = {}
                for ip, dt in unique_ips:
                    ip_freq[ip] = ip_freq.get(ip, 0) + 1
                for ip, cnt in sorted(ip_freq.items(), key=lambda x: -x[1])[:10]:
                    dates_for_ip = sorted(set(d for i, d in unique_ips if i == ip))
                    findings.append(make_finding(
                        entity=ip,
                        ftype="Passive DNS Timeline - Historical IP",
                        source="ViewDNS",
                        confidence="Medium",
                        color="slate",
                        status="Historical",
                        resolution=f"Seen {cnt}x from {dates_for_ip[0] if dates_for_ip else '?'} to {dates_for_ip[-1] if dates_for_ip else '?'}",
                        raw_data=f"IP {ip} seen {cnt} times",
                        tags=["pdns", "ip", "historical-ip"]
                    ))
                if len(ip_freq) >= 5:
                    findings.append(make_finding(
                        entity=f"High IP volatility: {len(ip_freq)} unique IPs over time",
                        ftype="Passive DNS Timeline - IP Volatility Alert",
                        source="ViewDNS",
                        confidence="Medium",
                        color="orange",
                        threat_level="Elevated Risk",
                        status="Volatile",
                        raw_data=f"Unique IPs in history: {len(ip_freq)}",
                        tags=["pdns", "ip-volatility", "fast-flux"]
                    ))
    except Exception:
        pass
    return findings

async def _check_fast_flux_patterns(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        tld = domain.split(".")[-1] if "." in domain else ""
        if tld in FAST_FLUX_TLDS:
            findings.append(make_finding(
                entity=f"TLD '{tld}' commonly used in fast-flux / DGAs",
                ftype="Passive DNS Timeline - Risky TLD Detection",
                source="Passive DNS Timeline",
                confidence="High",
                color="orange",
                threat_level="Elevated Risk",
                status="Suspicious TLD",
                raw_data=f"TLD {tld} is in known fast-flux/DGA list",
                tags=["pdns", "fast-flux", "dga", "risky-tld"]
            ))
        doh_resp = await safe_fetch(client, f"https://dns.google/resolve?name={domain}&type=A", timeout=10.0)
        if doh_resp.status_code == 200:
            data = doh_resp.json()
            answers = data.get("Answer", [])
            ips = set()
            ttl_values = []
            for ans in answers:
                if ans.get("type") == 1:
                    ips.add(ans.get("data", ""))
                    ttl_values.append(ans.get("TTL", 0))
            if ttl_values:
                avg_ttl = sum(ttl_values) / len(ttl_values)
                if avg_ttl < 300:
                    findings.append(make_finding(
                        entity=f"Low avg TTL: {avg_ttl:.0f}s - possible fast-flux",
                        ftype="Passive DNS Timeline - Fast Flux Indicator",
                        source="Passive DNS Timeline",
                        confidence="Medium",
                        color="red",
                        threat_level="High Risk",
                        status="Fast-Flux Suspected",
                        raw_data=f"Average TTL: {avg_ttl:.0f}s, min: {min(ttl_values)}, max: {max(ttl_values)}",
                        tags=["pdns", "fast-flux", "low-ttl"]
                    ))
                if len(ips) > 3:
                    findings.append(make_finding(
                        entity=f"{len(ips)} IPs for single domain: {', '.join(sorted(ips)[:5])}...",
                        ftype="Passive DNS Timeline - Multi-IP Detection",
                        source="Passive DNS Timeline",
                        confidence="High",
                        color="orange",
                        threat_level="Standard Target",
                        status="Multi-IP",
                        raw_data=f"A records: {', '.join(sorted(ips))}",
                        tags=["pdns", "multi-ip", "load-balancing"]
                    ))
    except Exception:
        pass
    return findings

async def _check_malware_association(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        otx_resp = await safe_fetch(client, f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/reputation", timeout=15.0)
        if otx_resp.status_code == 200:
            rep = otx_resp.json()
            pulse_count = rep.get("pulse_info", {}).get("count", 0)
            if pulse_count > 0:
                pulses = rep.get("pulse_info", {}).get("pulses", [])
                for pulse in pulses[:10]:
                    findings.append(make_finding(
                        entity=pulse.get("name", "Unknown"),
                        ftype="Passive DNS Timeline - Malware Threat Intel",
                        source="AlienVault OTX",
                        confidence="High" if pulse_count > 5 else "Medium",
                        color="red",
                        threat_level="High Risk",
                        status="Associated with Threat",
                        resolution=f"Pulse: {pulse.get('id', 'N/A')[:20]}",
                        raw_data=f"Threat name: {pulse.get('name', 'Unknown')}, Tags: {', '.join(pulse.get('tags', []))}",
                        tags=["pdns", "malware", "threat-intel", "otx"]
                    ))
                findings.append(make_finding(
                    entity=f"Domain associated with {pulse_count} threat pulses",
                    ftype="Passive DNS Timeline - Malware Association Summary",
                    source="AlienVault OTX",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    status="Threat Associated",
                    raw_data=f"Total pulses: {pulse_count}",
                    tags=["pdns", "malware", "summary"]
                ))
    except Exception:
        pass
    return findings

async def _check_dns_record_types_timeline(domain: str, client: AsyncClient) -> list:
    findings = []
    record_types = {
        "A": 1, "AAAA": 28, "MX": 15, "NS": 2, "CNAME": 5,
        "TXT": 16, "SOA": 6, "SRV": 33, "CAA": 257, "DS": 43
    }
    for rtype_name, rtype_num in record_types.items():
        try:
            resp = await safe_fetch(client, f"https://dns.google/resolve?name={domain}&type={rtype_name}", timeout=10.0)
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", [])
                matching = [a for a in answers if a.get("type") == rtype_num]
                if matching:
                    for ans in matching[:3]:
                        findings.append(make_finding(
                            entity=f"{rtype_name}: {ans.get('data', '')[:200]}",
                            ftype=f"DNS Record - {rtype_name}",
                            source="Passive DNS Timeline",
                            confidence="High",
                            color="slate",
                            status="Active",
                            raw_data=f"{rtype_name} record: {ans.get('data', '')}",
                            tags=["pdns", rtype_name.lower(), "dns-record"]
                        ))
        except Exception:
            pass
    return findings

async def _check_ip_change_frequency(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        ht_resp = await safe_fetch(client, f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=12.0)
        if ht_resp.status_code == 200:
            lines = ht_resp.text.strip().split("\n")
            sub_ip_map = {}
            for line in lines:
                if "," in line:
                    sub, ip = line.split(",", 1)
                    sub = sub.strip().lower()
                    ip = ip.strip()
                    if sub not in sub_ip_map:
                        sub_ip_map[sub] = set()
                    sub_ip_map[sub].add(ip)
            multi_ip_subs = {s: ips for s, ips in sub_ip_map.items() if len(ips) > 1}
            for sub, ips in list(multi_ip_subs.items())[:15]:
                findings.append(make_finding(
                    entity=f"{sub} -> {', '.join(sorted(ips))}",
                    ftype="Passive DNS Timeline - Multi-IP Subdomain",
                    source="Passive DNS Timeline",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                    status=f"{len(ips)} IPs",
                    raw_data=f"Subdomain {sub} resolves to {len(ips)} different IPs",
                    tags=["pdns", "multi-ip", "subdomain", "ip-change"]
                ))
            if multi_ip_subs:
                findings.append(make_finding(
                    entity=f"{len(multi_ip_subs)} subdomains have multiple IPs - possible load balancing or flux",
                    ftype="Passive DNS Timeline - IP Change Frequency",
                    source="Passive DNS Timeline",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                    status="High Change Frequency",
                    raw_data=f"Subdomains with >1 IP: {len(multi_ip_subs)}",
                    tags=["pdns", "ip-volatility", "summary"]
                ))
    except Exception:
        pass
    return findings

async def crawl(target: str, client: AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    raw_target = target.strip().lower()
    if "://" in raw_target:
        domain = urlparse(raw_target).netloc
    else:
        domain = raw_target

    findings.append(make_finding(
        entity=f"Starting passive DNS timeline reconstruction for {domain}",
        ftype="Passive DNS Timeline - Start",
        source="Passive DNS Timeline",
        confidence="High",
        color="blue",
        status="Started",
        tags=["pdns", "start"]
    ))

    ct_findings = await _fetch_ct_logs(domain, client)
    findings.extend(ct_findings)

    otx_findings = await _fetch_otx_pdns(domain, client)
    findings.extend(otx_findings)

    vdns_findings = await _fetch_viewdns_history(domain, client)
    findings.extend(vdns_findings)

    flux_findings = await _check_fast_flux_patterns(domain, client)
    findings.extend(flux_findings)

    mal_findings = await _check_malware_association(domain, client)
    findings.extend(mal_findings)

    rec_findings = await _check_dns_record_types_timeline(domain, client)
    findings.extend(rec_findings)

    ipfreq_findings = await _check_ip_change_frequency(domain, client)
    findings.extend(ipfreq_findings)

    summary_count = len(findings)
    if summary_count > 0:
        findings.append(make_finding(
            entity=f"Passive DNS Timeline complete: {summary_count} findings across multiple sources",
            ftype="Passive DNS Timeline - Summary",
            source="Passive DNS Timeline",
            confidence="High",
            color="purple",
            status="Complete",
            raw_data=f"Total findings: {summary_count}",
            tags=["pdns", "summary", "complete"]
        ))

    return findings
