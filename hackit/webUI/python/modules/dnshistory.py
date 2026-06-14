import httpx
import asyncio
import socket
import re
from datetime import datetime
from models import IntelligenceFinding
from urllib.parse import urlparse

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    raw_target = target.strip().lower()
    if "://" in raw_target:
        domain = urlparse(raw_target).netloc
    else:
        domain = raw_target

    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    is_ip = bool(ip_pattern.match(domain))

    if is_ip:
        try:
            host = await asyncio.get_event_loop().run_in_executor(
                None, lambda: socket.gethostbyaddr(domain)
            )
            findings.append(IntelligenceFinding(
                entity=host[0],
                type="Reverse DNS (PTR)",
                source="DNSHistory",
                confidence="High",
                color="blue",
                status="Active",
                resolution=f"PTR for {domain}",
                raw_data=f"Hostname: {host[0]}",
                tags=["dns", "ptr"]
            ))
        except Exception:
            pass
        try:
            crt_resp = await client.get(
                f"https://crt.sh/?q={domain}&output=json",
                timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
            )
            if crt_resp.status_code == 200:
                certs = crt_resp.json()
                if isinstance(certs, list):
                    seen = set()
                    for cert in certs[:80]:
                        name = cert.get("name_value", "")
                        if name and name not in seen:
                            seen.add(name)
                            findings.append(IntelligenceFinding(
                                entity=name[:200],
                                type="Domain Associated with IP (crt.sh)",
                                source="DNSHistory",
                                confidence="High",
                                color="blue",
                                status="Historical",
                                resolution=cert.get("not_before", "")[:10],
                                raw_data=f"Cert valid {cert.get('not_before','')[:10]} to {cert.get('not_after','')[:10]}"
                            ))
        except Exception:
            pass
        return findings

    loop = asyncio.get_event_loop()

    try:
        whois_resp = await client.get(
            f"https://api.hackertarget.com/whois/?q={domain}",
            timeout=12.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if whois_resp.status_code == 200 and "error" not in whois_resp.text.lower()[:50]:
            whois_text = whois_resp.text
            creation_date = None
            expiry_date = None
            registrar = None
            name_servers = []
            org = None
            for line in whois_text.split("\n"):
                if "Creation Date" in line and ":" in line:
                    val = line.split(":", 1)[1].strip()
                    creation_date = val[:20]
                elif "Registry Expiry Date" in line and ":" in line:
                    val = line.split(":", 1)[1].strip()
                    expiry_date = val[:20]
                elif "Registrar" in line and ":" in line and not registrar:
                    registrar = line.split(":", 1)[1].strip()
                elif "Name Server" in line and ":" in line:
                    ns = line.split(":", 1)[1].strip()
                    if ns:
                        name_servers.append(ns)
                elif "Registrant Organization" in line and ":" in line:
                    org = line.split(":", 1)[1].strip()

            if creation_date:
                try:
                    created_dt = datetime.strptime(creation_date[:10], "%Y-%m-%d")
                    age_days = (datetime.now() - created_dt).days
                    age_years = age_days / 365.25
                    age_label = f"{age_years:.1f} years"
                    if age_years < 1:
                        age_label = f"{age_days} days"
                    findings.append(IntelligenceFinding(
                        entity=f"Domain age: {age_label} (created {creation_date[:10]})",
                        type="DNS History - Domain Age",
                        source="DNSHistory (WHOIS)",
                        confidence="High",
                        color="emerald" if age_years > 3 else "orange",
                        status="Active",
                        resolution=creation_date[:10],
                        raw_data=f"Created: {creation_date}, Age: {age_label}",
                        tags=["domain-age", "whois"]
                    ))
                except Exception:
                    pass

            if expiry_date:
                findings.append(IntelligenceFinding(
                    entity=f"Domain expires: {expiry_date[:10]}",
                    type="DNS History - Domain Expiry",
                    source="DNSHistory (WHOIS)",
                    confidence="High",
                    color="red" if "202" not in expiry_date[:7] else "emerald",
                    status="Active" if "202" in expiry_date[:7] else "Expiring",
                    raw_data=f"Expiry: {expiry_date[:10]}"
                ))

            if registrar:
                findings.append(IntelligenceFinding(
                    entity=registrar[:200],
                    type="DNS History - Registrar",
                    source="DNSHistory (WHOIS)",
                    confidence="High",
                    color="slate",
                    raw_data=f"Registrar: {registrar}"
                ))

            if org:
                findings.append(IntelligenceFinding(
                    entity=org[:200],
                    type="DNS History - Registrant Organization",
                    source="DNSHistory (WHOIS)",
                    confidence="High",
                    color="slate",
                    raw_data=f"Organization: {org}"
                ))

            if name_servers:
                for ns in name_servers[:5]:
                    findings.append(IntelligenceFinding(
                        entity=ns[:200],
                        type="DNS History - Nameserver",
                        source="DNSHistory (WHOIS)",
                        confidence="High",
                        color="blue",
                        raw_data=f"Nameserver: {ns}"
                    ))
    except Exception:
        pass

    try:
        crt_url = f"https://crt.sh/?q=%25.{domain}&output=json"
        crt_resp = await client.get(crt_url, timeout=20.0, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        })
        if crt_resp.status_code == 200:
            certs = crt_resp.json()
            if isinstance(certs, list) and certs:
                name_data = {}
                for cert in certs[:300]:
                    name_val = cert.get("name_value", "").strip()
                    if not name_val or "*" in name_val:
                        continue
                    nb = cert.get("not_before", "")[:10]
                    na = cert.get("not_after", "")[:10]
                    for single_name in name_val.split("\n"):
                        single_name = single_name.strip().lower()
                        if not single_name or single_name == domain or "*" in single_name:
                            continue
                        if not single_name.endswith("." + domain):
                            continue
                        if single_name not in name_data:
                            name_data[single_name] = {"first": nb, "last": na, "count": 0}
                        if nb and (nb < name_data[single_name]["first"] or not name_data[single_name]["first"]):
                            name_data[single_name]["first"] = nb
                        if na and (na > name_data[single_name]["last"] or not name_data[single_name]["last"]):
                            name_data[single_name]["last"] = na
                        name_data[single_name]["count"] += 1

                for name, data in sorted(name_data.items(), key=lambda x: x[1]["first"])[:40]:
                    findings.append(IntelligenceFinding(
                        entity=name[:200],
                        type="DNS History - Historic Subdomain (CT Log)",
                        source="DNSHistory (crt.sh)",
                        confidence="High",
                        color="emerald",
                        status="Historical",
                        resolution=f"First seen: {data['first']}",
                        raw_data=f"First: {data['first']}, Last: {data['last']}, Certs: {data['count']}",
                        tags=["dns-history", "subdomain", "certificate-transparency"]
                    ))

                findings.append(IntelligenceFinding(
                    entity=f"{len(name_data)} unique subdomains found in CT logs",
                    type="DNS History - CT Log Summary",
                    source="DNSHistory (crt.sh)",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    raw_data=f"Total historic subdomains: {len(name_data)}",
                    tags=["summary"]
                ))

                earliest_date = None
                for data in name_data.values():
                    if data["first"] and (earliest_date is None or data["first"] < earliest_date):
                        earliest_date = data["first"]
                if earliest_date:
                    findings.append(IntelligenceFinding(
                        entity=f"Earliest SSL cert: {earliest_date}",
                        type="DNS History - SSL Timeline Start",
                        source="DNSHistory (crt.sh)",
                        confidence="High",
                        color="slate",
                        raw_data=f"First certificate logged: {earliest_date}"
                    ))
    except Exception:
        pass

    try:
        ht_resp = await client.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=12.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if ht_resp.status_code == 200 and "error" not in ht_resp.text.lower()[:50]:
            lines = ht_resp.text.strip().split("\n")
            sub_ip_map = {}
            for line in lines:
                if "," in line:
                    parts = line.split(",", 1)
                    sub = parts[0].strip().lower()
                    ip = parts[1].strip()
                    if sub not in sub_ip_map:
                        sub_ip_map[sub] = set()
                    sub_ip_map[sub].add(ip)

            for sub, ips in list(sub_ip_map.items())[:30]:
                ip_list = ", ".join(sorted(ips)[:3])
                extra = f" and {len(ips)-3} more" if len(ips) > 3 else ""
                findings.append(IntelligenceFinding(
                    entity=sub[:200],
                    type="DNS History - Current Subdomain",
                    source="DNSHistory (HackerTarget)",
                    confidence="High",
                    color="cyan",
                    status="Active",
                    resolution=ip_list[:100],
                    raw_data=f"Subdomain: {sub} -> {ip_list}{extra}",
                    tags=["subdomain", "active"]
                ))

            findings.append(IntelligenceFinding(
                entity=f"{len(sub_ip_map)} active subdomains from passive DNS",
                type="DNS History - Subdomain Summary",
                source="DNSHistory (HackerTarget)",
                confidence="High",
                color="slate",
                threat_level="Informational",
                raw_data=f"Total current subdomains: {len(sub_ip_map)}",
                tags=["summary"]
            ))

            all_ips = set()
            for ips in sub_ip_map.values():
                all_ips.update(ips)
            if len(all_ips) >= 5:
                findings.append(IntelligenceFinding(
                    entity=f"{len(all_ips)} unique IPs across {len(sub_ip_map)} subdomains",
                    type="DNS History - IP Diversity",
                    source="DNSHistory",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                    raw_data=f"IPs: {', '.join(sorted(all_ips)[:10])}",
                    tags=["fast-flux", "ip-diversity"]
                ))
    except Exception:
        pass

    try:
        rev_resp = await client.get(
            f"https://api.hackertarget.com/reverseip/?q={domain}",
            timeout=12.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if rev_resp.status_code == 200 and "error" not in rev_resp.text.lower()[:50]:
            lines = rev_resp.text.strip().split("\n")
            rev_hosts = []
            for line in lines:
                if "," in line:
                    host_part = line.split(",")[0].strip()
                    if host_part and host_part != domain:
                        rev_hosts.append(host_part)
            for host in rev_hosts[:15]:
                findings.append(IntelligenceFinding(
                    entity=host[:200],
                    type="DNS History - Co-hosted Domain (Reverse IP)",
                    source="DNSHistory (HackerTarget)",
                    confidence="Medium",
                    color="purple",
                    raw_data=f"Co-hosted domain: {host}",
                    tags=["reverse-ip", "co-hosting"]
                ))
    except Exception:
        pass

    try:
        doh_resp = await client.get(
            f"https://dns.google/resolve?name={domain}&type=A",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if doh_resp.status_code == 200:
            doh_data = doh_resp.json()
            answers = doh_data.get("Answer", [])
            current_ips = set()
            for ans in answers:
                if ans.get("type") == 1:
                    ip_val = ans.get("data", "")
                    if ip_val:
                        current_ips.add(ip_val)

            for ip_val in sorted(current_ips):
                findings.append(IntelligenceFinding(
                    entity=ip_val,
                    type="DNS History - Current A Record",
                    source="DNSHistory (Google DoH)",
                    confidence="High",
                    color="emerald",
                    status="Active",
                    resolution=f"A record for {domain}",
                    raw_data=f"{domain} -> {ip_val}",
                    tags=["dns", "a-record"]
                ))

            if len(current_ips) > 2:
                findings.append(IntelligenceFinding(
                    entity=f"{len(current_ips)} A records: {', '.join(sorted(current_ips))}",
                    type="DNS History - Multiple A Records",
                    source="DNSHistory (Google DoH)",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                    raw_data=f"Multiple IPs: {', '.join(sorted(current_ips))}",
                    tags=["load-balancing", "multi-ip"]
                ))
    except Exception:
        pass

    try:
        mx_doh = await client.get(
            f"https://dns.google/resolve?name={domain}&type=MX",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if mx_doh.status_code == 200:
            mx_data = mx_doh.json()
            mx_answers = mx_data.get("Answer", [])
            for ans in mx_answers:
                if ans.get("type") == 15:
                    mx_val = ans.get("data", "")
                    if mx_val:
                        findings.append(IntelligenceFinding(
                            entity=mx_val[:200],
                            type="DNS History - MX Record",
                            source="DNSHistory (Google DoH)",
                            confidence="High",
                            color="slate",
                            raw_data=f"MX: {mx_val}",
                            tags=["dns", "mx"]
                        ))
    except Exception:
        pass

    try:
        ns_doh = await client.get(
            f"https://dns.google/resolve?name={domain}&type=NS",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if ns_doh.status_code == 200:
            ns_data = ns_doh.json()
            ns_answers = ns_data.get("Answer", [])
            for ans in ns_answers:
                if ans.get("type") == 2:
                    ns_val = ans.get("data", "")
                    if ns_val:
                        findings.append(IntelligenceFinding(
                            entity=ns_val[:200],
                            type="DNS History - NS Record",
                            source="DNSHistory (Google DoH)",
                            confidence="High",
                            color="blue",
                            raw_data=f"NS: {ns_val}",
                            tags=["dns", "nameserver"]
                        ))
    except Exception:
        pass

    try:
        aaaa_resp = await client.get(
            f"https://dns.google/resolve?name={domain}&type=AAAA",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if aaaa_resp.status_code == 200:
            aaaa_data = aaaa_resp.json()
            aaaa_answers = aaaa_data.get("Answer", [])
            for ans in aaaa_answers:
                if ans.get("type") == 28:
                    aaaa_val = ans.get("data", "")
                    if aaaa_val:
                        findings.append(IntelligenceFinding(
                            entity=aaaa_val[:200],
                            type="DNS History - AAAA Record (IPv6)",
                            source="DNSHistory (Google DoH)",
                            confidence="High",
                            color="emerald",
                            status="Active",
                            raw_data=f"AAAA: {aaaa_val}",
                            tags=["dns", "aaaa", "ipv6"]
                        ))
    except Exception:
        pass

    try:
        txt_doh = await client.get(
            f"https://dns.google/resolve?name={domain}&type=TXT",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if txt_doh.status_code == 200:
            txt_data = txt_doh.json()
            txt_answers = txt_data.get("Answer", [])
            for ans in txt_answers:
                if ans.get("type") == 16:
                    txt_val = ans.get("data", "")
                    if txt_val and txt_val.startswith("v=") and len(txt_val) > 10:
                        findings.append(IntelligenceFinding(
                            entity=txt_val[:200],
                            type="DNS History - TXT Record",
                            source="DNSHistory (Google DoH)",
                            confidence="High",
                            color="slate",
                            raw_data=f"TXT: {txt_val[:500]}",
                            tags=["dns", "txt"]
                        ))
    except Exception:
        pass

    try:
        cname_resp = await client.get(
            f"https://dns.google/resolve?name={domain}&type=CNAME",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if cname_resp.status_code == 200:
            cname_data = cname_resp.json()
            cname_answers = cname_data.get("Answer", [])
            for ans in cname_answers:
                if ans.get("type") == 5:
                    cname_val = ans.get("data", "")
                    if cname_val:
                        findings.append(IntelligenceFinding(
                            entity=cname_val[:200],
                            type="DNS History - CNAME Record",
                            source="DNSHistory (Google DoH)",
                            confidence="High",
                            color="purple",
                            resolution=f"CNAME target",
                            raw_data=f"CNAME: {cname_val}",
                            tags=["dns", "cname"]
                        ))
    except Exception:
        pass

    try:
        soa_resp = await client.get(
            f"https://dns.google/resolve?name={domain}&type=SOA",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if soa_resp.status_code == 200:
            soa_data = soa_resp.json()
            soa_answers = soa_data.get("Answer", [])
            for ans in soa_answers:
                if ans.get("type") == 6:
                    soa_val = ans.get("data", "")
                    if soa_val:
                        findings.append(IntelligenceFinding(
                            entity=soa_val[:200],
                            type="DNS History - SOA Record",
                            source="DNSHistory (Google DoH)",
                            confidence="High",
                            color="slate",
                            raw_data=f"SOA: {soa_val[:500]}",
                            tags=["dns", "soa"]
                        ))
    except Exception:
        pass

    dnstwister_url = f"https://dnstwister.report/api/fuzz/{domain}"
    try:
        dw_resp = await client.get(dnstwister_url, timeout=15.0, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        })
        if dw_resp.status_code == 200:
            dw_data = dw_resp.json() if isinstance(dw_resp.text, str) and dw_resp.text.startswith("{") else {}
            if isinstance(dw_data, dict):
                fuzzy = dw_data.get("fuzzy", [])
                if isinstance(fuzzy, list):
                    registered = [f for f in fuzzy if isinstance(f, dict) and f.get("domain") and f.get("registered")]
                    for fuzz_item in registered[:10]:
                        fuzz_domain = fuzz_item.get("domain", "")
                        fuzz_ip = fuzz_item.get("ip", "")
                        if fuzz_domain:
                            findings.append(IntelligenceFinding(
                                entity=fuzz_domain[:200],
                                type="DNS History - Typosquatting Variant",
                                source="DNSHistory (DNSTwister)",
                                confidence="Medium",
                                color="red",
                                threat_level="Elevated Risk",
                                resolution=fuzz_ip[:50] if fuzz_ip else "",
                                raw_data=f"Registered typosquat: {fuzz_domain} -> {fuzz_ip}",
                                tags=["typosquatting", "dns-twister"]
                            ))
    except Exception:
        pass

    try:
        rt_resp = await client.get(
            f"https://api.hackertarget.com/zonetransfer/?q={domain}",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if rt_resp.status_code == 200:
            zt_text = rt_resp.text.strip()
            if zt_text and "error" not in zt_text.lower()[:50] and "fail" not in zt_text.lower()[:50]:
                zt_lines = [l.strip() for l in zt_text.split("\n") if l.strip()]
                for zl in zt_lines[:20]:
                    findings.append(IntelligenceFinding(
                        entity=zl[:200],
                        type="DNS History - Zone Transfer Data",
                        source="DNSHistory (HackerTarget)",
                        confidence="High",
                        color="red",
                        threat_level="High Risk",
                        raw_data=f"Zone transfer: {zl[:500]}",
                        tags=["zone-transfer"]
                    ))
                findings.append(IntelligenceFinding(
                    entity=f"Zone transfer VULNERABLE - {len(zt_lines)} records leaked",
                    type="DNS History - Zone Transfer Risk",
                    source="DNSHistory (HackerTarget)",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    tags=["zone-transfer", "critical"]
                ))
    except Exception:
        pass

    return findings
