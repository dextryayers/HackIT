import httpx
import re
import json
import asyncio
from urllib.parse import urlparse
from module_common import safe_fetch, safe_fetch_json, make_finding, resolve_ip
from models import IntelligenceFinding

CDN_PROVIDERS = {
    "Cloudflare": ["cloudflare", "cf-ray"],
    "Akamai": ["akamai", "akamaiedge", "edgesuite", "edgekey"],
    "Fastly": ["fastly"],
    "CloudFront": ["cloudfront"],
    "Azure CDN": ["azureedge", "azurefd"],
    "Google Cloud CDN": ["gcp-cdn"],
    "KeyCDN": ["keycdn"],
    "BunnyCDN": ["bunnycdn", "b-cdn"],
    "StackPath": ["stackpath"],
}

async def _find_historical_dns_before_cdn(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, 
            f"https://viewdns.info/iphistory/?domain={domain}",
            timeout=20.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        )
        if resp.status_code == 200:
            ip_dates = re.findall(r'>(\d+\.\d+\.\d+\.\d+)</td><td>(\d{4}-\d{2}-\d{2})', resp.text)
            unique_ips = list(set(ip_dates))
            if unique_ips:
                findings.append(make_finding(
                    entity=f"{len(unique_ips)} historical IPs found",
                    type="CDN Bypass - Historical IPs (ViewDNS)",
                    source="ViewDNS",
                    confidence="Medium",
                    color="blue",
                    status="Historical",
                    raw_data=f"Historical IPs from ViewDNS: {len(unique_ips)}",
                    tags=["cdn-bypass", "historical-ip", "viewdns"]
                ))
                for ip, dt in unique_ips[:15]:
                    findings.append(make_finding(
                        entity=f"Historical IP: {ip} (seen {dt})",
                        type="CDN Bypass - Pre-CDN IP Candidate",
                        source="ViewDNS",
                        confidence="Medium",
                        color="orange",
                        status=f"Historical ({dt})",
                        raw_data=f"IP {ip} was used on {dt}",
                        tags=["cdn-bypass", "origin-ip", "historical"]
                    ))
    except Exception:
        pass
    return findings

async def _find_origin_via_ct_logs(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, 
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=20.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            certs = resp.json() if isinstance(resp.text, str) and resp.text.startswith("[") else []
            ips_in_certs = set()
            for cert in certs[:200]:
                name_val = str(cert.get("name_value", ""))
                for sub in name_val.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith("." + domain) and "*" not in sub:
                            try:
                                loop = asyncio.get_event_loop()
                                ip = await loop.run_in_executor(None, lambda s=sub: resolve_ip(s))
                                if ip:
                                    ips_in_certs.add(ip)
                            except Exception:
                                pass
            if ips_in_certs:
                findings.append(make_finding(
                    entity=f"{len(ips_in_certs)} unique IPs resolved from CT subdomains",
                    type="CDN Bypass - IPs from CT Logs",
                    source="crt.sh",
                    confidence="High",
                    color="orange",
                    status="Origin Candidates",
                    raw_data=f"IPs from CT subdomain resolution: {', '.join(sorted(ips_in_certs)[:10])}",
                    tags=["cdn-bypass", "ct-ip", "origin-candidate"]
                ))
                for ip in list(sorted(ips_in_certs))[:10]:
                    findings.append(make_finding(
                        entity=f"Origin IP candidate: {ip}",
                        type="CDN Bypass - Origin IP (CT Resolution)",
                        source="crt.sh",
                        confidence="High",
                        color="orange",
                        status="Candidate",
                        raw_data=f"Subdomain resolution returned {ip}",
                        tags=["cdn-bypass", "origin-ip"]
                    ))
    except Exception:
        pass
    return findings

async def _find_origin_via_spf(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, 
            f"https://dns.google/resolve?name={domain}&type=TXT",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            answers = data.get("Answer", [])
            for ans in answers:
                if ans.get("type") == 16:
                    txt = ans.get("data", "").lower()
                    if "v=spf" in txt:
                        ip4s = re.findall(r'ip4:([\d.]+)', txt)
                        includes = re.findall(r'include:([\w.]+)', txt)
                        for ip4 in ip4s:
                            findings.append(make_finding(
                                entity=f"SPF IP: {ip4}",
                                type="CDN Bypass - Origin IP (SPF ip4)",
                                source="Passive CDN Bypass",
                                confidence="High",
                                color="orange",
                                status="Origin Candidate",
                                raw_data=f"SPF authorized IP: {ip4}",
                                tags=["cdn-bypass", "origin-ip", "spf"]
                            ))
                        for inc in includes:
                            findings.append(make_finding(
                                entity=f"SPF include: {inc}",
                                type="CDN Bypass - SPF Include Domain",
                                source="Passive CDN Bypass",
                                confidence="High",
                                color="slate",
                                raw_data=f"SPF includes {inc}",
                                tags=["cdn-bypass", "spf", "include"]
                            ))
    except Exception:
        pass
    return findings

async def _find_origin_via_mx(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, 
            f"https://dns.google/resolve?name={domain}&type=MX",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            answers = data.get("Answer", [])
            for ans in answers:
                if ans.get("type") == 15:
                    mx_full = ans.get("data", "")
                    mx_parts = mx_full.split()
                    if len(mx_parts) >= 2:
                        mx_server = mx_parts[1].rstrip(".")
                        try:
                            loop = asyncio.get_event_loop()
                            mx_ip = await loop.run_in_executor(None, lambda: resolve_ip(mx_server))
                            if mx_ip:
                                findings.append(make_finding(
                                    entity=f"MX server: {mx_server} -> {mx_ip}",
                                    type="CDN Bypass - MX Server IP",
                                    source="Passive CDN Bypass",
                                    confidence="High",
                                    color="orange",
                                    status="Origin Candidate",
                                    raw_data=f"MX {mx_server} resolves to {mx_ip}",
                                    tags=["cdn-bypass", "origin-ip", "mx"]
                                ))
                        except Exception:
                            pass
    except Exception:
        pass
    return findings

async def _check_non_cdn_subdomains(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        ht_resp = await safe_fetch(client, 
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=12.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if ht_resp.status_code == 200:
            lines = ht_resp.text.strip().split("\n")
            sub_ip_map = {}
            for line in lines:
                if "," in line:
                    sub, ip = line.split(",")
                    sub = sub.strip().lower()
                    ip = ip.strip()
                    if sub not in sub_ip_map:
                        sub_ip_map[sub] = ip
            all_ips = set(sub_ip_map.values())
            if len(all_ips) > 1:
                findings.append(make_finding(
                    entity=f"{len(all_ips)} unique IPs across subdomains",
                    type="CDN Bypass - IP Diversity Across Subdomains",
                    source="Passive CDN Bypass",
                    confidence="High",
                    color="blue",
                    status="Diverse IPs",
                    raw_data=f"Unique IPs: {', '.join(sorted(all_ips))}",
                    tags=["cdn-bypass", "ip-diversity"]
                ))
                for sub, ip in list(sub_ip_map.items())[:10]:
                    findings.append(make_finding(
                        entity=f"{sub} -> {ip}",
                        type="CDN Bypass - Subdomain IP Mapping",
                        source="Passive CDN Bypass",
                        confidence="High",
                        color="slate",
                        status="Mapped",
                        raw_data=f"{sub} resolves to {ip}",
                        tags=["cdn-bypass", "subdomain", "ip"]
                    ))
    except Exception:
        pass
    return findings

async def _check_reverse_dns(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        ht_resp = await safe_fetch(client, 
            f"https://api.hackertarget.com/reverseip/?q={domain}",
            timeout=12.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if ht_resp.status_code == 200:
            lines = ht_resp.text.strip().split("\n")
            non_cdn_hosts = []
            for line in lines:
                if "," in line:
                    host = line.split(",")[0].strip()
                    is_cdn = False
                    for provider, patterns in CDN_PROVIDERS.items():
                        for pat in patterns:
                            if pat in host.lower():
                                is_cdn = True
                                break
                        if is_cdn:
                            break
                    if not is_cdn:
                        non_cdn_hosts.append(host)
            if non_cdn_hosts:
                findings.append(make_finding(
                    entity=f"{len(non_cdn_hosts)} non-CDN hosts co-located with origin IP",
                    type="CDN Bypass - Non-CDN Co-hosted Domains",
                    source="Passive CDN Bypass",
                    confidence="Medium",
                    color="orange",
                    status="Origin Candidates",
                    raw_data=f"Non-CDN hosts: {', '.join(non_cdn_hosts[:10])}",
                    tags=["cdn-bypass", "co-hosted", "origin-candidate"]
                ))
                for host in non_cdn_hosts[:10]:
                    findings.append(make_finding(
                        entity=host[:200],
                        type="CDN Bypass - Co-hosted Domain",
                        source="Passive CDN Bypass",
                        confidence="Medium",
                        color="slate",
                        status="Co-hosted",
                        tags=["cdn-bypass", "co-hosted"]
                    ))
    except Exception:
        pass
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).netloc

    hist_findings = await _find_historical_dns_before_cdn(domain, client)
    findings.extend(hist_findings)

    ct_findings = await _find_origin_via_ct_logs(domain, client)
    findings.extend(ct_findings)

    spf_findings = await _find_origin_via_spf(domain, client)
    findings.extend(spf_findings)

    mx_findings = await _find_origin_via_mx(domain, client)
    findings.extend(mx_findings)

    sub_findings = await _check_non_cdn_subdomains(domain, client)
    findings.extend(sub_findings)

    rev_findings = await _check_reverse_dns(domain, client)
    findings.extend(rev_findings)

    if findings:
        findings.append(make_finding(
            entity=f"CDN Bypass analysis complete: {len(findings)} findings",
            type="CDN Bypass - Summary",
            source="Passive CDN Bypass",
            confidence="High", color="purple",
            status="Complete",
            tags=["cdn-bypass", "summary"]
        ))

    return findings
