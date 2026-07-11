import httpx
import re
import socket
import asyncio
from urllib.parse import urlparse
from datetime import datetime
from typing import Optional
from module_common import safe_fetch, safe_fetch_json, make_finding, resolve_ip, is_ip
from models import IntelligenceFinding

ROBTEX_API = "https://freeapi.robtex.com"
ROBTEX_WEB = "https://www.robtex.com"
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
BULK_BATCH_SIZE = 10
MAX_PDNS_RESULTS = 50


async def _robtex_get(url: str, client: httpx.AsyncClient, is_json: bool = True) -> dict | list | str | None:
    resp = await safe_fetch(client, url, timeout=15.0,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json" if is_json else "text/html"})
    if resp and resp.status_code == 200:
        if is_json:
            try:
                return resp.json()
            except Exception:
                pass
        return resp.text
    return None


async def _resolve_dns(hostname: str) -> str | None:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: resolve_ip(hostname))


async def _dns_lookup_full(hostname: str, record_type: str) -> list[str]:
    results = []
    try:
        _, _, addresses = socket.gethostbyname_ex(hostname)
        if record_type == "A":
            results.extend(addresses)
    except Exception:
        pass
    try:
        if record_type in ("MX", "NS"):
            results.append(f"{record_type} lookup performed via socket")
    except Exception:
        pass
    return results


def _extract_ip_ranges(text: str) -> list[str]:
    cidr_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b')
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    return list(set(cidr_pattern.findall(text) + ip_pattern.findall(text)))


def _extract_asn_info(text: str) -> list[dict]:
    results = []
    asn_pattern = re.compile(r'AS(\d+)', re.IGNORECASE)
    for m in asn_pattern.finditer(text):
        asn = m.group(1)
        results.append({"asn": asn})
    return results


async def _query_ip(ip: str, client: httpx.AsyncClient) -> dict | None:
    return await _robtex_get(f"{ROBTEX_API}/ipquery/{ip}", client)


async def _query_forward_pdns(domain: str, client: httpx.AsyncClient) -> dict | None:
    return await _robtex_get(f"{ROBTEX_API}/pdns/forward/{domain}", client)


async def _query_reverse_pdns(ip: str, client: httpx.AsyncClient) -> dict | None:
    return await _robtex_get(f"{ROBTEX_API}/pdns/reverse/{ip}", client)


async def _query_asn(asn: str, client: httpx.AsyncClient) -> dict | None:
    return await _robtex_get(f"{ROBTEX_API}/asnquery/{asn}", client)


async def _query_bulk_ips(ips: list[str], client: httpx.AsyncClient) -> list[dict]:
    results = []
    for i in range(0, len(ips), BULK_BATCH_SIZE):
        batch = ips[i:i + BULK_BATCH_SIZE]
        ips_str = ",".join(batch)
        data = await _robtex_get(f"{ROBTEX_API}/_bulk/{ips_str}", client)
        if isinstance(data, list):
            results.extend(data)
        elif isinstance(data, dict):
            results.append(data)
    return results


async def _query_pdns_forward_filtered(domain: str, client: httpx.AsyncClient,
                                        filter_types: Optional[list[str]] = None) -> dict | None:
    if filter_types is None:
        filter_types = ["A", "AAAA", "MX", "NS", "CNAME", "TXT"]
    raw = await _robtex_get(f"{ROBTEX_API}/pdns/forward/{domain}", client)
    if not isinstance(raw, dict):
        return None
    filtered = {}
    for rtype, records in raw.items():
        if rtype.upper() in [t.upper() for t in filter_types] and isinstance(records, list):
            filtered[rtype] = records[:MAX_PDNS_RESULTS]
    return filtered if filtered else None


async def _query_pdns_reverse_filtered(ip: str, client: httpx.AsyncClient,
                                        filter_types: Optional[list[str]] = None) -> dict | None:
    if filter_types is None:
        filter_types = ["A", "AAAA", "MX", "NS", "CNAME", "TXT"]
    raw = await _robtex_get(f"{ROBTEX_API}/pdns/reverse/{ip}", client)
    if not isinstance(raw, dict):
        return None
    filtered = {}
    for rtype, records in raw.items():
        if rtype.upper() in [t.upper() for t in filter_types] and isinstance(records, list):
            filtered[rtype] = records[:MAX_PDNS_RESULTS]
    return filtered if filtered else None


async def _scrape_robtex_ip(ip: str, client: httpx.AsyncClient) -> dict:
    data = {"raw_text": "", "sections": {}}
    html = await _robtex_get(f"{ROBTEX_WEB}/en/address/{ip}", client, is_json=False)
    if not html or not isinstance(html, str):
        return data
    data["raw_text"] = html[:5000]
    ip_block = re.search(r'IP\s*address[^<]*<strong>([^<]+)</strong>', html, re.IGNORECASE)
    if ip_block:
        data["sections"]["ip"] = ip_block.group(1).strip()
    asn_block = re.search(r'AS(\d+)', html)
    if asn_block:
        data["sections"]["asn"] = f"AS{asn_block.group(1)}"
    rdns_block = re.search(r'(?:PTR|rDNS|Reverse\s*DNS)[^<]*<[^>]+>([^<]+)</', html, re.IGNORECASE)
    if rdns_block:
        data["sections"]["rdns"] = rdns_block.group(1).strip()
    country_block = re.search(r'Country[^<]*<[^>]+>([^<]+)</', html, re.IGNORECASE)
    if country_block:
        data["sections"]["country"] = country_block.group(1).strip()
    desc_block = re.search(r'(?:Description|Whois|Org(?:anization)?)[^<]*<[^>]+>([^<]+)</', html, re.IGNORECASE)
    if desc_block:
        data["sections"]["descr"] = desc_block.group(1).strip()
    domains_block = re.search(r'Domains\s*on\s*this\s*IP[^<]*<[^>]+>\s*(\d+)', html, re.IGNORECASE)
    if domains_block:
        data["sections"]["co_hosted_count"] = domains_block.group(1).strip()
    return data


async def _scrape_robtex_dns(domain: str, client: httpx.AsyncClient) -> dict:
    data = {"raw_text": "", "records": []}
    html = await _robtex_get(f"{ROBTEX_WEB}/en/dns/{domain}", client, is_json=False)
    if not html or not isinstance(html, str):
        return data
    data["raw_text"] = html[:5000]
    record_pattern = re.compile(
        r'<tr[^>]*>.*?<td[^>]*>([^<]+)</td>.*?<td[^>]*>([^<]+)</td>.*?<td[^>]*>([^<]+)</td>.*?</tr>',
        re.IGNORECASE | re.DOTALL
    )
    for m in record_pattern.finditer(html):
        rtype = m.group(1).strip()
        rname = m.group(2).strip()
        rvalue = m.group(3).strip()
        data["records"].append({"type": rtype, "name": rname, "value": rvalue})
    return data


def _parse_pdns_timeline(pdns_data: dict) -> list[dict]:
    timeline = []
    for rtype, records in pdns_data.items():
        if not isinstance(records, list):
            continue
        for rec in records:
            if isinstance(rec, dict):
                host = rec.get("hostname", rec.get("rrname", rec.get("host", "")))
                rtype_rec = rec.get("type", rec.get("rtype", rtype))
                time_rec = rec.get("time", rec.get("timestamp", ""))
                if host:
                    timeline.append({
                        "host": host,
                        "type": rtype_rec,
                        "timestamp": str(time_rec),
                        "time_int": int(time_rec) if str(time_rec).isdigit() else 0
                    })
    timeline.sort(key=lambda x: x["time_int"])
    return timeline


def _analyze_dns_timeline(timeline: list[dict]) -> dict:
    analysis = {
        "new_records": [],
        "removed_records": [],
        "changed_ips": [],
        "total_entries": len(timeline)
    }
    if not timeline:
        return analysis
    host_history = {}
    for entry in timeline:
        host = entry["host"]
        if host not in host_history:
            host_history[host] = []
        host_history[host].append(entry)
    t_min = min(e["time_int"] for e in timeline)
    t_max = max(e["time_int"] for e in timeline)
    time_span = t_max - t_min if t_max > t_min else 1
    cutoff_recent = t_max - (time_span * 0.1)
    for host, entries in host_history.items():
        earliest = min(e["time_int"] for e in entries)
        latest = max(e["time_int"] for e in entries)
        if latest >= cutoff_recent and earliest < cutoff_recent:
            analysis["new_records"].append({"host": host, "first_seen": str(earliest)})
        if earliest < t_min + time_span * 0.1 and latest < cutoff_recent:
            analysis["removed_records"].append({"host": host, "last_seen": str(latest)})
        if entries[0].get("type") == "A":
            ips_seen = list(dict.fromkeys(e.get("host", "") for e in entries))
            if len(set(ips_seen)) > 1:
                analysis["changed_ips"].append({
                    "host": host,
                    "previous": ips_seen[-2] if len(ips_seen) >= 2 else "",
                    "current": ips_seen[-1]
                })
    return analysis


def _categorize_cosited_domain(domain: str, threat_data: set) -> str:
    domain_lower = domain.lower()
    suspicious_keywords = ["phish", "login", "secure", "bank", "account", "verify", "update",
                           "confirm", "signin", "webmail", "mail", "cpanel", "whm", "plesk",
                           "test", "staging", "dev", "admin", "backup", "vpn", "proxy"]
    for kw in suspicious_keywords:
        if kw in domain_lower:
            return "suspicious"
    if any(tld in domain_lower for tld in [".xyz", ".top", ".gq", ".ml", ".cf", ".tk", ".pw", ".cc"]):
        return "suspicious"
    if domain_lower in threat_data:
        return "malicious"
    if any(domain_lower.endswith(f".{tld}") for tld in ["com", "org", "net", "edu", "gov", "mil"]):
        return "legitimate"
    return "unknown"


def _analyze_cosited_domains(reverse_entries: list[dict], active_entries: list[dict],
                              threat_data: set) -> list[dict]:
    domains_map = {}
    for entry in reverse_entries + active_entries:
        host = entry.get("host", entry.get("hostname", entry.get("rrname", ""))) if isinstance(entry, dict) else ""
        if host:
            category = _categorize_cosited_domain(host, threat_data)
            if category not in domains_map:
                domains_map[category] = []
            if host not in domains_map[category]:
                domains_map[category].append(host)
    result = []
    for category, domains in domains_map.items():
        result.append({
            "category": category,
            "count": len(domains),
            "domains": domains[:20]
        })
    return result


def _detect_subprefix_hijack(asn_routes: list[dict], asn_ipset: list[dict], asn_number: str) -> list[dict]:
    alerts = []
    own_prefixes = set()
    route_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})')
    for route in asn_routes:
        route_str = route.get("route", route) if isinstance(route, dict) else str(route)
        m = route_pattern.search(str(route_str))
        if m:
            own_prefixes.add(m.group(1))
    ip_entries = []
    for entry in asn_ipset:
        ip_str = entry.get("ip", entry) if isinstance(entry, dict) else str(entry)
        m = route_pattern.search(str(ip_str))
        if m:
            ip_entries.append(m.group(1))
    for prefix in own_prefixes:
        net, mask_str = prefix.split("/")
        mask = int(mask_str)
        net_int = sum(int(o) << (24 - 8 * i) for i, o in enumerate(net.split(".")))
        for ip_entry in ip_entries:
            if "/" in ip_entry:
                ep_net, ep_mask_str = ip_entry.split("/")
                ep_mask = int(ep_mask_str)
                ep_int = sum(int(o) << (24 - 8 * i) for i, o in enumerate(ep_net.split(".")))
                if ep_mask > mask:
                    range_start = ep_int
                    range_end = ep_int + (1 << (32 - ep_mask)) - 1
                    own_start = net_int
                    own_end = net_int + (1 << (32 - mask)) - 1
                    if range_start >= own_start and range_end <= own_end:
                        alerts.append({
                            "type": "sub_prefix",
                            "parent_prefix": prefix,
                            "specific_prefix": ip_entry,
                            "detail": f"More specific prefix {ip_entry} found within {prefix} on AS{asn_number}"
                        })
    return alerts


async def _check_threat_intel(ip: str, domain: str | None, client: httpx.AsyncClient) -> dict:
    result = {
        "malicious": False,
        "sources": [],
        "threat_score": 0,
        "details": []
    }
    try:
        urlhaus_resp = await safe_fetch(client, 
            f"https://urlhaus-api.abuse.ch/v1/host/{domain or ip}",
            timeout=10.0,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
        )
        if urlhaus_resp.status_code == 200:
            uh_data = urlhaus_resp.json()
            if uh_data.get("query_status") == "ok":
                result["threat_score"] += 40
                result["malicious"] = True
                result["sources"].append("URLhaus")
                result["details"].append(f"URLhaus: {uh_data.get('urlhaus_reference', 'listed')}")
    except Exception:
        pass
    try:
        if ip:
            abuse_resp = await safe_fetch(client, 
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                timeout=10.0,
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            )
            if abuse_resp.status_code == 200:
                ab_data = abuse_resp.json()
                ab_score = ab_data.get("data", {}).get("abuseConfidenceScore", 0)
                if ab_score > 0:
                    result["threat_score"] += int(ab_score) * 0.4
                    result["malicious"] = result["threat_score"] >= 30
                    result["sources"].append("AbuseIPDB")
                    result["details"].append(f"AbuseIPDB score: {ab_score}")
    except Exception:
        pass
    try:
        if domain:
            urlhaus_url = await client.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": f"http://{domain}"},
                timeout=10.0,
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
            )
            if urlhaus_url.status_code == 200:
                uhu_data = urlhaus_url.json()
                if uhu_data.get("query_status") == "ok" and uhu_data.get("url_count", 0) > 0:
                    result["threat_score"] += 20
                    result["malicious"] = True
                    result["sources"].append("URLhaus-URL")
                    result["details"].append(f"URLhaus URL: domain listed")
    except Exception:
        pass
    try:
        if ip:
            isc_resp = await safe_fetch(client, 
                f"https://isc.sans.edu/api/ip/{ip}?json",
                timeout=10.0,
                headers={"User-Agent": USER_AGENT}
            )
            if isc_resp.status_code == 200:
                isc_data = isc_resp.json()
                isc_score = 0
                if isinstance(isc_data, dict):
                    isc_score = int(isc_data.get("max_domain", 0)) + int(isc_data.get("max_attacks", 0))
                if isc_score > 0:
                    result["threat_score"] += min(isc_score, 20)
                    result["sources"].append("ISC SANS")
                    result["details"].append(f"ISC SANS score: {isc_score}")
    except Exception:
        pass
    try:
        tor_resp = await safe_fetch(client, 
            "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1",
            timeout=10.0,
            headers={"User-Agent": USER_AGENT}
        )
        if tor_resp.status_code == 200 and ip and ip in tor_resp.text:
            result["threat_score"] += 15
            result["sources"].append("Tor-Exit")
            result["details"].append("IP is a Tor exit node")
    except Exception:
        pass
    try:
        blocklist_resp = await safe_fetch(client, 
            f"https://www.binarydefense.com/banlist.txt",
            timeout=10.0,
            headers={"User-Agent": USER_AGENT}
        )
        if blocklist_resp.status_code == 200 and ip and ip in blocklist_resp.text:
            result["threat_score"] += 25
            result["malicious"] = True
            result["sources"].append("BinaryDefense")
            result["details"].append("IP in BinaryDefense banlist")
    except Exception:
        pass
    result["threat_score"] = min(int(result["threat_score"]), 100)
    return result


def _categorize_dns_records(pdns_forward: dict | None, pdns_reverse: dict | None) -> dict:
    categories = {
        "web_servers": [],
        "mail_servers": [],
        "nameservers": [],
        "redirects": [],
        "other": []
    }
    for source_name, source_data in [("forward", pdns_forward), ("reverse", pdns_reverse)]:
        if not isinstance(source_data, dict):
            continue
        for rtype, records in source_data.items():
            if not isinstance(records, list):
                continue
            rtype_upper = rtype.upper()
            for rec in records:
                if not isinstance(rec, dict):
                    continue
                host = rec.get("hostname", rec.get("rrname", rec.get("host", "")))
                value = rec.get("value", rec.get("ip", rec.get("rdata", "")))
                if not host:
                    continue
                entry = {"host": host, "value": str(value)[:100], "source": source_name}
                if rtype_upper == "A" or rtype_upper == "AAAA":
                    if len(categories["web_servers"]) < 20:
                        categories["web_servers"].append(entry)
                elif rtype_upper == "MX":
                    if len(categories["mail_servers"]) < 10:
                        categories["mail_servers"].append(entry)
                elif rtype_upper == "NS":
                    if len(categories["nameservers"]) < 10:
                        categories["nameservers"].append(entry)
                elif rtype_upper == "CNAME":
                    if len(categories["redirects"]) < 20:
                        categories["redirects"].append(entry)
                else:
                    if len(categories["other"]) < 20:
                        entry["rtype"] = rtype_upper
                        categories["other"].append(entry)
    return categories


def _compute_ip_reputation(threat_data: dict, dns_timeline: dict, cosited: list[dict],
                            pdns_count: int, asn_info: dict | None) -> dict:
    score = 0
    reasons = []
    score += min(threat_data.get("threat_score", 0), 40)
    if threat_data.get("threat_score", 0) > 0:
        reasons.append(f"Threat feed score: {threat_data.get('threat_score')}")
    new_records = dns_timeline.get("new_records", [])
    changed_ips = dns_timeline.get("changed_ips", [])
    suspicious_domains = dns_timeline.get("removed_records", [])
    score += min(len(new_records) * 2, 15)
    if new_records:
        reasons.append(f"Recently added DNS records: {len(new_records)}")
    score += min(len(changed_ips) * 3, 15)
    if changed_ips:
        reasons.append(f"IP changes detected: {len(changed_ips)}")
    score += min(len(suspicious_domains), 5)
    for cat_group in cosited:
        if cat_group["category"] == "suspicious":
            score += min(cat_group["count"] * 2, 15)
            reasons.append(f"Co-hosted suspicious domains: {cat_group['count']}")
        elif cat_group["category"] == "malicious":
            score += min(cat_group["count"] * 5, 20)
            reasons.append(f"Co-hosted malicious domains: {cat_group['count']}")
    if pdns_count > 100:
        score += 10
        reasons.append(f"High passive DNS count: {pdns_count}")
    elif pdns_count > 50:
        score += 5
    if asn_info:
        asn_country = asn_info.get("country", "")
        if asn_country.upper() in ["RU", "CN", "IR", "KP", "SY", "VE"]:
            score += 5
            reasons.append(f"ASN country: {asn_country}")
    score = min(score, 100)
    return {
        "score": score,
        "level": "Malicious" if score >= 70 else "Suspicious" if score >= 40 else "Low Risk" if score >= 20 else "Clean",
        "reasons": reasons[:5]
    }


def _build_comprehensive_summary(findings: list[IntelligenceFinding], target: str,
                                  ip: str | None, asn: str | None,
                                  dns_timeline: dict, cosited: list[dict],
                                  threat_data: dict, reputation: dict) -> IntelligenceFinding:
    finding_types = {}
    for f in findings:
        finding_types[f.type] = finding_types.get(f.type, 0) + 1
    summary_lines = [
        f"Target: {target}",
        f"IP: {ip or 'N/A'}",
        f"ASN: {asn or 'N/A'}",
        f"Reputation: {reputation['level']} (score: {reputation['score']}/100)",
    ]
    if threat_data.get("malicious"):
        summary_lines.append(f"Threat: Flagged by {', '.join(threat_data.get('sources', ['unknown']))}")
    if dns_timeline.get("new_records"):
        summary_lines.append(f"New DNS records: {len(dns_timeline['new_records'])}")
    if cosited:
        for cat_group in cosited:
            summary_lines.append(f"Co-hosted ({cat_group['category']}): {cat_group['count']}")
    type_summary = "; ".join([f"{k}: {v}" for k, v in sorted(finding_types.items(), key=lambda x: -x[1])[:8]])
    summary_lines.append(f"Findings: {len(findings)} total | {type_summary}")
    tags = ["summary", "robtex", target.replace('.', '_')]
    tags.append(f"reputation_{reputation['level'].lower().replace(' ', '_')}")
    if threat_data.get("malicious"):
        tags.append("threat_flagged")
    return make_finding(
        entity=f"Robtex comprehensive intelligence for {target}",
        type="Robtex Comprehensive Summary",
        source="Robtex",
        confidence="High",
        color="purple",
        threat_level="Informational",
        status="Complete",
        resolution=str(ip or ""),
        raw_data=" | ".join(summary_lines),
        tags=tags
    )





async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    raw_target = target.strip().lower()
    if raw_target.startswith("http"):
        raw_target = urlparse(raw_target).netloc
    raw_target = raw_target.strip().lower()

    is_ip_target = is_ip(raw_target)
    target_ip = raw_target if is_ip_target else None
    target_domain = raw_target if not is_ip_target else None

    ip_to_use = None
    asn = None
    all_pdns_forward_records = {}
    all_pdns_reverse_records = {}

    try:
        resp_ip_dict = None
        pdns_forward = None
        pdns_reverse = None
        asn_data = None

        if is_ip_target:
            resp_ip_dict = await _query_ip(target_ip, client)
            ip_to_use = target_ip
        elif target_domain:
            resolved_ip = await _resolve_dns(target_domain)
            if resolved_ip:
                ip_to_use = resolved_ip
                resp_ip_dict = await _query_ip(ip_to_use, client)
            else:
                findings.append(make_finding(
                    entity=f"Cannot resolve {target_domain} to IP",
                    ftype="Robtex Resolution Error",
                    confidence="Low", color="red",
                    threat_level="Informational", status="Failed",
                    tags=["error", target_domain.replace('.', '_')]
                ))
                return findings

        if resp_ip_dict and isinstance(resp_ip_dict, dict):
            ip = resp_ip_dict.get("ip") or ip_to_use
            asn = resp_ip_dict.get("asn") or resp_ip_dict.get("as", "")
            as_name = resp_ip_dict.get("asname") or resp_ip_dict.get("as_name", "")
            as_desc = resp_ip_dict.get("asdesc") or ""
            country = resp_ip_dict.get("country", "")
            city = resp_ip_dict.get("city", "")
            owner = resp_ip_dict.get("owner", "")
            routes = resp_ip_dict.get("routes", [])
            actives = resp_ip_dict.get("actives", [])
            passive_dns = resp_ip_dict.get("passive", [])

            if ip:
                findings.append(make_finding(
                    entity=ip, ftype="Robtex IP Address",
                    confidence="High", color="slate",
                    status="Confirmed",
                    raw_data=f"Target IP: {ip}",
                    tags=["ip", ip.replace('.', '_')]
                ))
            if asn:
                asn_str = f"AS{asn}" if not str(asn).startswith("AS") else str(asn)
                findings.append(make_finding(
                    entity=f"{asn_str} - {as_name[:200]}",
                    ftype="Robtex ASN",
                    confidence="High", color="orange",
                    status="Confirmed", resolution=asn_str,
                    raw_data=f"ASN: {asn}, Name: {as_name}, Desc: {as_desc}",
                    tags=["asn", asn_str.replace(':', '_')]
                ))
            if country:
                findings.append(make_finding(
                    entity=country, ftype="Robtex Country",
                    confidence="High", color="slate",
                    status="GeoLocated",
                    raw_data=f"Country: {country}",
                    tags=["geo", "country"]
                ))
            if city:
                findings.append(make_finding(
                    entity=city, ftype="Robtex City",
                    confidence="Medium", color="slate",
                    status="GeoLocated",
                    raw_data=f"City: {city}",
                    tags=["geo", "city"]
                ))
            if owner:
                findings.append(make_finding(
                    entity=owner[:200], ftype="Robtex IP Owner",
                    confidence="High", color="slate",
                    status="Identified",
                    raw_data=f"Owner: {owner}",
                    tags=["ownership"]
                ))
            for route in routes[:10]:
                route_str = route.get("route", route) if isinstance(route, dict) else str(route)
                findings.append(make_finding(
                    entity=str(route_str)[:200], ftype="Robtex Route",
                    confidence="High", color="blue",
                    status="Announced",
                    raw_data=f"Route: {route_str}",
                    tags=["route", "bgp"]
                ))
            for active in actives[:15]:
                active_host = active.get("host", "") if isinstance(active, dict) else str(active)
                active_ip_val = active.get("ip", "") if isinstance(active, dict) else ""
                if active_host:
                    findings.append(make_finding(
                        entity=active_host[:200], ftype="Robtex Active DNS",
                        confidence="Medium", color="emerald",
                        status="Active", resolution=active_ip_val,
                        raw_data=f"Active DNS: {active_host} -> {active_ip_val}",
                        tags=["active_dns", "forward"]
                    ))
            for pdns_entry in passive_dns[:15]:
                pdns_host = pdns_entry.get("host", pdns_entry.get("rrname", "")) if isinstance(pdns_entry, dict) else ""
                pdns_type = pdns_entry.get("type", pdns_entry.get("rtype", "")) if isinstance(pdns_entry, dict) else ""
                pdns_time = pdns_entry.get("time", pdns_entry.get("timestamp", "")) if isinstance(pdns_entry, dict) else ""
                if pdns_host:
                    findings.append(make_finding(
                        entity=pdns_host[:200], ftype=f"Robtex Passive DNS ({pdns_type})",
                        confidence="High", color="emerald",
                        status="Historical", resolution=ip_to_use,
                        raw_data=f"Passive DNS: {pdns_host} ({pdns_type}) at {pdns_time}",
                        tags=["passive_dns", pdns_type.lower() if pdns_type else "dns"]
                    ))

        if target_domain:
            pdns_forward = await _query_pdns_forward_filtered(target_domain, client)
            all_pdns_forward_records = pdns_forward or {}
            if pdns_forward and isinstance(pdns_forward, dict):
                for rtype, records in pdns_forward.items():
                    if isinstance(records, list):
                        for rec in records[:15]:
                            if isinstance(rec, dict):
                                host = rec.get("hostname", rec.get("rrname", rec.get("host", "")))
                                rtype_rec = rec.get("type", rec.get("rtype", rtype))
                                time_rec = rec.get("time", rec.get("timestamp", ""))
                                if host:
                                    findings.append(make_finding(
                                        entity=host[:200], ftype=f"Robtex Forward PDNS ({rtype_rec})",
                                        confidence="High", color="blue",
                                        status="Historical",
                                        raw_data=f"Forward PDNS: {host} type {rtype_rec} at {time_rec}",
                                        tags=["forward_pdns", "passive_dns", rtype_rec.lower()]
                                    ))

        if ip_to_use:
            pdns_reverse = await _query_pdns_reverse_filtered(ip_to_use, client)
            all_pdns_reverse_records = pdns_reverse or {}
            if pdns_reverse and isinstance(pdns_reverse, dict):
                for rtype, records in pdns_reverse.items():
                    if isinstance(records, list):
                        for rec in records[:15]:
                            if isinstance(rec, dict):
                                host = rec.get("hostname", rec.get("rrname", rec.get("host", "")))
                                rtype_rec = rec.get("type", rec.get("rtype", rtype))
                                time_rec = rec.get("time", rec.get("timestamp", ""))
                                if host:
                                    findings.append(make_finding(
                                        entity=host[:200], ftype=f"Robtex Reverse PDNS ({rtype_rec})",
                                        confidence="High", color="emerald",
                                        status="Historical", resolution=ip_to_use,
                                        raw_data=f"Reverse PDNS: {host} type {rtype_rec} at {time_rec}",
                                        tags=["reverse_pdns", "passive_dns", rtype_rec.lower()]
                                    ))

        if asn:
            asn_clean = str(asn).replace("AS", "")
            asn_data = await _query_asn(asn_clean, client)
            if asn_data and isinstance(asn_data, dict):
                asn_routes = asn_data.get("routes", [])
                asn_ipset = asn_data.get("ipset", [])
                asn_name = asn_data.get("asname", "")
                for route in asn_routes[:10]:
                    route_str = route.get("route", route) if isinstance(route, dict) else str(route)
                    findings.append(make_finding(
                        entity=str(route_str)[:200], ftype="Robtex ASN Route",
                        confidence="High", color="blue",
                        status="Announced",
                        raw_data=f"AS{asn_clean} route: {route_str}",
                        tags=["asn_route", f"as{asn_clean}"]
                    ))
                for ip_entry in asn_ipset[:10]:
                    ip_str = ip_entry.get("ip", ip_entry) if isinstance(ip_entry, dict) else str(ip_entry)
                    findings.append(make_finding(
                        entity=str(ip_str)[:200], ftype="Robtex ASN IP Set",
                        confidence="Medium", color="slate",
                        status="Member",
                        raw_data=f"AS{asn_clean} IP: {ip_str}",
                        tags=["asn_ipset", f"as{asn_clean}"]
                    ))
                hijack_alerts = _detect_subprefix_hijack(asn_routes, asn_ipset, asn_clean)
                for alert in hijack_alerts[:5]:
                    findings.append(make_finding(
                        entity=alert["specific_prefix"],
                        ftype="Robtex ASN Sub-Prefix Alert",
                        confidence="Low", color="yellow",
                        threat_level="Warning",
                        status="Potential Hijack",
                        raw_data=alert["detail"],
                        tags=["bgp_hijack", "sub_prefix", f"as{alert['specific_prefix'].replace('/', '_')}"]
                    ))

        if ip_to_use or target_domain:
            scrape_ip = ip_to_use
            scrape_data = {}
            if scrape_ip:
                scrape_data = await _scrape_robtex_ip(scrape_ip, client)
                if scrape_data.get("raw_text"):
                    scraped_asn = scrape_data.get("sections", {}).get("asn")
                    scraped_country = scrape_data.get("sections", {}).get("country")
                    if scraped_asn:
                        findings.append(make_finding(
                            entity=f"Scraped {scraped_asn}",
                            ftype="Robtex Scraped ASN",
                            confidence="Low", color="orange",
                            status="Scraped",
                            raw_data=f"Scraped ASN: {scraped_asn}",
                            tags=["scraped", "asn"]
                        ))
                    if scraped_country:
                        findings.append(make_finding(
                            entity=scraped_country,
                            ftype="Robtex Scraped Country",
                            confidence="Low", color="slate",
                            status="Scraped",
                            raw_data=f"Scraped Country: {scraped_country}",
                            tags=["scraped", "geo"]
                        ))
            if target_domain:
                dns_scrape = await _scrape_robtex_dns(target_domain, client)
                if dns_scrape.get("records"):
                    for rec in dns_scrape["records"][:10]:
                        findings.append(make_finding(
                            entity=rec.get("name", ""),
                            ftype=f"Robtex Scraped DNS ({rec.get('type', '')})",
                            confidence="Low", color="cyan",
                            status="Scraped",
                            raw_data=f"{rec.get('type', '')}: {rec.get('name', '')} = {rec.get('value', '')}",
                            tags=["scraped", "dns", rec.get('type', '').lower()]
                        ))

        dns_timeline_raw = _parse_pdns_timeline({**all_pdns_forward_records, **all_pdns_reverse_records})
        dns_timeline = _analyze_dns_timeline(dns_timeline_raw)

        if dns_timeline.get("new_records"):
            for nr in dns_timeline["new_records"][:10]:
                findings.append(make_finding(
                    entity=nr["host"], ftype="Robtex New DNS Record",
                    confidence="Medium", color="yellow",
                    threat_level="Notice",
                    status="Recently Added",
                    raw_data=f"Newly observed: {nr['host']} first seen {nr['first_seen']}",
                    tags=["dns_timeline", "new_record", nr["host"].replace('.', '_')]
                ))
        if dns_timeline.get("changed_ips"):
            for ci in dns_timeline["changed_ips"][:10]:
                findings.append(make_finding(
                    entity=ci["host"], ftype="Robtex IP Change Detected",
                    confidence="Medium", color="amber",
                    threat_level="Notice",
                    status="Changed",
                    resolution=ci.get("current", ""),
                    raw_data=f"IP changed: {ci['host']} from {ci.get('previous', '?')} to {ci.get('current', '?')}",
                    tags=["dns_timeline", "ip_change", ci["host"].replace('.', '_')]
                ))
        if dns_timeline.get("removed_records"):
            for rr in dns_timeline["removed_records"][:10]:
                findings.append(make_finding(
                    entity=rr["host"], ftype="Robtex Removed DNS Record",
                    confidence="Medium", color="red",
                    threat_level="Notice",
                    status="Removed",
                    raw_data=f"No longer observed: {rr['host']} last seen {rr['last_seen']}",
                    tags=["dns_timeline", "removed_record", rr["host"].replace('.', '_')]
                ))

        if ip_to_use:
            threat_data = await _check_threat_intel(ip_to_use, target_domain, client)
            if threat_data.get("malicious") or threat_data.get("threat_score", 0) > 0:
                findings.append(make_finding(
                    entity=f"Threat intel for {ip_to_use}",
                    ftype="Robtex Threat Intelligence",
                    confidence="Medium" if threat_data.get("malicious") else "Low",
                    color="red" if threat_data.get("malicious") else "amber",
                    threat_level="High" if threat_data.get("malicious") else "Medium",
                    status="Flagged" if threat_data.get("malicious") else "Clean",
                    raw_data=f"Score: {threat_data['threat_score']}/100, Sources: {', '.join(threat_data.get('sources', []))}",
                    tags=["threat_intel", "malicious" if threat_data.get("malicious") else "clean"]
                ))
        else:
            threat_data = {"malicious": False, "sources": [], "threat_score": 0, "details": []}

        cosited_data = _analyze_cosited_domains(
            list(all_pdns_reverse_records.values())[0] if all_pdns_reverse_records else [],
            list(all_pdns_forward_records.values())[0] if all_pdns_forward_records else [],
            set()
        )
        for cat_group in cosited_data:
            findings.append(make_finding(
                entity=f"{cat_group['category'].title()}: {cat_group['count']} co-hosted domains",
                ftype="Robtex Co-Hosted Domains",
                confidence="Medium" if cat_group["category"] == "legitimate" else "Low",
                color="green" if cat_group["category"] == "legitimate" else "red" if cat_group["category"] == "malicious" else "amber",
                threat_level="Warning" if cat_group["category"] in ("suspicious", "malicious") else "Informational",
                status="Analyzed",
                raw_data=f"Co-hosted ({cat_group['category']}): {', '.join(cat_group['domains'][:10])}",
                tags=["cohosted", cat_group["category"], f"count_{cat_group['count']}"]
            ))

        dns_categories = _categorize_dns_records(
            all_pdns_forward_records if all_pdns_forward_records else None,
            all_pdns_reverse_records if all_pdns_reverse_records else None
        )
        for cat_name, entries in dns_categories.items():
            if entries:
                unique_hosts = list(dict.fromkeys(e["host"] for e in entries))
                findings.append(make_finding(
                    entity=f"{cat_name.replace('_', ' ').title()}: {len(unique_hosts)} records",
                    ftype=f"Robtex DNS Category: {cat_name.replace('_', ' ').title()}",
                    confidence="Medium", color="blue",
                    status="Categorized",
                    raw_data=f"{cat_name}: {', '.join(unique_hosts[:10])}",
                    tags=["dns_category", cat_name]
                ))

        pdns_total_count = (
            sum(len(v) if isinstance(v, list) else 0 for v in all_pdns_forward_records.values()) +
            sum(len(v) if isinstance(v, list) else 0 for v in all_pdns_reverse_records.values())
        )
        reputation = _compute_ip_reputation(
            threat_data, dns_timeline, cosited_data, pdns_total_count,
            {"country": resp_ip_dict.get("country", "")} if resp_ip_dict and isinstance(resp_ip_dict, dict) else None
        )
        if ip_to_use:
            findings.append(make_finding(
                entity=f"IP Reputation: {reputation['level']} ({reputation['score']}/100)",
                ftype="Robtex IP Reputation",
                confidence="Medium",
                color="red" if reputation["score"] >= 70 else "amber" if reputation["score"] >= 40 else "yellow" if reputation["score"] >= 20 else "green",
                threat_level=reputation["level"],
                status="Scored",
                raw_data=f"Score: {reputation['score']}/100 - {'; '.join(reputation['reasons'])}",
                tags=["reputation", f"score_{reputation['score']}", reputation['level'].lower().replace(' ', '_')]
            ))

    except Exception as e:
        findings.append(make_finding(
            entity=f"Robtex query error: {str(e)[:100]}",
            ftype="Robtex Error",
            confidence="Low", color="red",
            threat_level="Informational", status="Error",
            tags=["error"]
        ))
        return findings

    if findings:
        summary = _build_comprehensive_summary(
            findings, raw_target, ip_to_use, asn,
            dns_timeline, cosited_data, threat_data, reputation
        )
        findings.append(summary)

    async def analyze_dns_health():
        findings.append(make_finding(entity=f"PDNS entries: {pdns_total_count}", type="Robtex: PDNS Volume", source="Robtex", confidence="Medium", color="slate", tags=["dns"]))
        findings.append(make_finding(entity=f"DNS changes: {len(dns_timeline.get('new_records', []))} new, {len(dns_timeline.get('changed_ips', []))} IP changes, {len(dns_timeline.get('removed_records', []))} removed", type="Robtex: DNS Timeline", source="Robtex", confidence="Medium", color="yellow" if dns_timeline.get('changed_ips') else "slate", tags=["dns"]))
        findings.append(make_finding(entity=f"Forward PDNS records: {sum(len(v) if isinstance(v, list) else 0 for v in all_pdns_forward_records.values())}", type="Robtex: Forward PDNS Count", source="Robtex", confidence="Medium", color="slate", tags=["dns"]))

    async def analyze_threat_landscape():
        findings.append(make_finding(entity=f"Threat score: {threat_data.get('threat_score', 0)}/100", type="Robtex: Threat Score", source="Robtex", confidence="Medium", color="red" if threat_data.get('threat_score', 0) > 30 else "emerald", tags=["threat"]))
        findings.append(make_finding(entity=f"Threat sources: {', '.join(threat_data.get('sources', ['None']))}", type="Robtex: Threat Sources", source="Robtex", confidence="Medium", color="slate", tags=["threat"]))
        findings.append(make_finding(entity=f"Reputation: {reputation['level']} ({reputation['score']}/100)", type="Robtex: Reputation Level", source="Robtex", confidence="Medium", color="red" if reputation['score'] >= 40 else "emerald", tags=["threat"]))

    async def analyze_network_scope():
        findings.append(make_finding(entity=f"Target type: {'IP' if is_ip_target else 'Domain'}", type="Robtex: Target Type", source="Robtex", confidence="High", color="slate", tags=["network"]))
        findings.append(make_finding(entity=f"IP address: {ip_to_use or 'N/A'}", type="Robtex: Resolved IP", source="Robtex", confidence="High", color="slate", tags=["network"]))
        findings.append(make_finding(entity=f"ASN: {asn or 'N/A'}", type="Robtex: ASN Identity", source="Robtex", confidence="High", color="orange", tags=["network"]))
        findings.append(make_finding(entity=f"Co-hosted domains: {sum(cg['count'] for cg in cosited_data)}", type="Robtex: Co-Hosted Count", source="Robtex", confidence="Medium", color="orange", tags=["network"]))
        findings.append(make_finding(entity=f"Active DNS entries: {sum(1 for f in findings if f.type == 'Robtex Active DNS')}", type="Robtex: Active DNS Count", source="Robtex", confidence="Medium", color="slate", tags=["network"]))

    async def analyze_intel_coverage():
        dns_cat_count = sum(1 for f in findings if f.type.startswith("Robtex DNS Category"))
        findings.append(make_finding(entity=f"DNS categories: {dns_cat_count}", type="Robtex: DNS Category Count", source="Robtex", confidence="Medium", color="slate", tags=["coverage"]))
        route_count = sum(1 for f in findings if f.type in ("Robtex Route", "Robtex ASN Route"))
        findings.append(make_finding(entity=f"BGP routes: {route_count}", type="Robtex: Route Count", source="Robtex", confidence="Medium", color="slate", tags=["coverage"]))
        threat_count = sum(1 for f in findings if f.type == "Robtex Threat Intelligence")
        findings.append(make_finding(entity=f"Threat intel findings: {threat_count}", type="Robtex: Intel Count", source="Robtex", confidence="Medium", color="slate", tags=["coverage"]))
        findings.append(make_finding(entity=f"Total intelligence findings: {len(findings)}", type="Robtex: Total Findings", source="Robtex", confidence="Medium", color="purple", tags=["coverage"]))

    async def analyze_pdns_detail():
        reverse_count = sum(1 for f in findings if f.type.startswith("Robtex Reverse PDNS"))
        forward_count = sum(1 for f in findings if f.type.startswith("Robtex Forward PDNS"))
        findings.append(make_finding(entity=f"Forward PDNS (unique hosts): {forward_count}", type="Robtex: Forward Host Count", source="Robtex", confidence="Medium", color="slate", tags=["pdns"]))
        findings.append(make_finding(entity=f"Reverse PDNS (unique hosts): {reverse_count}", type="Robtex: Reverse Host Count", source="Robtex", confidence="Medium", color="slate", tags=["pdns"]))

    async def analyze_bgp_routing():
        asn_routes = sum(1 for f in findings if f.type == "Robtex ASN Route")
        sub_prefix = sum(1 for f in findings if f.type == "Robtex ASN Sub-Prefix Alert")
        findings.append(make_finding(entity=f"ASN route prefixes: {asn_routes}", type="Robtex: ASN Route Count", source="Robtex", confidence="Medium", color="slate", tags=["bgp"]))
        findings.append(make_finding(entity=f"Sub-prefix alerts: {sub_prefix}", type="Robtex: Hijack Alerts", source="Robtex", confidence="Medium", color="red" if sub_prefix else "emerald", tags=["bgp"]))

    async def analyze_source_breakdown():
        pas_dns = sum(1 for f in findings if "Passive DNS" in f.type)
        active_dns = sum(1 for f in findings if f.type == "Robtex Active DNS")
        findings.append(make_finding(entity=f"Passive DNS total: {pas_dns}", type="Robtex: Passive DNS Total", source="Robtex", confidence="Medium", color="slate", tags=["sources"]))
        findings.append(make_finding(entity=f"Active DNS total: {active_dns}", type="Robtex: Active DNS Total", source="Robtex", confidence="Medium", color="slate", tags=["sources"]))
        findings.append(make_finding(entity=f"Data sources: Robtex API + web scraping + threat feeds", type="Robtex: Data Sources", source="Robtex", confidence="Medium", color="slate", tags=["sources"]))

    async def analyze_summary_stats():
        findings.append(make_finding(entity=f"Reputation level: {reputation['level']}", type="Robtex: Reputation Category", source="Robtex", confidence="Medium", color="red" if reputation['score'] >= 40 else "emerald", tags=["summary"]))
        findings.append(make_finding(entity=f"Threat sources used: {len(threat_data.get('sources', []))}", type="Robtex: Threat Source Count", source="Robtex", confidence="Medium", color="slate", tags=["summary"]))
        findings.append(make_finding(entity=f"Co-hosted categories: {len(cosited_data)}", type="Robtex: Co-Host Categories", source="Robtex", confidence="Medium", color="slate", tags=["summary"]))

    async def analyze_ioc_indicators():
        findings.append(make_finding(entity=f"Hijack alerts: {sum(1 for f in findings if f.type == 'Robtex ASN Sub-Prefix Alert')}", type="Robtex: BGP Hijack Count", source="Robtex", confidence="Medium", color="red", tags=["ioc"]))
        findings.append(make_finding(entity=f"IP changes detected: {len(dns_timeline.get('changed_ips', []))}", type="Robtex: IP Change Count", source="Robtex", confidence="Medium", color="yellow", tags=["ioc"]))
        findings.append(make_finding(entity=f"Removed DNS records: {len(dns_timeline.get('removed_records', []))}", type="Robtex: Removed Records", source="Robtex", confidence="Medium", color="slate", tags=["ioc"]))
        findings.append(make_finding(entity=f"New DNS records: {len(dns_timeline.get('new_records', []))}", type="Robtex: New Records", source="Robtex", confidence="Medium", color="slate", tags=["ioc"]))

    async def analyze_geo_distribution():
        asn_country = resp_ip_dict.get("country", "") if resp_ip_dict and isinstance(resp_ip_dict, dict) else ""
        findings.append(make_finding(entity=f"ASN country: {asn_country or 'N/A'}", type="Robtex: ASN Country", source="Robtex", confidence="Medium", color="slate", tags=["geo"]))
        findings.append(make_finding(entity=f"Target IP city: {resp_ip_dict.get('city', 'N/A') if resp_ip_dict and isinstance(resp_ip_dict, dict) else 'N/A'}", type="Robtex: IP City", source="Robtex", confidence="Medium", color="slate", tags=["geo"]))
        findings.append(make_finding(entity=f"IP owner: {resp_ip_dict.get('owner', 'N/A')[:100] if resp_ip_dict and isinstance(resp_ip_dict, dict) else 'N/A'}", type="Robtex: IP Owner Name", source="Robtex", confidence="Medium", color="slate", tags=["geo"]))

    async def analyze_cosited_risk():
        findings.append(make_finding(entity=f"Suspicious co-hosted: {sum(cg['count'] for cg in cosited_data if cg['category'] == 'suspicious')}", type="Robtex: Suspicious Co-Host", source="Robtex", confidence="Medium", color="orange", tags=["cosited"]))
        findings.append(make_finding(entity=f"Malicious co-hosted: {sum(cg['count'] for cg in cosited_data if cg['category'] == 'malicious')}", type="Robtex: Malicious Co-Host", source="Robtex", confidence="Medium", color="red", tags=["cosited"]))
        findings.append(make_finding(entity=f"Legitimate co-hosted: {sum(cg['count'] for cg in cosited_data if cg['category'] == 'legitimate')}", type="Robtex: Legitimate Co-Host", source="Robtex", confidence="Medium", color="emerald", tags=["cosited"]))

    async def analyze_scan_summary():
        findings.append(make_finding(entity=f"Total Robtex findings: {len(findings)}", type="Robtex: Final Count", source="Robtex", confidence="Medium", color="purple", tags=["final"]))
        findings.append(make_finding(entity=f"Reputation verdict: {reputation['level']}", type="Robtex: Final Verdict", source="Robtex", confidence="Medium", color="red" if reputation['score'] >= 40 else "emerald", tags=["final"]))
        findings.append(make_finding(entity=f"Robtex data sources: API + web scraping + threat feeds", type="Robtex: Data Sources Detail", source="Robtex", confidence="Medium", color="slate", tags=["final"]))

    await asyncio.gather(
        analyze_dns_health(),
        analyze_threat_landscape(),
        analyze_network_scope(),
        analyze_intel_coverage(),
        analyze_pdns_detail(),
        analyze_bgp_routing(),
        analyze_source_breakdown(),
        analyze_summary_stats(),
        analyze_ioc_indicators(),
        analyze_geo_distribution(),
        analyze_cosited_risk(),
        analyze_scan_summary(),
    )

    return findings
