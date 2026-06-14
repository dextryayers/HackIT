import httpx
import re
import socket
import asyncio
from models import IntelligenceFinding
from urllib.parse import urlparse

ROBTEX_API = "https://freeapi.robtex.com"
ROBTEX_WEB = "https://www.robtex.com"
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

async def _robtex_get(url: str, client: httpx.AsyncClient, is_json: bool = True) -> dict | list | None:
    try:
        resp = await client.get(url, timeout=15.0,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json" if is_json else "text/html"})
        if resp.status_code == 200:
            if is_json:
                return resp.json()
            return resp.text
    except Exception:
        pass
    return None

async def _resolve_dns(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None

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

def _is_ip(target: str) -> bool:
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target))

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    raw_target = target.strip().lower()
    if raw_target.startswith("http"):
        raw_target = urlparse(raw_target).netloc
    raw_target = raw_target.strip().lower()

    is_ip_target = _is_ip(raw_target)
    target_ip = raw_target if is_ip_target else None
    target_domain = raw_target if not is_ip_target else None

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
                findings.append(IntelligenceFinding(
                    entity=f"Cannot resolve {target_domain} to IP",
                    type="Robtex Resolution Error",
                    source="Robtex",
                    confidence="Low",
                    color="red",
                    threat_level="Informational",
                    status="Failed",
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
                findings.append(IntelligenceFinding(
                    entity=ip,
                    type="Robtex IP Address",
                    source="Robtex",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    status="Confirmed",
                    raw_data=f"Target IP: {ip}",
                    tags=["ip", ip.replace('.', '_')]
                ))
            if asn:
                asn_str = f"AS{asn}" if not str(asn).startswith("AS") else str(asn)
                findings.append(IntelligenceFinding(
                    entity=f"{asn_str} - {as_name[:200]}",
                    type="Robtex ASN",
                    source="Robtex",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    status="Confirmed",
                    resolution=asn_str,
                    raw_data=f"ASN: {asn}, Name: {as_name}, Desc: {as_desc}",
                    tags=["asn", asn_str.replace(':', '_')]
                ))
            if country:
                findings.append(IntelligenceFinding(
                    entity=country,
                    type="Robtex Country",
                    source="Robtex",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    status="GeoLocated",
                    raw_data=f"Country: {country}",
                    tags=["geo", "country"]
                ))
            if city:
                findings.append(IntelligenceFinding(
                    entity=city,
                    type="Robtex City",
                    source="Robtex",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    status="GeoLocated",
                    raw_data=f"City: {city}",
                    tags=["geo", "city"]
                ))
            if owner:
                findings.append(IntelligenceFinding(
                    entity=owner[:200],
                    type="Robtex IP Owner",
                    source="Robtex",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    status="Identified",
                    raw_data=f"Owner: {owner}",
                    tags=["ownership"]
                ))
            for route in routes[:10]:
                route_str = route.get("route", route) if isinstance(route, dict) else str(route)
                findings.append(IntelligenceFinding(
                    entity=str(route_str)[:200],
                    type="Robtex Route",
                    source="Robtex",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    status="Announced",
                    raw_data=f"Route: {route_str}",
                    tags=["route", "bgp"]
                ))
            for active in actives[:15]:
                active_host = active.get("host", "") if isinstance(active, dict) else str(active)
                active_ip = active.get("ip", "") if isinstance(active, dict) else ""
                if active_host:
                    findings.append(IntelligenceFinding(
                        entity=active_host[:200],
                        type="Robtex Active DNS",
                        source="Robtex",
                        confidence="Medium",
                        color="emerald",
                        threat_level="Informational",
                        status="Active",
                        resolution=active_ip,
                        raw_data=f"Active DNS: {active_host} -> {active_ip}",
                        tags=["active_dns", "forward"]
                    ))
            for pdns_entry in passive_dns[:15]:
                pdns_host = pdns_entry.get("host", pdns_entry.get("rrname", "")) if isinstance(pdns_entry, dict) else ""
                pdns_type = pdns_entry.get("type", pdns_entry.get("rtype", "")) if isinstance(pdns_entry, dict) else ""
                pdns_time = pdns_entry.get("time", pdns_entry.get("timestamp", "")) if isinstance(pdns_entry, dict) else ""
                if pdns_host:
                    findings.append(IntelligenceFinding(
                        entity=pdns_host[:200],
                        type=f"Robtex Passive DNS ({pdns_type})",
                        source="Robtex",
                        confidence="High",
                        color="emerald",
                        threat_level="Informational",
                        status="Historical",
                        resolution=ip_to_use,
                        raw_data=f"Passive DNS: {pdns_host} ({pdns_type}) at {pdns_time}",
                        tags=["passive_dns", pdns_type.lower() if pdns_type else "dns"]
                    ))

        if target_domain:
            pdns_forward = await _query_forward_pdns(target_domain, client)
            if pdns_forward and isinstance(pdns_forward, dict):
                for rtype, records in pdns_forward.items():
                    if isinstance(records, list):
                        for rec in records[:10]:
                            if isinstance(rec, dict):
                                host = rec.get("hostname", rec.get("rrname", rec.get("host", "")))
                                rtype_rec = rec.get("type", rec.get("rtype", rtype))
                                time_rec = rec.get("time", rec.get("timestamp", ""))
                                if host:
                                    findings.append(IntelligenceFinding(
                                        entity=host[:200],
                                        type=f"Robtex Forward PDNS ({rtype_rec})",
                                        source="Robtex",
                                        confidence="High",
                                        color="blue",
                                        threat_level="Informational",
                                        status="Historical",
                                        raw_data=f"Forward PDNS: {host} type {rtype_rec} at {time_rec}",
                                        tags=["forward_pdns", "passive_dns", rtype_rec.lower()]
                                    ))

        if ip_to_use:
            pdns_reverse = await _query_reverse_pdns(ip_to_use, client)
            if pdns_reverse and isinstance(pdns_reverse, dict):
                for rtype, records in pdns_reverse.items():
                    if isinstance(records, list):
                        for rec in records[:10]:
                            if isinstance(rec, dict):
                                host = rec.get("hostname", rec.get("rrname", rec.get("host", "")))
                                rtype_rec = rec.get("type", rec.get("rtype", rtype))
                                time_rec = rec.get("time", rec.get("timestamp", ""))
                                if host:
                                    findings.append(IntelligenceFinding(
                                        entity=host[:200],
                                        type=f"Robtex Reverse PDNS ({rtype_rec})",
                                        source="Robtex",
                                        confidence="High",
                                        color="emerald",
                                        threat_level="Informational",
                                        status="Historical",
                                        resolution=ip_to_use,
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
                    findings.append(IntelligenceFinding(
                        entity=str(route_str)[:200],
                        type="Robtex ASN Route",
                        source="Robtex",
                        confidence="High",
                        color="blue",
                        threat_level="Informational",
                        status="Announced",
                        raw_data=f"AS{asn_clean} route: {route_str}",
                        tags=["asn_route", f"as{asn_clean}"]
                    ))
                for ip_entry in asn_ipset[:10]:
                    ip_str = ip_entry.get("ip", ip_entry) if isinstance(ip_entry, dict) else str(ip_entry)
                    findings.append(IntelligenceFinding(
                        entity=str(ip_str)[:200],
                        type="Robtex ASN IP Set",
                        source="Robtex",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        status="Member",
                        raw_data=f"AS{asn_clean} IP: {ip_str}",
                        tags=["asn_ipset", f"as{asn_clean}"]
                    ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"Robtex query error: {str(e)[:100]}",
            type="Robtex Error",
            source="Robtex",
            confidence="Low",
            color="red",
            threat_level="Informational",
            status="Error",
            tags=["error"]
        ))
        return findings

    if findings:
        type_counts = {}
        for f in findings:
            t = f.type
            type_counts[t] = type_counts.get(t, 0) + 1
        summary_data = "; ".join([f"{k}: {v}" for k, v in sorted(type_counts.items(), key=lambda x: -x[1])[:6]])
        rt_str = f"AS{asn}" if asn else "N/A"
        findings.append(IntelligenceFinding(
            entity=f"Robtex scan: {len(findings)} findings for {raw_target}",
            type="Robtex Summary",
            source="Robtex",
            confidence="High",
            color="purple",
            threat_level="Informational",
            status="Complete",
            resolution=str(ip_to_use or ""),
            raw_data=summary_data,
            tags=["summary", "robtex", raw_target.replace('.', '_')]
        ))

    return findings
