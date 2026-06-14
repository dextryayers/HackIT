import httpx
import re
import socket
import asyncio
from models import IntelligenceFinding
from urllib.parse import urlparse

ST_API_BASE = "https://api.securitytrails.com/v1"
ST_SUBDOMAIN_ENDPOINT = f"{ST_API_BASE}/domain/{{domain}}/subdomains"
ST_DNS_ENDPOINT = f"{ST_API_BASE}/domain/{{domain}}/dns"
ST_WHOIS_ENDPOINT = f"{ST_API_BASE}/domain/{{domain}}/whois"
ST_TAGS_ENDPOINT = f"{ST_API_BASE}/domain/{{domain}}/tags"
ST_NEIGHBORS_ENDPOINT = f"{ST_API_BASE}/domain/{{domain}}/neighbors"
ST_ASSOCIATED_ENDPOINT = f"{ST_API_BASE}/domain/{{domain}}/associated"
ST_PING_ENDPOINT = f"{ST_API_BASE}/ping"
ST_FEEDS_ENDPOINT = f"{ST_API_BASE}/feeds/domains"
ST_USAGE_ENDPOINT = f"{ST_API_BASE}/account/usage"

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

THREAT_KEYWORDS = {
    "malware": "Malware Associated",
    "phishing": "Phishing Associated",
    "suspicious": "Suspicious Activity",
    "attack": "Attack Vector",
    "botnet": "Botnet Infrastructure",
    "c2": "C2 Server",
    "ransomware": "Ransomware Related",
    "exploit": "Exploit Kit Related",
    "spam": "Spam Related",
    "scanning": "Scanning Activity",
}

async def _st_api_get(endpoint: str, client: httpx.AsyncClient, params: dict = None) -> dict | None:
    try:
        resp = await client.get(endpoint, params=params, timeout=15.0,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None

async def _resolve_ip(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None

def _detect_threat_indicators(text: str, entity: str) -> list[tuple[str, str]]:
    indicators = []
    for keyword, label in THREAT_KEYWORDS.items():
        if keyword in text.lower() or keyword in entity.lower():
            indicators.append((keyword, label))
    return indicators

def _extract_tags_domain(domain: str) -> list[str]:
    tags = []
    tld = domain.split(".")[-1] if "." in domain else ""
    risky_tlds = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "date", "men", "loan"}
    if tld in risky_tlds:
        tags.append("risky_tld")
    if re.search(r'\d{4}', domain):
        tags.append("contains_year")
    subdepth = domain.count(".") - 1
    if subdepth >= 3:
        tags.append("deep_subdomain")
    return tags

async def _enrich_whois(whois_data: dict, client: httpx.AsyncClient) -> dict:
    enriched = {}
    if isinstance(whois_data, dict):
        for key in ["registrar", "registrant_name", "registrant_organization", "registrant_email",
                     "registrant_country", "creation_date", "expiration_date", "updated_date",
                     "name_servers", "whois_server", "contact_email", "abuse_email", "status"]:
            val = whois_data.get(key, whois_data.get(key.lower(), whois_data.get(key.upper(), "")))
            if val:
                enriched[key] = val
    return enriched

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc
    domain = domain.strip().lower()

    if not domain or "." not in domain:
        findings.append(IntelligenceFinding(
            entity=f"Invalid domain: {target}",
            type="SecurityTrails Error",
            source="SecurityTrails",
            confidence="Low",
            color="red",
            threat_level="Informational",
            status="Invalid",
            tags=["error"]
        ))
        return findings

    subdomain_data = await _st_api_get(ST_SUBDOMAIN_ENDPOINT.format(domain=domain), client)
    if subdomain_data and isinstance(subdomain_data, dict):
        subs = subdomain_data.get("subdomains", [])
        for sub in subs[:80]:
            full_domain = f"{sub}.{domain}" if not sub.endswith(f".{domain}") else sub
            ip = await _resolve_ip(full_domain)
            tags = _extract_tags_domain(full_domain)
            findings.append(IntelligenceFinding(
                entity=full_domain,
                type="SecurityTrails Subdomain",
                source="SecurityTrails",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                status="Resolved" if ip else "Unresolved",
                resolution=ip or "",
                raw_data=f"Subdomain: {full_domain} {'-> ' + ip if ip else ''}",
                tags=["subdomain"] + tags
            ))
        if subs:
            findings.append(IntelligenceFinding(
                entity=f"{len(subs)} subdomains via SecurityTrails",
                type="SecurityTrails Subdomain Summary",
                source="SecurityTrails",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status="Complete",
                raw_data=f"Subdomains found: {len(subs)}",
                tags=["summary", "subdomain_count"]
            ))

    dns_data = await _st_api_get(ST_DNS_ENDPOINT.format(domain=domain), client)
    if dns_data and isinstance(dns_data, dict):
        record_types = {
            "a": "A", "aaaa": "AAAA", "mx": "MX", "ns": "NS",
            "txt": "TXT", "soa": "SOA", "cname": "CNAME",
            "ptr": "PTR", "srv": "SRV", "caa": "CAA"
        }
        for api_key, display_key in record_types.items():
            records = dns_data.get(api_key, dns_data.get(api_key.upper(), []))
            if isinstance(records, dict):
                records = records.get("records", [])
            if isinstance(records, list):
                for rec in records[:8]:
                    if isinstance(rec, dict):
                        host = rec.get("hostname", rec.get("host", rec.get("id", "")))
                        value = rec.get("value", rec.get("target", rec.get("ip", "")))
                        ttl = rec.get("ttl", "")
                        if value:
                            findings.append(IntelligenceFinding(
                                entity=str(value)[:200],
                                type=f"SecurityTrails DNS {display_key}",
                                source="SecurityTrails",
                                confidence="High",
                                color="blue",
                                threat_level="Informational",
                                status="Confirmed",
                                resolution=str(host)[:200] if host else "",
                                raw_data=f"DNS {display_key}: {host or domain} -> {value} (TTL: {ttl})",
                                tags=["dns", display_key.lower(), domain.replace('.', '_')]
                            ))

    whois_data = await _st_api_get(ST_WHOIS_ENDPOINT.format(domain=domain), client)
    if whois_data and isinstance(whois_data, dict):
        whois_enriched = await _enrich_whois(whois_data, client)
        whois_mappings = {
            "registrar": ("WHOIS Registrar", "slate"),
            "registrant_organization": ("WHOIS Organization", "slate"),
            "registrant_name": ("WHOIS Registrant Name", "slate"),
            "registrant_email": ("WHOIS Email", "orange"),
            "registrant_country": ("WHOIS Country", "slate"),
            "creation_date": ("WHOIS Creation Date", "emerald"),
            "expiration_date": ("WHOIS Expiration Date", "emerald"),
            "updated_date": ("WHOIS Updated Date", "slate"),
            "name_servers": ("WHOIS Nameservers", "blue"),
            "abuse_email": ("WHOIS Abuse Email", "orange"),
            "status": ("WHOIS Domain Status", "slate"),
        }
        for key, (ftype, color) in whois_mappings.items():
            val = whois_enriched.get(key)
            if val:
                val_str = str(val)[:200] if isinstance(val, str) else ", ".join([str(v)[:100] for v in val[:5]])[:200]
                findings.append(IntelligenceFinding(
                    entity=val_str,
                    type=ftype,
                    source="SecurityTrails",
                    confidence="High",
                    color=color,
                    threat_level="Informational",
                    status="Confirmed",
                    raw_data=f"WHOIS {key}: {val_str}",
                    tags=["whois", key, domain.replace('.', '_')]
                ))

    tags_data = await _st_api_get(ST_TAGS_ENDPOINT.format(domain=domain), client)
    if tags_data and isinstance(tags_data, dict):
        tags_list = tags_data.get("tags", [])
        if isinstance(tags_list, list):
            for tag in tags_list[:15]:
                tag_str = str(tag)[:100]
                threat_label = "Informational"
                threat_color = "slate"
                for keyword, label in THREAT_KEYWORDS.items():
                    if keyword in tag_str.lower():
                        threat_label = "Suspicious"
                        threat_color = "orange"
                        break
                findings.append(IntelligenceFinding(
                    entity=tag_str,
                    type="SecurityTrails Domain Tag",
                    source="SecurityTrails",
                    confidence="Medium",
                    color=threat_color,
                    threat_level=threat_label,
                    status="Categorized",
                    raw_data=f"Tag: {tag_str}",
                    tags=["tag", tag_str.lower().replace(' ', '_')]
                ))

    neighbors_data = await _st_api_get(ST_NEIGHBORS_ENDPOINT.format(domain=domain), client)
    if neighbors_data and isinstance(neighbors_data, dict):
        neighbors = neighbors_data.get("neighbors", neighbors_data.get("records", []))
        if isinstance(neighbors, list):
            for neighbor in neighbors[:10]:
                if isinstance(neighbor, dict):
                    nb_host = neighbor.get("hostname", neighbor.get("host", neighbor.get("ip", "")))
                    nb_ip = neighbor.get("ip", neighbor.get("value", ""))
                    if nb_host:
                        findings.append(IntelligenceFinding(
                            entity=str(nb_host)[:200],
                            type="SecurityTrails IP Neighbor",
                            source="SecurityTrails",
                            confidence="Medium",
                            color="blue",
                            threat_level="Informational",
                            status="Related",
                            resolution=str(nb_ip)[:100],
                            raw_data=f"IP Neighbor: {nb_host} shares IP space with {domain}",
                            tags=["neighbor", "related"]
                        ))

    associated_data = await _st_api_get(ST_ASSOCIATED_ENDPOINT.format(domain=domain), client)
    if associated_data and isinstance(associated_data, dict):
        associated = associated_data.get("associated", associated_data.get("records", associated_data.get("domains", [])))
        if isinstance(associated, list):
            for assoc in associated[:10]:
                if isinstance(assoc, dict):
                    assoc_domain = assoc.get("domain", assoc.get("hostname", assoc.get("host", "")))
                    assoc_ip = assoc.get("ip", "")
                    if assoc_domain:
                        findings.append(IntelligenceFinding(
                            entity=str(assoc_domain)[:200],
                            type="SecurityTrails Associated Domain",
                            source="SecurityTrails",
                            confidence="Medium",
                            color="slate",
                            threat_level="Informational",
                            status="Related",
                            resolution=str(assoc_ip)[:100] if assoc_ip else "",
                            raw_data=f"Associated domain: {assoc_domain} related to {domain}",
                            tags=["associated", "related", "domain"]
                        ))

    threat_indicators = _detect_threat_indicators(domain, domain)
    for keyword, label in threat_indicators:
        findings.append(IntelligenceFinding(
            entity=f"{domain} flagged: {label}",
            type="SecurityTrails Threat Indicator",
            source="SecurityTrails",
            confidence="Medium",
            color="red",
            threat_level="Suspicious",
            status="Flagged",
            raw_data=f"Threat keyword '{keyword}' matched for {domain}",
            tags=["threat", keyword, "indicator"]
        ))

    if findings:
        type_dist = {}
        for f in findings:
            t = f.type.replace("SecurityTrails ", "")
            type_dist[t] = type_dist.get(t, 0) + 1
        summary_str = "; ".join([f"{k}: {v}" for k, v in sorted(type_dist.items(), key=lambda x: -x[1])[:6]])
        findings.append(IntelligenceFinding(
            entity=f"SecurityTrails scan: {len(findings)} findings for {domain}",
            type="SecurityTrails Summary",
            source="SecurityTrails",
            confidence="High",
            color="purple",
            threat_level="Informational",
            status="Complete",
            raw_data=summary_str,
            tags=["summary", domain.replace('.', '_')]
        ))

    return findings
