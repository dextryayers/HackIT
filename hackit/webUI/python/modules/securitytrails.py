import httpx
import re
from urllib.parse import urlparse
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

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
ST_HISTORY_ENDPOINT = f"{ST_API_BASE}/domain/{{domain}}/dns/history"

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

SUBDOMAIN_CATEGORIES = {
    r"\b(admin|administrator)\b": "Administrative",
    r"\b(api|rest|graphql|endpoint|service)\b": "API",
    r"\b(dev|develop|staging|stage|test|testing|qa|uat)\b": "Development",
    r"\b(mail|email|webmail|smtp|imap|pop3|exchange|outlook)\b": "Email",
    r"\b(cdn|static|assets|media|img|css|js|fonts|images|upload)\b": "CDN/Static",
    r"\b(blog|news|press|media|article)\b": "Content",
    r"\b(shop|store|cart|checkout|payment|billing|order)\b": "E-Commerce",
    r"\b(forum|community|chat|support|helpdesk|help|ticket)\b": "Support",
    r"\b(login|signin|register|auth|oauth|sso)\b": "Authentication",
    r"\b(monitor|status|health|uptime|alerts|logs)\b": "Monitoring",
    r"\b(vpn|remote|access|gateway|tunnel|proxy)\b": "Remote Access",
    r"\b(files|docs|document|wiki|kb|knowledgebase)\b": "Documentation",
}


async def _st_api_get(endpoint: str, client: httpx.AsyncClient, params: dict = None) -> dict | None:
    try:
        resp = await safe_fetch(client, endpoint, params=params, timeout=15.0,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


async def _resolve_ip(hostname: str) -> str | None:
    try:
        return resolve_ip(hostname)
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


def _classify_subdomain(subdomain: str) -> str:
    sub_lower = subdomain.split(".")[0].lower()
    for pattern, category in SUBDOMAIN_CATEGORIES.items():
        if re.search(pattern, sub_lower):
            return category
    return "General/Uncategorized"


async def _check_http_service(hostname: str, client: httpx.AsyncClient) -> tuple:
    for proto in ["https", "http"]:
        try:
            resp = await safe_fetch(client, f"{proto}://{hostname}", timeout=8.0,
                headers={"User-Agent": USER_AGENT}, follow_redirects=False)
            server = resp.headers.get("server", "")
            title_m = re.search(r'<title[^>]*>(.*?)</title>', resp.text[:5000], re.DOTALL | re.IGNORECASE)
            title = title_m.group(1).strip()[:100] if title_m else ""
            return (resp.status_code, server, title)
        except Exception:
            continue
    return (None, None, None)


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc
    domain = domain.strip().lower()

    if not domain or "." not in domain:
        findings.append(make_finding(
            entity=f"Invalid domain: {target}",
            ftype="SecurityTrails Error",
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
        sub_classification = {}
        for sub in subs[:80]:
            full_domain = f"{sub}.{domain}" if not sub.endswith(f".{domain}") else sub
            ip = await _resolve_ip(full_domain)
            tags = _extract_tags_domain(full_domain)
            sub_class = _classify_subdomain(full_domain)
            sub_classification[sub_class] = sub_classification.get(sub_class, 0) + 1
            findings.append(make_finding(
                entity=full_domain,
                ftype="SecurityTrails Subdomain",
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
            findings.append(make_finding(
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
        for cat, count in sorted(sub_classification.items(), key=lambda x: -x[1])[:5]:
            findings.append(make_finding(
                entity=f"Category '{cat}': {count} subdomains",
                ftype="Subdomain Category",
                source="SecurityTrails",
                confidence="Medium",
                color="purple",
                status="Classified",
                raw_data=f"{cat}: {count}",
                tags=["classification", cat.lower().replace(' ', '-')]
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
                            findings.append(make_finding(
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
            "contact_email": ("WHOIS Contact Email", "orange"),
            "whois_server": ("WHOIS Server", "slate"),
            "status": ("WHOIS Domain Status", "slate"),
        }
        for key, (ftype, color) in whois_mappings.items():
            val = whois_enriched.get(key)
            if val:
                val_str = str(val)[:200] if isinstance(val, str) else ", ".join([str(v)[:100] for v in val[:5]])[:200]
                findings.append(make_finding(
                    entity=val_str,
                    ftype=ftype,
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
                findings.append(make_finding(
                    entity=tag_str,
                    ftype="SecurityTrails Domain Tag",
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
                        findings.append(make_finding(
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
                    assoc_asn = assoc.get("asn", "")
                    if assoc_domain:
                        findings.append(make_finding(
                            entity=str(assoc_domain)[:200],
                            type="SecurityTrails Associated Domain",
                            source="SecurityTrails",
                            confidence="Medium",
                            color="slate",
                            threat_level="Informational",
                            status="Related",
                            resolution=str(assoc_ip)[:100] if assoc_ip else "",
                            raw_data=f"Associated domain: {assoc_domain} related to {domain} (ASN: {assoc_asn})",
                            tags=["associated", "related", "domain"]
                        ))
                        if assoc_asn:
                            findings.append(make_finding(
                                entity=f"ASN: {assoc_asn}",
                                ftype="SecurityTrails ASN Info",
                                source="SecurityTrails",
                                confidence="Medium",
                                color="slate",
                                status="Related",
                                raw_data=f"Associated ASN: {assoc_asn} for {assoc_domain}",
                                tags=["asn", "network", domain.replace('.', '_')]
                            ))

    threat_indicators = _detect_threat_indicators(domain, domain)
    for keyword, label in threat_indicators:
        findings.append(make_finding(
            entity=f"{domain} flagged: {label}",
            ftype="SecurityTrails Threat Indicator",
            source="SecurityTrails",
            confidence="Medium",
            color="red",
            threat_level="Suspicious",
            status="Flagged",
            raw_data=f"Threat keyword '{keyword}' matched for {domain}",
            tags=["threat", keyword, "indicator"]
        ))

    dns_history = await _st_api_get(ST_HISTORY_ENDPOINT.format(domain=domain), client)
    if dns_history and isinstance(dns_history, dict):
        history_types = dns_history.get("records", dns_history.get("history", {}))
        if isinstance(history_types, dict):
            for rtype, hrecords in history_types.items():
                if isinstance(hrecords, list):
                    findings.append(make_finding(
                        entity=f"{len(hrecords)} historical {rtype.upper()} records",
                        type=f"DNS History - {rtype.upper()}",
                        source="SecurityTrails (History)",
                        confidence="High",
                        color="blue",
                        status="Historical",
                        raw_data=f"{rtype.upper()} history: {len(hrecords)} entries",
                        tags=["dns-history", rtype.lower(), "historical"]
                    ))
                    for hrec in hrecords[:5]:
                        if isinstance(hrec, dict):
                            hval = hrec.get("value", hrec.get("ip", hrec.get("data", "")))
                            hdate = hrec.get("first_seen", hrec.get("date", hrec.get("last_seen", "")))
                            if hval:
                                findings.append(make_finding(
                                    entity=str(hval)[:200],
                                    type=f"DNS History - {rtype.upper()} Change",
                                    source="SecurityTrails (History)",
                                    confidence="High",
                                    color="orange",
                                    status="Historical Change",
                                    resolution=hdate[:10] if hdate else "",
                                    raw_data=f"Historical {rtype.upper()}: {hval} ({hdate})",
                                    tags=["dns-history", rtype.lower(), "change"]
                                ))

    sub_list_to_probe = [f"{sub}.{domain}" for sub in subs[:20]] if subs else []
    for s_probe in sub_list_to_probe:
        ip = await _resolve_ip(s_probe)
        if ip:
            try:
                status_code, server, title = await _check_http_service(s_probe, client)
                if status_code:
                    sub_class = _classify_subdomain(s_probe)
                    findings.append(make_finding(
                        entity=f"{s_probe}: HTTP {status_code}",
                        ftype="SecurityTrails HTTP Probe",
                        source="SecurityTrails",
                        confidence="High",
                        color="orange" if status_code < 400 else "slate",
                        threat_level="Informational",
                        status="Active" if status_code < 400 else "Inactive",
                        resolution=ip,
                        raw_data=f"HTTP {status_code} on {s_probe} (Server: {server or 'unknown'}, Title: {title or 'none'})",
                        tags=["http-probe", sub_class.lower().replace(' ', '-'), domain.replace('.', '_')]
                    ))
                    if server:
                        findings.append(make_finding(
                            entity=f"Server: {server}",
                            ftype="SecurityTrails Server Banner",
                            source="SecurityTrails",
                            confidence="Medium",
                            color="slate",
                            status="Detected",
                            resolution=ip,
                            raw_data=f"Server header for {s_probe}: {server}",
                            tags=["server", "banner", domain.replace('.', '_')]
                        ))
            except Exception:
                pass

    if findings:
        type_dist = {}
        for f in findings:
            t = f.type.replace("SecurityTrails ", "")
            type_dist[t] = type_dist.get(t, 0) + 1
        summary_str = "; ".join([f"{k}: {v}" for k, v in sorted(type_dist.items(), key=lambda x: -x[1])[:6]])
        findings.append(make_finding(
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
