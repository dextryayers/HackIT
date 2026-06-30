import httpx
import re
import socket
import asyncio
from models import IntelligenceFinding
from urllib.parse import urlparse

RAPIDDNS_BASE = "https://rapiddns.io"
RAPIDDNS_ALT = "https://rapiddns.io"
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV", "CAA"]

SUBDOMAIN_PATTERNS = {
    r"\b(admin|administrator)\b": "Administrative",
    r"\b(api|rest|graphql|endpoint|service)\b": "API",
    r"\b(dev|develop|staging|stage|test|testing|qa|uat|integration)\b": "Development",
    r"\b(mail|email|webmail|smtp|imap|pop3|exchange|outlook)\b": "Email",
    r"\b(cdn|static|assets|media|img|css|js|fonts|images|upload)\b": "CDN/Static Assets",
    r"\b(blog|news|press|media|article)\b": "Blog/Content",
    r"\b(shop|store|cart|checkout|payment|billing|order)\b": "E-Commerce",
    r"\b(forum|community|chat|support|helpdesk|help|ticket)\b": "Community/Support",
    r"\b(login|signin|signup|register|auth|oauth|sso|saml|openid)\b": "Authentication",
    r"\b(monitor|status|health|uptime|alerts|logs|metrics)\b": "Monitoring",
    r"\b(vpn|remote|access|gateway|tunnel|proxy)\b": "Remote Access/VPN",
    r"\b(files|docs|document|wiki|kb|knowledgebase)\b": "Documentation",
    r"\b(jobs|careers|apply|recruit|hr)\b": "HR/Jobs",
    r"\b(investor|ir|shareholder|financial|report)\b": "Investor Relations",
    r"\b(partner|affiliate|reseller|vendor|distributor)\b": "Partners",
    r"\b(m|mobile|app|ios|android|play|itunes)\b": "Mobile",
    r"\b(podcast|radio|stream|video|tv)\b": "Media Streaming",
    r"\b(backup|backup|recovery|disaster|dr|failover)\b": "Backup/DR",
    r"\b(sftp|ftp|ftps|ssh|scp|rsync)\b": "File Transfer",
    r"\b(git|svn|hg|repo|repository|code|jenkins|ci|cd|build)\b": "Development/CI-CD",
}


async def _fetch_page(url: str, client: httpx.AsyncClient, max_retries: int = 2) -> str | None:
    for attempt in range(max_retries):
        try:
            resp = await client.get(url, timeout=15.0,
                headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"})
            if resp.status_code == 200:
                return resp.text
        except Exception:
            if attempt < max_retries - 1:
                await asyncio.sleep(1)
    return None


def _extract_table_rows(html: str, domain: str) -> list[dict]:
    rows = []
    table_pattern = re.compile(r'<tr[^>]*>(.*?)</tr>', re.DOTALL | re.IGNORECASE)
    cell_pattern = re.compile(r'<td[^>]*>(.*?)</td>', re.DOTALL | re.IGNORECASE)
    link_pattern = re.compile(r'<a[^>]*>(.*?)</a>', re.DOTALL | re.IGNORECASE)

    for tr in table_pattern.finditer(html):
        cells = [c.strip() for c in cell_pattern.findall(tr.group(1))]
        if len(cells) >= 2:
            row = {}
            for i, c in enumerate(cells):
                clean = re.sub(r'<[^>]+>', '', c).strip()
                link_m = link_pattern.search(c)
                if link_m:
                    clean = link_m.group(1).strip()
                if i == 0:
                    row["hostname"] = clean
                elif i == 1:
                    row["value"] = clean
                else:
                    row[f"col_{i}"] = clean
            if "hostname" in row:
                rows.append(row)
    return rows


def _extract_subdomains_from_text(text: str, domain: str) -> set:
    escaped = re.escape(domain)
    pattern = re.compile(
        r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + escaped,
        re.IGNORECASE
    )
    found = set()
    for m in pattern.finditer(text):
        sub = m.group(0).lower().strip()
        if sub.endswith(f".{domain}") or sub == domain:
            found.add(sub)
    return found


def _extract_ips(text: str) -> set:
    return set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text))


async def _resolve_dns(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


async def _check_http_service(hostname: str, client: httpx.AsyncClient) -> tuple:
    for proto in ["https", "http"]:
        try:
            resp = await client.get(f"{proto}://{hostname}", timeout=8.0,
                headers={"User-Agent": USER_AGENT}, follow_redirects=False)
            server = resp.headers.get("server", "")
            ctype = resp.headers.get("content-type", "")
            location = resp.headers.get("location", "")
            title_m = re.search(r'<title[^>]*>(.*?)</title>', resp.text[:5000], re.DOTALL | re.IGNORECASE)
            title = title_m.group(1).strip()[:100] if title_m else ""
            return (resp.status_code, server, title, ctype, location)
        except Exception:
            continue
    return (None, None, None, None, None)


def _classify_subdomain(subdomain: str) -> str:
    sub_lower = subdomain.split(".")[0].lower()
    for pattern, category in SUBDOMAIN_PATTERNS.items():
        if re.search(pattern, sub_lower):
            return category
    if len(sub_lower) <= 3:
        return "Short/Prefix"
    return "General/Uncategorized"


async def _check_crtsh_for_comparison(domain: str, client: httpx.AsyncClient) -> set:
    subs = set()
    try:
        resp = await client.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=15.0,
            headers={"User-Agent": USER_AGENT}
        )
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for entry in data:
                    nv = entry.get("name_value", "")
                    for sub in nv.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith("." + domain) and "*" not in sub:
                            subs.add(sub)
    except:
        pass
    return subs


async def _check_securitytrails_for_comparison(domain: str, client: httpx.AsyncClient) -> set:
    subs = set()
    try:
        resp = await client.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            timeout=10.0,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            for sub in data.get("subdomains", []):
                subs.add(f"{sub}.{domain}")
    except:
        pass
    return subs


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc
    domain = domain.strip().lower()

    seen_subs = set()
    source_subs_map = {"rapiddns": set()}

    for record_type in DNS_RECORD_TYPES[:6]:
        url = f"{RAPIDDNS_BASE}/subdomain/{domain}?type={record_type}&full=1"
        html = await _fetch_page(url, client)
        if not html:
            alt_url = f"{RAPIDDNS_ALT}/subdomain/{domain}?type={record_type}"
            html = await _fetch_page(alt_url, client)
            if not html:
                continue
        subs = _extract_subdomains_from_text(html, domain)
        rows = _extract_table_rows(html, domain)

        for sub in subs:
            if sub in seen_subs:
                continue
            seen_subs.add(sub)
            source_subs_map["rapiddns"].add(sub)
            ip = await _resolve_dns(sub)
            sub_class = _classify_subdomain(sub)
            findings.append(IntelligenceFinding(
                entity=sub,
                type=f"RapidDNS {record_type}",
                source="RapidDNS",
                confidence="Medium",
                color="emerald",
                threat_level="Informational",
                status="Resolved" if ip else "Unresolved",
                resolution=ip or "",
                raw_data=f"DNS {record_type} record for {sub}: {ip or 'unresolved'} (Category: {sub_class})",
                tags=["subdomain", record_type.lower(), domain.replace('.', '_'), sub_class.lower().replace('/', '-').replace(' ', '-')]
            ))

        for row in rows[:15]:
            hostname = row.get("hostname", "")
            value = row.get("value", "")
            if hostname and (hostname.endswith(f".{domain}") or hostname == domain) and hostname not in seen_subs:
                seen_subs.add(hostname)
                source_subs_map["rapiddns"].add(hostname)
                sub_class = _classify_subdomain(hostname)
                findings.append(IntelligenceFinding(
                    entity=hostname,
                    type=f"RapidDNS Table {record_type}",
                    source="RapidDNS",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    status="Confirmed",
                    resolution=value,
                    raw_data=f"Table result: {hostname} -> {value}",
                    tags=["subdomain", "table", record_type.lower(), domain.replace('.', '_'), sub_class.lower().replace('/', '-').replace(' ', '-')]
                ))

    sameip_url = f"{RAPIDDNS_BASE}/sameip/{domain}?full=1"
    sameip_html = await _fetch_page(sameip_url, client)
    if sameip_html:
        sameip_subs = _extract_subdomains_from_text(sameip_html, domain)
        ips = _extract_ips(sameip_html)
        for sub in sameip_subs:
            if sub in seen_subs:
                continue
            seen_subs.add(sub)
            source_subs_map["rapiddns"].add(sub)
            ip = await _resolve_dns(sub)
            sub_class = _classify_subdomain(sub)
            findings.append(IntelligenceFinding(
                entity=sub,
                type="RapidDNS SameIP",
                source="RapidDNS",
                confidence="Medium",
                color="blue",
                threat_level="Informational",
                status="Resolved" if ip else "Unresolved",
                resolution=ip or "",
                raw_data=f"SameIP result: {sub} shares IP with {domain}",
                tags=["subdomain", "sameip", domain.replace('.', '_'), sub_class.lower().replace('/', '-').replace(' ', '-')]
            ))
        for ip in ips:
            findings.append(IntelligenceFinding(
                entity=ip,
                type="RapidDNS Related IP",
                source="RapidDNS",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Observed",
                raw_data=f"IP found on sameip page for {domain}",
                tags=["ip", domain.replace('.', '_')]
            ))

    rdns_url = f"{RAPIDDNS_BASE}/reverse/{domain}?full=1"
    rdns_html = await _fetch_page(rdns_url, client)
    if rdns_html:
        rdns_entries = _extract_subdomains_from_text(rdns_html, domain)
        for entry in list(rdns_entries)[:30]:
            if entry in seen_subs:
                continue
            seen_subs.add(entry)
            source_subs_map["rapiddns"].add(entry)
            sub_class = _classify_subdomain(entry)
            findings.append(IntelligenceFinding(
                entity=entry,
                type="RapidDNS Reverse DNS",
                source="RapidDNS",
                confidence="Medium",
                color="purple",
                threat_level="Informational",
                status="Discovered",
                raw_data=f"Reverse DNS lookup for {domain} resolved {entry}",
                tags=["reverse_dns", "rdns", domain.replace('.', '_'), sub_class.lower().replace('/', '-').replace(' ', '-')]
            ))

    dns_history_url = f"{RAPIDDNS_BASE}/dns/{domain}?full=1"
    dns_html = await _fetch_page(dns_history_url, client)
    if dns_html:
        hist_subs = _extract_subdomains_from_text(dns_html, domain)
        for hs in list(hist_subs)[:15]:
            if hs not in seen_subs:
                seen_subs.add(hs)
                source_subs_map["rapiddns"].add(hs)
                findings.append(IntelligenceFinding(
                    entity=hs,
                    type="RapidDNS DNS History",
                    source="RapidDNS",
                    confidence="Low",
                    color="slate",
                    threat_level="Informational",
                    status="Historical",
                    raw_data=f"Historical DNS record from RapidDNS for {domain}: {hs}",
                    tags=["dns_history", domain.replace('.', '_')]
                ))

    sub_list = list(seen_subs)[:30]
    for sub in sub_list:
        ip = await _resolve_dns(sub)
        if ip:
            try:
                status_code, server, title, ctype, location = await _check_http_service(sub, client)
                if status_code:
                    findings.append(IntelligenceFinding(
                        entity=f"{sub}:{status_code}",
                        type="RapidDNS HTTP Verify",
                        source="RapidDNS",
                        confidence="High",
                        color="orange" if status_code < 400 else "slate",
                        threat_level="Informational",
                        status="Active" if status_code < 400 else "Inactive",
                        resolution=ip,
                        raw_data=f"HTTP {status_code} on {sub} (Server: {server or 'unknown'})",
                        tags=["http_verify", "live", domain.replace('.', '_')]
                    ))
                    if title:
                        findings.append(IntelligenceFinding(
                            entity=f"Page Title: {title}",
                            type="RapidDNS HTTP Title",
                            source="RapidDNS",
                            confidence="Medium",
                            color="slate",
                            threat_level="Informational",
                            status="Captured",
                            resolution=ip,
                            raw_data=f"Title for {sub}: {title}",
                            tags=["title", domain.replace('.', '_')]
                        ))
                    if server:
                        findings.append(IntelligenceFinding(
                            entity=server[:200],
                            type="RapidDNS Server Banner",
                            source="RapidDNS",
                            confidence="Medium",
                            color="slate",
                            threat_level="Informational",
                            status="Detected",
                            resolution=ip,
                            raw_data=f"Server header for {sub}: {server}",
                            tags=["server", "banner", domain.replace('.', '_')]
                        ))
                    if ctype:
                        findings.append(IntelligenceFinding(
                            entity=f"Content-Type: {ctype}",
                            type="RapidDNS Content Type",
                            source="RapidDNS",
                            confidence="Low",
                            color="slate",
                            status="Detected",
                            raw_data=f"{sub} serves {ctype}",
                            tags=["content-type", domain.replace('.', '_')]
                        ))
            except Exception:
                pass

    crt_subs = await _check_crtsh_for_comparison(domain, client)
    st_subs = await _check_securitytrails_for_comparison(domain, client)

    only_crt = crt_subs - seen_subs
    only_st = st_subs - seen_subs
    both_rapiddns = seen_subs & crt_subs & st_subs

    if only_crt:
        findings.append(IntelligenceFinding(
            entity=f"{len(only_crt)} subdomains found ONLY in crt.sh (not in RapidDNS)",
            type="Source Comparison - crt.sh Exclusive",
            source="RapidDNS",
            confidence="High",
            color="orange",
            threat_level="Informational",
            status="Comparison",
            raw_data=f"Subdomains unique to crt.sh: {', '.join(list(only_crt)[:10])}",
            tags=["comparison", "crtsh", "exclusive"]
        ))
    if only_st:
        findings.append(IntelligenceFinding(
            entity=f"{len(only_st)} subdomains found ONLY in SecurityTrails (not in RapidDNS)",
            type="Source Comparison - SecurityTrails Exclusive",
            source="RapidDNS",
            confidence="High",
            color="orange",
            threat_level="Informational",
            status="Comparison",
            raw_data=f"Subdomains unique to SecurityTrails: {', '.join(list(only_st)[:10])}",
            tags=["comparison", "securitytrails", "exclusive"]
        ))
    if both_rapiddns:
        findings.append(IntelligenceFinding(
            entity=f"{len(both_rapiddns)} subdomains found across ALL sources (RapidDNS + crt.sh + SecurityTrails)",
            type="Source Comparison - Cross-Source Confirmed",
            source="RapidDNS",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            status="Cross-Confirmed",
            raw_data=f"Subdomains in all sources: {len(both_rapiddns)}",
            tags=["comparison", "cross-source", "confirmed"]
        ))

    if seen_subs:
        sub_categories = {}
        for s in seen_subs:
            cat = _classify_subdomain(s)
            sub_categories[cat] = sub_categories.get(cat, 0) + 1
        for cat, count in sorted(sub_categories.items(), key=lambda x: -x[1])[:5]:
            findings.append(IntelligenceFinding(
                entity=f"Subdomain Category: {cat} ({count})",
                type="RapidDNS Subdomain Classification",
                source="RapidDNS",
                confidence="Medium",
                color="purple",
                status="Classified",
                raw_data=f"Category '{cat}' has {count} subdomains",
                tags=["classification", cat.lower().replace('/', '-').replace(' ', '-'), domain.replace('.', '_')]
            ))

    if findings:
        summary_data = [f for f in findings if "RapidDNS" in f.source]
        types_present = {}
        for f in summary_data:
            t = f.type.split("RapidDNS ")[-1] if "RapidDNS " in f.type else f.type
            types_present[t] = types_present.get(t, 0) + 1
        summary_str = ", ".join([f"{k}: {v}" for k, v in sorted(types_present.items(), key=lambda x: -x[1])[:5]])
        findings.append(IntelligenceFinding(
            entity=f"RapidDNS scan: {len(seen_subs)} unique subdomains across {len(summary_data)} findings",
            type="RapidDNS Summary",
            source="RapidDNS",
            confidence="High",
            color="purple",
            threat_level="Informational",
            status="Complete",
            raw_data=summary_str,
            tags=["summary", "rapiddns", domain.replace('.', '_')]
        ))

    return findings
