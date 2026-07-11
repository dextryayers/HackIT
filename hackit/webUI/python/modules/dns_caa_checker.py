import asyncio
import dns.resolver
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

SUBDOMAINS_CAA = [
    "www", "mail", "api", "app", "admin", "blog", "cdn", "dev",
    "staging", "vpn", "smtp", "imap", "pop3", "git", "jenkins",
    "jira", "confluence", "webmail", "remote", "portal", "ssh",
    "ftp", "sftp", "db", "mysql", "redis", "mongo", "kibana",
    "grafana", "prometheus", "k8s", "kubernetes", "docker",
    "registry", "nexus", "artifactory", "gitlab", "bitbucket",
    "aws", "azure", "gcp", "cloud", "auth", "sso", "login",
    "account", "billing", "payment", "checkout", "cart",
    "status", "monitor", "health", "dashboard", "analytics",
    "docs", "wiki", "support", "help", "forum", "community",
    "download", "uploads", "files", "media", "static", "assets",
    "img", "video", "stream", "live", "tv", "radio", "news",
    "blog", "shop", "store", "market", "event", "tickets",
    "test", "beta", "alpha", "preview", "demo", "sandbox",
    "stage", "dev1", "dev2", "qa", "uat", "loadtest",
    "ns1", "ns2", "ns3", "mx1", "mx2", "mail1", "mail2",
    "sip", "voip", "phone", "chat", "meet", "zoom",
    "calendar", "drive", "docs", "sheets", "slides",
    "forms", "sites", "groups", "admin-console",
    "manager", "management", "operation", "operations",
    "recovery", "backup", "restore", "snapshot", "archive",
    "search", "crawl", "spider", "bot", "agent",
    "sync", "transfer", "import", "export", "migrate",
    "proxy", "relay", "gateway", "router", "hub",
    "harvester", "collector", "aggregator", "feed",
    "cdr", "report", "billing", "invoice", "receipt",
    "training", "learn", "academy", "course", "classroom",
    "career", "job", "apply", "hr", "employee", "staff",
    "partner", "vendor", "supplier", "reseller", "distributor",
    "global", "local", "europe", "asia", "america", "africa",
    "us", "uk", "eu", "asia", "china", "india", "japan",
    "de", "fr", "es", "it", "nl", "se", "no", "dk", "fi",
    "br", "mx", "ar", "cl", "co", "au", "nz", "sg",
]

KNOWN_CAS = [
    "letsencrypt.org", "amazon.com", "digicert.com", "comodoca.com",
    "sectigo.com", "godaddy.com", "globalsign.com", "entrust.net",
    "geotrust.com", "thawte.com", "rapidssl.com", "symantec.com",
    "verisign.com", "buypass.com", "ssl.com", "network-solutions.com",
    "namecheap.com", "ssls.com", "zerossl.com", "ssltrust.com.au",
    "certum.pl", "pki.goog", "google.com", "microsoft.com",
    "cisco.com", "cloudflare.com", "akamai.com", "cdn77.com",
    "stackpath.com", "keycdn.com", "bunnycdn.com", "ovh.com",
    "gandi.net", "iwantmyname.com", "hover.com", "dynadot.com",
    "porkbun.com", "namesilo.com", "internetbs.net", "epik.com",
    "cloudns.net", "dnsimple.com", "ns1.com", "route53.com",
]

async def get_caa(domain: str):
    loop = asyncio.get_event_loop()
    try:
        answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'CAA'))
        return list(answers)
    except:
        return []

async def crawl(target: str, client=None):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    seen_cas = set()
    seen_iodef = set()
    caa_configured = False
    total_subdomains = 0
    caa_subdomains = 0

    domains_to_check = [domain] + [f"{s}.{domain}" for s in SUBDOMAINS_CAA]

    batch_size = 30
    for i in range(0, len(domains_to_check), batch_size):
        batch = domains_to_check[i:i+batch_size]
        tasks = [get_caa(d) for d in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for d, records in zip(batch, results):
            total_subdomains += 1
            if isinstance(records, list) and records:
                caa_subdomains += 1
                caa_configured = True
                for r in records:
                    tag = getattr(r, 'tag', '').lower()
                    value = getattr(r, 'value', '')
                    flags = getattr(r, 'flags', 0)
                    if tag == 'issue' and value:
                        seen_cas.add(value.strip('"'))
                        findings.append(make_finding(
                            entity=f"{d}: issue \"{value.strip(chr(34))}\"",
                            type="CAA Issue Permission",
                            source="DNS CAA Checker",
                            confidence="High",
                            color="emerald",
                            threat_level="Informational",
                            status="CAA Configured",
                            resolution=d,
                            raw_data=f"CAA tag=issue, value={value}, flags={flags}",
                            tags=["caa", "issue", "certificate"]
                        ))
                    elif tag == 'issuewild' and value:
                        seen_cas.add(value.strip('"'))
                        findings.append(make_finding(
                            entity=f"{d}: issuewild \"{value.strip(chr(34))}\"",
                            type="CAA Wildcard Permission",
                            source="DNS CAA Checker",
                            confidence="High",
                            color="purple",
                            threat_level="Informational",
                            status="Wildcard CAA",
                            resolution=d,
                            raw_data=f"CAA tag=issuewild, value={value}, flags={flags}",
                            tags=["caa", "issuewild", "wildcard"]
                        ))
                    elif tag == 'iodef' and value:
                        seen_iodef.add(value.strip('"'))
                        findings.append(make_finding(
                            entity=f"{d}: iodef \"{value.strip(chr(34))}\"",
                            type="CAA iodef Report URI",
                            source="DNS CAA Checker",
                            confidence="High",
                            color="blue",
                            threat_level="Informational",
                            status="iodef Configured",
                            resolution=d,
                            raw_data=f"CAA tag=iodef, value={value}, flags={flags}",
                            tags=["caa", "iodef", "reporting"]
                        ))

    root_caa = await get_caa(domain)
    if not root_caa:
        findings.append(make_finding(
            entity=f"No CAA records for {domain}",
            ftype="CAA Record Missing",
            source="DNS CAA Checker",
            confidence="High",
            color="orange",
            threat_level="Standard Target",
            status="No CAA",
            raw_data="Any CA can issue certificates for this domain",
            tags=["caa", "missing"]
        ))

    if seen_cas:
        authorized = [c for c in seen_cas if any(kc.lower() in c.lower() for kc in KNOWN_CAS)]
        unknown = [c for c in seen_cas if c not in authorized]
        findings.append(make_finding(
            entity=f"Authorized CAs: {', '.join(sorted(seen_cas))}",
            type="CAA Authorized CA Summary",
            source="DNS CAA Checker",
            confidence="High",
            color="blue",
            threat_level="Informational",
            status="CAs Identified",
            raw_data=f"Total CAs: {len(seen_cas)} | Known: {len(authorized)} | Unknown: {len(unknown)}",
            tags=["caa", "cas", "authorized"]
        ))
        if unknown:
            findings.append(make_finding(
                entity=f"Unknown/uncommon CAs: {', '.join(unknown)}",
                type="CAA Unknown CA Alert",
                source="DNS CAA Checker",
                confidence="Medium",
                color="orange",
                threat_level="Standard Target",
                status="Unknown CA",
                tags=["caa", "unknown-ca"]
            ))

    if seen_iodef:
        findings.append(make_finding(
            entity=f"iodef reporting to: {', '.join(seen_iodef)}",
            type="CAA iodef Reporting",
            source="DNS CAA Checker",
            confidence="High",
            color="blue",
            threat_level="Informational",
            status="Reporting Configured",
            tags=["caa", "iodef"]
        ))

    wildcard_subdomains = [d for d in SUBDOMAINS_CAA if d == '*' or any(c in d for c in '*')]
    issuewild_found = any(
        str(f.entity).startswith(f"{s}.{domain}") and 'issuewild' in f.type
        for s in SUBDOMAINS_CAA for f in findings
    )
    if not issuewild_found:
        findings.append(make_finding(
            entity=f"No issuewild CAA records for wildcard domains",
            ftype="CAA Wildcard Compliance",
            source="DNS CAA Checker",
            confidence="Medium",
            color="orange",
            threat_level="Standard Target",
            status="No Wildcard CAA",
            raw_data="Without issuewild, CAA policy for wildcard certs is undefined",
            tags=["caa", "wildcard", "compliance"]
        ))

    findings.append(make_finding(
        entity=f"Scanned {total_subdomains} subdomains, {caa_subdomains} have CAA records",
        ftype="CAA Scan Summary",
        source="DNS CAA Checker",
        confidence="High",
        color="purple",
        threat_level="Informational",
        status="Complete",
        raw_data=f"Total: {total_subdomains} | CAA Found: {caa_subdomains} | Authorized CAs: {', '.join(sorted(seen_cas)) if seen_cas else 'None'}",
        tags=["caa", "summary"]
    ))

    return findings
