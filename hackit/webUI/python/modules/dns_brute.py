import asyncio
import dns.resolver
from models import IntelligenceFinding

COMMON_PREFIXES = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "vpn", "cdn",
    "blog", "app", "webmail", "remote", "portal", "ssh", "git", "jenkins",
    "jira", "confluence", "mysql", "db", "ns1", "ns2", "cloud", "test",
    "stage", "demo", "beta", "nginx", "api2", "develop", "prod", "production",
    "smtp", "imap", "pop3", "autodiscover", "m", "mobile", "chat", "forum",
    "help", "support", "docs", "wiki", "status", "tracker", "monitor",
    "dashboard", "analytics", "metrics", "logs", "sync", "static", "assets",
    "media", "img", "upload", "download", "files", "backup", "cpanel",
    "whm", "webmail2", "server", "ns3", "ns4", "www2", "www3",
    "test1", "test2", "dev1", "dev2", "stage1", "stage2",
    "redis", "mongo", "postgres", "elastic", "kibana", "grafana",
    "prometheus", "alertmanager", "consul", "vault", "nomad",
    "k8s", "kubernetes", "docker", "registry", "nexus", "artifactory",
    "travis", "circleci", "gitlab", "bitbucket", "npm", "yarn",
    "lms", "learning", "training", "academy", "campus",
    "erp", "crm", "hr", "payroll", "intranet", "extranet",
    "owa", "exchange", "lync", "skype", "teams", "zoom",
    "radius", "ldap", "kerberos", "ntp", "dhcp", "dns",
    "proxy", "squid", "webproxy", "gateway", "firewall",
    "ws", "wss", "websocket", "socket", "stream",
    "live", "production", "staging2", "qa", "quality",
    "sandbox", "playground", "lab", "experimental",
]

async def crawl(target, client):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    loop = asyncio.get_event_loop()
    seen = set()

    async def check_prefix(p):
        sub = f"{p}.{domain}"
        if sub in seen:
            return None
        seen.add(sub)
        try:
            answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(sub, 'A'))
            if answers:
                ip = str(answers[0])
                return IntelligenceFinding(
                    entity=sub,
                    type="Subdomain (Brute Forced)",
                    source="DNSBrute",
                    confidence="High",
                    color="emerald",
                    category="Network Intelligence",
                    threat_level="Standard Target",
                    status="Live",
                    resolution=ip,
                    raw_data=f"Resolved to {ip} (prefix: {p})"
                )
        except: pass
        return None

    batch_size = 20
    for i in range(0, len(COMMON_PREFIXES), batch_size):
        batch = COMMON_PREFIXES[i:i+batch_size]
        batch_results = await asyncio.gather(*[check_prefix(p) for p in batch])
        for r in batch_results:
            if r:
                findings.append(r)

    wildcard_prefixes = ["*", "all", "any", "wildcard"]
    for wp in wildcard_prefixes:
        try:
            test_sub = f"{wp}-test-{domain[:5]}.{domain}"
            wc = await loop.run_in_executor(None, lambda: dns.resolver.resolve(test_sub, 'A'))
            if wc and not any(f.type == "Wildcard DNS" for f in findings):
                findings.append(IntelligenceFinding(
                    entity=f"*.{domain} (Wildcard DNS detected)",
                    type="Wildcard DNS",
                    source="DNSBrute",
                    confidence="High",
                    color="orange",
                    threat_level="Elevated Risk",
                    raw_data=f"Wildcard DNS resolves random subdomains to {str(wc[0])}"
                ))
                break
        except: pass

    if findings:
        findings.append(IntelligenceFinding(
            entity=f"Total: {len(findings)} live subdomains via brute force",
            type="DNSBrute Summary",
            source="DNSBrute",
            confidence="High",
            color="blue",
            threat_level="Informational",
            raw_data=f"{len(findings)} subdomains found from {len(COMMON_PREFIXES)} common prefixes"
        ))

    return findings
