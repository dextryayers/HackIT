import asyncio
import dns.resolver
import httpx
import re
import json
from urllib.parse import urlparse
from models import IntelligenceFinding

ADDITIONAL_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "vpn", "cdn",
    "blog", "app", "webmail", "remote", "portal", "ssh", "git",
    "jenkins", "jira", "confluence", "mysql", "db", "ns1", "ns2",
    "cloud", "test", "stage", "demo", "beta", "smtp", "imap", "pop3",
    "autodiscover", "m", "mobile", "chat", "forum", "help", "support",
    "docs", "wiki", "status", "tracker", "monitor", "dashboard",
    "analytics", "metrics", "logs", "sync", "static", "assets",
    "media", "img", "upload", "download", "files", "backup", "cpanel",
    "server", "redis", "mongo", "postgres", "elastic", "kibana",
    "grafana", "prometheus", "docker", "registry", "nexus",
    "artifactory", "gitlab", "bitbucket", "owa", "exchange",
    "sharepoint", "slack", "teams", "zoom", "vpns", "proxy",
    "gateway", "firewall", "waf", "load", "lb", "balancer",
    "auth", "login", "sso", "oauth", "signin",
    "data", "database", "search", "notification",
    "stream", "video", "audio", "deploy",
    "monitoring", "alert", "alarm", "health",
    "pay", "payment", "billing", "invoice",
    "support", "helpdesk", "knowledgebase", "kb",
    "partner", "partners", "vendor", "vendors",
    "internal", "external", "corp", "corporate",
    "us", "uk", "eu", "asia", "china", "india", "japan",
    "nyc", "london", "paris", "tokyo", "dubai",
    "sg", "hk", "au", "de", "fr", "br", "mx",
]

async def resolve_a(host: str):
    loop = asyncio.get_event_loop()
    try:
        answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(host, 'A'))
        return [str(r) for r in answers]
    except:
        return []

async def resolve_cname(host: str):
    loop = asyncio.get_event_loop()
    try:
        answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(host, 'CNAME'))
        return str(answers[0]).rstrip('.')
    except:
        return ""

async def crtsh_search(domain: str, client: httpx.AsyncClient):
    try:
        resp = await client.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15.0)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for entry in data:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n.endswith(domain) and n != domain:
                        subs.add(n)
            return list(subs)[:100]
    except: pass
    return []

async def resolv(host: str):
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, lambda: dns.resolver.resolve(host, 'A'))
        return True
    except:
        return False

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    initial_subs = set()
    crtsh_results = await crtsh_search(domain, client)
    for sub in crtsh_results:
        sub_clean = sub.lstrip('.').lstrip('*').strip()
        if sub_clean.endswith(domain) and sub_clean != domain:
            initial_subs.add(sub_clean)

    batch_size = 50
    for i in range(0, len(ADDITIONAL_WORDLIST), batch_size):
        batch = ADDITIONAL_WORDLIST[i:i+batch_size]
        tasks = [resolv(f"{w}.{domain}") for w in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for word, ok in zip(batch, results):
            if isinstance(ok, bool) and ok:
                initial_subs.add(f"{word}.{domain}")

    discovered_tree = {}
    all_discovered = set(initial_subs)
    queue = list(initial_subs)[:20]

    depth = 0
    while queue and depth < 3:
        depth += 1
        current_level = list(queue)
        queue = []
        for parent_sub in current_level:
            parent_short = parent_sub.replace(f".{domain}", "")
            child_subs = set()
            for word in ADDITIONAL_WORDLIST[:30]:
                child_host = f"{word}.{parent_sub}"
                if child_host not in all_discovered:
                    ok = await resolv(child_host)
                    if ok:
                        child_subs.add(child_host)
                        all_discovered.add(child_host)
                        queue.append(child_host)
            if child_subs:
                discovered_tree[parent_sub] = list(child_subs)

    for sub in sorted(initial_subs)[:30]:
        ips = await resolve_a(sub)
        cname = await resolve_cname(sub)
        findings.append(IntelligenceFinding(
            entity=sub,
            type="Discovered Subdomain",
            source="Subdomain Recursive",
            confidence="High",
            color="blue" if ips else "slate",
            threat_level="Informational",
            status="Active" if ips else "No A",
            resolution=', '.join(ips[:3]) if ips else "",
            raw_data=f"IPs: {', '.join(ips[:3]) if ips else 'N/A'} | CNAME: {cname if cname else 'N/A'}",
            tags=["subdomain", "discovered"]
        ))

    for parent, children in discovered_tree.items():
        findings.append(IntelligenceFinding(
            entity=f"{parent} -> {len(children)} sub-subdomains: {', '.join(children[:5])}",
            type="Recursive Subdomain Node",
            source="Subdomain Recursive",
            confidence="Medium",
            color="purple",
            threat_level="Informational",
            status=f"Depth {depth}",
            raw_data=f"Parent: {parent} | Children: {', '.join(children[:10])}",
            tags=["subdomain", "recursive"]
        ))

    if initial_subs:
        cname_chains = []
        for sub in list(initial_subs)[:10]:
            ips = await resolve_a(sub)
            cname = await resolve_cname(sub)
            if cname:
                cname_chains.append(f"{sub} -> {cname}")
        if cname_chains:
            findings.append(IntelligenceFinding(
                entity="CNAME chains: " + " | ".join(cname_chains[:5]),
                type="Subdomain CNAME Chain",
                source="Subdomain Recursive",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status="CNAME Found",
                tags=["subdomain", "cname", "chain"]
            ))

        sub_depth_tree = {}
        for sub in all_discovered:
            parts = sub.replace(f".{domain}", "").split(".")
            depth_count = len(parts)
            if depth_count not in sub_depth_tree:
                sub_depth_tree[depth_count] = []
            sub_depth_tree[depth_count].append(sub)

        for d, subs in sorted(sub_depth_tree.items()):
            findings.append(IntelligenceFinding(
                entity=f"Depth {d}: {len(subs)} subdomains (e.g., {', '.join(s[:3] for s in subs[:3])})",
                type="Subdomain Depth Analysis",
                source="Subdomain Recursive",
                confidence="High",
                color="blue",
                threat_level="Informational",
                status=f"Depth {d}",
                tags=["subdomain", "depth"]
            ))

    findings.append(IntelligenceFinding(
        entity=f"Recursive scan: {len(all_discovered)} subdomains found across {depth} depth levels",
        type="Recursive Subdomain Summary",
        source="Subdomain Recursive",
        confidence="High",
        color="blue",
        threat_level="Informational",
        status=f"{len(all_discovered)} Subdomains",
        raw_data=f"Initial: {len(initial_subs)} | Recursive levels: {depth} | Total unique: {len(all_discovered)}",
        tags=["subdomain", "summary", "recursive"]
    ))

    return findings
