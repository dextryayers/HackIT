import asyncio
import dns.resolver
import httpx
from models import IntelligenceFinding

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "vpn", "cdn",
    "blog", "app", "webmail", "remote", "portal", "ssh", "git", "jenkins",
    "jira", "confluence", "mysql", "db", "ns1", "ns2", "cloud", "test",
    "stage", "demo", "beta", "nginx", "smtp", "imap", "pop3",
    "autodiscover", "m", "mobile", "chat", "forum", "help", "support",
    "docs", "wiki", "status", "tracker", "monitor", "dashboard",
    "analytics", "metrics", "logs", "sync", "static", "assets",
    "media", "img", "upload", "download", "files", "backup", "cpanel",
    "whm", "server", "redis", "mongo", "postgres", "elastic",
    "kibana", "grafana", "prometheus", "alertmanager", "consul",
    "k8s", "kubernetes", "docker", "registry", "nexus", "artifactory",
    "gitlab", "bitbucket", "npm", "lms", "erp", "crm", "hr",
    "owa", "exchange", "lync", "skype", "teams", "zoom",
    "radius", "ldap", "kerberos", "ntp", "dhcp", "dns",
    "proxy", "squid", "webproxy", "gateway", "firewall",
    "ws", "wss", "websocket", "socket", "stream",
    "mx", "mail2", "mail1", "email", "sip", "voip",
    "auth", "login", "signin", "register", "sso", "oauth",
    "password", "reset", "account", "profile", "settings",
    "admin-console", "admin-panel", "manage", "management",
    "oracle", "sap", "salesforce", "zendesk", "servicenow",
    "sharepoint", "slack", "discord", "office", "office365",
    "outlook", "calendar", "drive", "hq", "headquarters",
    "us", "uk", "eu", "asia", "china", "japan", "india",
    "data", "database", "db1", "db2", "db3",
    "search", "solr", "lucene", "sphinx", "algolia",
    "notification", "notify", "alert", "alarm",
    "streaming", "video", "audio", "media-server",
    "load", "load-balancer", "lb", "balancer",
    "health", "healthcheck", "heartbeat",
    "monitoring", "watchdog", "sentry",
    "inventory", "asset", "cmdb", "discovery",
    "deploy", "deployment", "release", "rollback", "canary",
    "blue", "green", "bluegreen", "feature", "flag",
    "compliance", "audit", "risk", "control",
    "version", "update", "upgrade", "migrate",
    "batch", "job", "task", "worker", "scheduler",
    "trigger", "hook", "webhook", "callback",
    "cache", "varnish", "memcache",
    "storage", "s3", "bucket", "minio",
    "ssl", "tls", "cert", "certificate", "acme",
    "firewall", "fw", "waf", "ids", "ips",
    "openvpn", "wireguard", "ipsec", "rdp", "citrix",
    "vdi", "vmware", "vcenter", "esxi", "openstack",
    "iaas", "paas", "saas", "serverless", "lambda",
    "ai", "ml", "bot", "chatbot", "gpt", "llm",
    "train", "training", "infer", "inference", "model",
    "pipeline", "ci", "cd", "runner", "actions",
    "graphql", "grpc", "rest", "soap", "xmlrpc",
    "swagger", "openapi", "redoc", "docs-api",
    "stage-api", "dev-api", "test-api", "sandbox-api",
    "preprod", "production", "prod", "dr", "disaster-recovery",
    "primary", "secondary", "main", "backup",
    "node1", "node2", "node3", "worker1", "worker2",
    "master", "slave", "replica", "replication",
    "config", "configuration", "settings", "setup",
    "init", "bootstrap", "start", "stop", "control",
    "panel", "console", "adminpanel", "cp",
    "direct", "directadmin", "plesk", "webmin",
    "phpmyadmin", "phpadmin", "phpmanager",
    "tomcat", "jboss", "wildfly", "glassfish",
    "jetty", "undertow", "weblogic", "websphere",
    "pay", "payment", "checkout", "cart", "shop",
    "order", "orders", "invoice", "billing",
    "subscription", "subscribe", "unsubscribe",
    "newsletter", "news", "mailing", "list",
    "campaign", "marketing", "email-marketing",
    "survey", "poll", "vote", "feedback",
    "ticket", "tickets", "helpdesk", "desk",
    "knowledge", "knowledgebase", "kb", "faq",
    "service", "services", "product", "products",
    "catalog", "catalogue", "listing", "listings",
    "auction", "bid", "bidding", "offer",
    "job", "jobs", "career", "careers", "recruit",
    "resume", "cv", "application", "apply",
    "partner", "partners", "affiliate", "affiliates",
    "vendor", "vendors", "supplier", "suppliers",
    "reseller", "resellers", "distributor", "wholesale",
    "legal", "privacy", "terms", "tos", "gdpr",
    "cookies", "cookie", "consent", "compliance",
    "report", "reports", "audit", "audits",
    "log", "logs", "syslog", "event", "events",
    "debug", "trace", "tracing", "profiling",
    "performance", "benchmark", "loadtest", "stress",
    "exp", "experiment", "experiments", "feature-flag",
    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j",
    "k", "l", "m", "n", "o", "p", "q", "r", "s", "t",
    "u", "v", "w", "x", "y", "z",
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
    "00", "01", "02", "03", "04", "05", "06", "07", "08", "09",
    "10", "11", "12", "20", "21", "22", "50", "100",
    "client", "clients", "customer", "customers",
    "user", "users", "member", "members",
    "agent", "agents", "broker", "brokers",
    "dealer", "dealers", "franchise",
    "internal", "external", "corp", "corporate",
    "office", "offices", "branch", "regional",
    "nyc", "london", "paris", "tokyo", "dubai",
    "sydney", "singapore", "hongkong", "shanghai",
    "frankfurt", "amsterdam", "dublin", "zurich",
    "north", "south", "east", "west",
    "north-america", "south-america", "europe", "apac",
    "emea", "latam", "nam", "anz",
    "edge", "edges", "endpoint", "endpoints",
    "origin", "origins", "source", "sources",
    "mirror", "mirrors", "cache", "caching",
    "accel", "accelerator", "optimizer",
    "compression", "compress", "gzip", "brotli",
    "minify", "minifier", "bundler", "bundle",
    "polyfill", "polyfills", "shim", "shims",
    "recaptcha", "captcha", "turnstile",
    "hcaptcha", "geetest", "funcaptcha",
    "challenge", "verify", "verification",
    "risk", "risk-engine", "fraud", "compliance",
    "kyc", "aml", "sanctions", "screening",
    "identity", "id", "idp", "identity-provider",
    "saml", "saml2", "wsfed", "adfs", "okta",
    "auth0", "keycloak", "fusionauth", "cognito",
    "onelogin", "ping", "pingfederate",
    "jumpcloud", "centrify", "duo",
    "phone", "phones", "sms", "voice", "call",
    "video", "video-call", "conference", "meeting",
    "webinar", "webinars", "live", "live-stream",
    "room", "rooms", "space", "spaces",
    "whiteboard", "board", "collab", "collaboration",
    "threat", "threats", "security", "sec",
    "vulnerability", "vuln", "cve", "advisory",
    "patch", "patches", "hotfix", "update",
    "antivirus", "av", "endpoint-security",
    "dlp", "edr", "xdr", "siem", "soar",
    "soc", "noc", "incident", "response",
    "forensic", "forensics", "investigation",
    "phishing", "malware", "ransomware",
    "sandbox", "sandboxing", "detonation",
    "ioc", "indicators", "threat-intel",
    "feeds", "feed", "ti", "threat-intelligence",
]

SUBCATEGORIES = {
    "dev": ["dev", "staging", "stage", "sandbox", "beta", "alpha", "test", "qa", "uat", "dev1", "dev2", "development", "preprod", "canary"],
    "api": ["api", "api-v1", "api-v2", "graphql", "rest", "swagger", "openapi", "grpc", "soap", "api-docs"],
    "admin": ["admin", "admin-panel", "admin-console", "cp", "panel", "console", "dashboard", "manage", "management"],
    "mail": ["mail", "webmail", "smtp", "imap", "pop3", "email", "mx", "mx1", "mx2", "mail1", "mail2", "autodiscover"],
    "cdn": ["cdn", "static", "assets", "media", "img", "images", "video", "files", "upload", "downloads", "static-assets"],
    "network": ["ns1", "ns2", "ns3", "vpn", "remote", "ssh", "proxy", "gateway", "firewall", "fw", "router"],
    "monitoring": ["monitor", "monitoring", "status", "health", "healthcheck", "heartbeat", "grafana", "kibana", "prometheus", "sentry"],
    "auth": ["auth", "sso", "login", "signin", "oauth", "oauth2", "oidc", "saml", "adfs", "okta", "keycloak"],
    "support": ["help", "support", "docs", "wiki", "knowledgebase", "kb", "faq", "ticket", "tickets", "helpdesk"],
    "storage": ["storage", "s3", "bucket", "backup", "archive", "db", "database", "mysql", "redis", "mongo", "elastic"],
    "ci-cd": ["jenkins", "gitlab", "bitbucket", "ci", "cd", "runner", "actions", "pipeline", "deploy", "deployment"],
    "collab": ["chat", "slack", "discord", "teams", "zoom", "meet", "meeting", "confluence", "wiki", "sharepoint"],
}

async def resolve_sub(domain: str, sub: str):
    loop = asyncio.get_event_loop()
    try:
        fqdn = f"{sub}.{domain}"
        answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(fqdn, 'A'))
        ips = [str(r) for r in answers]
        cname = ""
        try:
            cname_answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(fqdn, 'CNAME'))
            if cname_answers:
                cname = str(cname_answers[0]).rstrip('.')
        except: pass
        return sub, ips, cname
    except:
        return sub, [], ""

async def http_probe(host: str, client: httpx.AsyncClient):
    try:
        resp = await client.get(f"http://{host}", timeout=8.0, follow_redirects=False,
                                headers={"User-Agent": "Mozilla/5.0"})
        return resp.status_code, resp.headers.get("server", ""), resp.headers.get("content-type", "")
    except:
        return 0, "", ""

def categorize_subdomain(sub: str):
    for cat, keywords in SUBCATEGORIES.items():
        if sub in keywords or any(kw == sub for kw in keywords):
            return cat
    if any(c in sub for c in ["-", "."]):
        parts = sub.replace(".", "-").split("-")
        for cat, keywords in SUBCATEGORIES.items():
            if any(kw in parts for kw in keywords):
                return cat
    return "other"

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    resolved_subs = []
    batch_size = 50
    for i in range(0, len(SUBDOMAIN_WORDLIST), batch_size):
        batch = SUBDOMAIN_WORDLIST[i:i+batch_size]
        tasks = [resolve_sub(domain, sub) for sub in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, tuple) and result[1]:
                resolved_subs.append(result)

    wildcard_ips = set()
    for _ in range(5):
        import random
        rand_sub = f"x{random.randint(10000,99999)}y{random.randint(10000,99999)}z"
        _, ips, _ = await resolve_sub(domain, rand_sub)
        if ips:
            wildcard_ips.update(ips)

    subs_to_probe = [item for item in resolved_subs if all(ip not in wildcard_ips for ip in item[1])]
    if not subs_to_probe:
        subs_to_probe = resolved_subs

    for sub, ips, cname in subs_to_probe:
        cat = categorize_subdomain(sub)
        fqdn = f"{sub}.{domain}"
        status_code = 0
        server = ""
        try:
            status_code, server, _ = await http_probe(fqdn, client)
        except: pass

        findings.append(IntelligenceFinding(
            entity=fqdn,
            type=f"Subdomain ({cat})",
            source="Subdomain Brute Force Deep",
            confidence="High",
            color="green" if status_code == 200 else "blue" if status_code else "slate",
            threat_level="Informational",
            status=f"HTTP {status_code}" if status_code else "No HTTP",
            resolution=', '.join(ips[:3]),
            raw_data=f"IPs: {', '.join(ips[:3])} | CNAME: {cname[:100] or 'N/A'} | Server: {server[:50] if server else 'N/A'}",
            tags=["subdomain", cat, f"http-{status_code}" if status_code else "no-http"]
        ))

        if cname:
            findings.append(IntelligenceFinding(
                entity=f"{fqdn} -> CNAME -> {cname}",
                type="Subdomain CNAME Record",
                source="Subdomain Brute Force Deep",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status="CNAME",
                resolution=cname,
                tags=["subdomain", "cname"]
            ))

    if resolved_subs:
        cat_counts = {}
        for sub, _, _ in resolved_subs:
            cat = categorize_subdomain(sub)
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
        cat_summary = " | ".join(f"{cat}: {cnt}" for cat, cnt in sorted(cat_counts.items(), key=lambda x: -x[1]))
        findings.append(IntelligenceFinding(
            entity=f"Resolved {len(resolved_subs)}/{len(SUBDOMAIN_WORDLIST)} subdomains",
            type="Subdomain Brute Force Summary",
            source="Subdomain Brute Force Deep",
            confidence="High",
            color="blue",
            threat_level="Informational",
            status=f"{len(resolved_subs)} Found",
            raw_data=cat_summary,
            tags=["subdomain", "summary", "bruteforce"]
        ))

        for cat in sorted(cat_counts.keys()):
            cat_subs = [f"{sub}.{domain}" for sub, _, _ in resolved_subs if categorize_subdomain(sub) == cat]
            if cat_subs:
                findings.append(IntelligenceFinding(
                    entity=f"{cat}: {', '.join(cat_subs[:8])}",
                    type=f"Subdomain Category: {cat}",
                    source="Subdomain Brute Force Deep",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    status=f"{len(cat_subs)} Found",
                    tags=["subdomain", cat, "category"]
                ))
    else:
        findings.append(IntelligenceFinding(
            entity=f"No subdomains resolved from {len(SUBDOMAIN_WORDLIST)} wordlist",
            type="Subdomain Brute Force Summary",
            source="Subdomain Brute Force Deep",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            status="No Results",
            tags=["subdomain", "summary"]
        ))

    return findings
