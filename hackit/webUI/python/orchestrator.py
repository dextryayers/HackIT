import asyncio, httpx, os, importlib.util, sys, dns.resolver, hashlib
from datetime import datetime
from collections import defaultdict, Counter
from functools import lru_cache
from typing import Optional
from models import IntelligenceFinding, SummaryItem
from osint_common import normalize_target
from rust_bridge import SCAN_FUNCTIONS, EngineResult, scan_all

sys.path.append(os.path.dirname(__file__))

MODULE_CATEGORIES = {
    "dns_domain": ["dnsdumpster","dnshistory","dnstwister","domain_profile_deep","rapiddns","viewdns","certificate_search","certspotter","hackertarget"],
    "web_server": ["api_scanner","builtwith","crawler_core","js_secrets","secret_finder","sensitive_files_hunter","urlscan","vulnerability_scanner_lite","web_surface_mapper","web_tech","cloud_fingerprint_deep","cve_exploit_lookup","publicwww","fofa","binaryedge","leakix","leakix_scanner","firewall_detector","javascript_deps_analyzer","http2_fingerprinter","api_endpoint_fuzzer","tracker_network_mapper","open_redirect_scanner","web_cookie_analyzer","technology_stack_profiler","cdn_origin_finder","vulnerability_db_scanner","censys","whoisxmlapi"],
    "email_osint": ["email_security_deep","email_verifier","hunterhow","breach_directory","haveibeenpwned","email_reputation_checker","mail_server_analyzer","rust_email_finder","emailrep"],
    "people_social": ["people_org_osint","social_search","tracker_identity_mapper","mobile_recon","reverse_image_search"],
    "cloud_infrastructure": ["cloud_infrastructure_hunter","cloud_probe","cloud_recon","asn_bgp_radar","bgp_he_net","robtex","cloudflare_resolver"],
    "threat_leaks": ["abuseipdb","breach_forensics","greynoise","malware_reputation_radar","otx","pastebin_monitor","shodan_full","shodan","virustotal_full","virustotal","crypto_abuse_radar","leak_checker_pro","malware_sandbox_check","phishing_detector","dehashed","intelx"],
    "historical_archive": ["archive_forensics","archive_url_miner","git_leaks","exposure_surface_deep"],
    "geolocation_network": ["geo_recon","ip_geolocation","network_topology_mapper","device_search","financial_recon","ipinfo"],
}
ALL_MODULES = {f for files in MODULE_CATEGORIES.values() for f in files}

# Module cache to avoid re-loading modules on every scan
_module_cache: dict = {}

def get_cached_module(mod_path: str):
    mod_name = os.path.basename(mod_path)[:-3]
    cache_key = f"{mod_name}:{os.path.getmtime(mod_path)}"
    if cache_key in _module_cache:
        return _module_cache[cache_key]
    try:
        spec = importlib.util.spec_from_file_location(mod_name, mod_path)
        if not spec or not spec.loader:
            return None
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        _module_cache[cache_key] = m
        return m
    except Exception:
        return None


class OSINTOrchestrator:
    def __init__(self, target, target_type="Domain", log_list=None, settings=None):
        self.target = normalize_target(target)
        self.target_type = target_type
        self.findings = []
        self.logs = []
        self.log_list = log_list if log_list is not None else []
        self.settings = settings or {}
        snr = self.settings.get("sniper_ratio", "max")
        if snr == "max":
            self.semaphore = asyncio.Semaphore(300)
            self.default_timeout, self.default_max_findings, self.default_connections = 25, 10000, 500
        elif snr == "balanced":
            self.semaphore = asyncio.Semaphore(150)
            self.default_timeout, self.default_max_findings, self.default_connections = 15, 3000, 300
        elif snr == "stealth":
            self.semaphore = asyncio.Semaphore(30)
            self.default_timeout, self.default_max_findings, self.default_connections = 20, 1000, 50
        else:
            self.semaphore = asyncio.Semaphore(int(self.settings.get("concurrency", 100)))
            self.default_timeout = int(self.settings.get("timeout", 15))
            self.default_max_findings = int(self.settings.get("max_findings", 5000))
            self.default_connections = int(self.settings.get("connections", 200))

    def log(self, msg, level="INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        pfx = {"SUCCESS":"[+]","ERROR":"[!]"}.get(level, f"[{level}]")
        line = f"[{ts}] {pfx} {msg}"
        self.log_list.append(line)
        print(line)

    async def run_scan(self):
        self.log(f"Scan started for {self.target} ({self.target_type})", "INFO")
        findings = []

        # Phase 1: Rust engine (primary, fast)
        self.log("Phase 1: Rust engine scan", "INFO")
        rust_config = self._build_rust_config()
        rust_result = await scan_all(self.target, config=rust_config)
        if rust_result.success:
            rust_findings = self._parse_rust_results(rust_result.raw)
            findings.extend(rust_findings)
            self.log(f"Rust engine: {len(rust_findings)} findings", "SUCCESS")
        else:
            self.log(f"Rust engine: {rust_result.error}", "ERROR")

        # Phase 2: Python modules (fallback, enrichment)
        self.log("Phase 2: Python module scan", "INFO")
        modules_path = os.path.join(os.path.dirname(__file__), "modules")
        depth = self.settings.get("depth", "deep")
        timeout_val = int(self.settings.get("timeout", self.default_timeout))
        conn_count = int(self.settings.get("connections", self.default_connections))
        enabled_categories = self.settings.get("modules", [])
        max_findings = int(self.settings.get("max_findings", self.default_max_findings))

        timeout_val = max(5, min(180, timeout_val))
        conn_count = max(10, min(1000, conn_count))
        if depth == "quick": timeout_val, conn_count = min(timeout_val, 8), min(conn_count, 50)
        elif depth == "deep": timeout_val, conn_count = max(timeout_val, 45), max(conn_count, 200)
        elif depth == "exhaustive": timeout_val, conn_count = max(timeout_val, 120), max(conn_count, 500)

        proxy_url = self.settings.get("proxy_http","") or self.settings.get("proxy_socks","") or None
        ua = self.settings.get("user_agent","") or None
        client_kwargs = dict(timeout=timeout_val, verify=False, follow_redirects=True,
            limits=httpx.Limits(max_connections=conn_count, max_keepalive_connections=conn_count//2))
        if proxy_url: client_kwargs["proxies"] = proxy_url
        if ua: client_kwargs["headers"] = {"User-Agent": ua}

        async with httpx.AsyncClient(**client_kwargs) as client:
            tasks = []
            for filename in sorted(os.listdir(modules_path)):
                if not filename.endswith(".py") or filename == "__init__.py": continue
                mod_name = filename[:-3]
                if enabled_categories:
                    if not any(mod_name in MODULE_CATEGORIES.get(c,[]) for c in enabled_categories): continue
                if mod_name not in ALL_MODULES:
                    continue
                module = get_cached_module(os.path.join(modules_path, filename))
                if module is None:
                    self.log(f"Module {mod_name} import failed", "ERROR")
                    self.logs.append({"module":mod_name,"status":"Error","error":"Import failed","time":datetime.now().strftime("%H:%M:%S")})
                    continue
                if hasattr(module, 'crawl'):
                    self.log(f"Engaging: {mod_name}", "INFO")
                    tasks.append(self._safe_crawl(module, client, timeout_val, mod_name))

            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, Exception):
                        continue
                    if r:
                        findings.extend(r)

        if max_findings > 0 and len(findings) > max_findings:
            findings = findings[:max_findings]

        unique = self._dedup(findings)
        await self._verify(unique)

        toggles = self.settings.get("toggles", {})
        if toggles.get("correlation_engine", True):
            unique = self._dedup(unique + self._correlate(unique))

        self.log(f"Scan complete: {len(unique)} unique findings", "SUCCESS")
        return unique

    def _parse_rust_results(self, raw: dict) -> list:
        findings = []
        target = raw.get("target", self.target)
        # Subdomains
        for sd in raw.get("subdomains") or []:
            findings.append(IntelligenceFinding(
                entity=sd.get("subdomain",""), type="Subdomain",
                source="Rust Engine", confidence="High", color="blue",
                status="Verified" if sd.get("resolution") else "Unverified",
                resolution=sd.get("resolution"), tags=["rust","subdomain"],
            ))
        # Ports
        for p in raw.get("ports") or []:
            findings.append(IntelligenceFinding(
                entity=f"{target}:{p['port']} ({p.get('service','?')})", type="Open Port",
                source="Rust Engine", confidence="High", color="amber",
                status="Open", tags=["rust","port-scan"],
            ))
        # DNS
        dns_data = raw.get("dns") or {}
        for rtype in ("a","aaaa","mx","ns","txt","cname","srv","ptr","caa"):
            for val in dns_data.get(rtype) or []:
                findings.append(IntelligenceFinding(
                    entity=val, type=f"DNS {rtype.upper()}", source="Rust Engine",
                    confidence="High", color="slate", status="Resolved", tags=["rust","dns"],
                ))
        # Emails
        for em in (raw.get("emails") or {}).get("patterns") or []:
            findings.append(IntelligenceFinding(
                entity=em, type="Email Address", source="Rust Engine",
                confidence="Medium", color="pink", status="Discovered", tags=["rust","email"],
            ))
        # Webtech
        wt = raw.get("webtech") or {}
        for tech in wt.get("tech") or []:
            findings.append(IntelligenceFinding(
                entity=tech, type="Web Technology", source="Rust Engine",
                confidence="High", color="green", status="Detected", tags=["rust","webtech"],
            ))
        # Sensitive files
        for sf in (raw.get("sensitive") or {}).get("found") or []:
            findings.append(IntelligenceFinding(
                entity=sf.get("path",""), type="Sensitive File",
                source="Rust Engine", confidence="Medium", color="red",
                status=f"HTTP {sf.get('status','?')}", tags=["rust","sensitive"],
            ))
        # Secrets
        for sc in (raw.get("secrets") or {}).get("secrets") or []:
            findings.append(IntelligenceFinding(
                entity=f"{sc.get('secret_type','?')}: {sc.get('value','')[:50]}",
                type="Hardcoded Secret", source="Rust Engine",
                confidence="High", color="red", status="Found", tags=["rust","secret"],
            ))
        # WAF
        waf = raw.get("waf") or {}
        if waf.get("detected"):
            findings.append(IntelligenceFinding(
                entity=f"WAF: {waf.get('waf','?')} | CDN: {waf.get('cdn','?')}",
                type="WAF/CDN", source="Rust Engine", confidence="High",
                color="orange", status="Detected", tags=["rust","waf"],
            ))
        # Social
        for sp in (raw.get("social") or {}).get("profiles") or []:
            if sp.get("exists"):
                findings.append(IntelligenceFinding(
                    entity=sp.get("url",""), type="Social Profile",
                    source="Rust Engine", confidence="Medium", color="purple",
                    status="Verified", tags=["rust","social"],
                ))
        # crt.sh
        crt = raw.get("crtsh") or {}
        for ce in crt.get("certificates") or []:
            for san in ce.get("sans") or []:
                findings.append(IntelligenceFinding(
                    entity=san, type="Subdomain", source="crt.sh (Rust)",
                    confidence="High", color="blue",
                    status=f"Issuer: {ce.get('issuer','?')[:40]}", tags=["rust","crtsh"],
                ))
        # Vulns
        for v in (raw.get("vulns") or {}).get("vulnerabilities") or []:
            findings.append(IntelligenceFinding(
                entity=v.get("name","?"), type="Vulnerability",
                source="Rust Engine", confidence="High",
                color="red", threat_level=v.get("severity","Medium"),
                status=v.get("cve_id") or "Identified",
                raw_data=v.get("description",""), tags=["rust","vuln"],
            ))
        # Cloud
        for cp in (raw.get("cloud") or {}).get("providers") or []:
            findings.append(IntelligenceFinding(
                entity=f"{cp.get('name','?')}: {', '.join(cp.get('services',[]))}",
                type="Cloud", source="Rust Engine", confidence=cp.get("confidence","Medium"),
                color="cyan", status="Detected", tags=["rust","cloud"],
            ))
        for cb in (raw.get("cloud") or {}).get("buckets") or []:
            findings.append(IntelligenceFinding(
                entity=cb.get("url",""), type="Cloud Bucket",
                source="Rust Engine", confidence="High",
                color="cyan", status="Accessible" if cb.get("accessible") else "Exists",
                tags=["rust","cloud","bucket"],
            ))
        # Crawl / Web analysis (merged from crawl)
        cr = raw.get("crawl") or {}
        for form in cr.get("forms") or []:
            findings.append(IntelligenceFinding(
                entity=f"Form: {form.get('action','?')} [{form.get('method','GET')}]",
                type="Web Form", source="Rust Engine", confidence="Medium",
                color="slate", status="Identified", tags=["rust","crawl"],
            ))
        for ep in cr.get("api_endpoints") or []:
            findings.append(IntelligenceFinding(
                entity=ep, type="API Endpoint", source="Rust Engine",
                confidence="Medium", color="indigo", status="Discovered",
                tags=["rust","crawl"],
            ))
        if cr.get("spa_framework"):
            findings.append(IntelligenceFinding(
                entity=f"SPA: {cr['spa_framework']}", type="Web Technology",
                source="Rust Engine", confidence="High", color="green",
                status="Detected", tags=["rust","spa"],
            ))

        # ── 01. WHOIS ──
        wh = raw.get("whois") or {}
        if wh.get("registrar"):
            findings.append(IntelligenceFinding(entity=wh["registrar"], type="Domain Registrar",
                source="Rust:WHOIS", confidence="High", color="slate", status="Identified", tags=["rust","whois"]))
        for ns in wh.get("name_servers") or []:
            findings.append(IntelligenceFinding(entity=ns, type="DNS Nameserver",
                source="Rust:WHOIS", confidence="High", color="slate", status="Authoritative", tags=["rust","whois","dns"]))
        if wh.get("registrant_org"):
            findings.append(IntelligenceFinding(entity=wh["registrant_org"], type="Registrant Organization",
                source="Rust:WHOIS", confidence="Medium", color="slate", status="Registered", tags=["rust","whois"]))
        if wh.get("creation_date"):
            findings.append(IntelligenceFinding(entity=f"Created: {wh['creation_date']}", type="Domain Registration",
                source="Rust:WHOIS", confidence="High", color="slate", status="Historical", tags=["rust","whois"]))
        if wh.get("expiration_date"):
            findings.append(IntelligenceFinding(entity=f"Expires: {wh['expiration_date']}", type="Domain Registration",
                source="Rust:WHOIS", confidence="High", color="slate", status="Historical", tags=["rust","whois"]))

        # ── 02. SSL/TLS ──
        tls = raw.get("ssl_tls") or {}
        if tls.get("grade"):
            findings.append(IntelligenceFinding(entity=f"SSL Grade: {tls['grade']}", type="SSL/TLS Certificate",
                source="Rust:SSL", confidence="High", color="green" if str(tls.get("grade","")).startswith(("A","B")) else "orange",
                status=tls.get("protocol","TLS"), tags=["rust","ssl"]))
        if tls.get("issuer"):
            findings.append(IntelligenceFinding(entity=f"Issuer: {tls['issuer']}", type="SSL/TLS Certificate",
                source="Rust:SSL", confidence="High", color="slate", status="Verified", tags=["rust","ssl"]))
        if tls.get("self_signed"):
            findings.append(IntelligenceFinding(entity="Self-Signed Certificate", type="SSL/TLS Warning",
                source="Rust:SSL", confidence="High", color="red", threat_level="Elevated Risk",
                status="Self-Signed", tags=["rust","ssl"]))
        if tls.get("expired"):
            findings.append(IntelligenceFinding(entity="Expired Certificate", type="SSL/TLS Warning",
                source="Rust:SSL", confidence="High", color="red", threat_level="High Risk",
                status="Expired", tags=["rust","ssl"]))
        for alt in tls.get("alt_names") or []:
            findings.append(IntelligenceFinding(entity=alt, type="Subdomain",
                source="Rust:SSL", confidence="High", color="blue",
                status="SAN Listed", tags=["rust","ssl","subdomain"]))

        # ── 03. HTTP Headers ──
        hh = raw.get("http_headers") or {}
        if hh.get("server"):
            findings.append(IntelligenceFinding(entity=hh["server"], type="Web Technology",
                source="Rust:HTTP Headers", confidence="High", color="green",
                status="Detected", tags=["rust","http"]))
        if hh.get("missing_headers"):
            for h in hh["missing_headers"]:
                findings.append(IntelligenceFinding(entity=f"Missing: {h}", type="Security Header",
                    source="Rust:HTTP Headers", confidence="Medium", color="orange",
                    threat_level="Elevated Risk", status="Missing", tags=["rust","http","security"]))
        if hh.get("security_score") is not None:
            findings.append(IntelligenceFinding(entity=f"Security Score: {hh['security_score']}/100", type="Security Header",
                source="Rust:HTTP Headers", confidence="High", color="slate", status="Scored", tags=["rust","http"]))

        # ── 04. CVE Search ──
        for cve in (raw.get("cve_search") or {}).get("matches") or []:
            severity = str(cve.get("severity","Medium"))
            color = "red" if severity in ("Critical","High") else "orange"
            findings.append(IntelligenceFinding(entity=cve.get("cve_id","?"), type="CVE",
                source="Rust:CVE Search", confidence="High", color=color,
                threat_level=severity, status=cve.get("affected_tech","?"),
                raw_data=cve.get("description",""), tags=["rust","cve"]))

        # ── 05. Breach Check ──
        for b in (raw.get("breach_check") or {}).get("checks") or []:
            if b.get("exposed"):
                findings.append(IntelligenceFinding(entity=f"Breach: {b['source']}", type="Data Breach",
                    source="Rust:Breach Check", confidence="Medium", color="red",
                    threat_level="High Risk", status=b.get("data_type","?"),
                    raw_data=b.get("description",""), tags=["rust","breach"]))

        # ── 06. Subdomain Takeover ──
        for t in (raw.get("subdomain_takeover") or {}).get("checks") or []:
            if t.get("vulnerable"):
                findings.append(IntelligenceFinding(entity=t.get("subdomain","?"), type="Subdomain Takeover",
                    source="Rust:Takeover", confidence="High", color="red",
                    threat_level="High Risk", status=f"Vulnerable: {t.get('service','?')}",
                    raw_data=t.get("description",""), tags=["rust","takeover"]))

        # ── 07. Tech Fingerprint ──
        tf = raw.get("tech_fingerprint") or {}
        if tf.get("cms"):
            findings.append(IntelligenceFinding(entity=tf["cms"], type="CMS",
                source="Rust:Tech Fingerprint", confidence="High", color="green",
                status="Detected", tags=["rust","tech"]))
        for fw in tf.get("frameworks") or []:
            findings.append(IntelligenceFinding(entity=fw, type="Web Framework",
                source="Rust:Tech Fingerprint", confidence="High", color="green",
                status="Detected", tags=["rust","tech"]))
        for al in tf.get("analytics") or []:
            findings.append(IntelligenceFinding(entity=al, type="Analytics",
                source="Rust:Tech Fingerprint", confidence="Medium", color="slate",
                status="Detected", tags=["rust","tech"]))
        for lib in tf.get("js_libraries") or []:
            findings.append(IntelligenceFinding(entity=lib, type="JavaScript Library",
                source="Rust:Tech Fingerprint", confidence="Medium", color="slate",
                status="Detected", tags=["rust","tech"]))

        # ── 08. API Discovery ──
        for ep in (raw.get("api_discovery") or {}).get("endpoints") or []:
            findings.append(IntelligenceFinding(entity=ep.get("path","?"), type="API Endpoint",
                source="Rust:API Discovery", confidence="Medium", color="indigo",
                status=f"HTTP {ep.get('status','?')}", tags=["rust","api"]))

        # ── 09. Cloud Buckets ──
        for b in (raw.get("cloud_buckets") or {}).get("buckets") or []:
            findings.append(IntelligenceFinding(entity=b.get("url",""), type="Cloud Bucket",
                source="Rust:Cloud Buckets", confidence="Medium", color="cyan",
                status="Accessible" if b.get("accessible") else "Exists",
                tags=["rust","cloud","bucket"]))

        # ── 10. Social Search ──
        for p in (raw.get("social_search") or {}).get("profiles") or []:
            if p.get("exists"):
                findings.append(IntelligenceFinding(entity=p.get("url",""), type="Social Profile",
                    source="Rust:Social Search", confidence="Medium", color="purple",
                    status=f"Found on {p.get('platform','?')}", tags=["rust","social"]))

        # ── 11. Paste Scan ──
        for p in (raw.get("paste_scan") or {}).get("matches") or []:
            findings.append(IntelligenceFinding(entity=f"Paste: {p.get('source','?')}", type="Leak",
                source="Rust:Paste Scan", confidence="Low", color="red",
                threat_level="Elevated Risk", status="Found",
                raw_data=p.get("snippet","")[:500], tags=["rust","paste","leak"]))

        # ── 12. Git Discovery ──
        gd = raw.get("git_discovery") or {}
        if gd.get("git_exposed"):
            for gf in gd.get("files") or []:
                findings.append(IntelligenceFinding(entity=f".git/{gf}", type="Exposed VCS",
                    source="Rust:Git Discovery", confidence="High", color="red",
                    threat_level="High Risk", status="Exposed", tags=["rust","git","exposure"]))

        # ── 13. DNS Zone Transfer ──
        dzt = raw.get("dns_zone_transfer") or {}
        if dzt.get("zone_transfer_possible"):
            findings.append(IntelligenceFinding(entity=f"Zone Transfer Possible: {dzt.get('domain','?')}",
                type="DNS Vulnerability", source="Rust:DNS Zone Transfer",
                confidence="High", color="red", threat_level="High Risk",
                status="Vulnerable", tags=["rust","dns","zone-transfer"]))
        if not dzt.get("dnssec_enabled"):
            findings.append(IntelligenceFinding(entity=f"DNSSEC Not Enabled: {dzt.get('domain','?')}",
                type="DNS Vulnerability", source="Rust:DNS Zone Transfer",
                confidence="Medium", color="orange", threat_level="Elevated Risk",
                status="Missing DNSSEC", tags=["rust","dns","dnssec"]))

        # ── 14. CORS Check ──
        cors = raw.get("cors_check") or {}
        if cors.get("vulnerable") or cors.get("origin_reflection") or cors.get("wildcard_origin"):
            findings.append(IntelligenceFinding(entity="CORS Misconfiguration",
                type="Web Vulnerability", source="Rust:CORS Check",
                confidence="High", color="red", threat_level="High Risk",
                status=f"Origin Reflection: {cors.get('origin_reflection')} | Wildcard: {cors.get('wildcard_origin')}",
                tags=["rust","cors","vuln"]))

        # ── 15. Redirect Trace ──
        rt = raw.get("redirect_trace") or {}
        chain = rt.get("chain") or []
        if len(chain) > 1:
            findings.append(IntelligenceFinding(entity=f"Redirect Chain: {len(chain)} hops → {rt.get('final_url','')[:60]}",
                type="Web Behavior", source="Rust:Redirect Trace",
                confidence="Medium", color="slate", status=f"{len(chain)} hops",
                tags=["rust","redirect"]))

        # ── 16. Cookie Audit ──
        ca = raw.get("cookie_audit") or {}
        for c in ca.get("cookies") or []:
            if not c.get("secure") or not c.get("http_only"):
                findings.append(IntelligenceFinding(entity=f"Insecure Cookie: {c.get('name','?')}",
                    type="Cookie Vulnerability", source="Rust:Cookie Audit",
                    confidence="Medium", color="orange", threat_level="Elevated Risk",
                    status=f"Secure={c.get('secure')} HttpOnly={c.get('http_only')} SameSite={c.get('same_site','?')}",
                    tags=["rust","cookie","vuln"]))

        # ── 17. Email Security ──
        es = raw.get("email_security") or {}
        if es.get("spf_record"):
            findings.append(IntelligenceFinding(entity=f"SPF: {'Valid' if es.get('spf_valid') else 'Invalid'}",
                type="Email Security", source="Rust:Email Security",
                confidence="High", color="green" if es.get("spf_valid") else "red",
                status=es.get("spf_record","")[:80], tags=["rust","email","spf"]))
        if es.get("dkim_record"):
            findings.append(IntelligenceFinding(entity=f"DKIM: {'Valid' if es.get('dkim_valid') else 'Invalid'}",
                type="Email Security", source="Rust:Email Security",
                confidence="High", color="green" if es.get("dkim_valid") else "red",
                status=es.get("dkim_record","")[:80], tags=["rust","email","dkim"]))
        if es.get("dmarc_record"):
            findings.append(IntelligenceFinding(entity=f"DMARC: {es.get('dmarc_policy','?')}",
                type="Email Security", source="Rust:Email Security",
                confidence="High", color="green" if es.get("dmarc_valid") else "red",
                status=es.get("dmarc_record","")[:80], tags=["rust","email","dmarc"]))

        # ── 18. ASN Network ──
        asn = raw.get("asn_network") or {}
        if asn.get("asn"):
            findings.append(IntelligenceFinding(entity=f"AS{asn['asn']} - {asn.get('asn_org','?')}",
                type="ASN", source="Rust:ASN Network",
                confidence="High", color="slate", status=asn.get("country","?"),
                tags=["rust","asn","network"]))
        if asn.get("org"):
            findings.append(IntelligenceFinding(entity=asn["org"], type="Organization",
                source="Rust:ASN Network", confidence="Medium", color="slate",
                status="Identified", tags=["rust","asn"]))

        # ── 19. JS Analysis ──
        jsa = raw.get("js_analysis") or {}
        for ak in jsa.get("api_keys") or []:
            findings.append(IntelligenceFinding(entity=f"API Key: {ak[:40]}...", type="Hardcoded Secret",
                source="Rust:JS Analysis", confidence="High", color="red",
                threat_level="High Risk", status="Found in JS",
                tags=["rust","js","secret"]))
        for ep in jsa.get("endpoints") or []:
            findings.append(IntelligenceFinding(entity=ep, type="API Endpoint",
                source="Rust:JS Analysis", confidence="Medium", color="indigo",
                status="Found in JS", tags=["rust","js","api"]))
        for sus in jsa.get("suspicious") or []:
            findings.append(IntelligenceFinding(entity=sus, type="Suspicious Pattern",
                source="Rust:JS Analysis", confidence="Low", color="orange",
                status="Found in JS", tags=["rust","js"]))

        # ── 20. Directory Enumeration ──
        for d in (raw.get("dir_enum") or {}).get("directories") or []:
            findings.append(IntelligenceFinding(entity=d.get("path","?"), type="Directory",
                source="Rust:Dir Enum", confidence="Medium", color="slate",
                status=f"HTTP {d.get('status','?')}", tags=["rust","directory"]))

        # ── 21. Social Media Check (NEW) ──
        for sm in raw.get("social_media_check") or []:
            if sm.get("found"):
                findings.append(IntelligenceFinding(entity=f"{sm.get('platform','?')}: {sm.get('url','')}",
                    type="Social Account", source="Rust:Social Media Check",
                    confidence="High", color="purple", status="Found",
                    tags=["rust","social","username"]))

        # ── 22. Email Intel (NEW) ──
        ei = raw.get("email_intel") or {}
        for em in ei.get("email_addresses") or []:
            findings.append(IntelligenceFinding(entity=em, type="Email Address",
                source="Rust:Email Intel", confidence="Medium", color="pink",
                status="Harvested", tags=["rust","email","intel"]))
        for src in ei.get("sources_found") or []:
            findings.append(IntelligenceFinding(entity=f"Email source: {src}", type="Data Source",
                source="Rust:Email Intel", confidence="Low", color="slate",
                status="Leak Found", tags=["rust","email","leak"]))

        # ── 23. DNS Intel (NEW) ──
        di = raw.get("dns_intel") or {}
        for rtype in ("a_records","aaaa_records","mx_records","ns_records","txt_records","cname_records","srv_records","ptr_records","caa_records"):
            for val in di.get(rtype) or []:
                tag = rtype.replace("_records","").upper()
                findings.append(IntelligenceFinding(entity=val, type=f"DNS {tag}",
                    source="Rust:DNS Intel", confidence="High", color="slate",
                    status="Resolved", tags=["rust","dns","intel"]))
        for prov in di.get("cloud_providers") or []:
            findings.append(IntelligenceFinding(entity=f"Cloud: {prov}", type="Cloud Provider",
                source="Rust:DNS Intel", confidence="Medium", color="cyan",
                status="Detected", tags=["rust","dns","cloud"]))

        # ── 24. Darkweb Search (NEW) ──
        dw = raw.get("darkweb_search") or {}
        for src in dw.get("sources") or []:
            if src.get("mentions", 0) > 0:
                findings.append(IntelligenceFinding(entity=f"{src.get('source','?')}: {src.get('mentions',0)} mentions",
                    type="Darkweb Mention", source="Rust:Darkweb Search",
                    confidence="Medium", color="red", threat_level="High Risk",
                    status=src.get("url","")[:80], tags=["rust","darkweb","leak"]))
        if dw.get("risk_assessment") and dw["risk_assessment"] != "NONE":
            findings.append(IntelligenceFinding(entity=f"Darkweb Risk: {dw['risk_assessment']}", type="Risk Assessment",
                source="Rust:Darkweb Search", confidence="Medium", color="red",
                threat_level=dw["risk_assessment"], status="Assessed", tags=["rust","darkweb"]))

        # ── 25. SSL Intel (NEW) ──
        si = raw.get("ssl_intel") or {}
        for port in si.get("open_ports") or []:
            findings.append(IntelligenceFinding(entity=f"TLS Port: {port}", type="Open Port",
                source="Rust:SSL Intel", confidence="High", color="green",
                status="Open", tags=["rust","ssl","port"]))
        for hdr in si.get("security_headers") or []:
            if not hdr.get("present"):
                findings.append(IntelligenceFinding(entity=f"Missing: {hdr.get('name','?')}",
                    type="Security Header", source="Rust:SSL Intel",
                    confidence="High", color="orange", threat_level="Elevated Risk",
                    status="Missing", tags=["rust","ssl","security"]))
        for h, v in si.get("http_headers") or []:
            if h.lower() in ("server","x-powered-by"):
                findings.append(IntelligenceFinding(entity=f"{h}: {v[:60]}", type="Web Technology",
                    source="Rust:SSL Intel", confidence="High", color="green",
                    status="Detected", tags=["rust","ssl","http"]))

        # ── 26. Web Intel (NEW) ──
        wi = raw.get("web_intel") or {}
        for sf in wi.get("sensitive_files") or []:
            severity = sf.get("severity","info")
            color = "red" if severity in ("critical","high") else "orange" if severity == "medium" else "slate"
            findings.append(IntelligenceFinding(entity=sf.get("path","?"), type="Sensitive File",
                source="Rust:Web Intel", confidence="Medium", color=color,
                status=f"HTTP {sf.get('status','?')}", tags=["rust","web","sensitive"]))
        for h, v in wi.get("headers") or []:
            if h.lower() in ("server","x-powered-by","x-aspnet-version","x-generator"):
                findings.append(IntelligenceFinding(entity=f"{h}: {v[:60]}", type="Web Technology",
                    source="Rust:Web Intel", confidence="High", color="green",
                    status="Detected", tags=["rust","web","tech"]))

        # ── 27. Google Dorks (NEW) ──
        gd2 = raw.get("google_dorks") or {}
        for dr in gd2.get("results") or []:
            if dr.get("results", 0) > 0:
                findings.append(IntelligenceFinding(
                    entity=f"{dr.get('dork_name','?')}: {dr.get('query','')[:60]}",
                    type="Google Dork", source="Rust:Google Dorks",
                    confidence="Medium", color="orange", threat_level="Elevated Risk",
                    status=f"{dr.get('results',0)} results via {dr.get('engine','?')}",
                    tags=["rust","dork","osint"]))

        # ── 28. Link Extractor (NEW) ──
        le = raw.get("link_extractor") or {}
        for url in le.get("internal_links") or []:
            findings.append(IntelligenceFinding(entity=url, type="Internal Link",
                source="Rust:Link Extractor", confidence="Medium", color="blue",
                status="Discovered", tags=["rust","link","internal"]))
        for url in le.get("external_links") or []:
            findings.append(IntelligenceFinding(entity=url, type="External Link",
                source="Rust:Link Extractor", confidence="Low", color="slate",
                status="Referenced", tags=["rust","link","external"]))
        for em in le.get("emails") or []:
            findings.append(IntelligenceFinding(entity=em, type="Email Address",
                source="Rust:Link Extractor", confidence="Medium", color="pink",
                status="Extracted", tags=["rust","link","email"]))
        if le.get("total_internal_links", 0) > 0:
            findings.append(IntelligenceFinding(
                entity=f"Link Extractor: {le.get('pages_visited',0)} pages, {le.get('total_internal_links',0)} internal, {le.get('total_external_links',0)} external, {le.get('total_emails',0)} emails",
                type="Link Extractor Summary", source="Rust:Link Extractor",
                confidence="High", color="slate", status="Complete",
                tags=["rust","link","summary"]))

        # ── 29. Web Form Discovery (NEW) ──
        wfd = raw.get("web_form_discovery") or {}
        for f in wfd.get("forms") or []:
            action = f.get("action","")
            method = f.get("method","GET")
            has_csrf = f.get("has_csrf", False)
            sensitive = f.get("sensitive_inputs", [])
            color = "green" if has_csrf else "red"
            findings.append(IntelligenceFinding(
                entity=f"Form: {action} [{method}] CSRF={has_csrf} Sensitive={len(sensitive)}",
                type="Web Form", source="Rust:Form Discovery",
                confidence="Medium", color=color,
                threat_level="Informational" if has_csrf else "High Risk",
                status=f"{method} {action[:40]}", tags=["rust","form"]))
            for si in sensitive:
                findings.append(IntelligenceFinding(
                    entity=f"Sensitive input: {si} in {action}",
                    type="Form Sensitive Input", source="Rust:Form Discovery",
                    confidence="High", color="red", threat_level="High Risk",
                    status="Detected", tags=["rust","form","sensitive"]))
        if wfd.get("total_forms", 0) > 0:
            findings.append(IntelligenceFinding(
                entity=f"Form Discovery: {wfd.get('total_forms',0)} forms on {wfd.get('pages_with_forms',0)}/{wfd.get('pages_checked',0)} pages",
                type="Form Discovery Summary", source="Rust:Form Discovery",
                confidence="High", color="slate", status="Complete",
                tags=["rust","form","summary"]))

        # ── 30. HTTP Method Fuzzer (NEW) ──
        hmf = raw.get("http_method_fuzzer") or {}
        for em in hmf.get("enabled_methods") or []:
            findings.append(IntelligenceFinding(
                entity=em, type="HTTP Method Enabled",
                source="Rust:HTTP Method Fuzzer",
                confidence="High", color="orange", threat_level="Elevated Risk",
                status="Enabled", tags=["rust","http","method"]))
        if hmf.get("enabled_endpoints", 0) > 0:
            findings.append(IntelligenceFinding(
                entity=f"HTTP Method Fuzzer: {hmf.get('enabled_endpoints',0)} enabled methods across {hmf.get('paths_tested',0)} paths",
                type="Method Fuzzer Summary", source="Rust:HTTP Method Fuzzer",
                confidence="High", color="red" if hmf.get("enabled_endpoints",0) > 10 else "orange",
                threat_level="High Risk" if hmf.get("enabled_endpoints",0) > 10 else "Elevated Risk",
                status=f"{hmf.get('enabled_endpoints',0)} enabled", tags=["rust","http","method","summary"]))

        # ── 31. Web Backup Scanner (NEW) ──
        wbs = raw.get("web_backup_scanner") or {}
        for f in wbs.get("files") or []:
            severity = f.get("severity","medium")
            color = "red" if severity == "critical" else "orange" if severity == "high" else "yellow"
            threat = "Critical" if severity == "critical" else "High Risk" if severity == "high" else "Elevated Risk"
            findings.append(IntelligenceFinding(
                entity=f"{f.get('path','?')} ({f.get('file_name','?')}) - HTTP {f.get('status','?')}",
                type=f"Backup File: {severity.title()}",
                source="Rust:Backup Scanner", confidence="High", color=color,
                threat_level=threat, status=f"HTTP {f.get('status','?')}",
                raw_data=f"size={f.get('size',0)}, response_ms={f.get('response_time_ms',0)}",
                tags=["rust","backup",severity]))
        if wbs.get("files_found", 0) > 0:
            findings.append(IntelligenceFinding(
                entity=f"Backup Scanner: {wbs.get('files_found',0)} files found ({wbs.get('critical_files',0)} critical, {wbs.get('high_risk_files',0)} high) from {wbs.get('paths_checked',0)} paths",
                type="Backup Scanner Summary", source="Rust:Backup Scanner",
                confidence="High", color="red", threat_level="Critical" if wbs.get('critical_files',0) > 0 else "High Risk",
                status=f"{wbs.get('files_found',0)} files", tags=["rust","backup","summary"]))

        # ── 32. Domain Permutation (NEW) ──
        dp = raw.get("domain_permutation") or {}
        for reg in dp.get("registered") or []:
            ips = ", ".join(reg.get("ips", []))
            findings.append(IntelligenceFinding(
                entity=f"{reg.get('domain','?')} resolves to {ips}",
                type="Domain Permutation",
                source="Rust:Domain Permutation",
                confidence="High", color="blue",
                threat_level="Elevated Risk" if ips else "Informational",
                status="Registered", tags=["rust","permutation","typosquat"]))
        if dp.get("registered_count", 0) > 0:
            findings.append(IntelligenceFinding(
                entity=f"Domain Permutation: {dp.get('registered_count',0)}/{dp.get('permutations_generated',0)} permutations registered",
                type="Permutation Summary", source="Rust:Domain Permutation",
                confidence="High", color="orange", threat_level="Elevated Risk",
                status=f"{dp.get('registered_count',0)} registered",
                tags=["rust","permutation","summary"]))

        # ── 33. HTTP Archive Scanner (NEW) ──
        has_ = raw.get("http_archive_scanner") or {}
        for snap in has_.get("snapshots") or []:
            findings.append(IntelligenceFinding(
                entity=f"{snap.get('original_url','?')} ({snap.get('timestamp','?')})",
                type="Archive Snapshot",
                source="Rust:HTTP Archive",
                confidence="Medium", color="slate",
                threat_level="Informational",
                status=f"HTTP {snap.get('status_code','?')} {snap.get('mime_type','?')}",
                raw_data=snap.get("wayback_url",""),
                tags=["rust","archive","wayback"]))
        if has_.get("total_snapshots", 0) > 0:
            findings.append(IntelligenceFinding(
                entity=f"Archive Scanner: {has_.get('total_snapshots',0)} snapshots across {has_.get('unique_years',0)} years ({has_.get('years_covered','?')})",
                type="Archive Summary", source="Rust:HTTP Archive",
                confidence="Medium", color="slate",
                threat_level="Informational", status="Complete",
                tags=["rust","archive","summary"]))

        return findings

    def _build_rust_config(self) -> dict:
        perf = self.settings.get("performance", {})
        return {
            "timeout": int(self.settings.get("timeout", 30)),
            "depth": self.settings.get("depth", "deep"),
            "concurrency": perf.get("concurrency") or int(
                {"max": 50, "balanced": 25, "stealth": 10}.get(
                    self.settings.get("sniper_ratio", "max"), 50)),
            "max_results": int(self.settings.get("max_findings", 5000)),
            "module_config": {
                "subdomain": {"max_results": perf.get("brute_depth", 500)},
                "dir_enum": {"max_results": perf.get("brute_depth", 500)},
                "ports": {"max_results": perf.get("port_range", 1000)},
            }
        }

    async def _safe_crawl(self, module, client, timeout_val=10, mod_name=""):
        async with self.semaphore:
            try:
                if hasattr(module, 'SUPPORTED_TYPES') and self.target_type not in module.SUPPORTED_TYPES:
                    return []
                coro = module.crawl(self.target, client)
                mf = await asyncio.wait_for(coro, timeout=timeout_val + 5)
                if mf is None:
                    mf = []
                if mf:
                    self.log(f"Module {mod_name}: {len(mf)} findings", "SUCCESS")
                self.logs.append({"module":mod_name,"status":"Success","found":str(len(mf)),"time":datetime.now().strftime("%H:%M:%S")})
                return mf
            except asyncio.TimeoutError:
                self.log(f"Module {mod_name} timed out", "ERROR")
                self.logs.append({"module":mod_name,"status":"Error","error":"Timeout","time":datetime.now().strftime("%H:%M:%S")})
            except Exception as e:
                self.log(f"Module {mod_name}: {str(e)[:80]}", "ERROR")
                self.logs.append({"module":mod_name,"status":"Error","error":str(e)[:80],"time":datetime.now().strftime("%H:%M:%S")})
            return []

    def _dedup(self, findings):
        seen = {}
        order = []
        for f in findings:
            entity = getattr(f, 'entity', str(f)) or str(f)
            ftype = getattr(f, 'type', 'Unknown') or 'Unknown'
            key = f"{entity}|{ftype}"
            if key not in seen:
                seen[key] = f
                order.append(f)
        return order

    def _correlate(self, findings):
        derived = []
        by_resolution, type_counts, email_domains, cloud_tags = defaultdict(list), Counter(), Counter(), Counter()
        high_risk = []
        for f in findings:
            type_counts[getattr(f, 'type', 'Unknown')] += 1
            resolution = getattr(f, 'resolution', '') or ''
            entity = getattr(f, 'entity', '') or ''
            ftype = getattr(f, 'type', '') or ''
            tags = getattr(f, 'tags', []) or []
            threat_level = getattr(f, 'threat_level', '') or ''
            if resolution and ftype == "Subdomain": by_resolution[resolution].append(entity)
            if ftype == "Email Address" and "@" in entity: email_domains[entity.split("@")[-1].lower()] += 1
            for tag in tags:
                if tag in ("AWS","Azure","Google Cloud","Cloudflare","Vercel","Netlify","Heroku"): cloud_tags[tag] += 1
            if threat_level in ("High Risk","Critical","Elevated Risk"): high_risk.append(f)
        for ip, hosts in by_resolution.items():
            if len(hosts) >= 2:
                derived.append(IntelligenceFinding(entity=f"{len(hosts)} hosts share {ip}",type="Relationship",source="Correlation Engine",confidence="High",color="purple",threat_level="Informational",status="Correlated",resolution=", ".join(sorted(hosts)[:10]),tags=["shared-infrastructure"]))
        for domain, count in email_domains.items():
            derived.append(IntelligenceFinding(entity=f"{count} email(s) for {domain}",type="Email Pattern",source="Correlation Engine",confidence="Medium",color="purple",status="Correlated",tags=["email-osint"]))
        for provider, count in cloud_tags.items():
            derived.append(IntelligenceFinding(entity=f"{provider}: {count}",type="Cloud Relationship",source="Correlation Engine",confidence="High",color="orange",status="Correlated",tags=["cloud"]))
        if high_risk:
            derived.append(IntelligenceFinding(entity=f"{len(high_risk)} high-risk signals",type="Risk Summary",source="Correlation Engine",confidence="High",color="red",threat_level="High Risk",status="Prioritize",tags=["risk"]))
        for ftype, count in type_counts.items():
            if count >= 10: derived.append(IntelligenceFinding(entity=f"{count} {ftype}",type="Correlation",source="Correlation Engine",confidence="Medium",color="slate",status="Clustered",tags=["summary"]))
        return derived

    async def _verify(self, findings):
        if not self.settings.get("toggles",{}).get("verify_findings",True):
            return
        async def resolve(f):
            if getattr(f, 'type', '') == "Subdomain" and not getattr(f, 'resolution', ''):
                try:
                    answers = await asyncio.get_event_loop().run_in_executor(None, lambda: dns.resolver.resolve(f.entity, 'A'))
                    f.status, f.resolution, f.color = "Live", str(answers[0]), "emerald"
                except: f.status = "Inactive"
        await asyncio.gather(*[resolve(f) for f in findings])

    def get_category(self, finding_type):
        mapping = {
            "Subdomain":"1. DOMAIN RECON","DNS Record":"1. DOMAIN RECON","IP Address":"2. IP / NETWORK RECON",
            "ASN":"2. IP / NETWORK RECON","Open Port":"2. IP / NETWORK RECON","Web Technology":"3. WEB APPLICATION ENUMERATION",
            "CMS":"3. WEB APPLICATION ENUMERATION","Header":"3. WEB APPLICATION ENUMERATION","Email Address":"4. EMAIL OSINT",
            "Social Profile":"5. USERNAME / SOCIAL MEDIA OSINT","Username":"5. USERNAME / SOCIAL MEDIA OSINT",
            "Employee":"6. PERSON / ORGANIZATION OSINT","Leak":"7. LEAK / BREACH ANALYSIS",
            "Cloud":"8. CLOUD / INFRASTRUCTURE OSINT","Document":"9. FILE / DOCUMENT ANALYSIS",
            "Source Code":"10. SOURCE CODE / DEVOPS OSINT","Hardcoded Secret":"10. SOURCE CODE / DEVOPS OSINT",
            "Dork":"11. INTERNET SEARCH ENGINE OSINT","Malicious":"12. DARK WEB / THREAT INTEL",
            "Threat":"12. DARK WEB / THREAT INTEL","SSL Certificate":"13. SSL / CERTIFICATE ANALYSIS",
            "Archive":"14. HISTORICAL / ARCHIVE RECON","Wayback":"14. HISTORICAL / ARCHIVE RECON",
            "Geolocation":"15. GEOLOCATION / PHYSICAL OSINT","Mobile":"16. MOBILE / APP OSINT",
            "Vulnerability":"17. RISK / SECURITY ANALYSIS","Relationship":"18. RELATIONSHIP MAPPING",
            "Correlation":"20. AUTOMATED CORRELATION ENGINE","Financial":"21. FINANCIAL INTELLIGENCE",
            "Crypto":"22. CRYPTO & BLOCKCHAIN ASSETS","Darknet":"23. DARKNET & DEEP WEB ANALYSIS",
            "CVE":"26. VULNERABILITY & CVE DATABASE","Web Form":"3. WEB APPLICATION ENUMERATION",
            "API Endpoint":"3. WEB APPLICATION ENUMERATION","Cloud Bucket":"8. CLOUD / INFRASTRUCTURE OSINT",
            "WAF/CDN":"8. CLOUD / INFRASTRUCTURE OSINT",
        }
        for key, cat in mapping.items():
            if key.lower() in finding_type.lower(): return cat
        return "MISCELLANEOUS"

    def generate_summary(self, findings):
        summary_map = {}
        for f in findings:
            ftype = getattr(f, 'type', '') or ''
            fentity = getattr(f, 'entity', '') or ''
            cat = self.get_category(ftype)
            f.category = cat
            if ftype not in summary_map:
                summary_map[ftype] = {"type": ftype, "count": 0, "last": "", "category": cat}
            summary_map[ftype]["count"] += 1
            summary_map[ftype]["last"] = fentity
        return [SummaryItem(
            type=v["type"], unique_count=v["count"], total_count=v["count"],
            last_finding=v["last"], category=v["category"]
        ) for v in summary_map.values()]


async def run_modular_scan(target, target_type="Domain", log_list=None, settings=None):
    o = OSINTOrchestrator(target, target_type, log_list, settings)
    findings = await o.run_scan()
    summary = o.generate_summary(findings)
    return findings, summary, o.logs
