import asyncio
import httpx
import os
import importlib.util
from models import IntelligenceFinding, SummaryItem
import dns.resolver
from datetime import datetime
import sys
from collections import defaultdict, Counter
from urllib.parse import urlparse

from osint_common import normalize_target

# Ensure modules can import models from the same directory
sys.path.append(os.path.dirname(__file__))

MODULE_CATEGORIES = {
    "dns_domain": ["crtsh", "dns_brute", "dns_deep_forensics", "dns_enum_full", "dns_resolver", "dnsdumpster", "dnshistory", "dnstwister", "domain_profile_deep", "rapiddns", "securitytrails", "subdomain_passive", "subdomain_takeover", "viewdns", "whois", "certificate_search", "certspotter", "hackertarget", "fullhunt"],
    "web_server": ["api_scanner", "builtwith", "crawler_core", "header_audit", "js_secrets", "secret_finder", "sensitive_files_hunter", "ssl_analyzer", "urlscan", "vulnerability_scanner_lite", "web_surface_mapper", "web_tech", "cloud_fingerprint_deep", "cve_exploit_lookup", "publicwww", "netlas", "fofa", "zoomeye", "binaryedge", "onyphe", "intelx", "leakix", "leakix_scanner", "censys", "firewall_detector", "javascript_deps_analyzer", "ssl_chain_analyzer", "http2_fingerprinter", "api_endpoint_fuzzer", "tracker_network_mapper", "open_redirect_scanner", "web_cookie_analyzer", "technology_stack_profiler", "cdn_origin_finder", "vulnerability_db_scanner"],
    "email_osint": ["email_harvester", "email_security_deep", "email_verifier", "hunterhow", "breach_directory", "haveibeenpwned", "email_reputation_checker", "mail_server_analyzer", "rust_email_finder"],
    "people_social": ["people_org_osint", "social_alias_hunter", "social_search", "tracker_identity_mapper", "whatsmyname_checker", "mobile_recon", "reverse_image_search"],
    "cloud_infrastructure": ["cloud_infrastructure_hunter", "cloud_probe", "cloud_recon", "asn_bgp_radar", "bgp_he_net", "robtex", "cloudflare_resolver"],
    "threat_leaks": ["abuseipdb", "breach_forensics", "darkweb_intel", "greynoise", "malware_reputation_radar", "otx", "pastebin_monitor", "shodan_full", "shodan", "threat_intel", "threatminer", "virustotal_full", "virustotal", "crypto_abuse_radar", "leak_checker_pro", "dark_web_scanner", "malware_sandbox_check", "phishing_detector"],
    "historical_archive": ["archive_forensics", "archive_url_miner", "archive", "wayback", "dork_engine", "git_leaks", "exposure_surface_deep", "google_dorks_deep"],
    "geolocation_network": ["geo_recon", "ip_geolocation", "network_topology_mapper", "port_scanner", "device_search", "financial_recon", "wigle"],
}
ALL_MODULES = {f for files in MODULE_CATEGORIES.values() for f in files}


class OSINTOrchestrator:
    def __init__(self, target: str, target_type: str = "Domain", log_list: list = None, settings: dict = None):
        self.target = normalize_target(target)
        self.target_type = target_type
        self.findings = []
        self.logs = []
        self.log_list = log_list if log_list is not None else []
        self.settings = settings or {}

        # ── Max-power defaults ──
        snr = self.settings.get("sniper_ratio", "max")
        if snr == "max":
            self.semaphore = asyncio.Semaphore(300)
            self.default_timeout = 25
            self.default_max_findings = 10000
            self.default_connections = 500
        elif snr == "balanced":
            self.semaphore = asyncio.Semaphore(150)
            self.default_timeout = 15
            self.default_max_findings = 3000
            self.default_connections = 300
        elif snr == "stealth":
            self.semaphore = asyncio.Semaphore(30)
            self.default_timeout = 20
            self.default_max_findings = 1000
            self.default_connections = 50
        else:  # custom
            self.semaphore = asyncio.Semaphore(int(self.settings.get("concurrency", 100)))
            self.default_timeout = int(self.settings.get("timeout", 15))
            self.default_max_findings = int(self.settings.get("max_findings", 5000))
            self.default_connections = int(self.settings.get("connections", 200))

    def log_verbose(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = f"[{level}]"
        if level == "SUCCESS": prefix = "[+]"
        if level == "ERROR": prefix = "[!]"
        formatted = f"[{timestamp}] {prefix} {message}"
        self.log_list.append(formatted)
        print(formatted)

    async def run_scan(self):
        modules_path = os.path.join(os.path.dirname(__file__), "modules")
        timeout_val = int(self.settings.get("timeout", self.default_timeout))
        depth = self.settings.get("depth", "deep")
        max_findings = int(self.settings.get("max_findings", self.default_max_findings))
        enabled_categories = self.settings.get("modules", [])
        conn_count = int(self.settings.get("connections", self.default_connections))

        timeout_val = max(5, min(180, timeout_val))
        conn_count = max(10, min(1000, conn_count))

        if depth == "quick":
            timeout_val = min(timeout_val, 8)
            conn_count = min(conn_count, 50)
        elif depth == "deep":
            timeout_val = max(timeout_val, 45)
            conn_count = max(conn_count, 200)
        elif depth == "exhaustive":
            timeout_val = max(timeout_val, 120)
            conn_count = max(conn_count, 500)

        proxy_url = self.settings.get("proxy_http", "") or self.settings.get("proxy_socks", "") or None
        ua = self.settings.get("user_agent", "") or None
        client_kwargs = dict(
            timeout=timeout_val,
            verify=False,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=conn_count, max_keepalive_connections=conn_count // 2),
        )
        if proxy_url:
            client_kwargs["proxies"] = proxy_url
        if ua:
            client_kwargs["headers"] = {"User-Agent": ua}
        async with httpx.AsyncClient(**client_kwargs) as client:
            self.log_verbose(f"Mission Initialized for {self.target} ({self.target_type}) | Depth={depth} | Timeout={timeout_val}s | Concurrency={conn_count}", "INFO")
            tasks = []
            module_names = sorted(os.listdir(modules_path))

            for filename in module_names:
                if not filename.endswith(".py") or filename == "__init__.py":
                    continue
                mod_name = filename[:-3]
                if enabled_categories:
                    allowed = False
                    for cat in enabled_categories:
                        if mod_name in MODULE_CATEGORIES.get(cat, []):
                            allowed = True
                            break
                    if not allowed:
                        continue
                try:
                    module = self.load_module(os.path.join(modules_path, filename))
                except Exception as e:
                    self.log_verbose(f"Module {mod_name} import failed: {str(e)[:80]}", "ERROR")
                    self.logs.append({
                        "module": mod_name,
                        "status": "Error",
                        "error": f"Import: {str(e)[:80]}",
                        "time": datetime.now().strftime("%H:%M:%S")
                    })
                    continue
                if hasattr(module, 'crawl'):
                    self.log_verbose(f"Engaging Module: {mod_name}", "INFO")
                    tasks.append(self.safe_crawl(module, client, timeout_val))

            if not tasks:
                self.log_verbose("No modules to execute", "ERROR")
                return []

            results = await asyncio.gather(*tasks)
            for r in results:
                if r: self.findings.extend(r)

        if max_findings > 0 and len(self.findings) > max_findings:
            self.findings = self.findings[:max_findings]

        # 1. Deduplicate
        unique_findings = self.deduplicate(self.findings)
        
        # 2. Verify (if enabled)
        await self.verify_findings(unique_findings)

        # 3. Correlate / enrich (if enabled)
        toggles = self.settings.get("toggles", {})
        if toggles.get("correlation_engine", True):
            unique_findings = self.deduplicate(unique_findings + self.correlate_findings(unique_findings))
        
        return unique_findings

    def load_module(self, path):
        module_name = os.path.basename(path)[:-3]
        spec = importlib.util.spec_from_file_location(module_name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    async def safe_crawl(self, module, client, timeout_val=10):
        async with self.semaphore:
            try:
                if hasattr(module, 'SUPPORTED_TYPES'):
                    if self.target_type not in module.SUPPORTED_TYPES:
                        return []
                
                if hasattr(module, 'crawl'):
                    coro = module.crawl(self.target, client)
                    module_findings = await asyncio.wait_for(coro, timeout=timeout_val + 5)
                else:
                    return []
                
                self.log_verbose(f"Module {module.__name__} completed. Findings: {len(module_findings)}", "SUCCESS")
                self.logs.append({
                    "module": module.__name__,
                    "status": "Success",
                    "found": str(len(module_findings)),
                    "time": datetime.now().strftime("%H:%M:%S")
                })
                return module_findings
            except asyncio.TimeoutError:
                self.log_verbose(f"Module {module.__name__} timed out ({timeout_val + 5}s)", "ERROR")
                self.logs.append({
                    "module": module.__name__,
                    "status": "Error",
                    "error": f"Timeout ({timeout_val + 5}s)",
                    "time": datetime.now().strftime("%H:%M:%S")
                })
                return []
            except Exception as e:
                self.log_verbose(f"Module {module.__name__} failed: {str(e)}", "ERROR")
                self.logs.append({
                    "module": module.__name__,
                    "status": "Error",
                    "error": str(e),
                    "time": datetime.now().strftime("%H:%M:%S")
                })
                return []

    def deduplicate(self, findings):
        seen = {}
        for f in findings:
            key = f"{f.entity}|{f.type}"
            if key not in seen:
                seen[key] = f
        return list(seen.values())

    def correlate_findings(self, findings):
        derived = []
        by_resolution = defaultdict(list)
        type_counts = Counter()
        email_domains = Counter()
        cloud_tags = Counter()
        high_risk = []

        for f in findings:
            type_counts[f.type] += 1
            if f.resolution and f.type == "Subdomain":
                by_resolution[f.resolution].append(f.entity)
            if f.type == "Email Address" and "@" in f.entity:
                email_domains[f.entity.split("@")[-1].lower()] += 1
            for tag in f.tags:
                if tag in ["AWS", "Azure", "Google Cloud", "Cloudflare Pages", "Vercel", "Netlify", "Heroku"]:
                    cloud_tags[tag] += 1
            if f.threat_level in ["High Risk", "Critical", "Elevated Risk"]:
                high_risk.append(f)

        for ip, hosts in by_resolution.items():
            if len(hosts) >= 2:
                derived.append(IntelligenceFinding(
                    entity=f"{len(hosts)} hosts share {ip}",
                    type="Relationship",
                    source="Correlation Engine",
                    confidence="High",
                    color="purple",
                    threat_level="Informational",
                    status="Correlated",
                    resolution=", ".join(sorted(hosts)[:10]),
                    raw_data="\n".join(sorted(hosts)),
                    tags=["shared-infrastructure"],
                ))

        for domain, count in email_domains.items():
            derived.append(IntelligenceFinding(
                entity=f"{count} email(s) observed for {domain}",
                type="Email Pattern",
                source="Correlation Engine",
                confidence="Medium",
                color="purple",
                status="Correlated",
                tags=["email-osint"],
            ))

        for provider, count in cloud_tags.items():
            derived.append(IntelligenceFinding(
                entity=f"{provider}: {count} indicator(s)",
                type="Cloud Relationship",
                source="Correlation Engine",
                confidence="High",
                color="orange",
                status="Correlated",
                tags=["cloud"],
            ))

        if high_risk:
            derived.append(IntelligenceFinding(
                entity=f"{len(high_risk)} elevated/high-risk exposure signal(s)",
                type="Risk Summary",
                source="Correlation Engine",
                confidence="High",
                color="red",
                threat_level="High Risk",
                status="Prioritize",
                raw_data="\n".join(f"{f.type}: {f.entity}" for f in high_risk[:30]),
                tags=["risk"],
            ))

        for ftype, count in type_counts.items():
            if count >= 10:
                derived.append(IntelligenceFinding(
                    entity=f"{count} {ftype} findings",
                    type="Correlation",
                    source="Correlation Engine",
                    confidence="Medium",
                    color="slate",
                    status="Clustered",
                    tags=["summary"],
                ))

        return derived

    async def verify_findings(self, findings):
        settings_toggles = self.settings.get("toggles", {})
        verify_enabled = settings_toggles.get("verify_findings", True)
        if not verify_enabled:
            return
        async def resolve(f):
            if f.type == "Subdomain" and not f.resolution:
                try:
                    answers = await asyncio.get_event_loop().run_in_executor(None, lambda: dns.resolver.resolve(f.entity, 'A'))
                    f.status, f.resolution, f.color = "Live", str(answers[0]), "emerald"
                except: f.status = "Inactive"
        await asyncio.gather(*[resolve(f) for f in findings])

    def get_category(self, finding_type: str) -> str:
        mapping = {
            "Subdomain": "1. DOMAIN RECON",
            "DNS Record": "1. DOMAIN RECON",
            "IP Address": "2. IP / NETWORK RECON",
            "ASN": "2. IP / NETWORK RECON",
            "Open Port": "2. IP / NETWORK RECON",
            "Web Technology": "3. WEB APPLICATION ENUMERATION",
            "CMS": "3. WEB APPLICATION ENUMERATION",
            "Header": "3. WEB APPLICATION ENUMERATION",
            "Email Address": "4. EMAIL OSINT",
            "Social Profile": "5. USERNAME / SOCIAL MEDIA OSINT",
            "Username": "5. USERNAME / SOCIAL MEDIA OSINT",
            "Employee": "6. PERSON / ORGANIZATION OSINT",
            "Leak": "7. LEAK / BREACH ANALYSIS",
            "Cloud": "8. CLOUD / INFRASTRUCTURE OSINT",
            "Document": "9. FILE / DOCUMENT ANALYSIS",
            "Source Code": "10. SOURCE CODE / DEVOPS OSINT",
            "Hardcoded Secret": "10. SOURCE CODE / DEVOPS OSINT",
            "Dork": "11. INTERNET SEARCH ENGINE OSINT",
            "Malicious": "12. DARK WEB / THREAT INTEL",
            "Threat": "12. DARK WEB / THREAT INTEL",
            "SSL Certificate": "13. SSL / CERTIFICATE ANALYSIS",
            "Archive": "14. HISTORICAL / ARCHIVE RECON",
            "Wayback": "14. HISTORICAL / ARCHIVE RECON",
            "Geolocation": "15. GEOLOCATION / PHYSICAL OSINT",
            "Mobile": "16. MOBILE / APP OSINT",
            "Vulnerability": "17. RISK / SECURITY ANALYSIS",
            "Relationship": "18. RELATIONSHIP MAPPING",
            "Screenshot": "19. SCREENSHOT / VISUAL RECON",
            "Correlation": "20. AUTOMATED CORRELATION ENGINE",
            "Financial": "21. FINANCIAL INTELLIGENCE",
            "Crypto": "22. CRYPTO & BLOCKCHAIN ASSETS",
            "Darknet": "23. DARKNET & DEEP WEB ANALYSIS",
            "Social Engineering": "24. SOCIAL ENGINEERING VECTORS",
            "Hardware": "25. IOT / HARDWARE INTELLIGENCE",
            "CVE": "26. VULNERABILITY & CVE DATABASE"
        }
        for key, cat in mapping.items():
            if key.lower() in finding_type.lower(): return cat
        return "MISCELLANEOUS"

    def generate_summary(self, findings):
        summary_map = {}
        for f in findings:
            f.category = self.get_category(f.type)
            if f.type not in summary_map:
                summary_map[f.type] = {"type": f.type, "count": 0, "last": ""}
            summary_map[f.type]["count"] += 1
            summary_map[f.type]["last"] = f.entity
        
        return [SummaryItem(
            type=v["type"],
            unique_count=v["count"],
            total_count=v["count"],
            last_finding=v["last"]
        ) for v in summary_map.values()]

async def run_modular_scan(target: str, target_type: str = "Domain", log_list: list = None, settings: dict = None):
    orchestrator = OSINTOrchestrator(target, target_type, log_list, settings)
    findings = await orchestrator.run_scan()
    summary = orchestrator.generate_summary(findings)
    return findings, summary, orchestrator.logs
