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

class OSINTOrchestrator:
    def __init__(self, target: str, target_type: str = "Domain", log_list: list = None):
        self.target = normalize_target(target)
        self.target_type = target_type
        self.findings = []
        self.logs = [] # Module summary logs
        self.log_list = log_list if log_list is not None else [] # Live verbose logs
        self.semaphore = asyncio.Semaphore(100) # Increased Concurrency for Ultra-Fast Scanning

    def log_verbose(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = f"[{level}]"
        if level == "SUCCESS": prefix = "[+]"
        if level == "ERROR": prefix = "[!]"
        formatted = f"[{timestamp}] {prefix} {message}"
        self.log_list.append(formatted)
        print(formatted) # Also print to stdout

    async def run_scan(self):
        modules_path = os.path.join(os.path.dirname(__file__), "modules")
        # Reduced timeout to 10s and increased connection limits for speed
        async with httpx.AsyncClient(
            timeout=10.0, 
            verify=False, 
            limits=httpx.Limits(max_connections=200, max_keepalive_connections=100)
        ) as client:
            self.log_verbose(f"Mission Initialized for {self.target} ({self.target_type})", "INFO")
            tasks = []
            for filename in os.listdir(modules_path):
                if filename.endswith(".py") and filename != "__init__.py":
                    module = self.load_module(os.path.join(modules_path, filename))
                    if hasattr(module, 'crawl'):
                        self.log_verbose(f"Engaging Module: {filename[:-3]}", "INFO")
                        tasks.append(self.safe_crawl(module, client))
            
            results = await asyncio.gather(*tasks)
            for r in results:
                if r: self.findings.extend(r)

        # 1. Deduplicate
        unique_findings = self.deduplicate(self.findings)
        
        # 2. Verify
        await self.verify_findings(unique_findings)

        # 3. Correlate / enrich
        unique_findings = self.deduplicate(unique_findings + self.correlate_findings(unique_findings))
        
        return unique_findings

    def load_module(self, path):
        module_name = os.path.basename(path)[:-3]
        spec = importlib.util.spec_from_file_location(module_name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    async def safe_crawl(self, module, client):
        async with self.semaphore:
            try:
                # Some modules might only support certain target types
                if hasattr(module, 'SUPPORTED_TYPES'):
                    if self.target_type not in module.SUPPORTED_TYPES:
                        return []
                
                module_findings = await module.crawl(self.target, client)
                
                self.log_verbose(f"Module {module.__name__} completed. Findings: {len(module_findings)}", "SUCCESS")
                # Log success
                self.logs.append({
                    "module": module.__name__,
                    "status": "Success",
                    "found": str(len(module_findings)),
                    "time": datetime.now().strftime("%H:%M:%S")
                })
                return module_findings
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

async def run_modular_scan(target: str, target_type: str = "Domain", log_list: list = None):
    orchestrator = OSINTOrchestrator(target, target_type, log_list)
    findings = await orchestrator.run_scan()
    summary = orchestrator.generate_summary(findings)
    return findings, summary, orchestrator.logs
