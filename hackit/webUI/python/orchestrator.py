import asyncio
import httpx
import os
import importlib.util
from models import IntelligenceFinding, SummaryItem
import dns.resolver
from datetime import datetime
import sys

# Ensure modules can import models from the same directory
sys.path.append(os.path.dirname(__file__))

class OSINTOrchestrator:
    def __init__(self, target: str, target_type: str = "Domain"):
        self.target = target
        self.target_type = target_type
        self.findings = []
        self.logs = []
        self.semaphore = asyncio.Semaphore(50) # Titan-Class concurrency

    async def run_scan(self):
        modules_path = os.path.join(os.path.dirname(__file__), "modules")
        async with httpx.AsyncClient(timeout=30.0, verify=False, limits=httpx.Limits(max_connections=100, max_keepalive_connections=50)) as client:
            tasks = []
            for filename in os.listdir(modules_path):
                if filename.endswith(".py") and filename != "__init__.py":
                    module = self.load_module(os.path.join(modules_path, filename))
                    if hasattr(module, 'crawl'):
                        tasks.append(self.safe_crawl(module, client))
            
            results = await asyncio.gather(*tasks)
            for r in results:
                if r: self.findings.extend(r)

        # 1. Deduplicate
        unique_findings = self.deduplicate(self.findings)
        
        # 2. Verify
        await self.verify_findings(unique_findings)
        
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
                
                # Log success
                self.logs.append({
                    "module": module.__name__,
                    "status": "Success",
                    "found": str(len(module_findings)),
                    "time": datetime.now().strftime("%H:%M:%S")
                })
                return module_findings
            except Exception as e:
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
            "Correlation": "20. AUTOMATED CORRELATION ENGINE"
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

async def run_modular_scan(target: str, target_type: str = "Domain"):
    orchestrator = OSINTOrchestrator(target, target_type)
    findings = await orchestrator.run_scan()
    summary = orchestrator.generate_summary(findings)
    return findings, summary, orchestrator.logs
