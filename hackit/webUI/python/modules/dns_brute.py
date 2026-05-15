import asyncio
import dns.resolver
from models import IntelligenceFinding

async def crawl(target, client):
    findings = []
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    # Common subdomain prefixes for industrial recon
    prefixes = [
        "www", "dev", "staging", "api", "vpn", "mail", "remote",
        "portal", "webmail", "blog", "app", "git", "jenkins",
        "jira", "confluence", "ssh", "mysql", "db", "admin",
        "ns1", "ns2", "cdn", "cloud", "internal", "test"
    ]
    
    async def check_prefix(p):
        sub = f"{p}.{domain}"
        try:
            # Using get_event_loop().run_in_executor to avoid blocking the async loop
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(sub, 'A'))
            if answers:
                return IntelligenceFinding(
                    entity=sub,
                    type="Subdomain",
                    source="DNSBrute",
                    confidence="High",
                    color="emerald",
                    category="Network Intelligence",
                    threat_level="Standard Target",
                    status="Live",
                    resolution=str(answers[0]),
                    raw_data=f"Resolved to {str(answers[0])}"
                )
        except: return None

    # Run checks in batches to avoid overwhelming the DNS resolver
    batch_size = 10
    for i in range(0, len(prefixes), batch_size):
        batch = prefixes[i:i+batch_size]
        batch_results = await asyncio.gather(*[check_prefix(p) for p in batch])
        findings.extend([r for r in batch_results if r])
        
    return findings
