import dns.resolver
import asyncio
from models import IntelligenceFinding

async def crawl(target, client):
    findings = []
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    # Signatures for potential takeovers
    signatures = {
        "github.io": "GitHub Pages",
        "herokuapp.com": "Heroku",
        "s3.amazonaws.com": "AWS S3",
        "wpengine.com": "WPEngine",
        "ghost.io": "Ghost",
        "bitbucket.io": "Bitbucket",
        "azurewebsites.net": "Azure"
    }
    
    # We check CNAME records for the domain and common subdomains
    targets = [domain, f"www.{domain}", f"dev.{domain}", f"staging.{domain}"]
    
    for sub in targets:
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(sub, 'CNAME'))
            
            for rdata in answers:
                cname = str(rdata.target).lower()
                for sig, name in signatures.items():
                    if sig in cname:
                        # Potential takeover! Now check if the target is actually dead
                        try:
                            # We attempt a simple GET to see if it returns a 404/Not Found characteristic
                            resp = await client.get(f"http://{sub}", timeout=5.0)
                            is_dead = False
                            if resp.status_code == 404: is_dead = True
                            elif "there is no app configured at this address" in resp.text.lower(): is_dead = True
                            elif "nosuchbucket" in resp.text.lower(): is_dead = True
                            
                            if is_dead:
                                findings.append(IntelligenceFinding(
                                    entity=sub,
                                    type="Subdomain Takeover",
                                    source="TakeoverProbe",
                                    confidence="High",
                                    color="red",
                                    category="Vulnerability",
                                    threat_level="High Risk",
                                    status=f"Potential {name} Takeover",
                                    resolution=cname,
                                    raw_data=f"CNAME: {cname} | HTTP: {resp.status_code}"
                                ))
                        except: pass
        except: continue
        
    return findings
