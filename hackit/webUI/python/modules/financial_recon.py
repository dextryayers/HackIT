import asyncio
from models import IntelligenceFinding

async def crawl(target, client):
    findings = []
    
    # Check for potential crypto addresses on home page or known patterns
    try:
        url = f"http://{target}"
        res = await client.get(url, timeout=5.0)
        content = res.text
        
        # Very basic regex for BTC/ETH (for demonstration)
        import re
        btc_pattern = r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}'
        eth_pattern = r'0x[a-fA-F0-9]{40}'
        
        btc_addresses = re.findall(btc_pattern, content)
        eth_addresses = re.findall(eth_pattern, content)
        
        for addr in set(btc_addresses):
            findings.append(IntelligenceFinding(
                entity=addr,
                type="Crypto | BTC Address",
                status="Identified",
                color="orange",
                source="HackIT FinancialRecon",
                resolution="Found on Page"
            ))
            
        for addr in set(eth_addresses):
            findings.append(IntelligenceFinding(
                entity=addr,
                type="Crypto | ETH Address",
                status="Identified",
                color="blue",
                source="HackIT FinancialRecon",
                resolution="Found on Page"
            ))
            
    except:
        pass
        
    return findings

SUPPORTED_TYPES = ["Domain"]
