import httpx
import asyncio
import re
from models import IntelligenceFinding

async def check_bitcoin_abuse(client, btc_address):
    # Public lookup via BitcoinAbuse (or similar scraping strategy if API requires key)
    # For demonstration, we'll hit the API (which typically needs a token, but some endpoints are open)
    # Using blockchain.info as a free alternative for transaction history
    url = f"https://blockchain.info/rawaddr/{btc_address}"
    try:
        resp = await client.get(url, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            total_received = data.get("total_received", 0)
            n_tx = data.get("n_tx", 0)
            
            return IntelligenceFinding(
                entity=btc_address,
                type="Crypto Wallet Tracing",
                source="Blockchain Explorer",
                confidence="Certain",
                color="orange",
                category="Financial Intel",
                threat_level="Medium Risk" if n_tx > 0 else "Informational",
                status="Active Wallet" if n_tx > 0 else "Empty Wallet",
                raw_data=f"Total TX: {n_tx} | Total Received: {total_received} Satoshi"
            )
    except:
        pass
    return None

async def crawl(target, client):
    findings = []
    
    # We will simulate finding a crypto address in the target.
    # In a full run, the crawler_core or HTML parser would pass found BTC addresses here.
    # We will just do a placeholder check or use the target directly if it IS a BTC address.
    
    btc_pattern = re.compile(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$')
    if btc_pattern.match(target):
        res = await check_bitcoin_abuse(client, target)
        if res:
            findings.append(res)
    else:
        # If the target is a domain, we could scrape its homepage for BTC addresses here
        # For performance, we'll keep it lightweight
        try:
            resp = await client.get(f"https://{target}", timeout=5.0)
            matches = btc_pattern.findall(resp.text)
            if matches:
                for match in set(matches):
                    res = await check_bitcoin_abuse(client, match)
                    if res:
                        findings.append(res)
        except:
            pass
            
    return findings
