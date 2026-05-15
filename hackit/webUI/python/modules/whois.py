import httpx
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """Who.is — fetches WHOIS data via the whoisjson free API."""
    findings = []
    try:
        url = f"https://api.hackertarget.com/whois/?q={target}"
        resp = await client.get(url)
        if resp.status_code == 200 and "error" not in resp.text.lower():
            text = resp.text
            # Parse key WHOIS fields
            fields = {
                "Registrar": "Registrar",
                "Creation Date": "Domain Created",
                "Registry Expiry Date": "Domain Expires",
                "Name Server": "Nameserver",
                "Registrant Organization": "Organization",
                "Registrant Country": "Country",
            }
            for key, ftype in fields.items():
                for line in text.splitlines():
                    if key.lower() in line.lower() and ':' in line:
                        value = line.split(':', 1)[1].strip()
                        if value:
                            findings.append(IntelligenceFinding(
                                entity=value,
                                type=f"Whois {ftype}",
                                source="Who.is",
                                confidence="High",
                                color="slate"
                            ))
                        break
    except Exception as e:
        print(f"[Who.is] Error: {e}")
    return findings
