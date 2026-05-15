import httpx
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """Intelligence X — queries the free phonebook API for email/subdomain enumeration."""
    findings = []
    try:
        # IntelX phonebook (free)
        url = f"https://phonebook.cz/api/v1/search?query={target}&type=domain&limit=20"
        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("results", []):
                entity = item if isinstance(item, str) else item.get("value", "")
                if entity:
                    etype = "Email Address" if "@" in entity else "Subdomain"
                    findings.append(IntelligenceFinding(
                        entity=entity,
                        type=etype,
                        source="Intelligence X",
                        confidence="High",
                        color="red" if "@" in entity else "blue"
                    ))
    except Exception as e:
        print(f"[IntelX] Error: {e}")
    return findings
