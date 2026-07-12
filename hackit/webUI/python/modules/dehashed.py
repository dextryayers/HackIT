import httpx, json, base64
from typing import List
from settings_store import get_api_key
from module_common import safe_fetch, make_finding

DEHASHED_API = "https://api.dehashed.com/search"
DEHASHED_OPERATORS = {
    "email": "email", "username": "username", "domain": "domain",
    "ip": "ip_address", "name": "name", "phone": "phone",
    "password": "password", "vin": "vin", "address": "address",
}

async def crawl(target: str, client: httpx.AsyncClient) -> List:
    findings = []
    t = target.strip().lower()
    api_key = get_api_key("dehashed")
    if not api_key:
        return findings

    email_parts = api_key.split(":", 1)
    if len(email_parts) != 2:
        return findings
    api_email, api_secret = email_parts
    auth = base64.b64encode(f"{api_email}:{api_secret}".encode()).decode()
    headers = {"Accept": "application/json", "Authorization": f"Basic {auth}"}

    import socket
    query_type = "email" if "@" in t else "domain" if "." in t and " " not in t else "username"

    resp = await safe_fetch(client, f"{DEHASHED_API}?query={query_type}:{t}&size=50", headers=headers, timeout=20.0)
    if not resp:
        return findings

    try:
        data = resp.json()
    except Exception:
        return findings

    entries = data.get("entries", [])
    total = data.get("total", 0)
    balance = data.get("balance", 0)

    if total == 0:
        return findings

    findings.append(make_finding(
        entity=f"Dehashed: {total} records found for {t}",
        ftype="Dehashed: Coverage",
        source="Dehashed", confidence="High", color="red",
        threat_level="Critical", status=f"{total} Records",
        raw_data=f"total={total}, balance={balance}",
        tags=["dehashed", "breach", "coverage"],
    ))

    seen_dbs = set()
    for entry in entries[:30]:
        db_name = entry.get("database_name", "?")
        email = entry.get("email", "")
        username = entry.get("username", "")
        password = entry.get("password", "")
        hashed_pass = entry.get("hashed_password", "")

        if db_name not in seen_dbs:
            seen_dbs.add(db_name)
            findings.append(make_finding(
                entity=f"Breach: {db_name}",
                ftype="Dehashed: Database",
                source="Dehashed", confidence="High", color="red",
                threat_level="Critical", status="Breached",
                raw_data=f"email={email}, username={username}",
                tags=["dehashed", "breach", db_name.lower().replace(" ","-")],
            ))

        if password:
            findings.append(make_finding(
                entity=f"Password found: {password[:30]}",
                ftype="Dehashed: Credential",
                source="Dehashed", confidence="High", color="red",
                threat_level="Critical", status="Exposed",
                raw_data=f"database={db_name}, email={email}, username={username}",
                tags=["dehashed", "credential", "password"],
            ))

        if hashed_pass and not password:
            findings.append(make_finding(
                entity=f"Hashed password exposed ({db_name})",
                ftype="Dehashed: Hashed Credential",
                source="Dehashed", confidence="Medium", color="orange",
                threat_level="High Risk", status="Exposed",
                tags=["dehashed", "credential", "hashed"],
            ))

    return findings
