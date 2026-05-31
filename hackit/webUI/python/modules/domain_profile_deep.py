import httpx

from osint_common import normalize_target, make_finding


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = normalize_target(target)

    try:
        resp = await client.get(f"https://rdap.org/domain/{domain}", timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            registrar = data.get("registrar") or data.get("registrarName")
            if registrar:
                findings.append(make_finding(registrar, "Registrar", "RDAP Domain Profile", "High", "slate", raw_data=str(data)[:2000]))
            for event in data.get("events", []):
                action = event.get("eventAction", "event")
                date = event.get("eventDate", "")
                findings.append(make_finding(f"{action}: {date}", "Domain Lifecycle Event", "RDAP Domain Profile", "High", "slate"))
            for ns in data.get("nameservers", []):
                name = ns.get("ldhName")
                if name:
                    findings.append(make_finding(name, "Nameserver", "RDAP Domain Profile", "High", "blue"))
            for entity in data.get("entities", []):
                roles = ",".join(entity.get("roles", []))
                handle = entity.get("handle")
                if handle:
                    findings.append(make_finding(f"{handle} ({roles})", "RDAP Entity", "RDAP Domain Profile", "Medium", "purple"))
    except Exception:
        pass

    return findings

