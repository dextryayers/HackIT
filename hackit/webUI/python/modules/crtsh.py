import httpx
from models import IntelligenceFinding
from collections import defaultdict

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = await client.get(url, timeout=20.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json() if isinstance(resp.text, str) and resp.text.startswith("[") else []
            if not data:
                return findings

            name_to_entries = defaultdict(list)
            seen_names = set()
            for item in data:
                name_value = item.get("name_value", "")
                common_name = item.get("common_name", "")
                issuer_name = item.get("issuer_name", "")
                not_before = item.get("not_before", "") or ""
                not_after = item.get("not_after", "") or ""
                id_val = item.get("id", 0)

                for raw_name in [name_value, common_name]:
                    if not raw_name:
                        continue
                    for sub in raw_name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith("." + domain) or sub == domain:
                            if "*" not in sub and sub not in seen_names:
                                seen_names.add(sub)
                                name_to_entries[sub].append({
                                    "issuer": issuer_name or "Unknown",
                                    "id": id_val,
                                    "not_before": not_before[:10] if not_before else "",
                                    "not_after": not_after[:10] if not_after else "",
                                })

            for sub, entries in name_to_entries.items():
                ids = [str(e["id"]) for e in entries[:3]]
                issuers = list(set(e["issuer"] for e in entries if e["issuer"] != "Unknown"))
                dates = []
                for e in entries:
                    if e["not_before"]:
                        dates.append(e["not_before"])
                earliest = min(dates) if dates else ""

                raw_parts = []
                if issuers:
                    raw_parts.append(f"Issuers: {', '.join(issuers[:3])}")
                if earliest:
                    raw_parts.append(f"Earliest: {earliest}")
                raw_parts.append(f"Cert IDs: {', '.join(ids)}")

                findings.append(IntelligenceFinding(
                    entity=sub,
                    type="Subdomain (Certificate Transparency)",
                    source="crt.sh",
                    confidence="High",
                    color="emerald",
                    category="Domain & DNS Enumeration",
                    threat_level="Standard Target",
                    status="Logged in CT",
                    raw_data=" | ".join(raw_parts)
                ))

            top_issuers = defaultdict(int)
            for entries in name_to_entries.values():
                for e in entries:
                    if e["issuer"] != "Unknown":
                        top_issuers[e["issuer"]] += 1

            if top_issuers:
                for issuer, count in sorted(top_issuers.items(), key=lambda x: -x[1])[:5]:
                    findings.append(IntelligenceFinding(
                        entity=f"{issuer}: {count} certificates",
                        type="Certificate Authority",
                        source="crt.sh",
                        confidence="High",
                        color="purple",
                        threat_level="Informational",
                        raw_data=f"CA {issuer} issued {count} certificates for {domain}"
                    ))

            if len(seen_names) > 10:
                findings.append(IntelligenceFinding(
                    entity=f"Total: {len(seen_names)} unique subdomains found",
                    type="Certificate Transparency Summary",
                    source="crt.sh",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    raw_data=f"{len(seen_names)} subdomains discovered via crt.sh"
                ))

        elif resp.status_code == 429:
            findings.append(IntelligenceFinding(
                entity="Rate limited by crt.sh",
                type="crt.sh Error",
                source="crt.sh",
                confidence="Medium",
                color="yellow",
                threat_level="Informational"
            ))
    except Exception as e:
        pass

    return findings
