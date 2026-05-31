import httpx
from urllib.parse import urlparse

from models import IntelligenceFinding
from osint_common import normalize_target, extract_emails, classify_url, make_finding


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = normalize_target(target)
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=timestamp,original,statuscode,mimetype&collapse=urlkey&limit=250"

    try:
        resp = await client.get(url, timeout=12.0)
        if resp.status_code != 200:
            return findings
        rows = resp.json()
        if not rows or len(rows) < 2:
            return findings

        for row in rows[1:]:
            if len(row) < 2:
                continue
            original = row[1]
            status = row[2] if len(row) > 2 else ""
            kind = classify_url(original)
            color = "blue"
            threat = "Informational"
            if kind == "Sensitive URL":
                color, threat = "red", "High Risk"
            elif kind in {"API Endpoint", "URL Parameter"}:
                color, threat = "orange", "Elevated Risk"

            findings.append(make_finding(
                original, kind, "Wayback Deep URL Miner", "Medium", color,
                threat_level=threat, status=status or "Archived",
                raw_data=" | ".join(row),
                tags=["archive", "url-mining"],
            ))

            host = urlparse(original).hostname
            if host and (host == domain or host.endswith("." + domain)):
                findings.append(make_finding(host, "Subdomain", "Wayback Deep URL Miner", "Medium", "blue"))

        text_blob = "\n".join(r[1] for r in rows[1:] if len(r) > 1)
        for email in extract_emails(text_blob, domain)[:50]:
            findings.append(make_finding(email, "Email Address", "Wayback Deep URL Miner", "Medium", "purple"))
    except Exception:
        pass
    return findings

