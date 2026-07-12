import httpx, json
from typing import List
from urllib.parse import urlparse
from settings_store import get_api_key
from module_common import safe_fetch_json, safe_fetch, make_finding, is_ip, classify_email

INTELX_API = "https://2.intelx.io"
INTELX_TYPES = {"email": "email", "domain": "domain", "ip": "ip", "username": "username"}

async def crawl(target: str, client: httpx.AsyncClient) -> List:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    api_key = get_api_key("intelx")
    if not api_key:
        return findings

    headers = {"x-key": api_key, "x-request-id": "hackit-osint", "User-Agent": "Mozilla/5.0"}

    qtype = "domain" if "." in t and not t.startswith("@") else "email" if "@" in t else "username"

    search = await safe_fetch_json(client, f"{INTELX_API}/intelligent/search",
        method="POST",
        headers=headers,
        data=json.dumps({
            "term": t, "buckets": [], "lookuplevel": 0, "maxresults": 50,
            "timeout": 10, "datefrom": "", "dateto": "", "sort": 2, "media": 0,
            "terminate": [qtype],
        }),
        params={},
    )

    if not search or "status" not in search:
        return findings

    selector = search.get("id", "")
    if not selector:
        return findings

    import asyncio
    await asyncio.sleep(2)

    result_data = await safe_fetch_json(client, f"{INTELX_API}/intelligent/result",
        params={"id": selector, "limit": 20, "statistics": 1, "preview": 1, "bucket": ""},
        headers=headers,
    )
    if not result_data:
        return findings

    records = result_data.get("records", result_data.get("selectors", []))
    if not records:
        return findings

    total = len(records)
    findings.append(make_finding(
        entity=f"IntelX: {total} results for {t}",
        ftype="IntelX: Coverage",
        source="IntelX", confidence="High", color="red",
        threat_level="High Risk", status=f"{total} Records",
        tags=["intelx", "coverage"],
    ))

    for record in records[:30]:
        source = record.get("source", "?")
        name = record.get("name", record.get("selector", ""))
        bucket = record.get("bucket", "")
        preview = record.get("preview", record.get("value", ""))

        if name:
            findings.append(make_finding(
                entity=f"[{source}] {name[:80]}",
                ftype="IntelX: Record",
                source="IntelX", confidence="Medium", color="orange",
                threat_level="High Risk", status="Discovered",
                raw_data=f"bucket={bucket}, source={source}, preview={preview[:200]}",
                tags=["intelx", "record", bucket.lower().replace(" ","-")],
            ))

    statistics = result_data.get("statistics", {})
    if statistics:
        dist = ", ".join([f"{k}: {v}" for k, v in list(statistics.items())[:5]])
        findings.append(make_finding(
            entity=f"IntelX Distribution: {dist}",
            ftype="IntelX: Statistics",
            source="IntelX", confidence="Medium", color="slate",
            threat_level="Informational", status="Analyzed",
            tags=["intelx", "statistics"],
        ))

    return findings
