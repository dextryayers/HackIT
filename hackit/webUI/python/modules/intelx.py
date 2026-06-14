import httpx
import json
from models import IntelligenceFinding

INTELX_BASE = "https://2.intelx.io"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
INTELX_KEY = ""

SEARCH_TYPES = {
    1: "Email",
    2: "Domain",
    3: "URL",
    4: "IP",
    5: "CIDR",
    6: "Phone",
    7: "Person",
    8: "Paste",
    9: "Darknet",
    10: "PGP Key",
}

LEAK_DATA_CLASSIFICATIONS = {
    "email": {"type": "Contact Data", "severity": "Medium", "color": "orange"},
    "password": {"type": "Credential", "severity": "Critical", "color": "red"},
    "credit": {"type": "Financial Data", "severity": "Critical", "color": "red"},
    "ssn": {"type": "Personal ID", "severity": "Critical", "color": "red"},
    "phone": {"type": "Contact Data", "severity": "High", "color": "orange"},
    "address": {"type": "Personal Data", "severity": "Medium", "color": "orange"},
    "ip": {"type": "Network Data", "severity": "Low", "color": "slate"},
    "paste": {"type": "Paste Leak", "severity": "High", "color": "red"},
    "darknet": {"type": "Darknet Listing", "severity": "Critical", "color": "red"},
    "domain": {"type": "Domain Info", "severity": "Medium", "color": "blue"},
}

def classify_intelx_result(selector_value: str, selector_type: int) -> dict:
    sv_lower = selector_value.lower()
    classification = {"type": "IntelX Data", "severity": "Informational", "color": "slate", "category": "General"}
    stype = SEARCH_TYPES.get(selector_type, "Unknown")
    classification["search_type"] = stype
    for keyword, info in LEAK_DATA_CLASSIFICATIONS.items():
        if keyword in sv_lower:
            classification["type"] = info["type"]
            classification["severity"] = info["severity"]
            classification["color"] = info["color"]
            classification["category"] = keyword
            break
    if selector_type == 1:
        classification["category"] = "email"
        classification["type"] = "Email Exposure"
        classification["severity"] = "High"
        classification["color"] = "red"
    elif selector_type == 2:
        classification["category"] = "domain"
        classification["type"] = "Domain Discovery"
    elif selector_type == 8:
        classification["category"] = "paste"
        classification["type"] = "Paste Leak"
        classification["severity"] = "High"
        classification["color"] = "red"
    elif selector_type == 9:
        classification["category"] = "darknet"
        classification["type"] = "Darknet Source"
        classification["severity"] = "Critical"
        classification["color"] = "red"
    return classification

async def phonebook_search(target: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await client.post(
            f"{INTELX_BASE}/phonebook/search",
            json={"term": target, "maxresults": 100, "browseentries": 1},
            timeout=20.0,
            headers={
                "User-Agent": UA,
                "x-key": INTELX_KEY,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        if resp.status_code == 200:
            data = resp.json()
            for entry in data.get("selectors", [])[:60]:
                selector = entry.get("selectorvalue", "")
                sel_type = entry.get("type", 0)
                if not selector:
                    continue
                classification = classify_intelx_result(selector, sel_type)
                results.append({
                    "value": selector,
                    "type_id": sel_type,
                    "type_name": classification.get("search_type", "Unknown"),
                    "classification": classification["type"],
                    "severity": classification["severity"],
                    "color": classification["color"],
                    "category": classification["category"],
                    "source": "IntelX Phonebook",
                })
            if data.get("selectors"):
                results.append({
                    "value": f"{len(data['selectors'])} selectors found in IntelX phonebook",
                    "type_name": "Summary",
                    "classification": "IntelX Summary",
                    "severity": "Informational",
                    "color": "purple",
                    "category": "summary",
                    "source": "IntelX Phonebook",
                })
            status = data.get("status", "")
            if status:
                results.append({
                    "value": f"Search status: {status}",
                    "type_name": "Status",
                    "classification": "IntelX Status",
                    "severity": "Informational",
                    "color": "slate",
                    "category": "status",
                    "source": "IntelX Phonebook",
                })
    except Exception as e:
        results.append({
                    "value": f"Phonebook error: {str(e)[:100]}",
                    "type_name": "Error",
                    "classification": "IntelX Error",
                    "severity": "Informational",
                    "color": "red",
                    "category": "error",
                    "source": "IntelX Phonebook",
                })
    return results

async def pastebin_search(target: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await client.get(
            f"{INTELX_BASE}/paste/search?term={target}&limit=50",
            timeout=15.0,
            headers={
                "User-Agent": UA,
                "x-key": INTELX_KEY,
                "Accept": "application/json",
            },
        )
        if resp.status_code == 200:
            data = resp.json()
            for paste in data.get("pastes", [])[:30]:
                paste_id = paste.get("id", paste.get("pasteid", ""))
                paste_title = paste.get("title", paste.get("name", ""))
                paste_date = paste.get("date", paste.get("timestamp", ""))
                paste_source = paste.get("source", "")
                if paste_id:
                    result = {
                        "value": f"{paste_title} ({paste_id[:16]})" if paste_title else paste_id[:16],
                        "type_name": "Paste",
                        "classification": "Paste Leak",
                        "severity": "High",
                        "color": "red",
                        "category": "paste",
                        "source": "IntelX Paste",
                    }
                    if paste_date:
                        result["value"] += f" [{paste_date}]"
                    if paste_source:
                        result["source_detail"] = paste_source
                    results.append(result)
            if data.get("pastes"):
                results.append({
                    "value": f"{len(data['pastes'])} pastes found for {target}",
                    "type_name": "Paste Summary",
                    "classification": "IntelX Paste Summary",
                    "severity": "Informational",
                    "color": "purple",
                    "category": "summary",
                    "source": "IntelX Paste",
                })
    except Exception as e:
        results.append({
                    "value": f"Paste search error: {str(e)[:100]}",
                    "type_name": "Error",
                    "classification": "IntelX Error",
                    "severity": "Informational",
                    "color": "red",
                    "category": "error",
                    "source": "IntelX Paste",
                })
    return results

async def darknet_search(target: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await client.get(
            f"{INTELX_BASE}/darknet/search?term={target}&limit=50",
            timeout=15.0,
            headers={
                "User-Agent": UA,
                "x-key": INTELX_KEY,
                "Accept": "application/json",
            },
        )
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("entries", [])[:30]:
                entry_id = item.get("id", "")
                entry_title = item.get("title", item.get("name", ""))
                entry_source = item.get("source", "")
                entry_date = item.get("date", "")
                if entry_id:
                    result = {
                        "value": f"{entry_title} ({entry_id[:16]})" if entry_title else entry_id[:16],
                        "type_name": "Darknet Entry",
                        "classification": "Darknet Listing",
                        "severity": "Critical",
                        "color": "red",
                        "category": "darknet",
                        "source": "IntelX Darknet",
                    }
                    if entry_source:
                        result["source_detail"] = entry_source
                    if entry_date:
                        result["value"] += f" [{entry_date}]"
                    results.append(result)
            if data.get("entries"):
                results.append({
                    "value": f"{len(data['entries'])} darknet entries for {target}",
                    "type_name": "Darknet Summary",
                    "classification": "IntelX Darknet Summary",
                    "severity": "Informational",
                    "color": "purple",
                    "category": "summary",
                    "source": "IntelX Darknet",
                })
    except Exception as e:
        results.append({
                    "value": f"Darknet search error: {str(e)[:100]}",
                    "type_name": "Error",
                    "classification": "IntelX Error",
                    "severity": "Informational",
                    "color": "red",
                    "category": "error",
                    "source": "IntelX Darknet",
                })
    return results

def score_source_diversity(pb_count: int, paste_count: int, darknet_count: int) -> str:
    sources = 0
    if pb_count > 0:
        sources += 1
    if paste_count > 0:
        sources += 1
    if darknet_count > 0:
        sources += 1
    total = pb_count + paste_count + darknet_count
    if sources >= 3 and total > 50:
        return "Very High"
    elif sources >= 2 or total > 30:
        return "High"
    elif sources >= 1 or total > 10:
        return "Medium"
    return "Low"

def categorize_threat(results: list) -> str:
    for r in results:
        cat = r.get("category", "")
        if cat in ("darknet", "credential", "financial"):
            return "Critical"
        if cat == "paste":
            return "High"
        if cat == "email":
            return "Medium"
    return "Informational"

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    phonebook_results = await phonebook_search(domain, client)
    paste_results = await pastebin_search(domain, client)
    darknet_results = await darknet_search(domain, client)

    all_results = phonebook_results + paste_results + darknet_results

    pb_count = len([r for r in phonebook_results if r.get("category") != "error" and r.get("category") != "summary" and r.get("category") != "status"])
    paste_count = len([r for r in paste_results if r.get("category") != "error" and r.get("category") != "summary"])
    darknet_count = len([r for r in darknet_results if r.get("category") != "error" and r.get("category") != "summary"])

    for result in all_results:
        try:
            sev = result.get("severity", "Informational")
            sev_color = result.get("color", "slate")
            source_tag = result.get("category", "general")
            tags = [source_tag]
            if result.get("source_detail"):
                tags.append(result["source_detail"].lower().replace(" ", "-"))

            finding = IntelligenceFinding(
                entity=result["value"][:200],
                type=result.get("classification", "IntelX Data"),
                source=result.get("source", "IntelligenceX"),
                confidence="Medium",
                color=sev_color,
                threat_level=sev if sev in ("Critical", "High", "Medium", "Low") else "Informational",
                status="Identified",
                raw_data=json.dumps(result)[:1000] if result else "",
                tags=tags,
            )
            if result.get("type_name") and result["type_name"] not in ("Summary", "Status", "Error"):
                finding.type = f"IntelX: {result['type_name']}"
            findings.append(finding)
        except Exception:
            continue

    if all_results:
        diversity = score_source_diversity(pb_count, paste_count, darknet_count)
        overall_threat = categorize_threat(all_results)
        color_map = {"Critical": "red", "High": "orange", "Medium": "orange", "Low": "slate", "Informational": "emerald"}
        findings.append(IntelligenceFinding(
            entity=f"IntelX summary: {pb_count} phonebook + {paste_count} paste + {darknet_count} darknet (threat: {overall_threat}, diversity: {diversity})",
            type="IntelX Intelligence Summary",
            source="IntelligenceX",
            confidence="High",
            color=color_map.get(overall_threat, "purple"),
            threat_level=overall_threat if overall_threat in ("Critical", "High", "Medium") else "Informational",
            status="Aggregated",
            raw_data=f"Phonebook: {pb_count}, Pastes: {paste_count}, Darknet: {darknet_count}, Diversity: {diversity}",
            tags=["intelx-summary", f"threat-{overall_threat.lower().replace(' ', '-')}"],
        ))

    return findings
