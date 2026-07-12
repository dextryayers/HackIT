import httpx, re
from typing import List
from settings_store import get_api_key
from module_common import safe_fetch_json, safe_fetch, make_finding, classify_email

API_URL = "https://emailrep.io/{email}"

async def crawl(target: str, client: httpx.AsyncClient) -> List:
    findings = []
    email = target.strip().lower()
    if "@" not in email:
        return findings

    api_key = get_api_key("email_rep")
    headers = {"Key": api_key} if api_key else {}
    headers["User-Agent"] = "Mozilla/5.0"

    data = await safe_fetch_json(client, API_URL.format(email=email), headers=headers)
    if not data:
        return findings

    if data.get("email"):
        findings.append(make_finding(
            entity=email, ftype="EmailRep: Profile",
            source="EmailRep", confidence="High", color="pink",
            threat_level="Informational", status="Analyzed",
            raw_data=f"reputation={data.get('reputation','?')}, details={data.get('details',{})}",
            tags=["emailrep", "email", "profile"],
        ))

    if data.get("suspicious"):
        findings.append(make_finding(
            entity=email, ftype="EmailRep: Suspicious",
            source="EmailRep", confidence="High", color="red",
            threat_level="High Risk", status="Suspicious",
            tags=["emailrep", "suspicious"],
        ))

    if data.get("details"):
        details = data["details"]
        if details.get("blacklisted"):
            findings.append(make_finding(
                entity=email, ftype="EmailRep: Blacklisted",
                source="EmailRep", confidence="High", color="red",
                threat_level="Critical", status="Blacklisted",
                tags=["emailrep", "blacklist"],
            ))
        if details.get("malicious_activity"):
            findings.append(make_finding(
                entity=email, ftype="EmailRep: Malicious Activity",
                source="EmailRep", confidence="High", color="red",
                threat_level="Critical", status="Malicious",
                tags=["emailrep", "malicious"],
            ))
        if details.get("spam"):
            findings.append(make_finding(
                entity=email, ftype="EmailRep: Spam Reported",
                source="EmailRep", confidence="Medium", color="orange",
                threat_level="Elevated Risk", status="Spam",
                tags=["emailrep", "spam"],
            ))
        if details.get("credentials_leaked"):
            findings.append(make_finding(
                entity=email, ftype="EmailRep: Credentials Leaked",
                source="EmailRep", confidence="High", color="red",
                threat_level="Critical", status="Leaked",
                tags=["emailrep", "leak", "credential"],
            ))
        if details.get("data_breach"):
            findings.append(make_finding(
                entity=email, ftype="EmailRep: Data Breach",
                source="EmailRep", confidence="High", color="red",
                threat_level="Critical", status="Breached",
                tags=["emailrep", "breach"],
            ))

    if data.get("last_breach"):
        findings.append(make_finding(
            entity=f"Last Breach: {data['last_breach']}",
            ftype="EmailRep: Last Breach",
            source="EmailRep", confidence="Medium", color="orange",
            threat_level="High Risk", status="Historical",
            tags=["emailrep", "breach"],
        ))

    email_class = classify_email(email)
    if email_class != "personal":
        findings.append(make_finding(
            entity=f"Email type: {email_class}",
            ftype="EmailRep: Classification",
            source="EmailRep", confidence="Medium", color="slate",
            threat_level="Informational", status="Classified",
            tags=["emailrep", "classification"],
        ))

    if not findings:
        findings.append(make_finding(
            entity=email, ftype="EmailRep: No Data",
            source="EmailRep", confidence="Low", color="emerald",
            threat_level="Informational", status="Clean",
            tags=["emailrep", "empty"],
        ))

    return findings
