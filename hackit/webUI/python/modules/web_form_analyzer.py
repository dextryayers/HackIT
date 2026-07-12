import re
import httpx
from urllib.parse import urlparse
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

PII_FIELD_PATTERNS = {
    "email": r"\bemail\b|e-mail|mail\b",
    "phone": r"\bphone\b|telephone|mobile|cellular|tel\b",
    "address": r"\baddress\b|street|city|state|zip\b|postal|country",
    "credit_card": r"\b(credit.?card|cc.?number|card.?number|cvv|cvc|expiration|expiry)\b",
    "ssn": r"\b(ssn|social.?security|social.?insurance)\b",
    "password": r"\bpassword\b|passwd|pwd\b",
    "dob": r"\b(dob|date.?of.?birth|birthday|birth.?date)\b",
    "name": r"\b(full.?name|first.?name|last.?name|your.?name)\b",
    "username": r"\b(username|user.?name|login)\b",
}

CSRF_PATTERNS = [
    r"csrf", r"token", r"authenticity_token", r"_token", r"xsrf",
    r"csrfmiddlewaretoken", r"csrf_token", r"__RequestVerificationToken",
]

HIDDEN_FIELD_INDICATORS = [
    r"display\s*:\s*none",
    r"visibility\s*:\s*hidden",
    r"type\s*=\s*['\"]?hidden['\"]?",
    r"position\s*:\s*absolute",
    r"left\s*:\s*-\d+",
    r"opacity\s*:\s*0",
]

async def extract_forms(client: httpx.AsyncClient, url: str) -> list:
    forms = []
    try:
        resp = await safe_fetch(client,url, timeout=10.0, follow_redirects=True, headers={"User-Agent": UA})
        if resp.status_code == 200:
            html = resp.text
            form_pattern = re.compile(r"<form\s[^>]*>(.*?)</form\s*>", re.I | re.DOTALL)
            for fm in form_pattern.finditer(html):
                form_html = fm.group(0)
                form_info = {"action": "", "method": "get", "fields": [], "has_file_upload": False, "password_count": 0, "csrf_found": False, "hidden_fields": [], "pii_fields": []}

                action_m = re.search(r'action\s*=\s*["\'](.*?)["\']', form_html, re.I)
                if action_m:
                    form_info["action"] = action_m.group(1)

                method_m = re.search(r'method\s*=\s*["\'](.*?)["\']', form_html, re.I)
                if method_m:
                    form_info["method"] = method_m.group(1).lower()

                input_pattern = re.compile(r"<(input|select|textarea)\s[^>]*>", re.I)
                for inp in input_pattern.finditer(form_html):
                    inp_html = inp.group(0)
                    field = {"type": "", "name": "", "id": "", "value": ""}

                    type_m = re.search(r'type\s*=\s*["\'](.*?)["\']', inp_html, re.I)
                    if type_m:
                        field["type"] = type_m.group(1).lower()

                    name_m = re.search(r'name\s*=\s*["\'](.*?)["\']', inp_html, re.I)
                    if name_m:
                        field["name"] = name_m.group(1)

                    id_m = re.search(r'id\s*=\s*["\'](.*?)["\']', inp_html, re.I)
                    if id_m:
                        field["id"] = id_m.group(1)

                    val_m = re.search(r'value\s*=\s*["\'](.*?)["\']', inp_html, re.I)
                    if val_m:
                        field["value"] = val_m.group(1)

                    form_info["fields"].append(field)

                    if field["type"] == "file":
                        form_info["has_file_upload"] = True
                    if field["type"] == "password":
                        form_info["password_count"] += 1

                    field_name = (field.get("name", "") + " " + field.get("id", "")).lower()
                    for pii_type, pattern in PII_FIELD_PATTERNS.items():
                        if re.search(pattern, field_name, re.I):
                            form_info["pii_fields"].append({"field": field, "pii_type": pii_type})

                    if field["type"] == "hidden":
                        form_info["hidden_fields"].append(field)
                        for csrf_pat in CSRF_PATTERNS:
                            if re.search(csrf_pat, field_name, re.I):
                                form_info["csrf_found"] = True

                forms.append(form_info)
    except Exception:
        pass
    return forms

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    forms_data = {}
    for proto in ["https", "http"]:
        url = f"{proto}://{domain}"
        forms = await extract_forms(client, url)
        if forms:
            forms_data[url] = forms

    if not forms_data:
        findings.append(make_finding(
            entity=f"No forms found on {domain}",
            ftype="Form: No Forms",
            source="FormAnalyzer",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            tags=["forms", "none"]
        ))
        return findings

    total_forms = sum(len(forms) for forms in forms_data.values())
    total_fields = sum(len(f["fields"]) for f_list in forms_data.values() for f in f_list)

    findings.append(make_finding(
        entity=f"Found {total_forms} form(s) with {total_fields} field(s) on {domain}",
        ftype="Form: Overview",
        source="FormAnalyzer",
        confidence="High",
        color="blue",
        threat_level="Informational",
        raw_data=f"forms={total_forms}, fields={total_fields}",
        tags=["forms", "overview"]
    ))

    password_forms = 0
    file_upload_forms = 0
    csrf_protected = 0
    all_pii = []
    all_hidden = []

    for url, f_list in forms_data.items():
        for form in f_list:
            if form["password_count"] > 0:
                password_forms += 1
            if form["has_file_upload"]:
                file_upload_forms += 1
            if form["csrf_found"]:
                csrf_protected += 1
            all_pii.extend(form["pii_fields"])
            all_hidden.extend(form["hidden_fields"])

            action = form.get("action", "")
            form_method = form.get("method", "get")
            findings.append(make_finding(
                entity=f"Form: {form_method.upper()} -> {action or '(same page)'} ({len(form['fields'])} fields)",
                ftype="Form: Form Found",
                source="FormAnalyzer",
                confidence="High",
                color="slate",
                threat_level="Informational",
                raw_data=f"method={form_method}, action={action}, fields={len(form['fields'])}, has_password={form['password_count'] > 0}",
                tags=["forms", "form-detected"]
            ))

    if password_forms > 0:
        findings.append(make_finding(
            entity=f"Found {password_forms} form(s) with password fields",
            ftype="Form: Login Forms",
            source="FormAnalyzer",
            confidence="High",
            color="purple",
            threat_level="Informational",
            raw_data=f"password_forms={password_forms}",
            tags=["forms", "login", "authentication"]
        ))

    if file_upload_forms > 0:
        findings.append(make_finding(
            entity=f"Found {file_upload_forms} form(s) with file upload capability",
            ftype="Form: File Upload",
            source="FormAnalyzer",
            confidence="High",
            color="orange",
            threat_level="Elevated Risk",
            raw_data=f"upload_forms={file_upload_forms}",
            tags=["forms", "file-upload", "attack-surface"]
        ))

    findings.append(make_finding(
        entity=f"CSRF Protection: {csrf_protected}/{total_forms} forms have CSRF tokens",
        ftype="Form: CSRF Protection",
        source="FormAnalyzer",
        confidence="High",
        color="emerald" if csrf_protected == total_forms else "red",
        threat_level="Informational" if csrf_protected == total_forms else "High Risk",
        raw_data=f"csrf_protected={csrf_protected}, total={total_forms}",
        tags=["forms", "csrf", "security"]
    ))

    if all_pii:
        pii_types = {}
        for p in all_pii:
            pii_types[p["pii_type"]] = pii_types.get(p["pii_type"], 0) + 1
        findings.append(make_finding(
            entity=f"PII collection detected: {', '.join([f'{k}={v}' for k, v in pii_types.items()])}",
            ftype="Form: PII Collection",
            source="FormAnalyzer",
            confidence="High",
            color="red",
            threat_level="High Risk",
            raw_data=f"PII fields: {all_pii}",
            tags=["forms", "pii", "privacy"]
        ))

    if all_hidden:
        findings.append(make_finding(
            entity=f"Found {len(all_hidden)} hidden form fields (some may be honeypots)",
            ftype="Form: Hidden Fields",
            source="FormAnalyzer",
            confidence="Medium",
            color="orange",
            threat_level="Elevated Risk",
            raw_data=f"hidden_fields={all_hidden}",
            tags=["forms", "hidden", "honeypot"]
        ))

    findings.append(make_finding(
        entity=f"Form Analysis: {total_forms} forms, {password_forms} login, {file_upload_forms} upload, {csrf_protected} CSRF",
        ftype="Form: Summary",
        source="FormAnalyzer",
        confidence="High",
        color="blue",
        threat_level="Informational",
        raw_data=f"forms={total_forms}, login={password_forms}, upload={file_upload_forms}, csrf={csrf_protected}, pii={len(all_pii)}",
        tags=["forms", "summary"]
    ))

    return findings
