import re
import httpx
from urllib.parse import urlparse
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]

METHOD_RISK = {
    "GET": "Safe (read-only)",
    "POST": "Moderate (data submission)",
    "PUT": "High (file upload, modification)",
    "DELETE": "Critical (resource deletion)",
    "PATCH": "Moderate (partial modification)",
    "HEAD": "Safe (headers only)",
    "OPTIONS": "Safe (discovery)",
    "TRACE": "Critical (XST vulnerability)",
    "CONNECT": "High (proxy tunneling)",
}

METHOD_COLORS = {
    "GET": "emerald",
    "POST": "yellow",
    "PUT": "orange",
    "DELETE": "red",
    "PATCH": "orange",
    "HEAD": "slate",
    "OPTIONS": "blue",
    "TRACE": "red",
    "CONNECT": "red",
}

async def test_method(client: httpx.AsyncClient, url: str, method: str) -> dict:
    result = {"method": method, "status": 0, "allowed": False, "headers": {}, "body_preview": "", "elapsed": 0.0}
    try:
        resp = await safe_fetch(client, url, method=method, timeout=10.0, follow_redirects=False, headers={"User-Agent": UA})
        result["status"] = resp.status_code
        result["headers"] = {k.lower(): v for k, v in dict(resp.headers).items()}
        result["body_preview"] = resp.text[:200]
        result["elapsed"] = resp.elapsed.total_seconds()
        if resp.status_code not in (405, 501, 400):
            result["allowed"] = True
    except httpx.HTTPError:
        pass
    except Exception:
        pass
    return result

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    base_url = f"https://{domain}"
    for proto in ["https", "http"]:
        try:
            r = await safe_fetch(client,f"{proto}://{domain}", timeout=10.0, follow_redirects=True, headers={"User-Agent": UA})
            if r.status_code < 500:
                base_url = f"{proto}://{domain}"
                break
        except Exception:
            continue

    findings.append(make_finding(
        entity=f"Testing HTTP methods on {base_url}",
        ftype="HTTP Method: Scan Started",
        source="HTTPMethodAnalyzer",
        confidence="High",
        color="slate",
        threat_level="Informational",
        tags=["http-methods", "scan"]
    ))

    test_paths = ["/", "/api", "/admin", "/test", "/upload"]

    all_methods_status = {}
    risky_methods_enabled = []

    for method in HTTP_METHODS:
        for path in test_paths[:2]:
            url = f"{base_url}{path}"
            resp = await test_method(client, url, method)
            if resp["allowed"]:
                if method not in all_methods_status:
                    all_methods_status[method] = []
                all_methods_status[method].append({"path": path, "status": resp["status"], "headers": resp["headers"]})

    for method, entries in all_methods_status.items():
        for entry in entries:
            risk = METHOD_RISK.get(method, "Unknown")
            color = METHOD_COLORS.get(method, "slate")
            threat_map = {"Safe": "Informational", "Moderate": "Elevated Risk", "High": "High Risk", "Critical": "Critical"}
            threat = "Informational"
            for risk_word, threat_level in threat_map.items():
                if risk_word in risk:
                    threat = threat_level
                    break

            findings.append(make_finding(
                entity=f"HTTP {method} enabled on {entry['path']} -> HTTP {entry['status']} ({risk})",
                ftype=f"HTTP Method: {method}",
                source="HTTPMethodAnalyzer",
                confidence="High",
                color=color,
                threat_level=threat,
                status="Enabled" if method not in ("GET", "HEAD", "OPTIONS") else "Expected",
                raw_data=f"method={method}, path={entry['path']}, status={entry['status']}, risk={risk}",
                tags=["http-methods", method.lower(), "enabled"]
            ))

            if method in ("PUT", "DELETE", "TRACE", "CONNECT"):
                risky_methods_enabled.append(method)

    opt_result = await test_method(client, base_url, "OPTIONS")
    if opt_result["allowed"]:
        allow_header = opt_result["headers"].get("allow", "")
        if allow_header:
            allowed_methods = [m.strip() for m in allow_header.split(",")]
            findings.append(make_finding(
                entity=f"OPTIONS response: Allowed methods: {', '.join(allowed_methods)}",
                ftype="HTTP Method: OPTIONS Discovery",
                source="HTTPMethodAnalyzer",
                confidence="High",
                color="blue",
                threat_level="Informational",
                raw_data=f"allow_header={allow_header}",
                tags=["http-methods", "options", "discovery"]
            ))

    trace_result = await test_method(client, base_url, "TRACE")
    if trace_result["allowed"] and trace_result["status"] == 200:
        findings.append(make_finding(
            entity="HTTP TRACE method enabled - XST (Cross-Site Tracing) vulnerability possible",
            ftype="HTTP Method: TRACE XST",
            source="HTTPMethodAnalyzer",
            confidence="High",
            color="red",
            threat_level="Critical",
            status="Vulnerable",
            raw_data=f"TRACE enabled, body_preview={trace_result['body_preview'][:100]}",
            tags=["http-methods", "trace", "xst", "vulnerability", "critical"]
        ))

    put_result = await test_method(client, f"{base_url}/", "PUT")
    if put_result["allowed"]:
        put_body = "test_upload_content"
        try:
            put_resp = await safe_fetch(client, f"{base_url}/test_put_{domain.replace('.', '_')}.txt", method="PUT", content=put_body, headers={"User-Agent": UA, "Content-Type": "text/plain"})
            if put_resp.status_code in (200, 201, 204):
                findings.append(make_finding(
                    entity=f"PUT method allows file upload (HTTP {put_resp.status_code})",
                    ftype="HTTP Method: PUT Upload",
                    source="HTTPMethodAnalyzer",
                    confidence="High",
                    color="red",
                    threat_level="Critical",
                    status="Upload Possible",
                    raw_data=f"PUT upload to / resulted in HTTP {put_resp.status_code}",
                    tags=["http-methods", "put", "upload", "critical"]
                ))
        except Exception:
            pass

    connect_result = await test_method(client, base_url, "CONNECT")
    if connect_result["allowed"]:
        findings.append(make_finding(
            entity="HTTP CONNECT method enabled - possible proxy functionality",
            ftype="HTTP Method: CONNECT Proxy",
            source="HTTPMethodAnalyzer",
            confidence="High",
            color="red",
            threat_level="High Risk",
            status="Proxy Possible",
            tags=["http-methods", "connect", "proxy"]
        ))

    if not all_methods_status:
        findings.append(make_finding(
            entity="Only standard HTTP methods (GET/HEAD/POST) appear to be enabled",
            ftype="HTTP Method: Standard Only",
            source="HTTPMethodAnalyzer",
            confidence="Medium",
            color="emerald",
            threat_level="Informational",
            tags=["http-methods", "secure"]
        ))

    findings.append(make_finding(
        entity=f"HTTP Method Analysis: {len(all_methods_status)} methods enabled, {len(risky_methods_enabled)} risky ({', '.join(risky_methods_enabled) if risky_methods_enabled else 'None'})",
        ftype="HTTP Method: Summary",
        source="HTTPMethodAnalyzer",
        confidence="High",
        color="red" if risky_methods_enabled else "emerald",
        threat_level="Critical" if risky_methods_enabled else "Informational",
        raw_data=f"enabled_methods={list(all_methods_status.keys())}, risky={risky_methods_enabled}",
        tags=["http-methods", "summary"]
    ))

    return findings
