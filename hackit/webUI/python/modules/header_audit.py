import re
import httpx
from module_base import BaseScanner

SECURITY_HEADERS = {
    "Content-Security-Policy": ("CSP","critical","Prevents XSS and data injection attacks"),
    "Strict-Transport-Security": ("HSTS","critical","Enforces HTTPS connections"),
    "X-Frame-Options": ("X-Frame-Options","high","Prevents clickjacking"),
    "X-Content-Type-Options": ("X-Content-Type-Options","high","Prevents MIME-type sniffing"),
    "Referrer-Policy": ("Referrer-Policy","medium","Controls referrer information"),
    "Permissions-Policy": ("Permissions-Policy","medium","Controls browser features"),
    "Cross-Origin-Opener-Policy": ("COOP","medium","Isolates cross-origin windows"),
    "Cross-Origin-Resource-Policy": ("CORP","medium","Controls resource sharing"),
    "Cross-Origin-Embedder-Policy": ("COEP","medium","Requires CORP for cross-origin resources"),
}

SECURITY_HEADERS_EXTRA = {
    "X-Powered-By": ("X-Powered-By","low","Information disclosure"),
    "X-AspNet-Version": ("X-AspNet-Version","low","ASP.NET version disclosure"),
    "X-Generator": ("X-Generator","low","Site generator disclosure"),
    "X-Varnish": ("X-Varnish","low","Varnish cache header"),
    "X-Cache": ("X-Cache","low","Cache status"),
    "X-Served-By": ("X-Served-By","low","Server identifier"),
    "X-Request-Id": ("X-Request-Id","low","Request tracking"),
    "X-Amzn-Trace-Id": ("X-Amzn-Trace-Id","low","AWS trace identifier"),
    "X-Runtime": ("X-Runtime","low","App runtime indicator"),
    "Access-Control-Allow-Origin": ("ACAO","high","CORS origin policy"),
    "Access-Control-Allow-Methods": ("ACAM","medium","CORS allowed methods"),
    "Access-Control-Allow-Credentials": ("ACAC","high","CORS credentials"),
    "Set-Cookie": ("Set-Cookie","high","Cookie configuration"),
    "Cache-Control": ("Cache-Control","medium","Cache policy"),
    "WWW-Authenticate": ("WWW-Authenticate","high","Authentication requirement"),
    "X-Permitted-Cross-Domain-Policies": ("X-Permitted-Cross-Domain-Policies","medium","Flash cross-domain policy"),
    "Public-Key-Pins": ("HPKP","high","Certificate pinning (deprecated)"),
    "Expect-CT": ("Expect-CT","medium","Certificate transparency"),
    "NEL": ("NEL","low","Network Error Logging"),
    "Feature-Policy": ("Feature-Policy","medium","Legacy feature policy"),
}

CDN_INDICATORS = {
    "cf-ray": "Cloudflare", "x-akamai-transformed": "Akamai",
    "x-fastly-request-id": "Fastly", "x-amz-cf-id": "AWS CloudFront",
    "x-sucuri-id": "Sucuri WAF", "x-azure-ref": "Azure CDN",
    "x-edge-location": "Edge Location",
}

SIGNATURE_MAP = {
    "nginx":"Nginx","apache":"Apache","cloudflare":"Cloudflare",
    "akamai":"Akamai","iis":"Microsoft IIS","lighttpd":"Lighttpd",
    "caddy":"Caddy","openresty":"OpenResty","gunicorn":"Gunicorn",
    "uvicorn":"Uvicorn","express":"Express.js","tomcat":"Apache Tomcat",
    "jetty":"Jetty","gws":"Google Web Server","gfe":"Google Front End",
    "cloudfront":"AWS CloudFront","kestrel":"Kestrel (.NET Core)",
    "varnish":"Varnish Cache","squid":"Squid Proxy","haproxy":"HAProxy",
    "envoy":"Envoy Proxy","traefik":"Traefik","litespeed":"LiteSpeed",
    "modsecurity":"ModSecurity","bigip":"F5 BIG-IP","imperva":"Imperva WAF",
}

GRADE_MAP = {10:"A+",9:"A",8:"B",7:"C",6:"D",5:"E",4:"F",3:"F",2:"F",1:"F",0:"F"}

class HeaderAuditScanner(BaseScanner):
    name = "header_audit"

    def _grade(self, headers: dict) -> tuple:
        score = 0
        details = []
        critical = {"strict-transport-security":"HSTS","content-security-policy":"CSP",
                     "x-frame-options":"XFO","x-content-type-options":"XCTO"}
        for h,n in critical.items():
            if h in headers: score+=2; details.append(f"{n}:+2")
            else: details.append(f"{n}:0")
        for h in ["referrer-policy","permissions-policy","cross-origin-opener-policy"]:
            if h in headers: score+=0.5; details.append(f"{h}:+0.5")
        cc = headers.get("cache-control","").lower()
        if "no-store" in cc: score+=0.5; details.append("Cache:no-store+0.5")
        if not headers.get("server",""): score+=0.5; details.append("Server-hide:+0.5")
        if not headers.get("x-powered-by",""): score+=0.5; details.append("Powered-hide:+0.5")
        grade = GRADE_MAP.get(int(score),"F")
        return grade, score, details

    async def scan(self) -> list:
        results = []
        base_url = f"https://{self.target}"
        resp = await self.safe_request(base_url, timeout=15, follow_redirects=True, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        })
        if not resp:
            return results

        headers = dict(resp.headers)
        status = resp.status_code

        f = self.finding(entity=str(status), ftype="HTTP Status Code",
            confidence="High", color="emerald" if status<400 else "orange",
            threat_level="Informational" if status<400 else "Standard Target",
            raw_data=f"Response status: {status}")
        if f: results.append(f)

        for hkey,(display,severity,desc) in SECURITY_HEADERS.items():
            val = headers.get(hkey.lower())
            if val:
                color = "emerald" if severity=="critical" else ("blue" if severity=="high" else "slate")
                f = self.finding(entity=f"{display}: {val[:80]}", ftype=f"Security Header: {display} (Present)",
                    confidence="High", color=color, threat_level="Informational", status="Implemented",
                    raw_data=f"{hkey}: {val[:2000]}", tags=[severity])
                if f: results.append(f)
                if hkey=="Strict-Transport-Security":
                    vl = val.lower()
                    feats = []
                    if "max-age=" in vl: feats.append("max-age set")
                    if "includesubdomains" in vl: feats.append("includeSubDomains")
                    if "preload" in vl: feats.append("preload ready")
                    if feats:
                        f = self.finding(entity=f"HSTS: {', '.join(feats)}", ftype="HSTS Configuration",
                            confidence="High", color="emerald" if "preload" in feats else "blue",
                            threat_level="Informational", tags=["hsts","security"])
                        if f: results.append(f)
                if hkey=="Content-Security-Policy":
                    vl = val.lower()
                    issues = []
                    if "unsafe-inline" in vl: issues.append("allows unsafe-inline")
                    if "unsafe-eval" in vl: issues.append("allows unsafe-eval")
                    if "*" in vl and "default-src" in vl: issues.append("wildcard default-src")
                    if issues:
                        f = self.finding(entity=f"CSP issues: {', '.join(issues)}", ftype="CSP Weakness",
                            confidence="High", color="red", threat_level="Elevated Risk",
                            raw_data=val[:500], tags=["csp","weakness"])
                        if f: results.append(f)
                if hkey=="Access-Control-Allow-Origin" and (val=="*" or "null" in val.lower()):
                    f = self.finding(entity=f"CORS misconfiguration: ACAO = {val}", ftype="CORS Misconfiguration",
                        confidence="High", color="red", threat_level="High Risk",
                        raw_data=val[:500], tags=["cors","misconfiguration"])
                    if f: results.append(f)
            else:
                color = "red" if severity=="critical" else ("orange" if severity=="high" else "yellow")
                f = self.finding(entity=display, ftype=f"Missing Security Header: {display}",
                    confidence="High", color=color, category="Security & Exposure Analysis",
                    threat_level="High Risk" if severity=="critical" else ("Elevated Risk" if severity=="high" else "Informational"),
                    status="Missing", raw_data=f"Missing: {hkey} - {desc}", tags=[severity])
                if f: results.append(f)

        for hkey,(display,severity,desc) in SECURITY_HEADERS_EXTRA.items():
            val = headers.get(hkey.lower())
            if val:
                f = self.finding(entity=f"{display}: {val[:120]}", ftype=f"Extra Header: {display}",
                    confidence="High", color="orange" if severity=="high" else "slate",
                    threat_level="Informational", status="Present",
                    raw_data=f"{hkey}: {val[:2000]}", tags=[severity])
                if f: results.append(f)

        for key, name in CDN_INDICATORS.items():
            if key in headers:
                f = self.finding(entity=name, ftype="CDN / Reverse Proxy",
                    confidence="High", color="orange", threat_level="Informational",
                    raw_data=f"Detected via {key}: {headers[key]}")
                if f: results.append(f)

        server = headers.get("server","")
        if server:
            matched = False
            for sig, ftype in SIGNATURE_MAP.items():
                if sig in server.lower():
                    f = self.finding(entity=f"{ftype}: {server[:200]}", ftype="Server Fingerprint",
                        confidence="High", color="indigo", threat_level="Informational",
                        status="Detected", raw_data=f"Server: {server}",
                        tags=["server", ftype.lower().replace(" ","-")])
                    if f: results.append(f)
                    matched=True; break
            if not matched:
                f = self.finding(entity=server[:200], ftype="Web Server (Unknown)",
                    confidence="High", color="slate", threat_level="Informational", status="Detected")
                if f: results.append(f)
        else:
            f = self.finding(entity="No Server header - information hidden", ftype="Server Header Hidden",
                confidence="Medium", color="emerald", threat_level="Informational",
                tags=["security","server-hiding"])
            if f: results.append(f)

        for info_h in ["X-Powered-By","X-Generator","X-AspNet-Version","X-Runtime","Via"]:
            val = headers.get(info_h.lower())
            if val:
                f = self.finding(entity=val[:200], ftype=f"Technology: {info_h}",
                    confidence="High", color="purple", threat_level="Informational",
                    raw_data=f"{info_h}: {val[:500]}")
                if f: results.append(f)

        cookies_raw = headers.get("set-cookie","")
        if cookies_raw:
            for cookie in cookies_raw.split("\n"):
                cookie = cookie.strip()
                if not cookie: continue
                parts = cookie.split(";")[0]
                f = self.finding(entity=parts[:150], ftype="Cookie Set",
                    confidence="Medium", color="yellow", threat_level="Informational",
                    raw_data=cookie[:500])
                if f: results.append(f)
                cl = cookie.lower()
                issues = []
                if "secure" not in cl: issues.append("Missing Secure flag")
                if "httponly" not in cl: issues.append("Missing HttpOnly flag")
                if "samesite" not in cl: issues.append("Missing SameSite attribute")
                if issues:
                    f = self.finding(entity=f"Cookie '{parts[:50]}': {', '.join(issues)}",
                        ftype="Cookie Security Issue", confidence="High", color="orange",
                        threat_level="Elevated Risk", raw_data=cookie[:500], tags=["cookie","security"])
                    if f: results.append(f)
                if "samesite=none" in cl and "secure" not in cl:
                    f = self.finding(entity=f"Cookie '{parts[:50]}' SameSite=None without Secure",
                        ftype="Cookie Vulnerability", confidence="High", color="red",
                        threat_level="High Risk", raw_data=cookie[:500], tags=["cookie","vulnerability"])
                    if f: results.append(f)

        ch_found = {ch: headers[ch.lower()] for ch in ["Cache-Control","Pragma","Expires","ETag","Age","X-Cache"] if ch.lower() in headers}
        if ch_found:
            f = self.finding(entity=f"Cache headers: {', '.join(ch_found.keys())}", ftype="Cache Headers Present",
                confidence="Medium", color="slate", threat_level="Informational",
                raw_data=str(ch_found)[:500], tags=["cache","headers"])
            if f: results.append(f)

        cc = headers.get("cache-control","")
        if cc:
            for directive, meaning in [("no-store","Sensitive - no caching"),("no-cache","Must revalidate"),
                                        ("must-revalidate","Must revalidate"),("public","Publicly cacheable"),
                                        ("private","Private cache only"),("max-age=0","No caching")]:
                if directive in cc.lower():
                    f = self.finding(entity=f"Cache-Control: {directive} - {meaning}", ftype="Cache Directive",
                        confidence="High", color="orange" if "no-store" in directive else "slate",
                        threat_level="Elevated Risk" if "no-store" in directive else "Informational",
                        tags=["cache", directive])
                    if f: results.append(f)

        location = headers.get("location")
        if location:
            f = self.finding(entity=location[:300], ftype="Redirect Target",
                confidence="High", color="slate", threat_level="Informational",
                raw_data=f"Redirects to: {location}")
            if f: results.append(f)

        via = headers.get("via","")
        if via:
            f = self.finding(entity=f"Via: {via[:200]}", ftype="Proxy Chain",
                confidence="Medium", color="slate", threat_level="Informational", tags=["proxy","via"])
            if f: results.append(f)

        xfo = headers.get("x-frame-options","").lower()
        if xfo and xfo not in ("deny","sameorigin"):
            f = self.finding(entity=f"X-Frame-Options: {xfo} - not DENY/SAMEORIGIN",
                ftype="Clickjacking Protection Issue", confidence="High", color="orange",
                threat_level="Elevated Risk", tags=["clickjacking"])
            if f: results.append(f)

        grade, score, details = self._grade(headers)
        f = self.finding(entity=f"Header Security Grade: {grade} (score: {score}/10)",
            ftype="Header Security Grade", confidence="High",
            color="emerald" if grade in ("A+","A") else ("orange" if grade in ("B","C") else "red"),
            threat_level="Informational" if grade in ("A+","A","B") else ("Elevated Risk" if grade in ("C","D") else "High Risk"),
            status=grade, raw_data=f"Score: {score}/10 | Details: {', '.join(details)}",
            tags=["grade","summary"])
        if f: results.append(f)
        return results


async def crawl(target: str, client: httpx.AsyncClient):
    scanner = HeaderAuditScanner(target, client)
    return await scanner.scan()
