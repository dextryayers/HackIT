import httpx
import asyncio
import re
import socket
import time
from urllib.parse import urlparse, quote
from models import IntelligenceFinding
from typing import List, Dict, Optional

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id", "__cfduid", "cf-chl-bypass", "cf-chl-opt"],
        "response_codes": [403, 503, 429],
        "block_page": ["cloudflare", "attention required", "please enable cookies", "checking your browser", "cf-ray:", "cloudflare-nginx", "just a moment", "verify you are human"],
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
    },
    "ModSecurity": {
        "headers": ["x-mod-security", "x-modsec"],
        "response_codes": [403, 406, 500, 501],
        "block_page": ["mod_security", "modsecurity", "not acceptable", "request blocked", "access denied by security policy", "modsecurity/"],
        "cookies": [],
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amzn-errortype", "x-amz-cf-id", "x-amz-cf-pop"],
        "response_codes": [403, 400, 502],
        "block_page": ["captcha", "aws waf", "amazon web services", "request blocked", "sorry, your request has been blocked", "awswaf"],
        "cookies": ["aws-waf-token", "aws-alb"],
    },
    "CloudFront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop", "x-cache", "via"],
        "response_codes": [403, 502, 503],
        "block_page": ["cloudfront", "amazon cloudfront"],
        "cookies": ["CloudFront-Policy", "CloudFront-Signature"],
    },
    "Akamai": {
        "headers": ["x-akamai-", "akamai-", "x-akamai-transformed", "x-akamai-config"],
        "response_codes": [403, 401, 421],
        "block_page": ["akamai", "reference number", "access denied", "akamaighost", "akamai ghost"],
        "cookies": ["ak_bmsc", "bm_sz", "_abck"],
    },
    "F5 BIG-IP ASM": {
        "headers": ["x-asm-", "x-asm_version", "x-wa-", "x-wa-info"],
        "response_codes": [403, 200, 500, 501],
        "block_page": ["the requested url was rejected", "please consult with your administrator", "support id", "f5 networks", "big-ip", "asm"],
        "cookies": ["ASM-Session", "LastMRH_Session", "MRHSession", "TS"],
    },
    "Imperva (Incapsula)": {
        "headers": ["x-iinfo", "visid_incap_", "incap_ses_"],
        "response_codes": [403, 509, 406],
        "block_page": ["incapsula", "imperva", "blocked because of malicious activity", "contact support for assistance", "imperva incapsula"],
        "cookies": ["incap_ses_", "visid_incap_", "nlbi_"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache", "x-sucuri-block"],
        "response_codes": [403, 412, 302],
        "block_page": ["sucuri", "cloudproxy", "website firewall", "access denied by sucuri", "sucuri.net"],
        "cookies": ["sucuri_cloudproxy", "sucuri_analytics"],
    },
    "Barracuda WAF": {
        "headers": ["x-barracuda-", "barracuda"],
        "response_codes": [403, 500, 501],
        "block_page": ["barracuda", "blocked by barracuda", "barracuda networks"],
        "cookies": ["barracuda_"],
    },
    "Fortinet FortiWeb": {
        "headers": ["x-fortinet-", "fortiweb", "x-fortiweb"],
        "response_codes": [403, 406, 501, 503],
        "block_page": ["fortiweb", "fortinet", "blocked by fortiweb", "attack detected"],
        "cookies": ["FORTIWAFSID"],
    },
    "Citrix NetScaler": {
        "headers": ["ns_client_ip", "ns_af", "x-ns-", "via"],
        "response_codes": [403, 400, 406],
        "block_page": ["netscaler", "citrix", "appfw"],
        "cookies": ["citrix_ns_id", "NSC_"],
    },
    "Radware": {
        "headers": ["x-sdn-", "radware", "x-radware"],
        "response_codes": [403, 503, 302],
        "block_page": ["radware", "appwall", "blocked by radware", "radware appwall"],
        "cookies": ["radi", "rw"],
    },
    "Palo Alto": {
        "headers": ["x-pan-", "pan"],
        "response_codes": [403, 500, 503],
        "block_page": ["panw", "palo alto", "threat blocked", "next-generation firewall"],
        "cookies": ["PANW"],
    },
    "StackPath": {
        "headers": ["x-stackpath-"],
        "response_codes": [403, 503, 301],
        "block_page": ["stackpath", "spedge", "stackpath cdn"],
        "cookies": ["stackpath"],
    },
    "Comodo WAF": {
        "headers": ["x-comodo-", "comodo"],
        "response_codes": [403, 302, 406],
        "block_page": ["comodo", "cwatch", "blocked by comodo", "comodo waf"],
        "cookies": ["comodo_"],
    },
    "WebARX": {
        "headers": ["x-webarx-"],
        "response_codes": [403, 401, 406],
        "block_page": ["webarx", "web application security"],
        "cookies": [],
    },
    "Reblaze": {
        "headers": ["x-reblaze-"],
        "response_codes": [403, 503, 301],
        "block_page": ["reblaze", "blocked", "reblaze waf"],
        "cookies": ["reblaze"],
    },
    "SafeLine": {
        "headers": ["x-safeline-", "safeline"],
        "response_codes": [403, 444, 406],
        "block_page": ["safeline", "chaitin", "safeline waf"],
        "cookies": [],
    },
    "Kona (Akamai)": {
        "headers": ["x-kona-", "kona"],
        "response_codes": [403, 419, 406],
        "block_page": ["kona", "akamai", "kona site defender"],
        "cookies": ["kona"],
    },
    "Airlock": {
        "headers": ["x-airlock-", "al-"],
        "response_codes": [403, 412, 406],
        "block_page": ["airlock", "ericson", "airlock waf"],
        "cookies": ["AL-SESS"],
    },
    "AppWall (Radware)": {
        "headers": ["x-appwall-"],
        "response_codes": [403, 500, 406],
        "block_page": ["appwall", "radware"],
        "cookies": [],
    },
    "Azure Application Gateway": {
        "headers": ["x-application-gateway", "x-azure-"],
        "response_codes": [403, 502, 503],
        "block_page": ["application gateway", "azure", "azure application gateway"],
        "cookies": [],
    },
    "Google Cloud Armor": {
        "headers": ["x-guploader", "x-goog-", "x-cloud-trace"],
        "response_codes": [403, 429, 502],
        "block_page": ["google cloud armor", "cloud armor", "access denied"],
        "cookies": [],
    },
    "DenyAll WAF": {
        "headers": ["x-denyall-", "denyall"],
        "response_codes": [403, 406, 500],
        "block_page": ["denyall", "deny all", "denyall waf"],
        "cookies": [],
    },
    "CrawlProtect": {
        "headers": ["x-crawlprotect-"],
        "response_codes": [403, 406],
        "block_page": ["crawlprotect", "blocked by crawler protection"],
        "cookies": [],
    },
    "Edgecast (Verizon)": {
        "headers": ["x-ec-", "x-verizon-"],
        "response_codes": [403, 404, 503],
        "block_page": ["edgecast", "verizon digital media"],
        "cookies": ["ecid"],
    },
    "LiteSpeed": {
        "headers": ["x-litespeed-", "litespeed"],
        "response_codes": [403, 503, 406],
        "block_page": ["litespeed", "lscache", "litespeed waf"],
        "cookies": ["_lscache_vary"],
    },
    "AliCloud WAF": {
        "headers": ["x-ali-", "alicdn"],
        "response_codes": [403, 503, 406],
        "block_page": ["alicloud", "aliyun", "web application firewall", "aliyun waf"],
        "cookies": ["aliyungf_tc"],
    },
    "Qrator": {
        "headers": ["x-qrator-", "qrator"],
        "response_codes": [403, 502, 503],
        "block_page": ["qrator", "request blocked", "qrator waf"],
        "cookies": [],
    },
    "Myra Security": {
        "headers": ["x-myra-", "myra"],
        "response_codes": [403, 503, 406],
        "block_page": ["myra", "myra security", "myra waf"],
        "cookies": [],
    },
    "ArvanCloud": {
        "headers": ["x-arvan-", "arvan"],
        "response_codes": [403, 406],
        "block_page": ["arvan", "arvancloud", "arvancloud waf"],
        "cookies": ["arvan"],
    },
    "Fastly": {
        "headers": ["x-fastly-", "fastly", "x-served-by", "x-cache-hits"],
        "response_codes": [403, 503, 429],
        "block_page": ["fastly", "fastly error", "fastly cdn"],
        "cookies": [],
    },
    "Varnish": {
        "headers": ["x-varnish", "x-cache", "via"],
        "response_codes": [403, 503, 406],
        "block_page": ["varnish", "varnish cache", "req.http.x-varnish"],
        "cookies": [],
    },
    "DDoS-Guard": {
        "headers": ["x-ddos-guard", "ddos-guard"],
        "response_codes": [403, 503, 302],
        "block_page": ["ddos-guard", "ddos guard", "request blocked", "ddos protection"],
        "cookies": [],
    },
    "SafeDog": {
        "headers": ["x-safedog", "safedog", "waf-safedog"],
        "response_codes": [403, 406, 500],
        "block_page": ["safedog", "safe dog", "safedog waf"],
        "cookies": [],
    },
    "Yundun (Yxom)": {
        "headers": ["x-yundun", "yundun"],
        "response_codes": [403, 503],
        "block_page": ["yundun", "yxom", "yundun waf"],
        "cookies": [],
    },
    "BlockDoS": {
        "headers": ["x-blockdos", "blockdos"],
        "response_codes": [403, 503, 406],
        "block_page": ["blockdos", "blocked", "blockdos protection"],
        "cookies": [],
    },
    "Cloudbric": {
        "headers": ["x-cloudbric", "cloudbric"],
        "response_codes": [403, 406, 503],
        "block_page": ["cloudbric", "blocked by cloudbric", "cloudbric waf"],
        "cookies": [],
    },
    "SiteGuard": {
        "headers": ["x-siteguard", "siteguard"],
        "response_codes": [403, 406],
        "block_page": ["siteguard", "site guard", "blocked by siteguard"],
        "cookies": [],
    },
    "Profense": {
        "headers": ["x-profense", "profense"],
        "response_codes": [403, 406, 500],
        "block_page": ["profense", "profense waf"],
        "cookies": [],
    },
    "WebKnight": {
        "headers": ["x-webknight", "webknight"],
        "response_codes": [403, 406, 500],
        "block_page": ["webknight", "web knight", "blocked by webknight", "aqtronix"],
        "cookies": [],
    },
    "URLScan": {
        "headers": ["x-urlscan", "urlscan"],
        "response_codes": [403, 406],
        "block_page": ["urlscan", "rejected by urlscan", "urlscan.io"],
        "cookies": [],
    },
    "IBM DataPower": {
        "headers": ["x-datapower", "datapower", "x-dp-"],
        "response_codes": [403, 500, 503],
        "block_page": ["datapower", "ibm datapower", "dp waf"],
        "cookies": [],
    },
    "Huawei Cloud WAF": {
        "headers": ["x-huawei-", "huawei"],
        "response_codes": [403, 503],
        "block_page": ["huawei cloud waf", "huawei", "waf.huawei"],
        "cookies": [],
    },
    "Tencent Cloud WAF": {
        "headers": ["x-tencent-", "tencent"],
        "response_codes": [403, 503, 406],
        "block_page": ["tencent cloud waf", "tencent", "tdwaf"],
        "cookies": [],
    },
    "Baidu Cloud WAF": {
        "headers": ["x-baidu-", "baidu"],
        "response_codes": [403, 503],
        "block_page": ["baidu cloud waf", "baidu waf", "yunjiasu"],
        "cookies": [],
    },
    "360 WangZhan": {
        "headers": ["x-360-", "360wzb"],
        "response_codes": [403, 503],
        "block_page": ["360", "wangzhan", "360 waf", "webscan"],
        "cookies": [],
    },
    "KeyCDN": {
        "headers": ["x-keycdn", "keycdn"],
        "response_codes": [403, 503, 502],
        "block_page": ["keycdn", "keycdn waf"],
        "cookies": [],
    },
    "BunnyCDN": {
        "headers": ["x-bunny", "bunnycdn"],
        "response_codes": [403, 503],
        "block_page": ["bunnycdn", "bunny cdn", "bunny"],
        "cookies": [],
    },
    "CacheFly": {
        "headers": ["x-cachefly", "cachefly"],
        "response_codes": [403, 503],
        "block_page": ["cachefly", "cachefly cdn"],
        "cookies": [],
    },
    "CDN77": {
        "headers": ["x-cdn77", "cdn77"],
        "response_codes": [403, 503],
        "block_page": ["cdn77", "cdn77 waf"],
        "cookies": [],
    },
    "Section.io": {
        "headers": ["x-section", "section.io"],
        "response_codes": [403, 503],
        "block_page": ["section.io", "section waf"],
        "cookies": [],
    },
    "Haltdos": {
        "headers": ["x-haltdos", "haltdos"],
        "response_codes": [403, 406, 503],
        "block_page": ["haltdos", "haltdos waf", "blocked by haltdos"],
        "cookies": [],
    },
    "Senginx": {
        "headers": ["x-senginx", "senginx"],
        "response_codes": [403, 503],
        "block_page": ["senginx", "senginx waf", "security nginx"],
        "cookies": [],
    },
    "NAXSI": {
        "headers": ["x-naxsi", "naxsi"],
        "response_codes": [403, 406],
        "block_page": ["naxsi", "naxsi waf", "blocked by naxsi"],
        "cookies": [],
    },
    "Shadow Daemon": {
        "headers": ["x-shadowd", "shadowdaemon"],
        "response_codes": [403, 406],
        "block_page": ["shadow daemon", "shadowd", "shadow daemon waf"],
        "cookies": [],
    },
    "Signal Sciences (Fastly)": {
        "headers": ["x-sigsci", "sigsci"],
        "response_codes": [403, 406, 503],
        "block_page": ["signal sciences", "sigsci", "sig sci"],
        "cookies": [],
    },
    "AppTrana": {
        "headers": ["x-apptrana", "apptrana"],
        "response_codes": [403, 503],
        "block_page": ["apptrana", "apptrana waf", "indusface"],
        "cookies": [],
    },
    "Armor Defense": {
        "headers": ["x-armor", "armor"],
        "response_codes": [403, 503],
        "block_page": ["armor defense", "armor waf", "armor.com"],
        "cookies": [],
    },
    "Alert Logic": {
        "headers": ["x-alertlogic", "alertlogic"],
        "response_codes": [403, 503],
        "block_page": ["alert logic", "alertlogic waf"],
        "cookies": [],
    },
    "Envoys (Tetrate)": {
        "headers": ["x-envoy", "x-tetrate"],
        "response_codes": [403, 503],
        "block_page": ["envoy", "tetrate", "envoy proxy"],
        "cookies": [],
    },
    "HAProxy WAF": {
        "headers": ["x-haproxy", "haproxy"],
        "response_codes": [403, 503, 406],
        "block_page": ["haproxy", "haproxy waf"],
        "cookies": [],
    },
    "Squid Proxy": {
        "headers": ["x-squid", "squid"],
        "response_codes": [403, 503, 407],
        "block_page": ["squid", "squid proxy", "cache"],
        "cookies": [],
    },
}

CHALLENGE_PATTERNS = {
    "cloudflare_challenge": r'(?:checking your browser|just a moment|cf-challenge|__cf_chl|verify you are human|attention required|cloudflare challenge)',
    "recaptcha": r'(?:g-recaptcha|recaptcha/api|recaptcha\.net|google\.com/recaptcha)',
    "hcaptcha": r'(?:hcaptcha\.com|h-captcha)',
    "turnstile": r'(?:challenges\.cloudflare\.com|turnstile\.cf)',
    "akamai_challenge": r'(?:akamai|referer|reference #|akamaighost)',
    "imperva_challenge": r'(?:incapsula|imperva|blocked because|contact support)',
}

MALICIOUS_PATH_PATTERNS = [
    "/admin", "/wp-admin", "/phpmyadmin", "/phpPgAdmin", "/adminer.php",
    "/.git/config", "/.env", "/wp-config.php",
    "/../../etc/passwd", "/?page=../../etc/passwd",
    "/?s=/index/\\think\\app/invokefunction",
    "/api/v1/admin", "/actuator", "/swagger-ui",
    "/solr", "/grafana", "/kibana", "/prometheus",
    "/console", "/debug", "/test", "/api/health",
    "/server-status", "/server-info", "/cgi-bin/",
    "/wp-json", "/xmlrpc.php", "/.well-known/",
    "/vendor/", "/storage/", "/bootstrap/",
]


async def detect_waf_by_headers(headers: Dict, resp_text: str, status_code: int, cookies: Dict) -> List[Dict]:
    detections = []
    headers_lower = {k.lower(): v for k, v in headers.items()}
    text_lower = resp_text.lower()[:5000]
    cookie_keys = list(cookies.keys()) if isinstance(cookies, dict) else []

    for waf_name, sig in WAF_SIGNATURES.items():
        score = 0
        evidence = []

        for header_pattern in sig["headers"]:
            for hk, hv in headers_lower.items():
                if hk.startswith(header_pattern.lower()):
                    score += 3
                    evidence.append(f"Header: {hk}={hv[:80]}")

        if status_code in sig["response_codes"]:
            score += 1

        for block_pattern in sig["block_page"]:
            if block_pattern.lower() in text_lower:
                score += 2
                evidence.append(f"Block text: {block_pattern}")

        for cookie_pattern in sig["cookies"]:
            for ck in cookie_keys:
                if ck.startswith(cookie_pattern):
                    score += 3
                    evidence.append(f"Cookie: {ck}")

        if score >= 4:
            detections.append({
                "waf": waf_name,
                "score": score,
                "evidence": evidence[:5],
                "confidence": "High" if score >= 7 else "Medium",
            })

    return detections


async def detect_challenge(resp_text: str, headers: Dict) -> List[Dict]:
    challenges = []
    text_lower = resp_text.lower()[:3000]

    for challenge_name, pattern in CHALLENGE_PATTERNS.items():
        if re.search(pattern, text_lower, re.I):
            challenges.append({
                "type": challenge_name,
                "pattern": pattern,
            })

    return challenges


async def probe_paths(client: httpx.AsyncClient, base_url: str, target: str) -> List[Dict]:
    results = []
    test_paths = [
        "/../../etc/passwd",
        "/.env",
        "/admin",
        "/?page=../../etc/passwd",
        "/?s=/index/\\think\\app/invokefunction",
        "/api/v1/admin",
        "/wp-admin",
        "/phpmyadmin",
        "/.git/config",
        "/actuator",
        "/swagger-ui",
        "/console",
    ]

    for path in test_paths:
        try:
            url = f"{base_url}{path}"
            resp = await client.get(url, headers={"User-Agent": UA}, timeout=10.0, follow_redirects=False)
            results.append({
                "path": path,
                "status": resp.status_code,
                "content_length": len(resp.text),
                "headers": dict(resp.headers),
                "text": resp.text[:2000],
            })
        except Exception:
            continue
        await asyncio.sleep(0.3)

    return results


async def check_ip_based_waf(target: str) -> List[Dict]:
    results = []
    try:
        ip = socket.gethostbyname(target)
        alt_ports = [80, 8080, 8443, 443]
        for port in alt_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((ip, port))
                sock.close()
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.settimeout(5)
                sock2.connect((target, port))
                sock2.close()
            except Exception:
                results.append({
                    "type": "IP-based WAF",
                    "evidence": f"Direct IP connection on port {port} behaves differently than domain",
                    "port": port,
                })
    except Exception:
        pass
    return results


async def check_delay_behavior(client: httpx.AsyncClient, base_url: str) -> Dict:
    result = {"delayed_responses": False, "avg_normal": 0, "avg_suspicious": 0}
    try:
        normal_times = []
        for _ in range(3):
            t1 = asyncio.get_event_loop().time()
            resp = await client.get(base_url, headers={"User-Agent": UA}, timeout=15.0)
            t2 = asyncio.get_event_loop().time()
            normal_times.append(t2 - t1)
        result["avg_normal"] = sum(normal_times) / len(normal_times)

        suspicious_params = [
            f"{base_url}?id=1 UNION SELECT * FROM users",
            f"{base_url}?page=../../../etc/passwd",
            f"{base_url}?cmd=cat /etc/shadow",
            f"{base_url}?q=<script>alert(1)</script>",
            f"{base_url}/.env",
        ]
        suspicious_times = []
        for param in suspicious_params:
            try:
                t1 = asyncio.get_event_loop().time()
                resp = await client.get(param, headers={"User-Agent": UA}, timeout=30.0)
                t2 = asyncio.get_event_loop().time()
                suspicious_times.append(t2 - t1)
            except Exception:
                suspicious_times.append(30.0)
        if suspicious_times:
            result["avg_suspicious"] = sum(suspicious_times) / len(suspicious_times)
        if result["avg_suspicious"] > result["avg_normal"] * 3 and result["avg_normal"] > 0:
            result["delayed_responses"] = True
    except Exception:
        pass
    return result


async def check_rate_limiting(client: httpx.AsyncClient, base_url: str) -> Dict:
    result = {"rate_limited": False, "status_codes": [], "avg_time": 0}
    try:
        times = []
        statuses = []
        for i in range(10):
            t1 = asyncio.get_event_loop().time()
            resp = await client.get(base_url, headers={"User-Agent": UA}, timeout=10.0)
            t2 = asyncio.get_event_loop().time()
            times.append(t2 - t1)
            statuses.append(resp.status_code)
            if i >= 5:
                await asyncio.sleep(0.1)
        result["status_codes"] = statuses
        result["avg_time"] = sum(times) / len(times)
        # Check for rate limit indicators
        rate_limit_statuses = [s for s in statuses if s in (429, 503)]
        if len(rate_limit_statuses) >= 3:
            result["rate_limited"] = True
        if statuses.count(429) >= 2:
            result["rate_limited"] = True
    except Exception:
        pass
    return result


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    base_url = f"https://{domain}"

    waf_detections = []
    challenge_detections = []

    try:
        resp = await client.get(base_url, headers={"User-Agent": UA}, timeout=15.0, follow_redirects=True)
        status_code = resp.status_code
        headers = dict(resp.headers)
        text = resp.text
        cookies = dict(resp.cookies)

        detections = await detect_waf_by_headers(headers, text, status_code, cookies)
        waf_detections.extend(detections)

        challenges = await detect_challenge(text, headers)
        challenge_detections.extend(challenges)

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"WAF check error: {str(e)[:100]}",
            type="WAF: Error",
            source="FirewallDetector",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["waf", "error"]
        ))

    path_probes = await probe_paths(client, base_url, domain)

    for probe in path_probes:
        probe_detections = await detect_waf_by_headers(
            probe["headers"], probe["text"], probe["status"], {}
        )
        for d in probe_detections:
            if d not in waf_detections:
                waf_detections.append(d)

    waf_names_seen = set()
    for detection in waf_detections:
        waf_name = detection["waf"]
        if waf_name in waf_names_seen:
            continue
        waf_names_seen.add(waf_name)

        score = detection["score"]
        confidence = detection["confidence"]
        evidence = detection["evidence"]

        color = "red" if confidence == "High" else "orange"
        threat = "Informational"

        tags = ["waf", "firewall", waf_name.lower().replace(" ", "-")]
        if "block" in str(evidence).lower() or "challenge" in str(evidence).lower():
            threat = "Elevated Risk"
            tags.append("blocking-requests")

        findings.append(IntelligenceFinding(
            entity=f"WAF: {waf_name} (confidence: {confidence})",
            type=f"WAF: {waf_name}",
            source="FirewallDetector",
            confidence=confidence,
            color=color,
            threat_level=threat,
            status="Detected",
            resolution=f"Detection score: {score}/10",
            raw_data="\n".join(evidence),
            tags=tags,
        ))

    if challenge_detections:
        for cd in challenge_detections:
            findings.append(IntelligenceFinding(
                entity=f"Challenge detected: {cd['type']}",
                type="WAF: Challenge Page",
                source="FirewallDetector",
                confidence="High",
                color="orange",
                threat_level="Elevated Risk",
                status="Active Challenge",
                tags=["waf", "challenge", "block-page"]
            ))

    different_path_behaviors = []
    if path_probes:
        statuses = [p["status"] for p in path_probes if p["status"] != 200]
        if len(set(statuses)) > 1:
            different_path_behaviors.append("Malicious paths trigger different responses (WAF likely active)")

        for probe in path_probes:
            if probe["status"] == 403 or probe["status"] == 406 or "blocked" in probe["text"].lower()[:500]:
                different_path_behaviors.append(f"Path {probe['path']} -> {probe['status']} (blocked)")

    if different_path_behaviors:
        for behavior in different_path_behaviors:
            findings.append(IntelligenceFinding(
                entity=behavior[:200],
                type="WAF: Behavior Analysis",
                source="FirewallDetector",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["waf", "behavior"]
            ))

    delay_analysis = await check_delay_behavior(client, base_url)
    if delay_analysis.get("delayed_responses"):
        findings.append(IntelligenceFinding(
            entity=f"Suspicious delayed responses: normal {delay_analysis['avg_normal']:.2f}s vs suspicious {delay_analysis['avg_suspicious']:.2f}s",
            type="WAF: Delay Analysis",
            source="FirewallDetector",
            confidence="Medium",
            color="orange",
            threat_level="Elevated Risk",
            tags=["waf", "delay", "timing"]
        ))

    # Rate limiting detection
    rate_limit_check = await check_rate_limiting(client, base_url)
    if rate_limit_check.get("rate_limited"):
        findings.append(IntelligenceFinding(
            entity=f"Rate limiting detected: {rate_limit_check['status_codes'][-3:]} after multiple requests",
            type="WAF: Rate Limiting",
            source="FirewallDetector",
            confidence="Medium",
            color="orange",
            threat_level="Elevated Risk",
            raw_data=f"Request times: {[f'{t:.2f}s' for t in rate_limit_check.get('status_codes', [])[-5:]]}",
            tags=["waf", "rate-limit", "throttling"]
        ))
    else:
        findings.append(IntelligenceFinding(
            entity="No rate limiting detected",
            type="WAF: Rate Limiting Check",
            source="FirewallDetector",
            confidence="Medium",
            color="emerald",
            threat_level="Informational",
            tags=["waf", "rate-limit"]
        ))

    # Server header detection
    try:
        resp = await client.get(base_url, headers={"User-Agent": UA}, timeout=10.0)
        server = resp.headers.get("Server", "")
        if server:
            findings.append(IntelligenceFinding(
                entity=f"Server: {server}",
                type="WAF: Server Header",
                source="FirewallDetector",
                confidence="High",
                color="slate",
                threat_level="Informational",
                tags=["waf", "server-header"]
            ))
    except:
        pass

    # Set-Cookie analysis for WAF cookies
    try:
        resp = await client.get(base_url, headers={"User-Agent": UA}, timeout=10.0)
        set_cookie = resp.headers.get("Set-Cookie", "")
        if set_cookie:
            waf_cookies_found = []
            for waf_name, sig in WAF_SIGNATURES.items():
                for cookie_pattern in sig["cookies"]:
                    if cookie_pattern in set_cookie:
                        waf_cookies_found.append(waf_name)
                        break
            if waf_cookies_found:
                findings.append(IntelligenceFinding(
                    entity=f"WAF cookies detected: {', '.join(waf_cookies_found)}",
                    type="WAF: Cookie Detection",
                    source="FirewallDetector",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    tags=["waf", "cookie"]
                ))
    except:
        pass

    if not waf_detections and not challenge_detections:
        findings.append(IntelligenceFinding(
            entity="No WAF detected",
            type="WAF: Not Detected",
            source="FirewallDetector",
            confidence="Medium",
            color="emerald",
            threat_level="Informational",
            tags=["waf", "none"]
        ))
        if different_path_behaviors:
            findings.append(IntelligenceFinding(
                entity="Potential custom firewall (non-standard signatures)",
                type="WAF: Custom / Generic",
                source="FirewallDetector",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                tags=["waf", "custom"]
            ))

    summary_lines = [
        f"WAFs detected: {len(waf_names_seen)}",
        f"Challenge pages: {len(challenge_detections)}",
        f"Behavioral indicators: {len(different_path_behaviors)}",
    ]
    if waf_names_seen:
        summary_lines.append(f"Detected: {', '.join(sorted(waf_names_seen))}")
    if delay_analysis.get("delayed_responses"):
        summary_lines.append("Timing analysis: Suspicious delays detected")
    if rate_limit_check.get("rate_limited"):
        summary_lines.append("Rate limiting: Detected")

    findings.append(IntelligenceFinding(
        entity=f"WAF Scan: {len(waf_names_seen)} WAF(s) detected",
        type="WAF: Summary",
        source="FirewallDetector",
        confidence="Medium",
        color="red" if waf_names_seen else "emerald",
        threat_level="Informational",
        raw_data="\n".join(summary_lines),
        tags=["summary", "waf", "firewall-detection"]
    ))

    return findings
