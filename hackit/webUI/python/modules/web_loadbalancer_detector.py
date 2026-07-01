import httpx
import re
import random
from urllib.parse import urlparse
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

LB_COOKIE_PATTERNS = {
    r"BIGipServer\w+": "F5 BIG-IP",
    r"TS01\w+": "Citrix NetScaler",
    r"citrix_ns_id": "Citrix NetScaler",
    r"AWSALB": "AWS ALB",
    r"AWSELB": "AWS ELB",
    r"ROUTEID": "F5 BIG-IP",
    r"__lb_id": "Generic Load Balancer",
    r"lb_hash": "Generic Load Balancer",
    r"^[A-Za-z]{2,6}Server": "Generic Load Balancer",
    r"rt[\w]{3,}": "F5 BIG-IP (alternate)",
    r"MRHSession": "Citrix NetScaler",
    r"NSC_[a-zA-Z0-9]+": "Citrix NetScaler",
    r"nlbi_\w+": "Citrix NetScaler",
    r"fe_?\w{4}": "F5 BIG-IP",
    r"servername": "Generic Load Balancer",
    r"affinity": "Generic Load Balancer",
    r"sticky": "Generic Load Balancer",
}

LB_HEADER_PATTERNS = {
    "x-forwarded-for": "Generic Reverse Proxy/LB",
    "x-forwarded-proto": "Generic Reverse Proxy/LB",
    "x-forwarded-host": "Generic Reverse Proxy/LB",
    "x-forwarded-server": "Generic Reverse Proxy/LB",
    "x-real-ip": "Reverse Proxy/LB",
    "x-cluster-client-ip": "F5 BIG-IP / Cisco",
    "x-nokia-cluster": "Nokia LB",
    "x-originating-ip": "Generic LB",
    "x-remote-ip": "Generic LB",
    "x-remote-addr": "Generic LB",
    "x-varnish": "Varnish Cache / LB",
    "via": "Generic Proxy/LB",
    "x-cache": "Generic CDN/LB",
    "x-served-by": "Generic LB",
    "x-akamai-config": "Akamai LB",
}

RESPONSE_TIME_VARIANCE_THRESHOLD = 0.3

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    for proto in ["https", "http"]:
        try:
            resp = await client.get(f"{proto}://{domain}", timeout=10.0, follow_redirects=True, headers={"User-Agent": UA})
            headers = {k.lower(): v for k, v in dict(resp.headers).items()}
            cookies = dict(resp.cookies)
            status = resp.status_code
            initial_time = resp.elapsed.total_seconds()

            findings.append(IntelligenceFinding(
                entity=f"Initial request: HTTP {status} ({initial_time:.2f}s)",
                type="LB: Initial Request",
                source="LoadBalancerDetector",
                confidence="High",
                color="slate",
                threat_level="Informational",
                tags=["load-balancer", "initial"]
            ))

            found_lb_headers = []
            for hdr, lb_type in LB_HEADER_PATTERNS.items():
                if hdr in headers:
                    found_lb_headers.append((hdr, headers[hdr], lb_type))
                    findings.append(IntelligenceFinding(
                        entity=f"LB Header: {hdr}: {headers[hdr][:60]}",
                        type="LB: Load Balancer Header",
                        source="LoadBalancerDetector",
                        confidence="High",
                        color="blue",
                        threat_level="Informational",
                        raw_data=f"header={hdr}, value={headers[hdr][:200]}, type={lb_type}",
                        tags=["load-balancer", "header", lb_type.lower().replace(" ", "-").replace("/", "-")]
                    ))

            found_lb_cookies = []
            for cookie_name, cookie_val in cookies.items():
                for pattern, lb_type in LB_COOKIE_PATTERNS.items():
                    if re.search(pattern, cookie_name, re.I):
                        found_lb_cookies.append((cookie_name, lb_type))
                        findings.append(IntelligenceFinding(
                            entity=f"LB Cookie: {cookie_name} = {lb_type}",
                            type="LB: Load Balancer Cookie",
                            source="LoadBalancerDetector",
                            confidence="High",
                            color="purple",
                            threat_level="Informational",
                            raw_data=f"cookie={cookie_name}, value={cookie_val[:50]}, type={lb_type}",
                            tags=["load-balancer", "cookie", "sticky-session"]
                        ))

            if not found_lb_cookies:
                findings.append(IntelligenceFinding(
                    entity="No load balancer cookies detected",
                    type="LB: No LB Cookies",
                    source="LoadBalancerDetector",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    tags=["load-balancer", "cookies", "none"]
                ))

            unique_headers = set(h for h, _, _ in found_lb_headers)
            unique_cookies = set(c for c, _ in found_lb_cookies)

            if unique_headers or unique_cookies:
                inferred_lb = " + ".join(set(lb for _, lb in found_lb_cookies) | set(lb for _, _, lb in found_lb_headers))
                findings.append(IntelligenceFinding(
                    entity=f"Load Balancer detected: {inferred_lb}",
                    type="LB: Load Balancer Detection",
                    source="LoadBalancerDetector",
                    confidence="High",
                    color="purple",
                    threat_level="Informational",
                    raw_data=f"headers={unique_headers}, cookies={unique_cookies}, inferred={inferred_lb}",
                    tags=["load-balancer", "detected"]
                ))
            else:
                findings.append(IntelligenceFinding(
                    entity="No load balancer indicators found from single request",
                    type="LB: No LB Detected",
                    source="LoadBalancerDetector",
                    confidence="Low",
                    color="slate",
                    threat_level="Informational",
                    tags=["load-balancer", "none"]
                ))

            response_times = []
            for i in range(3):
                try:
                    r = await client.get(f"{proto}://{domain}", timeout=10.0, follow_redirects=False, headers={"User-Agent": UA, "X-Forwarded-For": f"10.0.0.{random.randint(1, 255)}"})
                    response_times.append(r.elapsed.total_seconds())
                except Exception:
                    continue

            if len(response_times) >= 2:
                variance = max(response_times) - min(response_times)
                if variance > RESPONSE_TIME_VARIANCE_THRESHOLD:
                    findings.append(IntelligenceFinding(
                        entity=f"Response time variance: {variance:.3f}s (possible load balancing)",
                        type="LB: Response Time Variance",
                        source="LoadBalancerDetector",
                        confidence="Medium",
                        color="yellow",
                        threat_level="Informational",
                        raw_data=f"times={response_times}, variance={variance:.3f}",
                        tags=["load-balancer", "response-time", "variance"]
                    ))
                else:
                    findings.append(IntelligenceFinding(
                        entity=f"Response times consistent: {variance:.3f}s variance",
                        type="LB: Consistent Response Times",
                        source="LoadBalancerDetector",
                        confidence="Medium",
                        color="emerald",
                        threat_level="Informational",
                        tags=["load-balancer", "response-time", "consistent"]
                    ))

            if found_lb_cookies or found_lb_headers:
                findings.append(IntelligenceFinding(
                    entity=f"LB Type Assessment: {len(found_lb_cookies)} cookie(s), {len(found_lb_headers)} header(s), {len(response_times)} time samples",
                    type="LB: Assessment",
                    source="LoadBalancerDetector",
                    confidence="High",
                    color="purple",
                    threat_level="Informational",
                    raw_data=f"cookies={len(found_lb_cookies)}, headers={len(found_lb_headers)}, times={response_times}",
                    tags=["load-balancer", "assessment"]
                ))
            break
        except Exception:
            continue

    server_header = headers.get("server", "") if headers else ""
    if server_header:
        findings.append(IntelligenceFinding(
            entity=f"Server header: {server_header}",
            type="LB: Server Header",
            source="LoadBalancerDetector",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            raw_data=f"Server: {server_header}",
            tags=["load-balancer", "server-header"]
        ))

    return findings
