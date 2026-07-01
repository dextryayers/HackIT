import httpx
import re
import time
from urllib.parse import urlparse, urljoin
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

MAX_REDIRECTS = 20

REDIRECT_CODES = {301: "Moved Permanently", 302: "Found", 303: "See Other", 307: "Temporary Redirect", 308: "Permanent Redirect"}

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    initial_urls = [
        f"https://{domain}",
        f"http://{domain}",
        f"https://www.{domain}",
    ]

    all_redirects = {}
    redirect_loops = []
    total_latency = 0

    for start_url in initial_urls:
        chain = []
        current = start_url
        visited = set()
        try:
            for hop in range(MAX_REDIRECTS):
                if current in visited:
                    redirect_loops.append({"start": start_url, "loop_url": current, "hop": hop})
                    break
                visited.add(current)

                t0 = time.time()
                resp = await client.get(current, timeout=10.0, follow_redirects=False, headers={"User-Agent": UA})
                latency = time.time() - t0
                total_latency += latency

                step = {
                    "url": current,
                    "status": resp.status_code,
                    "location": dict(resp.headers).get("location", ""),
                    "latency": round(latency, 3),
                    "cookies": dict(resp.cookies),
                    "headers": {k.lower(): v for k, v in dict(resp.headers).items()},
                }
                chain.append(step)

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = step["location"]
                    if location:
                        current = urljoin(current, location)
                    else:
                        break
                else:
                    break
        except Exception:
            continue

        if chain:
            all_redirects[start_url] = chain

    if not all_redirects:
        findings.append(IntelligenceFinding(
            entity=f"No redirect chains found for {domain}",
            type="Redirect: No Redirects",
            source="RedirectAnalyzer",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            tags=["redirect", "none"]
        ))
        return findings

    for start_url, chain in all_redirects.items():
        final_url = chain[-1]["url"]
        chain_length = len(chain)
        final_status = chain[-1]["status"]

        findings.append(IntelligenceFinding(
            entity=f"Redirect chain for {start_url}: {chain_length} hop(s) -> {final_url} (HTTP {final_status})",
            type="Redirect: Chain Overview",
            source="RedirectAnalyzer",
            confidence="High",
            color="blue",
            threat_level="Informational",
            raw_data=f"start={start_url}, hops={chain_length}, final={final_url}, status={final_status}",
            tags=["redirect", "chain"]
        ))

        for idx, step in enumerate(chain):
            status = step["status"]
            location = step["location"]
            latency = step["latency"]

            if status in REDIRECT_CODES:
                redirect_type = REDIRECT_CODES[status]
                findings.append(IntelligenceFinding(
                    entity=f"Hop {idx+1}: {step['url']} -> HTTP {status} ({redirect_type}) -> {location[:80] or 'Final'}",
                    type="Redirect: Hop Detail",
                    source="RedirectAnalyzer",
                    confidence="High",
                    color="slate" if status in (301, 308) else "yellow",
                    threat_level="Informational",
                    raw_data=f"hop={idx+1}, from={step['url']}, status={status}, location={location}, latency={latency}s",
                    tags=["redirect", "hop", f"http-{status}"]
                ))

            if step["cookies"]:
                for cookie_name, cookie_val in step["cookies"].items():
                    findings.append(IntelligenceFinding(
                        entity=f"Cookie set during redirect: {cookie_name}={cookie_val[:30]}",
                        type="Redirect: Cookie Tracked",
                        source="RedirectAnalyzer",
                        confidence="Medium",
                        color="orange",
                        threat_level="Informational",
                        raw_data=f"hop={idx+1}, cookie={cookie_name}={cookie_val}, url={step['url']}",
                        tags=["redirect", "cookie"]
                    ))

            response_time = latency
            findings.append(IntelligenceFinding(
                entity=f"Hop {idx+1} latency: {response_time:.3f}s",
                type="Redirect: Hop Latency",
                source="RedirectAnalyzer",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                raw_data=f"hop={idx+1}, latency={response_time:.3f}s",
                tags=["redirect", "latency"]
            ))

        cross_domain_redirects = []
        for step in chain:
            try:
                loc = step.get("location", "")
                if loc:
                    loc_domain = urlparse(loc).netloc
                    start_domain = urlparse(start_url).netloc
                    if loc_domain and loc_domain != start_domain:
                        cross_domain_redirects.append((step["url"], loc))
            except Exception:
                continue

        if cross_domain_redirects:
            findings.append(IntelligenceFinding(
                entity=f"Cross-domain redirects detected: {len(cross_domain_redirects)} hop(s) leave original domain",
                type="Redirect: Cross-Domain",
                source="RedirectAnalyzer",
                confidence="High",
                color="red",
                threat_level="High Risk",
                raw_data="\n".join([f"{f} -> {t}" for f, t in cross_domain_redirects[:5]]),
                tags=["redirect", "cross-domain", "risk"]
            ))

        if chain_length > 3:
            findings.append(IntelligenceFinding(
                entity=f"Long redirect chain ({chain_length} hops). Each hop adds latency and attack surface.",
                type="Redirect: Long Chain Warning",
                source="RedirectAnalyzer",
                confidence="High",
                color="red",
                threat_level="Elevated Risk",
                raw_data=f"hops={chain_length}, start={start_url}, final={final_url}",
                tags=["redirect", "long-chain", "performance"]
            ))

    if redirect_loops:
        for loop in redirect_loops:
            findings.append(IntelligenceFinding(
                entity=f"Redirect LOOP detected: {loop['start']} loops at {loop['loop_url']} (hop {loop['hop']})",
                type="Redirect: Loop Detected",
                source="RedirectAnalyzer",
                confidence="High",
                color="red",
                threat_level="Critical",
                status="Redirect Loop",
                raw_data=f"start={loop['start']}, loop_url={loop['loop_url']}, hop={loop['hop']}",
                tags=["redirect", "loop", "critical"]
            ))

    findings.append(IntelligenceFinding(
        entity=f"Redirect Analysis: {len(all_redirects)} chain(s), {sum(len(c) for c in all_redirects.values())} total hops, {len(redirect_loops)} loops",
        type="Redirect: Summary",
        source="RedirectAnalyzer",
        confidence="High",
        color="red" if redirect_loops else ("orange" if any(len(c) > 3 for c in all_redirects.values()) else "blue"),
        threat_level="Critical" if redirect_loops else ("Elevated Risk" if any(len(c) > 3 for c in all_redirects.values()) else "Informational"),
        raw_data=f"chains={len(all_redirects)}, total_hops={sum(len(c) for c in all_redirects.values())}, loops={len(redirect_loops)}",
        tags=["redirect", "summary"]
    ))

    return findings
