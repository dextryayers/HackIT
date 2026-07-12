import re
import httpx
from urllib.parse import urlparse
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    html = ""
    headers = {}
    status = 0

    for proto in ["https", "http"]:
        try:
            resp = await safe_fetch(client,f"{proto}://{domain}", timeout=10.0, follow_redirects=True, headers={"User-Agent": UA})
            html = resp.text
            status = resp.status_code
            headers = {k.lower(): v for k, v in dict(resp.headers).items()}
            break
        except Exception:
            continue

    if not html:
        findings.append(make_finding(
            entity=f"Could not fetch {domain}",
            ftype="Frame: Fetch Failed",
            source="FrameAnalyzer",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["frame", "error"]
        ))
        return findings

    xfo = headers.get("x-frame-options", "")
    if xfo:
        xfo_upper = xfo.upper()
        color_map = {"DENY": "emerald", "SAMEORIGIN": "yellow", "ALLOW-FROM": "orange"}
        findings.append(make_finding(
            entity=f"X-Frame-Options: {xfo}",
            ftype="Frame: X-Frame-Options",
            source="FrameAnalyzer",
            confidence="High",
            color=color_map.get(xfo_upper, "orange"),
            threat_level="Informational" if xfo_upper in ("DENY", "SAMEORIGIN") else "Elevated Risk",
            status=xfo_upper,
            raw_data=f"X-Frame-Options: {xfo}",
            tags=["frame", "x-frame-options", "clickjacking"]
        ))
    else:
        findings.append(make_finding(
            entity="X-Frame-Options header MISSING - vulnerable to clickjacking",
            ftype="Frame: X-Frame-Options Missing",
            source="FrameAnalyzer",
            confidence="High",
            color="red",
            threat_level="High Risk",
            status="Vulnerable",
            tags=["frame", "x-frame-options", "clickjacking", "vulnerability"]
        ))

    csp = headers.get("content-security-policy", "")
    frame_ancestors = ""
    if csp:
        fa_match = re.search(r"frame-ancestors\s+([^;]+)", csp, re.I)
        if fa_match:
            frame_ancestors = fa_match.group(1).strip()
            findings.append(make_finding(
                entity=f"CSP frame-ancestors: {frame_ancestors}",
                ftype="Frame: CSP frame-ancestors",
                source="FrameAnalyzer",
                confidence="High",
                color="emerald" if "'none'" in frame_ancestors or "'self'" in frame_ancestors else "orange",
                threat_level="Informational",
                raw_data=f"frame-ancestors: {frame_ancestors}",
                tags=["frame", "csp", "clickjacking"]
            ))
        else:
            findings.append(make_finding(
                entity="CSP header present but no frame-ancestors directive",
                ftype="Frame: CSP Missing Directive",
                source="FrameAnalyzer",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                tags=["frame", "csp", "clickjacking"]
            ))
    else:
        findings.append(make_finding(
            entity="No Content-Security-Policy header - no frame-ancestors protection",
            ftype="Frame: CSP Missing",
            source="FrameAnalyzer",
            confidence="High",
            color="red",
            threat_level="High Risk",
            status="Missing",
            tags=["frame", "csp", "clickjacking"]
        ))

    iframe_pattern = re.compile(r"<iframe\s[^>]*>", re.I | re.DOTALL)
    iframes = iframe_pattern.findall(html)

    if iframes:
        findings.append(make_finding(
            entity=f"Found {len(iframes)} iframe(s) on the page",
            ftype="Frame: Iframes Detected",
            source="FrameAnalyzer",
            confidence="High",
            color="slate",
            threat_level="Informational",
            raw_data=f"iframe_count={len(iframes)}",
            tags=["frame", "iframe"]
        ))

        for idx, ifr in enumerate(iframes[:10]):
            src_m = re.search(r'src\s*=\s*["\'](.*?)["\']', ifr, re.I)
            src = src_m.group(1) if src_m else "(no src)"
            findings.append(make_finding(
                entity=f"Iframe {idx+1}: src={src[:80]}",
                ftype="Frame: Iframe Detail",
                source="FrameAnalyzer",
                confidence="High",
                color="slate",
                threat_level="Informational",
                raw_data=f"iframe_html={ifr[:200]}",
                tags=["frame", "iframe", "embed"]
            ))

        findings.append(make_finding(
            entity=f"Iframe count: {len(iframes)} - verify iframe content source for security",
            ftype="Frame: Iframe Assessment",
            source="FrameAnalyzer",
            confidence="Medium",
            color="orange" if len(iframes) > 3 else "yellow",
            threat_level="Elevated Risk" if len(iframes) > 3 else "Informational",
            tags=["frame", "iframe", "assessment"]
        ))
    else:
        findings.append(make_finding(
            entity="No iframes detected on the page",
            ftype="Frame: No Iframes",
            source="FrameAnalyzer",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            tags=["frame", "iframe", "clean"]
        ))

    framebusting_scripts = re.findall(
        r'(top\.location|self\.location|window\.top|parent\.location|top\.window|break\s*parent|frameElement|framebuster)',
        html, re.I
    )

    if framebusting_scripts:
        findings.append(make_finding(
            entity=f"Framebusting script(s) detected ({len(framebusting_scripts)} instances)",
            ftype="Frame: Framebusting",
            source="FrameAnalyzer",
            confidence="High",
            color="blue",
            threat_level="Informational",
            raw_data=f"framebusting_patterns={list(set(framebusting_scripts))}",
            tags=["frame", "framebusting", "protection"]
        ))
    else:
        findings.append(make_finding(
            entity="No framebusting scripts detected",
            ftype="Frame: No Framebusting",
            source="FrameAnalyzer",
            confidence="Medium",
            color="orange",
            threat_level="Elevated Risk",
            tags=["frame", "framebusting", "missing"]
        ))

    clickjacking_vulnerable = not xfo and (not frame_ancestors or "self" not in frame_ancestors)
    findings.append(make_finding(
        entity=f"Clickjacking Risk: {'VULNERABLE' if clickjacking_vulnerable else 'Protected'}",
        ftype="Frame: Clickjacking Assessment",
        source="FrameAnalyzer",
        confidence="High",
        color="red" if clickjacking_vulnerable else "emerald",
        threat_level="High Risk" if clickjacking_vulnerable else "Informational",
        status="Vulnerable" if clickjacking_vulnerable else "Protected",
        raw_data=f"xfo={xfo or 'MISSING'}, csp_frame_ancestors={frame_ancestors or 'MISSING'}, iframes={len(iframes)}, framebusting={len(framebusting_scripts)}",
        tags=["frame", "clickjacking", "vulnerability"]
    ))

    findings.append(make_finding(
        entity=f"Frame Security Analysis: XFO={'OK' if xfo else 'MISSING'}, CSP-FA={'OK' if frame_ancestors else 'MISSING'}, Iframes={len(iframes)}",
        ftype="Frame: Summary",
        source="FrameAnalyzer",
        confidence="High",
        color="emerald" if not clickjacking_vulnerable else "red",
        threat_level="Informational" if not clickjacking_vulnerable else "High Risk",
        tags=["frame", "summary"]
    ))

    return findings
