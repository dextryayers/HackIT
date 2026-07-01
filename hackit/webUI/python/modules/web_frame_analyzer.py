import httpx
import re
from urllib.parse import urlparse
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
            resp = await client.get(f"{proto}://{domain}", timeout=10.0, follow_redirects=True, headers={"User-Agent": UA})
            html = resp.text
            status = resp.status_code
            headers = {k.lower(): v for k, v in dict(resp.headers).items()}
            break
        except Exception:
            continue

    if not html:
        findings.append(IntelligenceFinding(
            entity=f"Could not fetch {domain}",
            type="Frame: Fetch Failed",
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
        findings.append(IntelligenceFinding(
            entity=f"X-Frame-Options: {xfo}",
            type="Frame: X-Frame-Options",
            source="FrameAnalyzer",
            confidence="High",
            color=color_map.get(xfo_upper, "orange"),
            threat_level="Informational" if xfo_upper in ("DENY", "SAMEORIGIN") else "Elevated Risk",
            status=xfo_upper,
            raw_data=f"X-Frame-Options: {xfo}",
            tags=["frame", "x-frame-options", "clickjacking"]
        ))
    else:
        findings.append(IntelligenceFinding(
            entity="X-Frame-Options header MISSING - vulnerable to clickjacking",
            type="Frame: X-Frame-Options Missing",
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
            findings.append(IntelligenceFinding(
                entity=f"CSP frame-ancestors: {frame_ancestors}",
                type="Frame: CSP frame-ancestors",
                source="FrameAnalyzer",
                confidence="High",
                color="emerald" if "'none'" in frame_ancestors or "'self'" in frame_ancestors else "orange",
                threat_level="Informational",
                raw_data=f"frame-ancestors: {frame_ancestors}",
                tags=["frame", "csp", "clickjacking"]
            ))
        else:
            findings.append(IntelligenceFinding(
                entity="CSP header present but no frame-ancestors directive",
                type="Frame: CSP Missing Directive",
                source="FrameAnalyzer",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                tags=["frame", "csp", "clickjacking"]
            ))
    else:
        findings.append(IntelligenceFinding(
            entity="No Content-Security-Policy header - no frame-ancestors protection",
            type="Frame: CSP Missing",
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
        findings.append(IntelligenceFinding(
            entity=f"Found {len(iframes)} iframe(s) on the page",
            type="Frame: Iframes Detected",
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
            findings.append(IntelligenceFinding(
                entity=f"Iframe {idx+1}: src={src[:80]}",
                type="Frame: Iframe Detail",
                source="FrameAnalyzer",
                confidence="High",
                color="slate",
                threat_level="Informational",
                raw_data=f"iframe_html={ifr[:200]}",
                tags=["frame", "iframe", "embed"]
            ))

        findings.append(IntelligenceFinding(
            entity=f"Iframe count: {len(iframes)} - verify iframe content source for security",
            type="Frame: Iframe Assessment",
            source="FrameAnalyzer",
            confidence="Medium",
            color="orange" if len(iframes) > 3 else "yellow",
            threat_level="Elevated Risk" if len(iframes) > 3 else "Informational",
            tags=["frame", "iframe", "assessment"]
        ))
    else:
        findings.append(IntelligenceFinding(
            entity="No iframes detected on the page",
            type="Frame: No Iframes",
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
        findings.append(IntelligenceFinding(
            entity=f"Framebusting script(s) detected ({len(framebusting_scripts)} instances)",
            type="Frame: Framebusting",
            source="FrameAnalyzer",
            confidence="High",
            color="blue",
            threat_level="Informational",
            raw_data=f"framebusting_patterns={list(set(framebusting_scripts))}",
            tags=["frame", "framebusting", "protection"]
        ))
    else:
        findings.append(IntelligenceFinding(
            entity="No framebusting scripts detected",
            type="Frame: No Framebusting",
            source="FrameAnalyzer",
            confidence="Medium",
            color="orange",
            threat_level="Elevated Risk",
            tags=["frame", "framebusting", "missing"]
        ))

    clickjacking_vulnerable = not xfo and (not frame_ancestors or "self" not in frame_ancestors)
    findings.append(IntelligenceFinding(
        entity=f"Clickjacking Risk: {'VULNERABLE' if clickjacking_vulnerable else 'Protected'}",
        type="Frame: Clickjacking Assessment",
        source="FrameAnalyzer",
        confidence="High",
        color="red" if clickjacking_vulnerable else "emerald",
        threat_level="High Risk" if clickjacking_vulnerable else "Informational",
        status="Vulnerable" if clickjacking_vulnerable else "Protected",
        raw_data=f"xfo={xfo or 'MISSING'}, csp_frame_ancestors={frame_ancestors or 'MISSING'}, iframes={len(iframes)}, framebusting={len(framebusting_scripts)}",
        tags=["frame", "clickjacking", "vulnerability"]
    ))

    findings.append(IntelligenceFinding(
        entity=f"Frame Security Analysis: XFO={'OK' if xfo else 'MISSING'}, CSP-FA={'OK' if frame_ancestors else 'MISSING'}, Iframes={len(iframes)}",
        type="Frame: Summary",
        source="FrameAnalyzer",
        confidence="High",
        color="emerald" if not clickjacking_vulnerable else "red",
        threat_level="Informational" if not clickjacking_vulnerable else "High Risk",
        tags=["frame", "summary"]
    ))

    return findings
