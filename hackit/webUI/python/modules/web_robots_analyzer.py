import httpx
import re
from urllib.parse import urlparse
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

async def parse_robots(content: str) -> dict:
    result = {
        "user_agents": [],
        "disallowed": [],
        "allowed": [],
        "crawl_delay": {},
        "sitemaps": [],
        "comments": [],
        "rules": [],
    }

    current_ua = "*"
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            result["comments"].append(line[1:].strip())
            continue

        m = re.match(r"^User-agent:\s*(.*)", line, re.I)
        if m:
            current_ua = m.group(1).strip()
            if current_ua not in result["user_agents"]:
                result["user_agents"].append(current_ua)
            continue

        m = re.match(r"^Disallow:\s*(.*)", line, re.I)
        if m:
            path = m.group(1).strip()
            if path:
                result["disallowed"].append({"path": path, "user_agent": current_ua})
            continue

        m = re.match(r"^Allow:\s*(.*)", line, re.I)
        if m:
            path = m.group(1).strip()
            if path:
                result["allowed"].append({"path": path, "user_agent": current_ua})
            continue

        m = re.match(r"^Crawl-Delay:\s*(\d+(?:\.\d+)?)", line, re.I)
        if m:
            result["crawl_delay"][current_ua] = float(m.group(1))
            continue

        m = re.match(r"^Sitemap:\s*(.*)", line, re.I)
        if m:
            sm = m.group(1).strip()
            if sm and sm not in result["sitemaps"]:
                result["sitemaps"].append(sm)
            continue

        result["rules"].append(line)

    return result

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    robots_content = ""
    robots_status = 0

    for proto in ["https", "http"]:
        try:
            resp = await client.get(f"{proto}://{domain}/robots.txt", timeout=10.0, follow_redirects=False, headers={"User-Agent": UA})
            robots_content = resp.text
            robots_status = resp.status_code
            break
        except Exception:
            continue

    if not robots_content or robots_status == 404:
        findings.append(IntelligenceFinding(
            entity=f"No robots.txt found for {domain} (HTTP {robots_status})",
            type="Robots: Not Found",
            source="RobotsAnalyzer",
            confidence="High",
            color="yellow",
            threat_level="Informational",
            status="Missing",
            tags=["robots", "not-found"]
        ))
        findings.append(IntelligenceFinding(
            entity=f"robots.txt Analysis: No robots.txt",
            type="Robots: Summary",
            source="RobotsAnalyzer",
            confidence="High",
            color="yellow",
            threat_level="Informational",
            tags=["robots", "summary"]
        ))
        return findings

    findings.append(IntelligenceFinding(
        entity=f"robots.txt found ({len(robots_content)} bytes, HTTP {robots_status})",
        type="Robots: Found",
        source="RobotsAnalyzer",
        confidence="High",
        color="emerald",
        threat_level="Informational",
        tags=["robots", "found"]
    ))

    parsed = await parse_robots(robots_content)

    if parsed["user_agents"]:
        findings.append(IntelligenceFinding(
            entity=f"Robots.txt defines rules for {len(parsed['user_agents'])} user-agent(s): {', '.join(parsed['user_agents'][:5])}",
            type="Robots: User Agents",
            source="RobotsAnalyzer",
            confidence="High",
            color="slate",
            threat_level="Informational",
            tags=["robots", "user-agents"]
        ))

    disallowed_paths = [d["path"] for d in parsed["disallowed"] if d["path"] and d["path"] != "/"]
    if disallowed_paths:
        findings.append(IntelligenceFinding(
            entity=f"Disallowed paths in robots.txt: {len(disallowed_paths)} paths",
            type="Robots: Disallowed Paths",
            source="RobotsAnalyzer",
            confidence="High",
            color="orange",
            threat_level="Informational",
            raw_data="\n".join(disallowed_paths[:20]),
            tags=["robots", "disallowed"]
        ))

        interesting_disallowed = [p for p in disallowed_paths if any(x in p.lower() for x in ["admin", "api", "backup", "private", "secret", "internal", "config", "db", "sql", "git", "env", "credentials", ".ht", "wp-admin", "login", "upload", "tmp", "debug", "test", "dev", "staging", "hidden", "cgi-bin"])]
        if interesting_disallowed:
            findings.append(IntelligenceFinding(
                entity=f"INTERESTING: {len(interesting_disallowed)} disallowed paths suggest sensitive areas",
                type="Robots: Interesting Disallowed",
                source="RobotsAnalyzer",
                confidence="Medium",
                color="red",
                threat_level="High Risk",
                raw_data="\n".join(interesting_disallowed[:15]),
                tags=["robots", "interesting", "sensitive"]
            ))
    else:
        findings.append(IntelligenceFinding(
            entity="No specific Disallow directives found (or all allowed)",
            type="Robots: No Disallows",
            source="RobotsAnalyzer",
            confidence="Medium",
            color="yellow",
            threat_level="Informational",
            tags=["robots", "no-disallow"]
        ))

    if parsed["allowed"]:
        findings.append(IntelligenceFinding(
            entity=f"Allow directives: {len(parsed['allowed'])} path(s)",
            type="Robots: Allow Directives",
            source="RobotsAnalyzer",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            raw_data="\n".join([a["path"] for a in parsed["allowed"][:10]]),
            tags=["robots", "allow"]
        ))

    if parsed["crawl_delay"]:
        for ua, delay in parsed["crawl_delay"].items():
            findings.append(IntelligenceFinding(
                entity=f"Crawl-Delay: {delay}s for {ua}",
                type="Robots: Crawl Delay",
                source="RobotsAnalyzer",
                confidence="High",
                color="slate",
                threat_level="Informational",
                raw_data=f"user_agent={ua}, delay={delay}",
                tags=["robots", "crawl-delay"]
            ))

    full_disallow = [d["path"] for d in parsed["disallowed"] if d["path"] == "/"]
    for ua_setting in parsed["user_agents"]:
        ua_disallows = [d["path"] for d in parsed["disallowed"] if d["user_agent"] == ua_setting and d["path"] == "/"]
        if ua_disallows:
            findings.append(IntelligenceFinding(
                entity=f"Full site disallowed for '{ua_setting}' (Disallow: /)",
                type="Robots: Full Disallow",
                source="RobotsAnalyzer",
                confidence="High",
                color="purple",
                threat_level="Informational",
                raw_data=f"user_agent={ua_setting}",
                tags=["robots", "disallow-all"]
            ))

    if parsed["sitemaps"]:
        findings.append(IntelligenceFinding(
            entity=f"Sitemap references in robots.txt: {len(parsed['sitemaps'])} found",
            type="Robots: Sitemap References",
            source="RobotsAnalyzer",
            confidence="High",
            color="blue",
            threat_level="Informational",
            raw_data="\n".join(parsed["sitemaps"]),
            tags=["robots", "sitemap"]
        ))

    if parsed["comments"]:
        comment_analysis = []
        for c in parsed["comments"]:
            if any(x in c.lower() for x in ["todo", "fixme", "hack", "secret", "password", "admin", "private", "hidden", "note", "important"]):
                comment_analysis.append(c)
        if comment_analysis:
            findings.append(IntelligenceFinding(
                entity=f"Interesting robots.txt comments: {len(comment_analysis)} found",
                type="Robots: Comment Analysis",
                source="RobotsAnalyzer",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                raw_data="\n".join(comment_analysis[:10]),
                tags=["robots", "comments", "leak"]
            ))

    findings.append(IntelligenceFinding(
        entity=f"robots.txt Analysis: {len(parsed['disallowed'])} disallows, {len(parsed['allowed'])} allows, {len(parsed['sitemaps'])} sitemaps, {len(parsed['user_agents'])} UAs",
        type="Robots: Summary",
        source="RobotsAnalyzer",
        confidence="High",
        color="red" if any("admin" in d["path"].lower() or "api" in d["path"].lower() for d in parsed["disallowed"][:5]) else "blue",
        threat_level="Informational",
        raw_data=f"disallows={len(parsed['disallowed'])}, allows={len(parsed['allowed'])}, sitemaps={len(parsed['sitemaps'])}, ua={len(parsed['user_agents'])}",
        tags=["robots", "summary"]
    ))

    return findings
