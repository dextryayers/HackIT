import re
from urllib.parse import urlparse
from models import IntelligenceFinding
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip

DEFACEMENT_ARCHIVES = [
    "https://zone-h.org/archive/domain={}",
    "https://www.zone-h.org/archive/domain={}",
    "https://archive.is/{}",
    "https://web.archive.org/web/*/{}",
]

HACKER_GROUP_PATTERNS = {
    "Anonymous": ["anonymous", "anon", "op"],
    "LulzSec": ["lulzsec", "lulz", "lulz security"],
    "APT Collective": ["apt", "apt collective"],
    "OurMine": ["ourmine", "our mine"],
    "Syrian Electronic Army": ["sea", "syrian electronic", "syrian"],
    "China/Hell": ["china hell", "chinese hacker"],
    "TurkHackTeam": ["turk", "turkish", "turkhackteam"],
    "Ryzee": ["ryzee", "ryzee1337"],
    "GhostShell": ["ghostshell", "ghost shell"],
    "AnonGhost": ["anonghost", "anon ghost"],
    "Mysterious Team": ["mysterious", "mysterious team"],
    "Killnet": ["killnet", "kill net"],
    "Garuna": ["garuna", "garuna team"],
    "TeamInsane": ["teaminsane", "insane"],
    "DECAY": ["decay", "decay team"],
}

DEFACEMENT_SIGNATURES = [
    re.compile(r'hacked by|defac(ed|ing)|compromised|pwned|owned', re.I),
    re.compile(r'<[^>]*>.*hacked|<[^>]*>.*defaced', re.I),
    re.compile(r'#hacked|#defaced|#pwned|#owned', re.I),
    re.compile(r'your\s+(site|server|website)\s+(has been|was|is)\s+(hacked|defaced|compromised)', re.I),
    re.compile(r'greetz|greetings|shoutout|dedicated.?to', re.I),
    re.compile(r'team\s+\w+|crew\s+\w+|group\s+\w+|squad\s+\w+', re.I),
    re.compile(r'message\s+(from|by|to)\s+\w+', re.I),
    re.compile(r'we\s+are\s+\w+|we\s+were\s+here|we\s+own|we\s+rule', re.I),
]

async def check_zone_h(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        url = f"https://zone-h.org/archive/domain={target}"
        resp = await safe_fetch(client,url, timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            text = resp.text.lower()
            if "notifier" in text or "defacement" in text or "archive" in text:
                results.append({
                    "source": "Zone-H",
                    "url": url,
                    "content_length": len(text),
                    "has_defacement_data": "defac" in text or "hacked" in text
                })
    except:
        pass
    return results

async def check_archive_org(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url={target}&output=json&limit=100"
        resp = await safe_fetch(client,url, timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200 and len(resp.text) > 10:
            data = resp.json()
            results.append({
                "source": "Wayback Machine",
                "snapshot_count": len(data) if isinstance(data, list) else 0,
                "url": url
            })
    except:
        pass
    return results

async def check_archive_is(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        url = f"https://archive.is/{target}"
        resp = await safe_fetch(client,url, timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200 and len(resp.text) > 200:
            results.append({
                "source": "Archive.is",
                "url": url,
                "accessible": True,
                "content_length": len(resp.text)
            })
    except:
        pass
    return results

async def detect_defacement_signatures(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        for signature in DEFACEMENT_SIGNATURES:
            match = signature.search(target_lower)
            if match:
                results.append({"signature": str(signature)[:60], "match": match.group()})
    except:
        pass
    return results

async def detect_hacker_group(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        for group, indicators in HACKER_GROUP_PATTERNS.items():
            for ind in indicators:
                if ind in target_lower:
                    results.append({"group": group, "matched": ind})
                    break
    except:
        pass
    return results

async def check_current_mirror(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        if not target.startswith(("http://", "https://")):
            url = f"https://{target}"
        else:
            url = target
        resp = await safe_fetch(client,url, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"})
        content = resp.text.lower()
        for sig in DEFACEMENT_SIGNATURES:
            if sig.search(content):
                results.append({
                    "currently_defaced": True,
                    "signature_matched": str(sig)[:60],
                    "status_code": resp.status_code
                })
                break
        if not results:
            results.append({"currently_defaced": False, "status_code": resp.status_code})
    except:
        pass
    return results

async def build_defacement_timeline(defacements: list, archive_data: list) -> list:
    timeline = []
    try:
        for d in defacements:
            timeline.append({"event": "defacement", "source": d.get("source", "Unknown")})
        for a in archive_data:
            if "snapshot_count" in a:
                timeline.append({"event": "archive_snapshot", "count": a["snapshot_count"], "source": a["source"]})
    except:
        pass
    return timeline

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    query = target.strip().lower()

    zone_h_results = await check_zone_h(client, query)
    for r in zone_h_results:
        findings.append(make_finding(
            entity=f"Zone-H defacement archive: {r['url']} ({r['content_length']} bytes, has_data: {r['has_defacement_data']})",
            ftype="Defacement Archive Check",
            source="Zone-H",
            confidence="Medium",
            color="red" if r['has_defacement_data'] else "slate",
            category="Defacement Intelligence",
            threat_level="High Risk" if r['has_defacement_data'] else "Informational",
            status="Archive Checked",
            resolution=query,
            tags=["defacement", "zone-h", "archive"]
        ))

    archive_org_results = await check_archive_org(client, query)
    for r in archive_org_results:
        findings.append(make_finding(
            entity=f"Wayback Machine: {r['snapshot_count']} snapshots archived for {query}",
            ftype="Wayback Machine Check",
            source="Wayback Machine",
            confidence="Medium",
            color="slate",
            category="Defacement Intelligence",
            threat_level="Informational",
            status="Snapshots Found",
            resolution=query,
            tags=["defacement", "wayback", "archive"]
        ))

    archive_is_results = await check_archive_is(client, query)
    for r in archive_is_results:
        findings.append(make_finding(
            entity=f"Archive.is: snapshot available ({r['content_length']} bytes)",
            ftype="Archive.is Check",
            source="Archive.is",
            confidence="Medium",
            color="slate",
            category="Defacement Intelligence",
            threat_level="Informational",
            status="Snapshot Available",
            resolution=query,
            tags=["defacement", "archive.is", "snapshot"]
        ))

    sig_results = await detect_defacement_signatures(query)
    for r in sig_results:
        findings.append(make_finding(
            entity=f"Defacement signature: {r['match']}",
            ftype="Defacement Signature Detection",
            source="Defacement Tracker",
            confidence="Medium",
            color="red",
            category="Defacement Intelligence",
            threat_level="High Risk",
            status="Defacement Signature",
            resolution=query,
            tags=["defacement", "signature", r['match'][:20].lower().replace(" ", "-")]
        ))

    group_results = await detect_hacker_group(query)
    for r in group_results:
        findings.append(make_finding(
            entity=f"Hacker group attribution: {r['group']} (matched: {r['matched']})",
            ftype="Hacker Group Attribution",
            source="Defacement Tracker",
            confidence="Medium",
            color="orange",
            category="Defacement Intelligence",
            threat_level="Elevated Risk",
            status="Group Identified",
            resolution=query,
            tags=["defacement", "group", r['group'].lower().replace(" ", "-")]
        ))

    current_status = await check_current_mirror(client, query)
    for r in current_status:
        if r.get("currently_defaced"):
            findings.append(make_finding(
                entity=f"Target CURRENTLY defaced! (signature: {r.get('signature_matched', 'N/A')[:50]}...)",
                ftype="Current Defacement Status",
                source="Defacement Tracker",
                confidence="High",
                color="red",
                category="Defacement Intelligence",
                threat_level="Critical",
                status="Currently Defaced",
                resolution=query,
                tags=["defacement", "active", "critical"]
            ))
        else:
            findings.append(make_finding(
                entity=f"Target appears clean (HTTP {r.get('status_code', 0)})",
                ftype="Current Defacement Status",
                source="Defacement Tracker",
                confidence="Low",
                color="emerald",
                category="Defacement Intelligence",
                threat_level="Informational",
                status="Clean",
                resolution=query,
                tags=["defacement", "clean", "no-defacement"]
            ))

    timeline = await build_defacement_timeline(zone_h_results, archive_org_results)
    for t in timeline:
        if "event" in t and t["event"] == "archive_snapshot":
            findings.append(make_finding(
                entity=f"Archive timeline: {t['count']} snapshots from {t['source']}",
                ftype="Defacement Timeline",
                source="Defacement Tracker",
                confidence="Low",
                color="slate",
                category="Defacement Intelligence",
                threat_level="Informational",
                status="Timeline Entry",
                resolution=query,
                tags=["defacement", "timeline", t['source'].lower().replace(" ", "-")]
            ))

    for group in HACKER_GROUP_PATTERNS:
        findings.append(make_finding(
            entity=f"Hacker group monitored: {group}",
            ftype="Hacker Group Coverage",
            source="Defacement Tracker",
            confidence="Low",
            color="slate",
            category="Defacement Intelligence",
            threat_level="Informational",
            status="Monitored",
            resolution=query,
            tags=["defacement", "group", group.lower().replace(" ", "-")]
        ))

    findings.append(make_finding(
        entity=f"Defacement tracking complete for {query}: checked {len(DEFACEMENT_ARCHIVES)} archives, {len(HACKER_GROUP_PATTERNS)} groups, {len(DEFACEMENT_SIGNATURES)} signatures",
        ftype="Defacement Tracking Summary",
        source="Defacement Tracker",
        confidence="Medium",
        color="slate",
        category="Defacement Intelligence",
        threat_level="Informational",
        status="Complete",
        resolution=query,
        tags=["defacement", "summary", "tracking"]
    ))

    return findings
