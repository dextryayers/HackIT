import httpx
import re
import hashlib
from urllib.parse import urlparse
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

TYPO_DOMAINS = [
    "goggle.com", "facebok.com", "twiter.com", "instagrm.com", "linkdin.com",
    "yutube.com", "gmail.com", "microsft.com", "amazn.com", "googl.com",
    "whatsapp.com", "whatsap.com", "telgram.com", "teligram.com",
]

PHISHING_INDICATORS = [
    r"login", r"signin", r"verify", r"account", r"secure", r"update",
    r"confirm", r"authenticate", r"password", r"credential", r"banking",
    r"reset.*password", r"2fa", r"two.?factor", r"security.?check",
]

CLONE_PLATFORMS = [
    "github.io", "gitlab.io", "netlify.app", "vercel.app", "pages.dev",
    "herokuapp.com", "firebaseapp.com", "web.app", "surge.sh",
    "onrender.com", "fly.dev", "railway.app", "cyclic.app",
    "glitch.me", "repl.co", "000webhostapp.com", "infinityfreeapp.com",
]

async def fetch_page_hash(client: httpx.AsyncClient, url: str) -> tuple:
    try:
        resp = await client.get(url, timeout=10.0, follow_redirects=True, headers={"User-Agent": UA})
        if resp.status_code == 200:
            content = resp.text[:50000]
            content_hash = hashlib.md5(content.encode()).hexdigest()
            title = ""
            m = re.search(r"<title>(.*?)</title>", content, re.I | re.DOTALL)
            if m:
                title = m.group(1).strip()
            return content_hash, title, resp.status_code
        return "", "", resp.status_code
    except Exception:
        return "", "", 0

async def fetch_favicon_hash(client: httpx.AsyncClient, url: str) -> str:
    try:
        for path in ["/favicon.ico", "/favicon.png", "/apple-touch-icon.png"]:
            try:
                resp = await client.get(f"{url.rstrip('/')}{path}", timeout=5.0)
                if resp.status_code == 200 and len(resp.content) > 50:
                    return hashlib.md5(resp.content[:10000]).hexdigest()
            except Exception:
                continue
    except Exception:
        pass
    return ""

async def check_clone_on_domain(client: httpx.AsyncClient, original_url: str, clone_domain: str) -> dict:
    result = {"domain": clone_domain, "is_clone": False, "similarity": 0, "details": []}
    try:
        for proto in ["https", "http"]:
            try:
                url = f"{proto}://{clone_domain}"
                page_hash, title, status = await fetch_page_hash(client, url)
                if page_hash:
                    result["title"] = title
                    result["status"] = status
                    result["page_hash"] = page_hash
                    return result
            except Exception:
                continue
    except Exception:
        pass
    return result

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    orig_hash, orig_title, orig_status = await fetch_page_hash(client, f"https://{domain}")
    if not orig_hash:
        orig_hash, orig_title, orig_status = await fetch_page_hash(client, f"http://{domain}")

    if not orig_hash:
        findings.append(IntelligenceFinding(
            entity=f"Could not fetch original page for {domain}",
            type="Clone: Fetch Failed",
            source="CloneDetector",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["clone", "phishing"]
        ))
        return findings

    findings.append(IntelligenceFinding(
        entity=f"Original page hash: {orig_hash[:16]}... | Title: {orig_title[:80] or 'None'}",
        type="Clone: Original Fingerprint",
        source="CloneDetector",
        confidence="High",
        color="slate",
        threat_level="Informational",
        raw_data=f"hash={orig_hash}, title={orig_title}",
        tags=["clone", "fingerprint"]
    ))

    orig_fav_hash = await fetch_favicon_hash(client, f"https://{domain}")
    if orig_fav_hash:
        findings.append(IntelligenceFinding(
            entity=f"Favicon hash: {orig_fav_hash[:16]}...",
            type="Clone: Favicon Fingerprint",
            source="CloneDetector",
            confidence="High",
            color="slate",
            threat_level="Informational",
            raw_data=f"favhash={orig_fav_hash}",
            tags=["clone", "favicon"]
        ))

    suspicious_candidates = TYPO_DOMAINS + [f"{d}{d_}" for d_ in [".com", ".net", ".org", ".xyz", ".top", ".club", ".work", ".live", ".site", ".online", ".tech", ".store", ".info", ".biz", ".cc", ".co", ".io", ".tk", ".ml", ".ga", ".cf", ".gq"] for d in TYPO_DOMAINS]
    suspicious_candidates = suspicious_candidates[:30]

    clones_found = []
    attempts = []
    for cand in suspicious_candidates[:15]:
        if domain.replace(".", "") in cand or cand in domain:
            continue
        result = await check_clone_on_domain(client, domain, cand)
        if result.get("page_hash") == orig_hash:
            clones_found.append(cand)
            attempts.append(result)

    parsed_domain = domain.split(".")
    if len(parsed_domain) > 2:
        base_domain = ".".join(parsed_domain[-2:])
        typo_variants = []
        for tld in [".com", ".net", ".org", ".xyz", ".top", ".io", ".co", ".cc"]:
            for prefix in ["", "www-", "login-", "secure-", "my-", "app-"]:
                variant = f"{prefix}{parsed_domain[-2]}{tld}"
                if variant != base_domain and variant not in typo_variants:
                    typo_variants.append(variant)
        for variant in typo_variants[:10]:
            result = await check_clone_on_domain(client, domain, variant)
            if result.get("page_hash") == orig_hash:
                clones_found.append(variant)
                attempts.append(result)

    if clones_found:
        findings.append(IntelligenceFinding(
            entity=f"Found {len(clones_found)} potential clones of {domain}",
            type="Clone: Clones Detected",
            source="CloneDetector",
            confidence="High",
            color="red",
            threat_level="Critical",
            raw_data="\n".join(clones_found[:10]),
            tags=["clone", "phishing", "typosquatting"]
        ))
        for clone in clones_found[:5]:
            findings.append(IntelligenceFinding(
                entity=f"Clone found: {clone}",
                type="Clone: Matched Clone",
                source="CloneDetector",
                confidence="High",
                color="red",
                threat_level="Critical",
                status="Confirmed Clone",
                raw_data=f"clone_domain={clone}, original={domain}",
                tags=["clone", "phishing", "matched"]
            ))
    else:
        findings.append(IntelligenceFinding(
            entity=f"No clones detected on typo-squatted domains (checked {len(attempts)})",
            type="Clone: No Clones Found",
            source="CloneDetector",
            confidence="Medium",
            color="emerald",
            threat_level="Informational",
            tags=["clone", "clean"]
        ))

    clone_platform_findings = []
    for platform in CLONE_PLATFORMS:
        test_url = f"{domain.replace('.', '-')}.{platform}"
        try:
            resp = await client.get(f"https://{test_url}", timeout=5.0, follow_redirects=True, headers={"User-Agent": UA})
            if resp.status_code == 200:
                test_hash = hashlib.md5(resp.text[:50000].encode()).hexdigest()
                clone_platform_findings.append((test_url, test_hash))
        except Exception:
            continue

    for plat_url, plat_hash in clone_platform_findings:
        findings.append(IntelligenceFinding(
            entity=f"Potential clone on platform: {plat_url}",
            type="Clone: Platform Clone",
            source="CloneDetector",
            confidence="Medium",
            color="red",
            threat_level="High Risk",
            raw_data=f"url={plat_url}, hash={plat_hash[:16]}",
            tags=["clone", "platform", "phishing"]
        ))

    findings.append(IntelligenceFinding(
        entity=f"Clone Detection summary: {len(clones_found)} clones, {len(clone_platform_findings)} platform copies",
        type="Clone: Summary",
        source="CloneDetector",
        confidence="High",
        color="red" if clones_found else "emerald",
        threat_level="Critical" if clones_found else "Informational",
        raw_data=f"clones={len(clones_found)}, platform_copies={len(clone_platform_findings)}",
        tags=["clone", "summary"]
    ))

    return findings
