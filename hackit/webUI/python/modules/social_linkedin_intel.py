import re
import json
from ..module_common import safe_fetch, make_finding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

LINKEDIN_PUBLIC_PREFIXES = [
    "https://www.linkedin.com/in/",
    "https://linkedin.com/in/",
    "https://www.linkedin.com/company/",
]

async def crawl(target: str, client: AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    identifier = target.strip()

    profile_url = None
    is_company = False
    if identifier.startswith("https://www.linkedin.com/in/") or identifier.startswith("https://linkedin.com/in/"):
        profile_url = identifier.rstrip("/")
    elif identifier.startswith("https://www.linkedin.com/company/") or identifier.startswith("https://linkedin.com/company/"):
        profile_url = identifier.rstrip("/")
        is_company = True
    elif identifier.startswith("in/"):
        profile_url = "https://www.linkedin.com/" + identifier
    elif "/" not in identifier and "." not in identifier.split("/")[0]:
        profile_url = f"https://www.linkedin.com/in/{identifier}"
    else:
        profile_url = f"https://www.linkedin.com/in/{identifier.split('/')[-1]}"

    google_cache_url = f"https://webcache.googleusercontent.com/search?q=cache:{profile_url}"
    textise_url = f"https://r.jina.ai/http://{profile_url}"
    textise_url2 = f"https://corsproxy.io/?url={profile_url}"

    html = None
    for url in [google_cache_url, textise_url, textise_url2, profile_url]:
        try:
            resp = await safe_fetch(client, url, timeout=15.0)
            if resp.status_code == 200 and len(resp.text) > 500:
                html = resp.text
                break
        except Exception:
            pass

    if not html:
        findings.append(make_finding(
            entity=f"Could not access LinkedIn profile: {identifier}",
            ftype="LinkedIn: Profile Not Accessible",
            source="SocialLinkedInIntel",
            confidence="High", color="orange",
            category="Social Media Intelligence",
            threat_level="Informational", status="Unreachable",
            tags=["linkedin", "unreachable"]
        ))
        return findings

    title_m = re.search(r'<title>([^<]+)</title>', html, re.IGNORECASE)
    title = title_m.group(1).strip() if title_m else ""

    findings.append(make_finding(
        entity=f"{'Company' if is_company else 'Profile'}: {title or identifier}",
        ftype=f"LinkedIn: {'Company' if is_company else 'Profile'} Found",
        source="SocialLinkedInIntel",
        confidence="Medium",
        color="purple",
        category="Social Media Intelligence",
        threat_level="Informational",
        status="Found",
        resolution=profile_url,
        tags=["linkedin", "company" if is_company else "profile"]
    ))

    name_m = re.search(r'<h1[^>]*class="[^"]*(?:text-heading-xlarge|profile-name|inline-block)[^"]*"[^>]*>([^<]+)', html)
    if not name_m:
        name_m = re.search(r'"firstName"\s*:\s*"([^"]+)"', html)
    if not name_m:
        name_m = re.search(r'<title>([^|]+)', html)
    if name_m:
        findings.append(make_finding(
            entity=f"Name: {name_m.group(1).strip()[:100]}",
            ftype="LinkedIn: Name",
            source="SocialLinkedInIntel",
            confidence="Medium",
            color="slate",
            category="Personal Information",
            threat_level="Informational",
            tags=["linkedin", "name"]
        ))

    headline_m = re.search(r'<div[^>]*class="[^"]*(?:text-body-medium|headline)[^"]*"[^>]*>([^<]+)', html)
    if not headline_m:
        headline_m = re.search(r'"headline"\s*:\s*"([^"]+)"', html)
    if not headline_m:
        headline_m = re.search(r'<title>[^|]+\|\s*([^|]+)', html)
    if headline_m:
        findings.append(make_finding(
            entity=f"Headline: {headline_m.group(1).strip()[:200]}",
            ftype="LinkedIn: Headline",
            source="SocialLinkedInIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["linkedin", "headline"]
        ))

    location_m = re.search(r'"location"\s*:\s*"([^"]+)"', html)
    if not location_m:
        location_m = re.search(r'(?:Location|location)[:\s]*([^<]{3,50})', html)
    if location_m:
        findings.append(make_finding(
            entity=f"Location: {location_m.group(1).strip()[:100]}",
            ftype="LinkedIn: Location",
            source="SocialLinkedInIntel",
            confidence="Medium",
            color="slate",
            category="Personal Information",
            threat_level="Informational",
            tags=["linkedin", "location"]
        ))

    industry_m = re.search(r'"industry"\s*:\s*"([^"]+)"', html)
    if industry_m:
        findings.append(make_finding(
            entity=f"Industry: {industry_m.group(1)}",
            ftype="LinkedIn: Industry",
            source="SocialLinkedInIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["linkedin", "industry"]
        ))

    about_m = re.search(r'"summary"\s*:\s*"([^"]+)"', html)
    if not about_m:
        about_m = re.search(r'(?:About|Summary|about)[:\s]*([^<]{30,500})', html)
    if about_m:
        findings.append(make_finding(
            entity=f"About/Summary: {about_m.group(1)[:200]}",
            ftype="LinkedIn: About",
            source="SocialLinkedInIntel",
            confidence="Low",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["linkedin", "about"]
        ))

    skills = re.findall(r'"name"\s*:\s*"([^"]+)"', html)
    if not skills:
        skills = []
        skill_matches = re.findall(r'<span[^>]*class="[^"]*(?:skill|pill)[^"]*"[^>]*>([^<]+)', html, re.IGNORECASE)
        for s in skill_matches[:15]:
            skills.append(s.strip())
    if skills:
        unique_skills = list(set(skills))[:15]
        findings.append(make_finding(
            entity=f"Skills ({len(unique_skills)}): {', '.join(unique_skills)}",
            ftype="LinkedIn: Skills",
            source="SocialLinkedInIntel",
            confidence="Medium",
            color="slate",
            category="Professional Intelligence",
            threat_level="Informational",
            tags=["linkedin", "skills"]
        ))

    experience = re.findall(r'"companyName"\s*:\s*"([^"]+)"', html)
    if experience:
        unique_experience = list(set(experience))[:8]
        findings.append(make_finding(
            entity=f"Companies: {', '.join(unique_experience)}",
            ftype="LinkedIn: Experience",
            source="SocialLinkedInIntel",
            confidence="Medium",
            color="slate",
            category="Professional Intelligence",
            threat_level="Informational",
            tags=["linkedin", "experience"]
        ))

    positions = re.findall(r'"title"\s*:\s*"([^"]+)"', html)
    if positions:
        unique_positions = list(set(positions))[:8]
        findings.append(make_finding(
            entity=f"Job titles: {', '.join(unique_positions)}",
            ftype="LinkedIn: Positions",
            source="SocialLinkedInIntel",
            confidence="Medium",
            color="slate",
            category="Professional Intelligence",
            threat_level="Informational",
            tags=["linkedin", "positions"]
        ))

    education_m = re.search(r'"educations"\s*:\s*\[(.*?)\]', html, re.DOTALL)
    if education_m:
        edu_data = education_m.group(1)
        schools = re.findall(r'"schoolName"\s*:\s*"([^"]+)"', edu_data)
        if schools:
            findings.append(make_finding(
                entity=f"Education: {', '.join(schools)}",
                ftype="LinkedIn: Education",
                source="SocialLinkedInIntel",
                confidence="Medium",
                color="slate",
                category="Personal Information",
                threat_level="Informational",
                tags=["linkedin", "education"]
            ))

    connections_m = re.search(r'(\d[\d,.]*[KkMmBb]?)\s*(?:connection|Connection|Connections)', html)
    if connections_m:
        findings.append(make_finding(
            entity=f"Connections: {connections_m.group(1)}",
            ftype="LinkedIn: Connections",
            source="SocialLinkedInIntel",
            confidence="Low",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["linkedin", "connections"]
        ))

    profile_pic_m = re.search(r'<meta[^>]+property="og:image"[^>]+content="([^"]+)"', html, re.IGNORECASE)
    if profile_pic_m:
        findings.append(make_finding(
            entity=f"Profile image: {profile_pic_m.group(1)[:100]}",
            ftype="LinkedIn: Profile Image",
            source="SocialLinkedInIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["linkedin", "profile-image"]
        ))

    if is_company:
        company_info = {
            "company_size": re.search(r'(?:Company Size|company size)[:\s]*([^<]{5,50})', html),
            "followers": re.search(r'(\d[\d,.]*[KkMmBb]?)\s*(?:follower|Follower|Followers)', html),
            "specialties": re.search(r'(?:Specialties|specialties)[:\s]*([^<]{10,200})', html),
        }
        for key, m in company_info.items():
            if m:
                findings.append(make_finding(
                    entity=f"{key.replace('_', ' ').title()}: {m.group(1).strip()[:100]}",
                    ftype=f"LinkedIn: Company {key.replace('_', ' ').title()}",
                    source="SocialLinkedInIntel",
                    confidence="Low",
                    color="slate",
                    category="Professional Intelligence",
                    threat_level="Informational",
                    tags=["linkedin", "company", key]
                ))

    findings.append(make_finding(
        entity=f"LinkedIn {'company' if is_company else 'profile'} intelligence complete: {title}",
        ftype="LinkedIn: Intel Summary",
        source="SocialLinkedInIntel",
        confidence="Medium",
        color="purple",
        category="General OSINT",
        threat_level="Informational",
        status="Complete",
        raw_data=f"Profile: {profile_url} | Skills: {len(skills) if 'skills' in dir() else 0} | Experience: {len(experience) if 'experience' in dir() else 0}",
        tags=["linkedin", "summary"]
    ))

    return findings
