import httpx
import re
import hashlib
import json
from datetime import datetime
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    email = target.strip().lower()
    if "@" not in email:
        findings.append(make_finding(
            entity="Not a valid email",
            ftype="Gravatar Error",
            source="EmailGravatar",
            confidence="High", color="red", category="General OSINT",
            threat_level="Informational", status="Error",
            tags=["error"]
        ))
        return findings

    email_hash = hashlib.md5(email.encode()).hexdigest()

    findings.append(make_finding(
        entity=f"Gravatar hash for {email}: {email_hash}",
        ftype="Gravatar: Hash Generation",
        source="EmailGravatar",
        confidence="High",
        color="slate",
        category="General OSINT",
        threat_level="Informational",
        status="Generated",
        raw_data=f"Email: {email} | MD5 Hash: {email_hash}",
        tags=["gravatar", "hash"]
    ))

    avatar_url = f"https://www.gravatar.com/avatar/{email_hash}"
    profile_url = f"https://www.gravatar.com/{email_hash}"

    profile_data = None
    try:
        resp = await safe_fetch(client, 
            f"https://www.gravatar.com/{email_hash}.json",
            timeout=15.0,
            headers={"User-Agent": UA, "Accept": "application/json"}
        )
        if resp.status_code == 200:
            profile_data = resp.json()
    except Exception:
        pass

    if profile_data:
        entry = profile_data.get("entry", [{}])[0]
        display_name = entry.get("displayName", "")
        preferred_username = entry.get("preferredUsername", "")
        about = entry.get("aboutMe", "")
        current_location = entry.get("currentLocation", "")
        phone_numbers = entry.get("phoneNumbers", [])
        emails = entry.get("emails", [])
        accounts = entry.get("accounts", [])
        urls = entry.get("urls", [])
        photos = entry.get("photos", [])
        profile_url_g = entry.get("profileUrl", "")
        thumbnail_url = entry.get("thumbnailUrl", "")

        findings.append(make_finding(
            entity=f"Gravatar profile: {display_name or preferred_username or 'Unknown'}",
            ftype="Gravatar: Profile Found",
            source="EmailGravatar",
            confidence="High",
            color="purple",
            category="Social Media Intelligence",
            threat_level="Informational",
            status="Found",
            resolution=profile_url,
            raw_data=f"Name: {display_name} | Username: {preferred_username} | Avatar: {avatar_url}",
            tags=["gravatar", "profile", "social-media"]
        ))

        if display_name:
            findings.append(make_finding(
                entity=f"Display Name: {display_name}",
                ftype="Gravatar: Display Name",
                source="EmailGravatar",
                confidence="High",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["gravatar", "name"]
            ))

        if preferred_username:
            findings.append(make_finding(
                entity=f"Username: {preferred_username}",
                ftype="Gravatar: Username",
                source="EmailGravatar",
                confidence="High",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["gravatar", "username"]
            ))

        if about:
            findings.append(make_finding(
                entity=f"Bio/About: {about[:200]}",
                ftype="Gravatar: Bio",
                source="EmailGravatar",
                confidence="Medium",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                raw_data=about[:500],
                tags=["gravatar", "bio"]
            ))

        if current_location:
            findings.append(make_finding(
                entity=f"Location: {current_location}",
                ftype="Gravatar: Location",
                source="EmailGravatar",
                confidence="Medium",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["gravatar", "location"]
            ))

        if phone_numbers:
            for pn in phone_numbers[:3]:
                pn_value = pn.get("value", "")
                pn_type = pn.get("type", "unknown")
                findings.append(make_finding(
                    entity=f"Phone: {pn_value} (type: {pn_type})",
                    type="Gravatar: Phone Number",
                    source="EmailGravatar",
                    confidence="High" if pn.get("primary") else "Medium",
                    color="orange",
                    category="Personal Information",
                    threat_level="Elevated Risk",
                    status="Exposed",
                    tags=["gravatar", "phone", "pii"]
                ))

        if emails:
            additional_email_count = len(emails)
            for em in emails[:3]:
                em_value = em.get("value", "")
                if em_value.lower() != email:
                    findings.append(make_finding(
                        entity=f"Additional email: {em_value}",
                        ftype="Gravatar: Associated Email",
                        source="EmailGravatar",
                        confidence="High",
                        color="slate",
                        category="Personal Information",
                        threat_level="Informational",
                        tags=["gravatar", "email", "associated-account"]
                    ))
            if additional_email_count > 3:
                findings.append(make_finding(
                    entity=f"Gravatar has {additional_email_count} total emails",
                    ftype="Gravatar: Email Count",
                    source="EmailGravatar",
                    confidence="Medium",
                    color="slate",
                    category="Personal Information",
                    threat_level="Informational",
                    tags=["gravatar", "email-count"]
                ))

        if accounts:
            for acc in accounts[:10]:
                domain = acc.get("domain", "")
                username = acc.get("username", "")
                display = acc.get("display", "")
                acc_url = acc.get("url", "")
                acc_shortname = acc.get("shortname", "")
                findings.append(make_finding(
                    entity=f"{domain}: {display or username}",
                    ftype=f"Gravatar: {domain} Account",
                    source="EmailGravatar",
                    confidence="High" if acc.get("verified") else "Medium",
                    color="purple",
                    category="Social Media Intelligence",
                    threat_level="Informational",
                    status="Verified" if acc.get("verified") else "Unverified",
                    resolution=acc_url,
                    raw_data=f"Platform: {domain} | Username: {username} | URL: {acc_url} | Verified: {acc.get('verified', False)}",
                    tags=["gravatar", "associated-account", domain.lower().replace(" ", "-")]
                ))

        if urls:
            for u in urls[:5]:
                u_value = u.get("value", "")
                u_title = u.get("title", "")
                findings.append(make_finding(
                    entity=f"URL: {u_title or u_value}",
                    ftype="Gravatar: Associated URL",
                    source="EmailGravatar",
                    confidence="Medium",
                    color="slate",
                    category="Social Media Intelligence",
                    threat_level="Informational",
                    resolution=u_value,
                    tags=["gravatar", "url"]
                ))

        if photos:
            avatar_photos = [p for p in photos if p.get("type") == "avatar" or "avatar" in p.get("value", "")]
            if avatar_photos:
                findings.append(make_finding(
                    entity=f"Avatar image available: {avatar_photos[0]['value'][:100]}",
                    ftype="Gravatar: Avatar Image",
                    source="EmailGravatar",
                    confidence="High",
                    color="slate",
                    category="Social Media Intelligence",
                    threat_level="Informational",
                    tags=["gravatar", "avatar"]
                ))

            if len(photos) > 1:
                findings.append(make_finding(
                    entity=f"Gravatar has {len(photos)} photo(s) on profile",
                    type="Gravatar: Photo Count",
                    source="EmailGravatar",
                    confidence="Medium",
                    color="slate",
                    category="Social Media Intelligence",
                    threat_level="Informational",
                    tags=["gravatar", "photos"]
                ))

        name_details = {}
        if entry.get("name"):
            name_details = entry["name"]
        if name_details:
            formatted = name_details.get("formatted", "")
            given = name_details.get("givenName", "")
            family = name_details.get("familyName", "")
            if formatted:
                findings.append(make_finding(
                    entity=f"Full Name: {formatted}",
                    ftype="Gravatar: Full Name",
                    source="EmailGravatar",
                    confidence="High",
                    color="slate",
                    category="Personal Information",
                    threat_level="Informational",
                    tags=["gravatar", "full-name"]
                ))
            if given:
                findings.append(make_finding(
                    entity=f"Given Name: {given}",
                    ftype="Gravatar: Given Name",
                    source="EmailGravatar",
                    confidence="High",
                    color="slate",
                    category="Personal Information",
                    threat_level="Informational",
                    tags=["gravatar", "given-name"]
                ))
            if family:
                findings.append(make_finding(
                    entity=f"Family Name: {family}",
                    ftype="Gravatar: Family Name",
                    source="EmailGravatar",
                    confidence="High",
                    color="slate",
                    category="Personal Information",
                    threat_level="Informational",
                    tags=["gravatar", "family-name"]
                ))

        profile_urls_associated = []
        if profile_url_g:
            profile_urls_associated.append(profile_url_g)
        for u in urls:
            val = u.get("value", "")
            if val:
                profile_urls_associated.append(val)

        if profile_urls_associated:
            findings.append(make_finding(
                entity=f"Total associated URLs/profiles: {len(profile_urls_associated)}",
                type="Gravatar: Associated URLs Summary",
                source="EmailGravatar",
                confidence="Medium",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["gravatar", "url-summary"]
            ))

        avatar_check_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404&s=200"
        try:
            av_resp = await safe_fetch(client, avatar_check_url, timeout=8.0,
                headers={"User-Agent": UA})
            if av_resp.status_code == 200:
                image_data = av_resp.content
                findings.append(make_finding(
                    entity=f"Avatar image: {len(image_data)} bytes, {av_resp.headers.get('content-type', 'unknown')}",
                    type="Gravatar: Avatar Metadata",
                    source="EmailGravatar",
                    confidence="High",
                    color="slate",
                    category="Social Media Intelligence",
                    threat_level="Informational",
                    raw_data=f"Size: {len(image_data)} bytes | Type: {av_resp.headers.get('content-type', 'unknown')} | URL: {avatar_url}",
                    tags=["gravatar", "avatar-meta"]
                ))
        except Exception:
            pass

    else:
        av_check = avatar_url + "?d=404"
        try:
            av_resp = await safe_fetch(client, av_check, timeout=8.0,
                headers={"User-Agent": UA})
            if av_resp.status_code == 200:
                findings.append(make_finding(
                    entity=f"Avatar exists but no profile JSON for {email}",
                    ftype="Gravatar: Avatar Without Profile",
                    source="EmailGravatar",
                    confidence="Medium",
                    color="slate",
                    category="Social Media Intelligence",
                    threat_level="Informational",
                    status="Avatar Only",
                    resolution=avatar_url,
                    tags=["gravatar", "avatar-only"]
                ))
            else:
                findings.append(make_finding(
                    entity="No Gravatar profile or avatar found",
                    ftype="Gravatar: Not Found",
                    source="EmailGravatar",
                    confidence="High",
                    color="slate",
                    category="Social Media Intelligence",
                    threat_level="Informational",
                    status="Not Found",
                    tags=["gravatar", "not-found"]
                ))
        except Exception:
            findings.append(make_finding(
                entity="No Gravatar profile or avatar found",
                ftype="Gravatar: Not Found",
                source="EmailGravatar",
                confidence="High",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                status="Not Found",
                tags=["gravatar", "not-found"]
            ))

    rating = "G"
    try:
        rating_resp = await safe_fetch(client, f"https://www.gravatar.com/avatar/{email_hash}?d=404&f=y", timeout=8.0,
            headers={"User-Agent": UA})
        rating_map = {"g": "G (General)", "pg": "PG (Parental Guidance)", "r": "R (Restricted)", "x": "X (Explicit)"}
        if rating_resp.status_code == 200:
            ct = rating_resp.headers.get("content-type", "")
            if "image" in ct:
                findings.append(make_finding(
                    entity=f"Avatar accessible without restrictions",
                    ftype="Gravatar: Accessibility",
                    source="EmailGravatar",
                    confidence="Medium",
                    color="emerald",
                    category="Social Media Intelligence",
                    threat_level="Informational",
                    tags=["gravatar", "accessibility"]
                ))
    except Exception:
        pass

    qr_url = f"https://www.gravatar.com/{email_hash}.qr"
    vcf_url = f"https://www.gravatar.com/{email_hash}.vcf"
    findings.append(make_finding(
        entity=f"Gravatar related URLs: QR={qr_url}, VCF={vcf_url}, Profile={profile_url}",
        ftype="Gravatar: Related URLs",
        source="EmailGravatar",
        confidence="High",
        color="slate",
        category="General OSINT",
        threat_level="Informational",
        tags=["gravatar", "related-urls"]
    ))

    association_count = sum(1 for f in findings if f.type.startswith("Gravatar:") and "Account" in f.type)
    findings.append(make_finding(
        entity=f"Gravatar scan complete: {association_count} associated accounts, profile={'FOUND' if profile_data else 'NOT FOUND'}",
        ftype="Gravatar: Scan Summary",
        source="EmailGravatar",
        confidence="High",
        color="purple",
        category="General OSINT",
        threat_level="Informational",
        status="Complete",
        tags=["gravatar", "summary"]
    ))

    return findings
