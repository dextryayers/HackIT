import json
from models import IntelligenceFinding
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

TELEGRAM_FRONTENDS = [
    ("t.me", "https://t.me/{username}"),
    ("t.me/s", "https://t.me/s/{username}"),
    ("tg.i-c-a.su", "https://tg.i-c-a.su/{username}"),
    ("tgstat.ru", "https://tgstat.ru/en/@{username}"),
    ("telemetr.io", "https://telemetr.io/en/channel/{username}"),
]

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    identifier = target.strip()

    username = identifier
    if identifier.startswith("http"):
        parts = identifier.rstrip("/").split("/")
        username = parts[-1] if parts[-1] else parts[-2]
    if username.startswith("@"):
        username = username[1:]

    for frontend_name, url_tpl in TELEGRAM_FRONTENDS:
        url = url_tpl.format(username=username)
        html = None
        try:
            resp = await safe_fetch(client,url, timeout=15.0,
                headers={"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"},
                follow_redirects=True)
            if resp.status_code == 200 and len(resp.text) > 300:
                html = resp.text
        except Exception:
            continue

        if not html:
            findings.append(make_finding(
                entity=f"Could not access {username} on {frontend_name}",
                ftype="Telegram: Unreachable",
                source="SocialTelegramIntel",
                confidence="Medium",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                status="Unreachable",
                tags=["telegram", frontend_name, "unreachable"]
            ))
            continue

        title_m = re.search(r'<title>([^<]+)</title>', html, re.IGNORECASE)
        title = title_m.group(1).strip() if title_m else username

        findings.append(make_finding(
            entity=f"Telegram: {title} (via {frontend_name})",
            ftype="Telegram: Channel/Profile Found",
            source="SocialTelegramIntel",
            confidence="High",
            color="purple",
            category="Social Media Intelligence",
            threat_level="Informational",
            status="Found",
            resolution=url,
            tags=["telegram", "channel", frontend_name.replace(".", "-")]
        ))

        description_m = re.search(r'<meta[^>]+name="description"[^>]+content="([^"]+)"', html, re.IGNORECASE)
        if not description_m:
            description_m = re.search(r'<div[^>]*class="[^"]*(?:tgme_channel_info_description|channel_info_description)[^"]*"[^>]*>([^<]+)', html)
        if description_m:
            desc = description_m.group(1).strip()[:200]
            findings.append(make_finding(
                entity=f"Description: {desc}",
                ftype="Telegram: Description",
                source="SocialTelegramIntel",
                confidence="High",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                raw_data=desc[:1000],
                tags=["telegram", "description"]
            ))

        member_m = re.search(r'(\d[\d,.]*[KkMmBb]?)\s*(?:member|Member|subscriber|Subscriber)', html)
        if not member_m:
            member_m = re.search(r'(\d[\d,.]*)\s*(?:members?|subscribers?)', html, re.IGNORECASE)
        if member_m:
            findings.append(make_finding(
                entity=f"Members: {member_m.group(1)}",
                ftype="Telegram: Member Count",
                source="SocialTelegramIntel",
                confidence="Medium",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["telegram", "members"]
            ))

        online_m = re.search(r'(\d[\d,.]*[KkMmBb]?)\s*(?:online|Online)', html)
        if online_m:
            findings.append(make_finding(
                entity=f"Online: {online_m.group(1)}",
                ftype="Telegram: Online Status",
                source="SocialTelegramIntel",
                confidence="Low",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["telegram", "online"]
            ))

        photo_m = re.search(r'<img[^>]*class="[^"]*(?:tgme_page_photo_image|channel_photo)[^"]*"[^>]+src="([^"]+)"', html)
        if not photo_m:
            photo_m = re.search(r'<meta[^>]+property="og:image"[^>]+content="([^"]+)"', html, re.IGNORECASE)
        if photo_m:
            findings.append(make_finding(
                entity=f"Channel photo: {photo_m.group(1)[:100]}",
                ftype="Telegram: Channel Photo",
                source="SocialTelegramIntel",
                confidence="Medium",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["telegram", "photo"]
            ))

        link_m = re.search(r'<meta[^>]+property="og:url"[^>]+content="([^"]+)"', html, re.IGNORECASE)
        if link_m:
            findings.append(make_finding(
                entity=f"Canonical URL: {link_m.group(1)[:100]}",
                ftype="Telegram: Canonical Link",
                source="SocialTelegramIntel",
                confidence="High",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["telegram", "canonical"]
            ))

        if frontend_name in ("tg.i-c-a.su", "tgstat.ru", "telemetr.io"):
            additional_data = extract_advanced_telegram_data(html, frontend_name)
            for key, val in additional_data.items():
                findings.append(make_finding(
                    entity=f"{key}: {val[:100]}",
                    ftype=f"Telegram: {key}",
                    source="SocialTelegramIntel",
                    confidence="Low",
                    color="slate",
                    category="Social Media Intelligence",
                    threat_level="Informational",
                    tags=["telegram", key.lower().replace(" ", "-"), frontend_name]
                ))

        username_refs = re.findall(r'@(\w+)', html)
        if username_refs:
            unique_refs = list(set(username_refs))
            if username in unique_refs:
                unique_refs.remove(username)
            if unique_refs:
                findings.append(make_finding(
                    entity=f"Referenced users/channels: @{', @'.join(unique_refs[:10])}",
                    ftype="Telegram: User/Channel References",
                    source="SocialTelegramIntel",
                    confidence="Low",
                    color="slate",
                    category="Social Media Intelligence",
                    threat_level="Informational",
                    tags=["telegram", "references"]
                ))

        link_refs = re.findall(r'(https://t\.me/\w+)', html)
        if link_refs:
            unique_links = list(set(link_refs))[:10]
            findings.append(make_finding(
                entity=f"Related Telegram links: {', '.join(unique_links)}",
                ftype="Telegram: Related Links",
                source="SocialTelegramIntel",
                confidence="Low",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["telegram", "related-links"]
            ))

        external_links = re.findall(r'href="(https?://(?:www\.)?(?!t\.me|telegram)[^"]+)"', html)
        if external_links:
            unique_ext = list(set(external_links))[:5]
            for link in unique_ext:
                findings.append(make_finding(
                    entity=f"External link: {link[:100]}",
                    ftype="Telegram: External Link",
                    source="SocialTelegramIntel",
                    confidence="Low",
                    color="slate",
                    category="Social Media Intelligence",
                    threat_level="Informational",
                    tags=["telegram", "external-link"]
                ))

        message_count_m = re.search(r'(\d+)\s*(?:message|Message|post|Post)', html)
        if message_count_m:
            findings.append(make_finding(
                entity=f"Messages/Posts: {message_count_m.group(1)}",
                ftype="Telegram: Message Count",
                source="SocialTelegramIntel",
                confidence="Low",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["telegram", "messages"]
            ))

        is_bot_m = re.search(r'(?:bot|Bot|BOT)', html)
        if is_bot_m and frontend_name == "t.me":
            findings.append(make_finding(
                entity="This may be a bot account (contains bot indicators)",
                ftype="Telegram: Bot Detection",
                source="SocialTelegramIntel",
                confidence="Low",
                color="orange",
                category="Social Media Intelligence",
                threat_level="Informational",
                status="Possible Bot",
                tags=["telegram", "bot"]
            ))

        is_restricted_m = re.search(r'(?:restricted|private|Private|private group)', html)
        if is_restricted_m:
            findings.append(make_finding(
                entity="Channel is private/restricted",
                ftype="Telegram: Access Restriction",
                source="SocialTelegramIntel",
                confidence="High",
                color="orange",
                category="Social Media Intelligence",
                threat_level="Informational",
                status="Private",
                tags=["telegram", "private"]
            ))

        break

    findings.append(make_finding(
        entity=f"Telegram intelligence gathering complete for @{username}",
        ftype="Telegram: Intel Summary",
        source="SocialTelegramIntel",
        confidence="Medium",
        color="purple",
        category="General OSINT",
        threat_level="Informational",
        status="Complete",
        tags=["telegram", "summary"]
    ))

    return findings

def extract_advanced_telegram_data(html: str, source: str) -> dict:
    result = {}
    if source == "tgstat.ru":
        eng_rate = re.search(r'(?:Engagement Rate|ER)[:\s]*([\d.]+%)', html)
        if eng_rate:
            result["Engagement Rate"] = eng_rate.group(1)
        posts_per_day = re.search(r'(?:Posts per day|Posts/day)[:\s]*([\d.]+)', html)
        if posts_per_day:
            result["Posts/Day"] = posts_per_day.group(1)
    elif source == "telemetr.io":
        views = re.search(r'(?:Views|views)[:\s]*(\d[\d,.]*[KkMmBb]?)', html)
        if views:
            result["Views"] = views.group(1)
        cpm = re.search(r'(?:CPM|cpm)[:\s]*([\d.]+)', html)
        if cpm:
            result["CPM"] = cpm.group(1)
    return result
