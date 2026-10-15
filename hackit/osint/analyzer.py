from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, List


HIGH_VALUE_CATEGORIES = {
    "Developer", "Security", "Professional", "Identity", "Forum", "Creator",
}

# Extra weight for media/diverse footprints (v3: broader coverage).
MEDIA_CATEGORIES = {
    "Media", "Music", "Social", "Messaging", "Video", "Streaming",
    "Podcast", "Photo", "Design",
}


def analyze_scan(data: Dict[str, object]) -> Dict[str, object]:
    profiles: List[Dict[str, object]] = data.get("profiles", [])
    hits = [item for item in profiles if item.get("status") == "hit"]
    possible = [item for item in profiles if item.get("status") == "possible"]
    unknown = [item for item in profiles if item.get("status") == "unknown"]

    category_counter = Counter(item.get("category", "Unknown") for item in hits)
    handle_counter = Counter(item.get("handle", "") for item in hits)

    clusters = defaultdict(list)
    for item in hits:
        clusters[item.get("category", "Unknown")].append({
            "platform": item.get("platform"),
            "handle": item.get("handle"),
            "url": item.get("url"),
            "title": item.get("title", ""),
        })

    high_value_hits = [
        item for item in hits
        if item.get("category") in HIGH_VALUE_CATEGORIES
    ]

    score = 0
    score += min(len(hits) * 4, 60)
    score += min(len(possible) * 2, 15)
    score += min(len(high_value_hits) * 3, 20)
    score += min(len(category_counter) * 2, 10)
    score = min(score, 100)

    media_hits = [item for item in hits if item.get("category") in MEDIA_CATEGORIES]
    score += min(len(media_hits), 8)

    corr = data.get("correlation", {}) if isinstance(data.get("correlation"), dict) else {}
    personae = corr.get("cross_platform_personae", 0)
    if personae >= 3:
        score += 10
    elif personae >= 1:
        score += 5
    if corr.get("category_breadth", 0) >= 6:
        score += 4

    source_count = data.get("source_count", 0)
    if source_count >= 500:
        score += 5

    if data.get("email", {}).get("is_email"):
        breaches = data.get("email", {}).get("breaches", [])
        if breaches:
            score += 5
        gravatar = data.get("email", {}).get("gravatar", {}).get("exists")
        if gravatar:
            score += 3

    phone = data.get("phone", {})
    if phone and "error" not in phone:
        social_found = phone.get("social_found", [])
        if social_found:
            score += 3

    domain = data.get("domain", {})
    if domain and domain.get("registrar"):
        score += 3

    score = min(score, 100)

    if score >= 70:
        confidence = "HIGH"
    elif score >= 35:
        confidence = "MEDIUM"
    elif score > 0:
        confidence = "LOW"
    else:
        confidence = "NONE"

    top_handles = [item for item, _ in handle_counter.most_common(8) if item]
    top_categories = [
        {"category": category, "hits": count}
        for category, count in category_counter.most_common()
    ]

    return {
        "confidence_score": score,
        "confidence": confidence,
        "hit_count": len(hits),
        "possible_count": len(possible),
        "unknown_count": len(unknown),
        "high_value_hits": len(high_value_hits),
        "media_hits": len([item for item in hits if item.get("category") in MEDIA_CATEGORIES]),
        "cross_platform_personae": corr.get("cross_platform_personae", 0) if isinstance(data.get("correlation"), dict) else 0,
        "top_handles": top_handles,
        "top_categories": top_categories,
        "clusters": dict(clusters),
    }
