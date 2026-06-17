from __future__ import annotations

import re
from typing import List


COMMON_EMAIL_DOMAINS = [
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com",
    "proton.me", "protonmail.com", "live.com", "aol.com", "mail.com",
    "yandex.com", "zoho.com", "gmx.com", "fastmail.com", "tutanota.com",
]

COUNTRY_DOMAINS = [
    "gmail.co.id", "yahoo.co.id", "yahoo.co.uk", "yahoo.co.jp",
    "hotmail.co.uk", "live.co.uk", "icloud.de", "mail.ru",
]

PROFESSIONAL_DOMAINS = [
    "me.com", "workmail.com", "email.com", "inbox.com",
    "usa.com", "asia.com", "europe.com", "consultant.com",
    "engineer.com", "techie.com", "hackermail.com",
]


def split_identity(query: str) -> List[str]:
    clean = re.sub(r"[^a-zA-Z0-9._@+\- ]", " ", query.strip().lower())
    if "@" in clean:
        clean = clean.split("@", 1)[0]
    parts = [part for part in re.split(r"[\s._+\-]+", clean) if part]
    return parts


def build_email_candidates(query: str) -> List[str]:
    parts = split_identity(query)
    if not parts:
        return []

    emails = set()

    first = parts[0]
    last = parts[-1] if len(parts) > 1 else ""
    middle = " ".join(parts[1:-1]) if len(parts) > 2 else ""

    patterns = []
    base_patterns = [first]
    if last:
        base_patterns.extend([
            f"{first}{last}", f"{first}.{last}", f"{first}_{last}", f"{first}-{last}",
            f"{first[0]}{last}", f"{first}.{last[0]}", f"{first[0]}.{last}",
            f"{last}{first}", f"{last}.{first}", f"{last}_{first}", f"{last}-{first}",
            f"{first[0]}{last[0]}",
        ])
    if middle:
        mi = middle[0]
        base_patterns.extend([
            f"{first}{mi}{last}", f"{first}.{mi}.{last}",
            f"{first}_{mi}_{last}", f"{first}-{mi}-{last}",
            f"{first}.{last}", f"{first}{last}",
        ])
    if len(parts) >= 2:
        base_patterns.extend([
            last, f"{last}{first[0]}",
            f"{first}.{last[0]}{last[1:]}" if len(last) > 1 else "",
        ])

    for pattern in base_patterns:
        if not pattern:
            continue
        pattern = pattern.strip("._- ").lower()
        if 3 <= len(pattern) <= 40 and re.match(r"^[a-z0-9._-]+$", pattern):
            for domain in COMMON_EMAIL_DOMAINS:
                emails.add(f"{pattern}@{domain}")
            for domain in PROFESSIONAL_DOMAINS:
                emails.add(f"{pattern}@{domain}")

    full_name = f"{first}.{last}" if last else first
    for domain in COMMON_EMAIL_DOMAINS[:5]:
        emails.add(f"{full_name}@{domain}")

    return sorted(emails, key=lambda e: (len(e), e))[:50]
