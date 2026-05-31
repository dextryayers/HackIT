"""
Username and email candidate mutation helpers.
"""

from __future__ import annotations

import random
import re
from typing import List


COMMON_EMAIL_DOMAINS = [
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com",
    "proton.me", "protonmail.com", "live.com", "aol.com", "mail.com",
]


def split_identity(query: str) -> List[str]:
    clean = re.sub(r"[^a-zA-Z0-9._@+\- ]", " ", query.strip().lower())
    if "@" in clean:
        clean = clean.split("@", 1)[0]
    return [part for part in re.split(r"[\s._+\-]+", clean) if part]


def build_handle_variants(query: str, random_count: int = 24) -> List[str]:
    parts = split_identity(query)
    if not parts:
        return []

    candidates = set()
    base = "".join(parts)
    dotted = ".".join(parts)
    underscored = "_".join(parts)
    dashed = "-".join(parts)
    candidates.update({base, dotted, underscored, dashed})

    first = parts[0]
    last = parts[-1]
    candidates.add(first)
    candidates.add(last)

    if len(parts) >= 2:
        candidates.update({
            f"{first}{last}",
            f"{first}.{last}",
            f"{first}_{last}",
            f"{first}-{last}",
            f"{first[0]}{last}",
            f"{first}{last[0]}",
            f"{last}{first}",
            f"{last}.{first}",
            f"{last}_{first}",
            f"{last}{first[0]}",
        })

    years = ["01", "02", "03", "07", "08", "09", "10", "11", "12", "17", "18", "19", "20", "21", "22", "23", "24", "25"]
    suffixes = ["id", "dev", "sec", "real", "official", "x", "me", "web", "code", "labs"]
    seed_pool = list(candidates)
    for item in seed_pool:
        for suffix in suffixes[:6]:
            candidates.add(f"{item}{suffix}")
            candidates.add(f"{item}.{suffix}")
        for year in years[:8]:
            candidates.add(f"{item}{year}")

    random_variants = set()
    separators = ["", ".", "_", "-"]
    while len(random_variants) < random_count and len(parts) >= 1:
        shuffled = parts[:]
        random.shuffle(shuffled)
        sep = random.choice(separators)
        tail = random.choice(["", random.choice(years), random.choice(suffixes)])
        random_variants.add(f"{sep.join(shuffled)}{tail}")

    candidates.update(random_variants)

    clean = []
    for item in candidates:
        item = item.strip("._- ")
        if 2 <= len(item) <= 40 and re.match(r"^[a-z0-9._-]+$", item):
            clean.append(item)
    return sorted(set(clean), key=lambda value: (len(value), value))[:36]


def build_email_candidates(query: str) -> List[str]:
    handles = build_handle_variants(query, random_count=4)[:12]
    return [f"{handle}@{domain}" for handle in handles[:8] for domain in COMMON_EMAIL_DOMAINS[:5]]
