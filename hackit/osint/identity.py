from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List
from urllib.parse import quote_plus


TITLES = {"dr", "mr", "mrs", "ms", "prof", "haji", "hajjah", "ir", "sis", "bro",
          "capt", "col", "gen", "lt", "maj", "sgt", "sir", "dame", "lord",
          "lady", "prince", "princess", "king", "queen", "emp", "empress",
          "fr", "sr", "br", "rev", "pastor", "ustadz", "kyai", "bapak", "ibu"}

SUFFIXES = {"jr", "sr", "ii", "iii", "iv", "v", "md", "phd", "esq", "cpa",
            "s.e", "s.kom", "s.t", "s.h", "s.sos", "m.kom", "m.t", "m.h"}


@dataclass(frozen=True)
class IdentityTarget:
    raw: str
    display_name: str
    canonical_handle: str
    exact_query: str
    search_query: str
    is_email: bool
    is_phone: bool
    first_name: str = ""
    last_name: str = ""
    middle_name: str = ""
    name_parts: List[str] = field(default_factory=list)
    initials: str = ""
    reversed_name: str = ""
    aliases: List[str] = field(default_factory=list)
    title: str = ""
    suffix: str = ""
    name_format: str = ""


def build_identity_target(query: str) -> IdentityTarget:
    raw = query.strip()
    display = re.sub(r"\s+", " ", raw)
    is_email = bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", display.lower()))
    is_phone = bool(re.match(r"^\+?[\d\s\-\(\)]{7,20}$", display))

    base = display.split("@", 1)[0] if is_email else display
    canonical = re.sub(r"[^a-zA-Z0-9]", "", base).lower()

    first_name = ""
    last_name = ""
    middle_name = ""
    initials = ""
    reversed_name = ""
    aliases = []
    title = ""
    suffix = ""
    name_format = ""

    clean_name = re.sub(r"[^a-zA-Z\s\.]", " ", display).strip()
    clean_name = re.sub(r"\s+", " ", clean_name)

    if clean_name and not is_email and not is_phone:
        parts = clean_name.split()
        parts_lower = [p.lower().rstrip(".") for p in parts]
        filtered = [parts[i] for i, pl in enumerate(parts_lower) if pl not in TITLES and pl not in SUFFIXES]
        titles_found = [parts[i] for i, pl in enumerate(parts_lower) if pl in TITLES]
        suffixes_found = [parts[i] for i, pl in enumerate(parts_lower) if pl in SUFFIXES]

        if titles_found:
            title = titles_found[0].lower().capitalize()

        if suffixes_found:
            suffix = suffixes_found[-1].upper()

        if len(filtered) >= 1:
            first_name = filtered[0].lower().capitalize()
        if len(filtered) >= 2:
            last_name = filtered[-1].lower().capitalize()
        if len(filtered) >= 3:
            middle_name = " ".join(filtered[1:-1]).lower().capitalize()

        name_parts = filtered

        if first_name and last_name:
            initials = (first_name[0] + last_name[0]).lower()
            reversed_name = f"{last_name}, {first_name}"
            if middle_name:
                mi = middle_name[0].upper()
                initials = (first_name[0] + mi + last_name[0]).lower()
                reversed_name = f"{last_name}, {first_name} {mi}."
        elif first_name:
            initials = first_name[0].lower()

        if len(name_parts) >= 2:
            name_format = f"{first_name} {last_name}"
            if title:
                name_format = f"{title} {name_format}"
            if suffix:
                name_format = f"{name_format}, {suffix}"
        elif name_parts:
            name_format = first_name

        aliases_set = set()
        if first_name and last_name:
            aliases_set.update([
                f"{first_name}{last_name}".lower(),
                f"{first_name}.{last_name}".lower(),
                f"{first_name}_{last_name}".lower(),
                f"{first_name}-{last_name}".lower(),
                f"{first_name[0]}{last_name}".lower(),
                f"{first_name}{last_name[0]}".lower(),
                f"{last_name}{first_name}".lower(),
                f"{last_name}.{first_name}".lower(),
                f"{last_name}_{first_name}".lower(),
                f"{first_name[0]}{last_name[0]}".lower(),
            ])
            if middle_name:
                mi = middle_name[0].lower()
                aliases_set.update([
                    f"{first_name}{mi}{last_name}".lower(),
                    f"{first_name}.{mi}.{last_name}".lower(),
                    f"{first_name}_{mi}_{last_name}".lower(),
                    f"{mi}{last_name}".lower(),
                ])
            if title:
                aliases_set.add(f"{title.lower()}{first_name}{last_name}".lower())
        aliases = [a for a in aliases_set if a and len(a) >= 2]

    return IdentityTarget(
        raw=raw, display_name=display,
        canonical_handle=canonical,
        exact_query=f'"{display}"',
        search_query=quote_plus(display),
        is_email=is_email, is_phone=is_phone,
        first_name=first_name, last_name=last_name,
        middle_name=middle_name,
        name_parts=[p.capitalize() for p in clean_name.split()] if clean_name else [],
        initials=initials, reversed_name=reversed_name,
        aliases=aliases, title=title, suffix=suffix,
        name_format=name_format,
    )
