"""
Single-target identity normalization.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote_plus


@dataclass(frozen=True)
class IdentityTarget:
    raw: str
    display_name: str
    canonical_handle: str
    exact_query: str
    search_query: str
    is_email: bool


def build_identity_target(query: str) -> IdentityTarget:
    raw = query.strip()
    display = re.sub(r"\s+", " ", raw)
    is_email = bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", display.lower()))

    base = display.split("@", 1)[0] if is_email else display
    canonical = re.sub(r"[^a-zA-Z0-9]", "", base).lower()

    return IdentityTarget(
        raw=raw,
        display_name=display,
        canonical_handle=canonical,
        exact_query=f'"{display}"',
        search_query=quote_plus(display),
        is_email=is_email,
    )

