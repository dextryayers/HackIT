"""
Source validation helpers.
"""

from __future__ import annotations

from typing import Dict


def normalize_source(source: Dict[str, str]) -> Dict[str, str] | None:
    name = str(source.get("name", "")).strip()
    category = str(source.get("category", "Unknown")).strip() or "Unknown"
    url = str(source.get("url", "")).strip()
    if not name or "{username}" not in url:
        return None
    url = url.replace("@ {username}", "@{username}")
    url = url.replace("/ {username}", "/{username}")
    return {"name": name, "category": category, "url": url}

