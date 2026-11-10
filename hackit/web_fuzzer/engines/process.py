"""URL normalization, filtering and parameter-signature collapse."""
import os
import re
from typing import Optional, Tuple
from urllib.parse import urlsplit, parse_qsl, urlunparse, urlencode

EXT_BLACKLIST = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp", ".tif", ".tiff",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".avi", ".mov", ".mkv", ".webm", ".wav", ".flac",
    ".zip", ".gz", ".rar", ".7z", ".tar", ".bz2", ".xz",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt",
    ".apk", ".ipa", ".dmg", ".exe", ".msi", ".iso", ".bin",
    ".js", ".mjs", ".jsx", ".map",
}


def clean_url(raw: str) -> Optional[str]:
    raw = raw.strip()
    if not raw or not raw.lower().startswith(("http://", "https://")):
        return None
    try:
        p = urlsplit(raw)
    except ValueError:
        return None
    if not p.scheme or not p.netloc:
        return None
    host = p.hostname.lower() if p.hostname else ""
    if not host or "." not in host:
        return None
    port = p.port
    netloc = host
    if port and not ((p.scheme == "http" and port == 80) or (p.scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    path = p.path or "/"
    ext = os.path.splitext(path.lower().rstrip("/"))[1]
    if ext in EXT_BLACKLIST:
        return None
    if not p.query:
        return None
    pairs = parse_qsl(p.query, keep_blank_values=True)
    pairs = [(k, v) for k, v in pairs if k and len(k) <= 128 and re.match(r"^[A-Za-z0-9_.\-\[\]:]+$", k)]
    if not pairs:
        return None
    query = urlencode(pairs, doseq=True)
    return urlunparse((p.scheme.lower(), netloc, path, "", query, ""))


def param_signature(url: str) -> Tuple[str, str, Tuple[str, ...]]:
    p = urlsplit(url)
    keys = tuple(sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)}))
    return (p.netloc.lower(), p.path, keys)
