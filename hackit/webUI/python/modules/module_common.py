"""Compatibility shim: every name here resolves to the canonical helper in
``python/module_common.py`` so all import styles share identical semantics.

Background: modules use two import styles (``from module_common import ...``
and ``from ..module_common import ...``). The orchestrator loader aliases both
to the top-level module, but any direct/stand-alone import of this file used to
expose a *different* 90-line implementation with a split return contract
(``resolve_ip -> list`` vs canonical ``str | None``, ``safe_fetch_json -> {}``
vs canonical ``None``). That split silently poisoned callers such as
``abuseipdb`` (list passed as ``ipAddress`` param). This shim removes the fork:
it re-exports the canonical objects and only falls back to local
implementations when the parent cannot be imported at all.
"""

import socket as _socket
import sys as _sys

_PARENT_NAMES = (
    "module_common",
    "webui_pkg.module_common",
)


def _load_parent():
    for _name in _PARENT_NAMES:
        _mod = _sys.modules.get(_name)
        if _mod is not None and _mod.__name__ != __name__:
            return _mod
    import importlib as _il
    for _name in _PARENT_NAMES:
        try:
            _mod = _il.import_module(_name)
        except Exception:
            continue
        if getattr(_mod, "__name__", None) != __name__:
            return _mod
    return None


_PARENT = _load_parent()

if _PARENT is not None:
    for _key in dir(_PARENT):
        if not _key.startswith("_"):
            globals()[_key] = getattr(_PARENT, _key)
else:  # pragma: no cover - last-resort fallbacks, canonical-compatible types
    import re as _re

    EMAIL_RE = _re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

    async def safe_fetch(client, url, method="GET", **kwargs):
        try:
            kwargs.setdefault("timeout", 10.0)
            kwargs.setdefault("follow_redirects", True)
            kwargs.setdefault(
                "headers",
                {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            )
            resp = await client.request(method, url, **kwargs)
            return resp if getattr(resp, "status_code", 0) == 200 else None
        except Exception:
            return None

    async def safe_fetch_json(client, url, method="GET", **kwargs):
        resp = await safe_fetch(client, url, method=method, **kwargs)
        if resp is None:
            return None
        try:
            return resp.json()
        except Exception:
            return None

    def make_finding(entity, ftype, source, confidence="Medium", color="slate",
                     threat_level="Informational", status=None, resolution=None,
                     raw_data=None, tags=None, **kwargs):
        from models import IntelligenceFinding
        kw = dict(entity=entity, type=ftype, source=source, confidence=confidence,
                  color=color, threat_level=threat_level)
        if status is not None:
            kw["status"] = status
        if resolution is not None:
            kw["resolution"] = resolution
        if raw_data is not None:
            kw["raw_data"] = raw_data
        if tags is not None:
            kw["tags"] = tags
        kw.update(kwargs)
        return IntelligenceFinding(**kw)

    def is_ip(addr: str) -> bool:
        try:
            _socket.inet_aton(addr)
            return addr.count(".") == 3
        except Exception:
            return False

    def resolve_ip(host: str):
        """Canonical-compatible: single primary IPv4 string or None."""
        try:
            return _socket.gethostbyname(host)
        except Exception:
            return None

    def classify_email(email: str) -> str:
        email_lower = (email or "").lower()
        if any(d in email_lower for d in ("guerrillamail", "tempmail", "yopmail",
                                          "mailinator", "trashmail", "temp-mail",
                                          "discard.email", "fakeinbox")):
            return "disposable"
        if any(c in email_lower for c in (".gov", ".edu", ".mil")):
            return "corporate"
        return "personal"

    def extract_emails(text: str) -> list:
        return list(set(EMAIL_RE.findall(text or "")))

    def compute_hash(data: str) -> str:
        import hashlib as _hl
        return _hl.sha256((data or "").encode()).hexdigest()

    def require_api_keys(*services: str) -> list:
        missing = []
        try:
            from settings_store import get_api_key as _gak
        except Exception:
            return list(services)
        for _svc in services:
            try:
                if not _gak(_svc):
                    missing.append(_svc)
            except Exception:
                missing.append(_svc)
        return missing
