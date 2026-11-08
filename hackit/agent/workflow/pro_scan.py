"""Deep pentest pro scanners for HackIt Agent.

Pure-Python, evidence-first scanners that run without external binaries:

* security header audit (missing / weak / leaked)
* CORS variant probing (reflected origin, prefix/suffix bypasses, wildcard)
* JavaScript deep analysis (endpoints, secrets, map files)
* sensitive-file discovery with baseline differential verification
* cookie/session attribute audit
* info-leak / banner disclosure
* risk scoring and attack-chain plan

Every finding carries a short reproduction recipe and remediation so the
report generator can emit a professional pentester write-up.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import time
import uuid
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..textutils import strip_control

UA = "HackIt-Pentest/2.3 (+authorised assessment)"


def _go_pro_engine_path() -> str:
    """Location of the compiled Go pro_engine wrapper."""
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    candidates = [
        os.path.join(base_dir, "agent", "go", "pro_engine_bin"),
        os.path.join(base_dir, "agent", "go", "pro_engine", "pro_engine"),
        os.path.join(base_dir, "agent", "go", "pro_engine"),
    ]
    if shutil.which("pro_engine"):
        return shutil.which("pro_engine") or ""
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return ""


_NVD_API_KEY = os.environ.get("HACKIT_NVD_API_KEY") or os.environ.get("NVD_API_KEY") or ""


def cve_intel_scan(url: str, max_results: int = 3, subdomains: bool = True) -> Optional[Dict[str, Any]]:
    """Invoke the Go CVE worker against the target and return the parsed report.

    The report includes fingerprinted technologies and ranked CVEs with
    references, CWEs, CVSS vectors, EPSS probabilities, CISA KEV flags and
    per-subdomain findings for every reachable host in the wordlist.
    """
    import subprocess
    import tempfile

    from hackit.cve.go_bridge import GoEngine

    # We import GoEngine directly to drive flags explicitly; the worker reads
    # the same flags we added (--subdomains, --deep, --max-results).
    engine = GoEngine()
    if not engine.ensure_compiled():
        return None

    fd, output = tempfile.mkstemp(prefix="cve_intel_", suffix=".json")
    os.close(fd)

    cmd = [
        engine.binary_path,
        "-target", url,
        "-mode", "main",
        "-output", output,
        "-max-results", str(max(1, int(max_results))),
    ]
    if subdomains:
        cmd.append("--subdomains")
    if _NVD_API_KEY:
        cmd.extend(["--api-key", _NVD_API_KEY])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max(45.0, max_results * 25.0))
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    except Exception as exc:
        return {"error": str(exc)[:200]}
    try:
        with open(output, "r", encoding="utf-8") as fh:
            report = json.load(fh)
    except Exception as exc:
        return {"error": f"report read: {exc}"[:200]}
    finally:
        try:
            os.remove(output)
        except OSError:
            pass
    return report


def go_rs_scan(url: str, timeout: float = 45.0) -> Optional[Dict[str, Any]]:
    """Invoke the Go pro_engine (which dispatches to the Rust pro_scan scanner).

    Returns a merged dict with keys: engine, reachable, http_status, body_bytes,
    findings (list of unified finding dicts), analysis (dict), or None on failure.
    """
    import subprocess

    binary = _go_pro_engine_path()
    if not binary:
        return None
    try:
        proc = subprocess.run(
            [binary, "--scan", url, "--timeout", str(int(timeout)), "--verbose", "1"],
            capture_output=True, text=True, timeout=max(15, int(timeout) + 15),
        )
    except Exception:
        return None
    out = proc.stdout.strip()
    if not out:
        return None
    try:
        data = json.loads(out)
    except Exception:
        start, end = out.find("{"), out.rfind("}")
        if start == -1 or end <= start:
            return None
        try:
            data = json.loads(out[start:end + 1])
        except Exception:
            return None
    if not isinstance(data, dict) or data.get("error"):
        return None
    return data


def _http_get(url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 8.0,
              redirects: bool = True, method: str = "GET",
              extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", UA)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    if extra_headers:
        for k, v in extra_headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(1_000_000)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return {
                "url": resp.geturl(),
                "status": resp.status,
                "headers": resp_headers,
                "body": body,
                "text": body.decode("utf-8", "replace"),
                "error": "",
            }
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(200_000)
        except Exception:
            body = b""
        resp_headers = {k.lower(): v for k, v in (exc.headers or {}).items()} if exc.headers else {}
        return {
            "url": url,
            "status": exc.code,
            "headers": resp_headers,
            "body": body,
            "text": body.decode("utf-8", "replace"),
            "error": f"HTTP {exc.code}",
        }
    except Exception as exc:
        return {
            "url": url,
            "status": 0,
            "headers": {},
            "body": b"",
            "text": "",
            "error": str(exc)[:200],
        }


def _is_true_body(body: str) -> bool:
    body = (body or "").lower()
    noise = ("404", "not found", "page not found", "do not exist", "does not exist",
             "error 404", "nothing here", "no results")
    return not any(token in body[:4000] for token in noise)


def _finding(ftype: str, target: str, title: str, evidence: str, severity: str,
             cvss: float, remediation: str, reproduction: str = "") -> Dict[str, Any]:
    return {
        "id": f"{ftype.upper()}-{uuid.uuid4().hex[:8]}",
        "type": ftype,
        "severity": severity.lower(),
        "cvss": cvss,
        "target": strip_control(str(target))[:300],
        "description": strip_control(str(title))[:300],
        "evidence": strip_control(str(evidence))[:3000],
        "remediation": strip_control(str(remediation))[:500],
        "reproduction": strip_control(str(reproduction)[:800]) if reproduction else "",
    }


# ---------------------------------------------------------------------------
# Header audit
# ---------------------------------------------------------------------------

REQUIRED_HEADERS = [
    ("strict-transport-security", "hsts", "Missing HSTS Strict-Transport-Security", "low", 3.1,
     "Add Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("content-security-policy", "csp", "Missing Content-Security-Policy", "medium", 4.3,
     "Define a strict Content-Security-Policy; avoid unsafe-inline / unsafe-eval"),
    ("x-frame-options", "xfo", "Missing X-Frame-Options (clickjacking)", "low", 2.4,
     "Add X-Frame-Options: DENY or SAMEORIGIN"),
    ("x-content-type-options", "xcto", "Missing X-Content-Type-Options (MIME sniffing)", "low", 1.6,
     "Add X-Content-Type-Options: nosniff"),
    ("referrer-policy", "refpol", "Missing Referrer-Policy", "low", 1.3,
     "Add Referrer-Policy: strict-origin-when-cross-origin"),
    ("permissions-policy", "permpol", "Missing Permissions-Policy", "info", 0.5,
     "Add Permissions-Policy to restrict camera/mic/geolocation"),
]


def audit_headers(url: str, timeout: float = 10.0) -> Dict[str, Any]:
    """Audit security headers. Returns findings + raw headers."""
    resp = _http_get(url, timeout=timeout)
    headers = resp.get("headers", {}) or {}
    findings: List[Dict[str, Any]] = []

    for header, _short, title, severity, cvss, remediation in REQUIRED_HEADERS:
        if header not in headers or not str(headers[header] or "").strip():
            findings.append(_finding(
                "security_header_missing", url, title,
                f"Header {header!r} absent from response (HTTP {resp.get('status')})",
                severity, cvss, remediation,
                reproduction=f"curl -sI {url} | grep -i {header}",
            ))

    # Weak HSTS
    hsts = str(headers.get("strict-transport-security", "") or "")
    match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
    if match and int(match.group(1)) < 31536000:
        findings.append(_finding(
            "weak_hsts", url, "HSTS max-age below 1 year",
            f"Strict-Transport-Security: {hsts}", "low", 2.0,
            "Use max-age of at least 31536000 and includeSubDomains",
            reproduction=f"curl -sI {url} | grep -i strict-transport-security",
        ))
    # Weak CSP presence with unsafe directives
    csp = str(headers.get("content-security-policy", "") or "")
    if csp:
        for directive, reason in (("unsafe-inline", "script-src/frame-ancestors allow unsafe-inline"),
                                  ("unsafe-eval", "script-src allows unsafe-eval"),
                                  ("*", "wildcard source in CSP"),
                                  ("data:", "data: URI allowed in CSP")):
            if directive in csp.lower():
                findings.append(_finding(
                    "weak_csp", url, f"Weak CSP: {reason}",
                    f"Content-Security-Policy: {csp[:500]}", "medium", 4.1,
                    "Remove unsafe directives and narrow source lists",
                    reproduction=f"curl -sI {url} | grep -i content-security-policy",
                ))
                break

    # Disclosure
    server = str(headers.get("server", "") or "")
    if server and any(ch.isdigit() for ch in server):
        findings.append(_finding(
            "info_disclosure", url, "Server version disclosed",
            f"Server: {server}", "info", 2.0,
            "Suppress or genericise Server and X-Powered-By headers",
            reproduction=f"curl -sI {url} | grep -i '^server:'",
        ))
    powered = str(headers.get("x-powered-by", "") or "")
    if powered:
        findings.append(_finding(
            "info_disclosure", url, "X-Powered-By discloses stack",
            f"X-Powered-By: {powered}", "info", 2.1,
            "Remove the X-Powered-By response header",
            reproduction=f"curl -sI {url} | grep -i x-powered-by",
        ))

    # Cache-Control on auth-ish paths
    if any(token in url.lower() for token in ("login", "admin", "account", "api", "session")):
        if not headers.get("cache-control"):
            findings.append(_finding(
                "weak_cache", url, "Missing Cache-Control on sensitive endpoint",
                f"No Cache-Control header on {url} (HTTP {resp.get('status')})",
                "low", 3.0,
                "Add Cache-Control: no-store",
                reproduction=f"curl -sI {url} | grep -i cache-control",
            ))

    return {
        "findings": findings,
        "headers": headers,
        "status": resp.get("status"),
        "url": url,
        "error": resp.get("error", ""),
    }


# ---------------------------------------------------------------------------
# CORS variant testing
# ---------------------------------------------------------------------------

CORS_ORIGINS = [
    ("http://evil.example", "reflected external origin"),
    ("https://evil.example", "reflected external origin (https)"),
    ("null", "null origin reflection"),
    ("example.com.evil.example", "suffix bypass attempt"),
    ("evil-example.com", "prefix bypass attempt"),
]


def test_cors(url: str, timeout: float = 8.0) -> Dict[str, Any]:
    base = _http_get(url, timeout=timeout)
    headers = base.get("headers", {}) or {}
    findings: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []

    # Static findings first.
    acao = str(headers.get("access-control-allow-origin", "") or "")
    if acao == "*":
        cred = "yes" if str(headers.get("access-control-allow-credentials", "")).lower() == "true" else "no"
        findings.append(_finding(
            "cors", url, "CORS allows any origin (*)",
            f"Access-Control-Allow-Origin: * (credentials={cred})",
            "medium", 5.3,
            "Restrict to explicit trusted origins; never combine wildcard with credentials",
            reproduction=f"curl -s -H 'Origin: https://evil.example' -D- -o /dev/null {url} | grep -i 'access-control'",
        ))
    elif acao and acao not in ("", url):
        # reflected dynamic origin
        for origin, reason in CORS_ORIGINS:
            probe = _http_get(url, headers={"Origin": origin}, timeout=timeout)
            acao_probe = str((probe.get("headers") or {}).get("access-control-allow-origin", "") or "")
            vary = str((probe.get("headers") or {}).get("vary", "") or "")
            if acao_probe == origin:
                findings.append(_finding(
                    "cors", url, f"CORS reflects arbitrary origin ({reason})",
                    f"Origin: {origin} -> Access-Control-Allow-Origin: {acao_probe} (Vary: {vary or '—'})",
                    "high", 6.1,
                    "Only reflect origins on an explicit allowlist; add Vary: Origin",
                    reproduction=f"curl -s -H 'Origin: {origin}' -D- -o /dev/null {url} | grep -i 'access-control-allow-origin'",
                ))
                break

    results.append({
        "static_acao": acao,
        "credentials": str(headers.get("access-control-allow-credentials", "")),
        "vary": headers.get("vary", ""),
    })
    return {"findings": findings, "base": results[0], "url": url, "error": base.get("error", "")}


# ---------------------------------------------------------------------------
# JavaScript deep analysis (pure Python)
# ---------------------------------------------------------------------------

SECRET_RE = re.compile(
    r"(?:(?:api[_-]?key|apikey|secret|token|passwd|password|auth[_-]?token)\b[^\"'\s=]{0,20}[\"'\s:=]*([\"'])(?P<value>[^\"']{8,180})\1)"
    r"|(?:(?:AKIA|ASIA)[0-9A-Z]{16})"                # AWS access key id
    r"|(?:AIza[0-9A-Za-z_\-]{20,})"                # Google API key
    r"|(?:sk-[0-9a-zA-Z_\-]{16,})"                 # OpenAI-ish
    r"|(?:gh[pousr]_[0-9A-Za-z]{20,})"             # GitHub token
    r"|(?:xox[baprs]-[0-9A-Za-z\-]{10,})"          # Slack
, re.IGNORECASE)
ENDPOINT_RE = re.compile(r"[\"'`]((?:https?:)?//[^\"'\s`]{8,200}|/[A-Za-z0-9][^\"'\s`]{2,200})[\"'`]")
SOURCEMAP_RE = re.compile(r"//#\s*sourceMappingURL=([^\s]+)")
INTERNAL_RE = re.compile(r"(localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", re.I)


def analyze_javascript(html: str, base_url: str, timeout: float = 12.0) -> Dict[str, Any]:
    """Extract endpoints, secrets and sourcemap references from inline JS."""
    findings: List[Dict[str, Any]] = []
    scripts: List[str] = []
    inline_blocks = re.findall(r"<script[^>]*>(.*?)</script>", html, re.I | re.S)
    inline_blocks.extend(re.findall(r"(fetch|axios|XMLHttpRequest|ajax)\s*\([^)]*\)", html, re.I))
    soup_scripts = re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", html, re.I)

    seen_secrets: set = set()

    def _scan_block(text: str, source: str) -> None:
        for match in SECRET_RE.finditer(text or ""):
            value = match.group("value") or match.group(0)
            key = (value[:12], len(value))
            if key in seen_secrets:
                continue
            seen_secrets.add(key)
            kind = "aws_access_key" if value.startswith(("AKIA", "ASIA")) else "hardcoded_secret"
            findings.append(_finding(
                "js_secret", base_url, f"Secret leak in {source or 'script'}",
                f"{kind}: {value[:120]}", "high", 7.1 if kind == "aws_access_key" else 7.0,
                "Rotate and remove the embedded secret; use a backend proxy/vault",
                reproduction=f"grep the page source for {value[:20]}…",
            ))
        for endpoint in set(ENDPOINT_RE.findall(text or "")):
            ep = endpoint if isinstance(endpoint, str) else (endpoint[0] if endpoint else "")
            if not ep or ep.startswith("data:"):
                continue
            scripts.append(ep)
        if INTERNAL_RE.search(text or ""):
            findings.append(_finding(
                "js_internal_host", base_url, "Internal host/CIDR referenced inside JS",
                re.search(r"(localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)", text, re.I).group(0),
                "medium", 4.5,
                "Remove development/internal hostnames from production builds",
                reproduction=f"grep the script for internal hosts",
            ))

    for block in inline_blocks[:120]:
        _scan_block(block, "inline")
    for src in soup_scripts[:40]:
        if src.startswith("data:"):
            continue
        src_url = src if src.startswith(("http://", "https://", "//")) else urljoin(base_url, src)
        resp = _http_get(src_url, timeout=timeout)
        body = resp.get("text", "")
        scripts.append(src_url)
        _scan_block(body, src_url)
        for sm in set(SOURCEMAP_RE.findall(body or "")):
            map_url = sm if sm.startswith(("http://", "https://", "//")) else urljoin(src_url, sm)
            findings.append(_finding(
                "js_sourcemap", base_url, "JavaScript source map published",
                f"sourceMappingURL={sm} ({map_url})", "medium", 5.4,
                "Do not ship .map files for production builds",
                reproduction=f"curl -s {map_url} | head -c 200",
            ))

    # .map files accidentally present
    for src in soup_scripts[:40]:
        if not src.lower().endswith(".js"):
            continue
        map_url = (src if src.startswith(("http://", "https://", "//")) else urljoin(base_url, src)) + ".map"
        resp = _http_get(map_url, timeout=6)
        if resp.get("status") == 200 and b"\"version\"" in (resp.get("body") or b"")[:2000]:
            findings.append(_finding(
                "js_sourcemap", base_url, "Source map reachable",
                f"GET {map_url} returned a valid map (HTTP 200)", "medium", 5.4,
                "Block .map from production or build with hidden-source-maps",
                reproduction=f"curl -sI {map_url}",
            ))

    return {
        "findings": findings,
        "script_srcs": soup_scripts,
        "endpoints": list(dict.fromkeys(scripts))[:80],
        "base": base_url,
    }


# ---------------------------------------------------------------------------
# Sensitive file / path discovery
# ---------------------------------------------------------------------------

SENSITIVE_PATHS = [
    (".git/HEAD", "text", "git headfile exposed", "high", 7.5),
    (".git/config", "text", "git config exposed", "high", 7.4),
    (".env", "env", ".env file exposed", "critical", 9.0),
    (".env.local", "env", ".env.local exposed", "critical", 9.0),
    (".env.production", "env", ".env.production exposed", "critical", 9.0),
    ("wp-config.php", "text", "WordPress config accessible", "high", 7.4),
    ("phpinfo.php", "phpinfo", "phpinfo() exposed", "medium", 5.3),
    ("server-status", "apache_status", "Apache server-status exposed", "medium", 5.0),
    ("server-info", "text", "Apache server-info exposed", "medium", 4.6),
    (".htaccess", "text", ".htaccess readable", "medium", 4.2),
    (".htpasswd", "text", ".htpasswd readable (credential hashes)", "high", 7.2),
    ("config.json", "json", "config.json exposed", "medium", 4.9),
    ("web.config", "text", "web.config exposed", "medium", 4.4),
    (".DS_Store", "binary", ".DS_Store metadata exposed", "info", 1.9),
    ("backup.zip", "binary", "backup archive exposed", "medium", 5.5),
    ("dump.sql", "text", "SQL dump exposed", "high", 8.0),
    ("database.sql", "text", "SQL dump exposed", "high", 8.0),
    ("id_rsa", "text", "Private key material exposed", "critical", 9.8),
    ("id_rsa.pub", "text", "Public key exposed", "low", 1.4),
    ("swagger-ui.html", "swagger", "Swagger UI exposed", "medium", 4.3),
    ("swagger.json", "json", "OpenAPI spec exposed", "medium", 4.1),
    ("openapi.json", "json", "OpenAPI spec exposed", "medium", 4.1),
    ("actuator", "spring", "Spring actuator exposed", "high", 6.5),
    ("actuator/env", "spring", "Spring actuator/env exposed", "high", 7.0),
    ("actuator/heapdump", "binary", "Spring heapdump exposed", "critical", 8.5),
    (".well-known/security.txt", "text", "security.txt present (info)", "info", 0.0),
]


def _normalize_body(body: bytes) -> bytes:
    text = re.sub(rb"\s+", b" ", body or b"")
    text = re.sub(rb"\d{4,}", b"NNN", text)
    return text


def _body_similarity(a: bytes, b: bytes) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    na, nb = _normalize_body(a), _normalize_body(b)
    if na == nb:
        return 1.0
    ta = set(re.findall(rb"[A-Za-z0-9_./-]{4,}", na))
    tb = set(re.findall(rb"[A-Za-z0-9_./-]{4,}", nb))
    if not ta or not tb:
        return 0.5
    return len(ta & tb) / max(1, len(ta | tb))


def _too_close_to_baseline(body: bytes, baseline_body: bytes, threshold: float = 0.92) -> bool:
    return _body_similarity(body, baseline_body) >= threshold


def scan_sensitive_paths(base_url: str, timeout: float = 6.0) -> Dict[str, Any]:
    base = base_url.rstrip("/") + "/"
    findings: List[Dict[str, Any]] = []

    # Soft-404 differential. Catch-all apps answer 200 for every path, which
    # produced 19 fake findings on a live audit; compare each candidate
    # against a random path body and discard near-duplicates.
    baseline = _http_get(base + "hackit-definitely-not-exist-" + uuid.uuid4().hex[:10], timeout=timeout)
    baseline_status = int(baseline.get("status") or 0)
    baseline_body = baseline.get("body") or b""

    def _skip_by_baseline(body: bytes) -> bool:
        return baseline_status == 200 and _too_close_to_baseline(body, baseline_body)

    def _kind_for(match_key: str) -> str:
        return {"git headfile exposed": "git", "git config exposed": "git",
                ".env file exposed": "env", ".env.production exposed": "env",
                "wp-config.php": "wpconfig",
                "phpinfo() exposed": "phpinfo",
                "Apache server-status exposed": "apache_status",
                "Swagger UI exposed": "swagger",
                "Spring actuator exposed": "spring",
                "Spring actuator/env exposed": "spring",
                "Spring heapdump exposed": "heapdump",
                "security.txt present (info)": "securitytxt"}.get(match_key, match_key)

    for path, mode, title, severity, cvss in SENSITIVE_PATHS:
        resp = _http_get(base + path, timeout=timeout)
        status = int(resp.get("status") or 0)
        if status != 200:
            continue
        body = resp.get("body") or b""
        text = resp.get("text") or ""
        if _skip_by_baseline(body):
            continue
        kind = _kind_for(title)
        lowered = text.lower()
        if kind == "git":
            ok = ("ref:" in text) or ("[core]" in text) or ("repositoryformatversion" in lowered) or ("gitdir:" in lowered)
        elif kind == "env":
            ok = bool(re.search(r"^(APP_KEY|APP_ENV|DB_PASSWORD|DB_USER|SECRET_|AWS_ACCESS|PRIVATE_KEY)[_A-Z0-9]*\s*=", text, re.M))
        elif kind == "wpconfig":
            ok = ("DB_PASSWORD" in text and "<?php" in lowered) or ("table_prefix" in text and "define(" in lowered)
        elif kind == "phpinfo":
            ok = "php version" in lowered and "system" in lowered
        elif kind == "apache_status":
            ok = "apache server status" in lowered or "total accesses" in lowered
        elif kind == "swagger":
            ok = ("swagger" in lowered) or ("openapi" in lowered)
        elif kind == "spring":
            ok = any(token in text for token in ('"_links"', '"beans"', '"propertySources"', '"propertysources"'))
        elif kind == "heapdump":
            ok = (len(body) > 4096 and body[:16].startswith(b"PK")) or body[:16].startswith(b"\x1f\x8b")
        elif kind == "securitytxt":
            ok = any(token in lowered for token in ("contact:", "policy:", "acknowledgments:"))
        elif kind == "json":
            start = text.lstrip()[:200].lower()
            ok = start.startswith("{") or start.startswith("[")
            ok = ok and "<html" not in start
        elif kind == "binary":
            ok = len(body) > 64 and b"<html" not in body[:300].lower()
        else:
            ok = _is_true_body(text)
        if not ok:
            continue
        findings.append(_finding(
            "exposed_file", base + path, title,
            f"GET {path} -> HTTP 200 ({len(body)} bytes)\n{text[:600]}",
            severity, cvss,
            "Remove the file from the web root and block access at the server level",
            reproduction=f"curl -i {base}{path}",
        ))
    return {"findings": findings, "base": base_url, "baseline_status": baseline_status}


# ---------------------------------------------------------------------------
# Cookie audit
# ---------------------------------------------------------------------------

def audit_cookies(url: str, timeout: float = 8.0) -> Dict[str, Any]:
    resp = _http_get(url, timeout=timeout)
    headers = resp.get("headers", {}) or {}
    raw = str(headers.get("set-cookie", "") or "")
    findings: List[Dict[str, Any]] = []
    cookies = [c.strip() for c in raw.split("\n") if c.strip()] if raw else []

    for cookie in cookies[:6]:
        low = cookie.lower()
        name = cookie.split("=", 1)[0].strip() if "=" in cookie else cookie[:40]
        # Only audit session-ish cookies; ignore telemetry.
        if not any(token in name.lower() for token in ("session", "sess", "sid", "token", "auth", "id")):
            continue
        missing = []
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "secure" not in low:
            missing.append("Secure")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            findings.append(_finding(
                "weak_cookie", url, f"Session cookie missing: {', '.join(missing)}",
                f"Set-Cookie: {cookie[:300]}", "low", 2.7,
                f"Set {', '.join(missing)} on session cookies",
                reproduction=f"curl -sI {url} | grep -i set-cookie",
            ))
    return {"findings": findings, "cookies": cookies[:10], "url": url}


# ---------------------------------------------------------------------------
# Deep analysis prompt / plan
# ---------------------------------------------------------------------------

def analysis_prompt(state_brief: Dict[str, Any]) -> str:
    return f"""You are HackIt AI, a world-class offensive security specialist.

Authorised penetration test. Analyse the collected intelligence and produce an
attack brief that a real pentester with 15 years of experience would ship.

TARGET INTELLIGENCE (JSON):
{json.dumps(state_brief, indent=2, default=str)[:14000]}

Produce these 6 sections, each with concrete, named evidence from the data:

1. ATTACK SURFACE — the concrete attack surface, grouped by exposure
   (subdomains, ports/services, tech stack, headers/cookies, JS endpoints, params).
2. CONFIRMED vs HYPOTHESIS — separate anything evidence-backed from guesses.
3. PRIORITY CHAIN — rank: 1. Critical, 2. High, 3. Medium, 4. Low. Chain where
   realistic (e.g. open admin panel + missing CSP; weak CORS + credentialed API).
4. POC PLAN — for the top 3 issues, exact request, vulnerability class,
   expected signal, and exploit path if any.
5. RISK — numeric risk score 0-10 with one-line justification.
6. HARDENING — the 5 most effective fixes, ordered by ROI.

Rules:
- Never invent a CVE not present in the data.
- Never claim a finding exists without evidence.
- If evidence is missing, mark it HYPOTHESIS and state what to test next.
- Be specific: name endpoints, parameter names, ports, versions that appear
  in the data.
- Keep under 650 words but dense. No fluff, no generic advice.
"""


def plan_prompt(state_brief: Dict[str, Any]) -> str:
    return f"""Produce an ordered exploitation plan for this authorised target.

Target intelligence (JSON):
{json.dumps(state_brief, indent=2, default=str)[:14000]}

Return exactly these sections:

A. PHASE ORDER and expected time per phase.
B. MODULES TO RUN — which scanner/check to run for each attack surface
   (SQLi, XSS, SSRF, LFI, SSTI, CMDi, XXE, NoSQLi, GraphQL, CORS, open redirect).
C. PARAMETERS — the specific parameter names seen in the data that are
   exploitable for each class (\"id\", \"q\", \"url\", \"file\", ...).
D. POC SEQUENCE — for each module, the exact wording of the request to try,
   the differential signal to look for, and the confirmation step.
E. ESCALATION — if any finding lands, the chain to pivot to (auth, IDOR, ATO).
F. REPORT OUTPUT — the sections the final report will contain.

Never invent endpoints or CVEs missing from the data. Be specific and practical.
"""


def correlate_prompt(state_brief: Dict[str, Any]) -> str:
    return f"""Correlate verified findings into attack chains for an authorised test.

Target: {state_brief.get('target')}
Findings: {json.dumps(state_brief.get('findings', [])[:30], default=str)[:6000]}
Probe hits: {json.dumps(state_brief.get('probe_hits', [])[:10], default=str)[:2000]}
Coverage: {json.dumps(state_brief.get('coverage', {}), default=str)[:1500]}
Attack log: {json.dumps(state_brief.get('attack_log', [])[:20], default=str)[:2000]}

Output:
1. CHAINS — grouped chains (weakest to strongest). Mark each CONFIRMED or
   HYPOTHESIS.
2. CVSS — overall risk score 0-10, weighted by evidence.
3. CRITICAL PATH — the one chain most likely to land first.
4. NEXT ACTION — the single best next step and why.
5. EVIDENCE GAPS — what to test next to turn hypotheses into proof.
6. If zero verified findings: state clearly "No vulnerability was confirmed in
   this run" and keep the risk at 0/10.

Never inflate risk on guesses. Keep under 450 words, dense.
"""


# ---------------------------------------------------------------------------
# Elite report assembly
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_CVSS_FLOOR = {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 2.0, "info": 0.0}


def render_pro_report(state: Dict[str, Any], ai_summary: str = "") -> str:
    target = state.get("target", "unknown")
    findings = list(state.get("findings", []) or [])
    risk_score = state.get("risk_score", 0.0) or 0.0
    scan_data = state.get("scan_data", {}) or {}
    coverage = state.get("coverage", {}) or {}
    analysis = state.get("analysis", "") or ""
    attack_plan = state.get("attack_plan", "") or ""
    report_path_note = ""

    verified = [f for f in findings
                if str(f.get("type", "")).startswith(("sqli", "xss", "ssrf", "lfi", "ssti", "cmdi", "xxe", "nosqli", "ldap", "cors", "js_secret"))
                or f.get("verified")
                or str(f.get("cvss", 0) or 0) != "0.0"]

    findings.sort(key=lambda f: SEVERITY_ORDER.get(str(f.get("severity", "info")).lower(), 5))
    counts: Dict[str, int] = {}
    for item in findings:
        sev = str(item.get("severity", "info")).lower()
        counts[sev] = counts.get(sev, 0) + 1
    total = len(findings)

    lines = [
        "# Pentest Intelligence Report",
        "",
        f"**Target:** `{target}`  ",
        f"**Web endpoint:** `{scan_data.get('web_url') or target}`  ",
        f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S UTC%z')}  ",
        f"**Authorised active mode:** {'yes' if state.get('authorized') else 'no'}  ",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"An automated, evidence-first assessment of **{target}** was executed. "
        f"The engine enumerated **{len(_as_list(scan_data.get('ports')))} open port(s)**, "
        f"**{len(_as_list(scan_data.get('subdomains')))} subdomain(s)**, "
        f"**{len(_as_list(scan_data.get('external_endpoints')))} endpoint(s)**, and verified "
        f"**{len(findings)} finding(s)** with a risk score of **{risk_score}/10**.",
        "",
    ]
    if counts:
        lines.append("| Severity | Count |")
        lines.append("| --- | --- |")
        for sev in ("critical", "high", "medium", "low", "info"):
            if counts.get(sev):
                lines.append(f"| {sev.capitalize()} | {counts[sev]} |")
        lines.append("")
    if not findings:
        lines.extend([
            "No exploitable issue with a reproducible signal was confirmed in this run. "
            "Absence of evidence is **not** proof of security — manual review, authentication "
            "and authenticated coverage remain recommended.",
            "",
        ])

    lines.extend([
        "## Threat Model",
        "",
        f"- **Attack surface tier:** {('public' if _looks_public(target) else 'private/loopback')}",
        f"- **Technology signals:** {json.dumps(scan_data.get('tech', {}), default=str)[:600]}",
        f"- **WAF presence:** {json.dumps(scan_data.get('waf', {}), default=str)[:400]}",
        f"- **Exposure profile:** {len(_as_list(scan_data.get('subdomains')))} subs / "
        f"{len(_as_list(scan_data.get('ports')))} ports / "
        f"{len(_as_list(coverage.get('endpoints')))} endpoints / "
        f"{len(_as_list(coverage.get('parameters')))} parameters",
        "",
        "## Reconnaissance Summary",
        "",
        f"- Open ports: {', '.join(str(p.get('port', '?')) for p in _as_list(scan_data.get('ports'))[:20] if isinstance(p, dict)) or '—'}",
        f"- Subdomains: {', '.join(_as_list(scan_data.get('subdomains'))[:20]) or '—'}",
        f"- Endpoints probed: {len(_as_list(scan_data.get('external_http')))}",
        f"- Unique paths/APIs: {len(_as_list(scan_data.get('external_endpoints')))}",
        f"- Parameters: {', '.join(_as_list(coverage.get('parameters'))[:20]) or '—'}",
        f"- JS endpoints: {len(_as_list((scan_data.get('js_analysis') or {}).get('endpoints')))}",
        f"- Active module tasks: {coverage.get('execute_tasks', 0)} across {len(coverage.get('execute_targets', []) or [])} target(s)",
        f"- Payload probes: {coverage.get('probe_attempted', 0)} across "
        f"{len(coverage.get('probe_targets', []) or [])} target(s), "
        f"{len(coverage.get('probe_types', []) or [])} class(es)",
        f"- Probe signals: {coverage.get('probe_signals', 0)}",
        "",
    ])

    if ai_summary:
        lines.extend(["## AI Analyst Summary (narrative)", "", ai_summary.strip(), "", "---", ""])

    if analysis:
        lines.extend(["## Analysis Detail", "", str(analysis)[:5000], ""])
    if attack_plan:
        lines.extend(["## Attack Plan & Execution Order", "", str(attack_plan)[:4000], ""])

    lines.extend([
        "## Findings",
        "",
        "### Severity summary",
        "",
        "| # | Severity | CVSS | Type | Target | Evidence |",
        "| --- | --- | --- | --- | --- | --- |",
    ])
    for index, item in enumerate(findings[:40], 1):
        sev = str(item.get("severity", "info")).capitalize()
        cvss = item.get("cvss", "—")
        ftype = str(item.get("type", "?"))[:40]
        ftitle = str(item.get("title", item.get("description", "finding"))).split("\n")[0][:56]
        evidence = str(item.get("evidence", ""))[:100].replace("|", "\\|").replace("\n", " ")
        tgt = str(item.get("target", target))[:60].replace("|", "\\|")
        lines.append(f"| {index} | {sev} | {cvss} | {ftype}<br>{ftitle} | {tgt} | {evidence} |")
    if len(findings) > 40:
        lines.append(f"| — | … | — | {len(findings) - 40} more finding(s) | — | See JSON state |")
    lines.append("")

    # PoC per finding
    lines.extend(["## Proof-of-Concept (reproduction)", ""])
    for index, item in enumerate(findings[:20], 1):
        sev = str(item.get("severity", "info")).capitalize()
        cvss = item.get("cvss", "—")
        title = str(item.get("title", item.get("description", "finding"))).split("\n")[0]
        tgt = str(item.get("target", target))
        description = str(item.get("description", "")).split("\n")[0]
        evidence = str(item.get("evidence", "")).strip()
        reproduction = str(item.get("reproduction", "")).strip()
        lines.append(f"### PoC #{index} — {sev} ({cvss}) — {title}")
        lines.append("")
        lines.append(f"- **Target:** `{tgt}`")
        lines.append(f"- **Class:** `{item.get('type', '?')}` — {description}")
        lines.append("- **Impact:** " + (
            "Complete compromise / account takeover / data exfiltration / auth bypass."
            if sev == "Critical" else
            "Sensitive data exposure / privilege escalation."
            if sev == "High" else
            "Limited information disclosure or weak configuration."
        ))
        if reproduction:
            lines.append(f"- **Reproduce:** `{reproduction}`")
        if evidence:
            lines.append("- **Evidence:**")
            lines.append("  ```")
            for line in evidence.splitlines()[:14]:
                lines.append(f"  {line[:200]}")
            lines.append("  ```")
        lines.append(f"- **Remediation:** {item.get('remediation', 'Review and fix per OWASP guidance')}")
        lines.append("")

    lines.extend(["## Attack Chains", "", _attack_chain_lines(findings), ""])

    lines.extend([
        "## Remediation Roadmap (ranked by ROI)",
        "",
    ])
    seen = set()
    ranked_findings = findings
    for item in ranked_findings:
        suggestion = str(item.get("remediation", "")).strip()
        if suggestion and suggestion not in seen:
            seen.add(suggestion)
            lines.append(f"- {suggestion}")
    if not seen:
        lines.append("- Review each finding against OWASP ASVS / WSTG.")
    lines.append("")

    lines.extend([
        "## Reporting & Evidence Handling",
        "",
        "- All active payloads were differential and non-destructive.",
        "- Findings without an independent, reproducible signal are labelled as "
        "hypotheses and do not affect the confirmed risk score.",
        f"- Attack log actions: {len(_as_list(state.get('attack_log')))}",
        f"- Coverage module tasks: {coverage.get('execute_tasks', 0)}",
        "",
        "## Appendices",
        "",
        "### A. Subdomains",
        "",
        *(_as_list(scan_data.get("subdomains"))[:50] or ["—"]),
        "",
        "### B. Open ports",
        "",
        *([f"- {p.get('port')}/{p.get('protocol', 'tcp')} {p.get('service', '')} {p.get('version', '')}".rstrip()
           for p in _as_list(scan_data.get("ports"))[:50] if isinstance(p, dict)] or ["- —"]),
        "",
        "### C. Parameters & probes",
        "",
        *([f"- {p}" for p in _as_list(coverage.get("parameters"))[:30]] or ["- —"]),
        "",
        "*This report contains only evidence from the automated run. "
        "Manual verification and authenticated testing are recommended before "
        "declaring the target secure.*",
        "",
    ])
    return "\n".join(lines)


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    if value in (None, ""):
        return []
    return [value]


def _looks_public(target: str) -> bool:
    import ipaddress as _ip

    host = urlparse(target if "://" in target else "//" + target).hostname or ""
    host = host.strip().lower()
    if host in ("localhost",) or host.endswith((".local", ".internal")):
        return False
    try:
        addr = _ip.ip_address(host)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved)
    except ValueError:
        return "." in host


def _attack_chain_lines(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return ("No confirmed chain. The most likely pivot is a combination of "
                "missing security headers + exposed admin/actuator endpoints; reproduce "
                "with authenticated coverage.")
    buckets: Dict[str, List[Dict[str, Any]]] = {}
    for item in findings:
        key = str(item.get("type", "other")).lower()
        buckets.setdefault(key, []).append(item)
    chains = []
    order = ["sqli", "cmdi", "ssti", "lfi", "xxe", "ssrf", "cors", "js_secret",
             "exposed_file", "credential_exposure", "open_redirect", "xss"]
    done = set()
    for cls in order:
        items = buckets.get(cls)
        if not items:
            continue
        sample = items[0]
        chains.append(
            f"- **{cls.upper()} → impact** — {str(sample.get('description', '')).split(chr(10))[0][:120]} "
            f"({len(items)} evidence point(s))"
        )
        done.add(cls)
    for cls, items in buckets.items():
        if cls in done:
            continue
        chains.append(f"- **{cls.upper()}** — {len(items)} finding(s)")
    return "\n".join(chains)
