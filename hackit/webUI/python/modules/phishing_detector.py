import httpx
import asyncio
import re
import json
from urllib.parse import urlparse, quote
from models import IntelligenceFinding
from typing import List, Dict, Set

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

COMMON_TLDS = [
    ".com", ".org", ".net", ".edu", ".gov", ".io", ".co", ".biz", ".info",
    ".ru", ".cn", ".xyz", ".top", ".club", ".online", ".site", ".shop",
    ".app", ".dev", ".tech", ".store", ".cloud", ".me", ".tv", ".cc", ".ws",
    ".in", ".uk", ".de", ".fr", ".eu", ".br", ".jp", ".au", ".ca", ".ch",
    ".nl", ".se", ".no", ".dk", ".fi", ".pl", ".cz", ".at", ".be", ".it",
    ".es", ".pt", ".com.cn", ".net.cn", ".org.cn",
]

HOMOGRAPH_CHARS = {
    'a': ['а', 'à', 'á', 'â', 'ã', 'ä', 'å', 'ɑ'],
    'b': ['Ь', 'ъ', 'ɓ'],
    'c': ['с', 'ç', 'ć', 'ĉ', 'ċ', 'č', '¢'],
    'd': ['ԁ', 'ɗ', 'đ'],
    'e': ['е', 'è', 'é', 'ê', 'ë', 'ē', 'ĕ', 'ė', 'ę', 'ě'],
    'f': ['ƒ'],
    'g': ['ɡ', 'ġ', 'ĝ', 'ğ', 'ģ'],
    'h': ['һ', 'ĥ', 'ħ'],
    'i': ['і', 'ì', 'í', 'î', 'ï', 'ĩ', 'ī', 'ĭ', 'į'],
    'j': ['ј', 'ĵ'],
    'k': ['κ', 'ķ', 'ĸ'],
    'l': ['ӏ', 'ĺ', 'ļ', 'ľ', 'ŀ', 'ł'],
    'm': ['м', 'ṃ'],
    'n': ['п', 'ñ', 'ń', 'ņ', 'ň', 'ŉ'],
    'o': ['ο', 'о', 'ò', 'ó', 'ô', 'õ', 'ö', 'ø', 'ō', 'ŏ', 'ő'],
    'p': ['р', 'ρ', 'ƿ'],
    'q': ['ԛ', 'ɋ'],
    'r': ['г', 'ŕ', 'ŗ', 'ř'],
    's': ['ѕ', 'ş', 'ś', 'ŝ', 'š', 'ș'],
    't': ['т', 'ţ', 'ť', 'ŧ'],
    'u': ['υ', 'ù', 'ú', 'û', 'ü', 'ũ', 'ū', 'ŭ', 'ů', 'ű'],
    'v': ['ν', 'ѵ'],
    'w': ['ω', 'ŵ'],
    'x': ['х', '×', 'χ'],
    'y': ['у', 'ý', 'ÿ', 'ŷ'],
    'z': ['z', 'ź', 'ż', 'ž', 'ƶ'],
}

LOOKALIKE_PATTERNS = [
    lambda d: d.replace('-', ''),
    lambda d: d.replace('.', ''),
    lambda d: re.sub(r'[aeiou]', '', d),
    lambda d: d + 's',
    lambda d: d + 'online',
    lambda d: d + 'login',
    lambda d: d + 'secure',
    lambda d: d + 'verify',
    lambda d: 'secure-' + d,
    lambda d: 'my-' + d,
    lambda d: 'login-' + d,
    lambda d: 'account-' + d,
    lambda d: 'support-' + d,
    lambda d: d.replace('o', '0'),
    lambda d: d.replace('i', '1'),
    lambda d: d.replace('e', '3'),
    lambda d: d.replace('a', '4'),
    lambda d: d.replace('s', '5'),
    lambda d: d.replace('t', '7'),
    lambda d: d.replace('l', '1'),
    lambda d: re.sub(r'(.)\1+', r'\1', d),
]


def generate_homograph_variants(domain: str) -> Set[str]:
    variants = set()
    domain_lower = domain.lower().split('.')[0]

    for i, char in enumerate(domain_lower):
        if char in HOMOGRAPH_CHARS:
            for replacement in HOMOGRAPH_CHARS[char]:
                variant = domain_lower[:i] + replacement + domain_lower[i+1:]
                for tld in COMMON_TLDS[:10]:
                    variants.add(f"{variant}{tld}")

    base = domain_lower
    for pattern_fn in LOOKALIKE_PATTERNS:
        try:
            variant = pattern_fn(base)
            if variant and variant != base and len(variant) >= 3:
                for tld in COMMON_TLDS[:10]:
                    variants.add(f"{variant}{tld}")
        except Exception:
            pass

    return variants


def check_lookalike_score(original: str, lookalike: str) -> int:
    score = 0
    orig_base = original.lower().split('.')[0]
    look_base = lookalike.lower().split('.')[0]

    if orig_base in look_base and orig_base != look_base:
        score += 3
    if look_base in orig_base and orig_base != look_base:
        score += 3

    common_len = sum(1 for a, b in zip(orig_base, look_base) if a == b)
    if len(orig_base) > 0:
        similarity = common_len / max(len(orig_base), len(look_base))
        if similarity >= 0.7 and orig_base != look_base:
            score += 4
        elif similarity >= 0.5:
            score += 2

    for char_set in HOMOGRAPH_CHARS.values():
        for hc in char_set:
            if hc in look_base:
                score += 2
                break

    return min(score, 10)


def check_certificate_for_phishing(cert_subject: str, target_domain: str) -> bool:
    if not cert_subject or not target_domain:
        return False
    subject_lower = cert_subject.lower()
    target_parts = target_domain.lower().split('.')
    target_base = target_parts[0] if target_parts else ""
    return target_base in subject_lower and target_domain.lower() not in subject_lower


def check_ssl_cert_issues(ssl_info: Dict) -> List[str]:
    issues = []
    if ssl_info.get("is_expired"):
        issues.append("Expired SSL certificate")
    if ssl_info.get("is_self_signed"):
        issues.append("Self-signed certificate")
    days = ssl_info.get("days_remaining")
    if days is not None and days < 30:
        issues.append(f"Certificate expiring soon ({days} days)")
    return issues


async def query_ct_logs(client: httpx.AsyncClient, domain: str) -> List[str]:
    certs = []
    try:
        url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
        headers = {"User-Agent": UA}
        resp = await client.get(url, headers=headers, timeout=30.0)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data[:100]:
                name = entry.get("name_value", "")
                if name:
                    certs.append(name.lower())
    except Exception:
        pass
    return certs


async def check_domain_registration(client: httpx.AsyncClient, lookalike_domain: str) -> Dict:
    result = {"registered": False, "registrar": "", "created": ""}
    try:
        url = f"https://www.whois.com/whois/{lookalike_domain}"
        headers = {"User-Agent": UA}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            text = resp.text
            if "No match for" not in text and "NOT FOUND" not in text and "No Data Found" not in text:
                result["registered"] = True
                reg_match = re.search(r'Registrar:\s*(.*?)<', text, re.I)
                if reg_match:
                    result["registrar"] = reg_match.group(1).strip()
                created_match = re.search(r'(?:Creation Date|Created On|Created):\s*(.*?)<', text, re.I)
                if created_match:
                    result["created"] = created_match.group(1).strip()
    except Exception:
        pass
    return result


async def check_ssl_validity(client: httpx.AsyncClient, domain: str) -> Dict:
    ssl_info = {"valid": False, "issuer": "", "expired": False, "self_signed": False}
    try:
        import ssl as ssl_mod
        import socket
        ctx = ssl_mod.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl_mod.CERT_NONE
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        wrapped = ctx.wrap_socket(sock, server_hostname=domain)
        wrapped.connect((domain, 443))
        cert = wrapped.getpeercert()
        if cert:
            ssl_info["valid"] = True
            issuer = dict(x[0] for x in cert.get("issuer", []))
            ssl_info["issuer"] = issuer.get("organizationName", "Unknown")
            not_after = cert.get("notAfter", "")
            from datetime import datetime
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                ssl_info["days_remaining"] = (expiry - datetime.now()).days
                if ssl_info["days_remaining"] < 0:
                    ssl_info["expired"] = True
            except Exception:
                pass
        wrapped.close()
    except Exception:
        ssl_info["valid"] = False
    return ssl_info


def is_parked_domain(resp_text: str) -> bool:
    parked_indicators = [
        "this domain is parked", "domain parking", "parked page",
        "buy this domain", "this domain may be for sale",
        "sedoparking", "bodis", "afternic", "dan.com",
        "parkingcrew", "domainmarket", "hugedomains",
        "coming soon", "under construction", "website coming soon",
    ]
    text_lower = resp_text.lower()[:2000]
    matches = sum(1 for indicator in parked_indicators if indicator in text_lower)
    return matches >= 2


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    ct_certs = await query_ct_logs(client, domain)

    suspicious_certs = []
    for cert_name in ct_certs:
        cert_name_clean = cert_name.strip().rstrip('.')
        if cert_name_clean != domain and domain in cert_name_clean:
            suspicious_certs.append(cert_name_clean)

    seen_variants = set()
    lookalike_tasks = []

    homograph_variants = generate_homograph_variants(domain)
    for variant in homograph_variants:
        if variant in seen_variants or variant == domain:
            continue
        seen_variants.add(variant)
        if variant.count('.') == 1 and len(variant) < 100:
            lookalike_tasks.append(check_domain_registration(client, variant))

    for suspicious_cert in suspicious_certs[:30]:
        if suspicious_cert not in seen_variants and suspicious_cert != domain:
            seen_variants.add(suspicious_cert)
            if suspicious_cert.count('.') >= 1:
                lookalike_tasks.append(check_domain_registration(client, suspicious_cert))

    registration_results = []
    if lookalike_tasks:
        batch_size = 10
        for i in range(0, len(lookalike_tasks), batch_size):
            batch = lookalike_tasks[i:i+batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)
            registration_results.extend(results)
            await asyncio.sleep(0.5)

    variants_list = list(seen_variants)
    for i, variant in enumerate(variants_list[:50]):
        score = check_lookalike_score(domain, variant)
        if score < 3:
            continue

        is_registered = False
        registrar = ""
        created = ""
        if i < len(registration_results):
            reg = registration_results[i]
            if isinstance(reg, dict):
                is_registered = reg.get("registered", False)
                registrar = reg.get("registrar", "")
                created = reg.get("created", "")

        threat = "Critical" if score >= 8 else ("High Risk" if score >= 6 else "Elevated Risk")
        color = "red" if score >= 8 else ("orange" if score >= 6 else "yellow")
        confidence = "High" if score >= 7 else "Medium"

        tags = ["phishing", "lookalike", "typosquatting"]
        if is_registered:
            tags.append("registered")

        if is_registered:
            ssl_info = await check_ssl_validity(client, variant)
            ssl_issues = check_ssl_cert_issues(ssl_info)
            is_parked = False
            try:
                resp = await client.get(f"https://{variant}", headers={"User-Agent": UA}, timeout=15.0, follow_redirects=True)
                is_parked = is_parked_domain(resp.text)
                if is_parked:
                    tags.append("parked-domain")
            except Exception:
                pass

            raw_lines = [f"Domain: {variant}", f"Lookalike Score: {score}/10"]
            if registrar:
                raw_lines.append(f"Registrar: {registrar}")
            if created:
                raw_lines.append(f"Created: {created}")
            if ssl_info.get("valid"):
                raw_lines.append(f"SSL: Valid ({ssl_info.get('issuer', 'Unknown')})")
            if ssl_issues:
                raw_lines.extend(ssl_issues)
            if is_parked:
                raw_lines.append("Domain appears parked")

            findings.append(IntelligenceFinding(
                entity=f"{variant} (lookalike score: {score}/10)",
                type="Phishing: Typosquatted Domain",
                source="PhishingDetector",
                confidence=confidence,
                color=color,
                threat_level=threat,
                status="Registered" if is_registered else "Available",
                resolution=f"Score: {score}/10 | {registrar[:50] if registrar else 'Unknown registrar'}",
                raw_data="\n".join(raw_lines),
                tags=tags,
            ))

    for cert_name in suspicious_certs[:20]:
        if any(f.entity.startswith(cert_name) for f in findings):
            continue

        try:
            ssl_info = await check_ssl_validity(client, cert_name)
            ssl_issues = check_ssl_cert_issues(ssl_info)
        except Exception:
            ssl_info = {"valid": False}
            ssl_issues = []

        raw_lines = [f"Cert Subject: {cert_name}", f"Contains target: {domain}"]
        if ssl_info.get("valid"):
            raw_lines.append(f"SSL: Valid ({ssl_info.get('issuer', 'Unknown')})")
        raw_lines.extend(ssl_issues)

        findings.append(IntelligenceFinding(
            entity=f"SSL Cert contains '{domain}': {cert_name[:120]}",
            type="Phishing: Suspicious Certificate",
            source="PhishingDetector/CT",
            confidence="Medium",
            color="orange",
            threat_level="Elevated Risk" if ssl_issues else "High Risk",
            status="Suspicious",
            resolution=f"Issuer: {ssl_info.get('issuer', 'Unknown')[:50]}",
            raw_data="\n".join(raw_lines),
            tags=["phishing", "certificate-transparency", "ssl", "suspicious-cert"],
        ))

    parked_domains = [f for f in findings if "parked-domain" in f.tags]
    registered_lookalikes = [f for f in findings if "registered" in f.tags and "Phishing: Typosquatted Domain" in f.type]
    suspicious_certs_findings = [f for f in findings if "Suspicious Certificate" in f.type]

    if findings:
        summary_lines = [
            f"Total phishing indicators: {len(findings)}",
            f"Registered lookalike domains: {len(registered_lookalikes)}",
            f"Suspicious certificates: {len(suspicious_certs_findings)}",
            f"Parked domains: {len(parked_domains)}",
        ]

        highest_threat = max(
            (f.threat_level for f in findings),
            key=lambda x: ["Informational", "Elevated Risk", "High Risk", "Critical"].index(x)
        )

        findings.append(IntelligenceFinding(
            entity=f"Phishing Scan: {len(registered_lookalikes)} lookalikes, {len(suspicious_certs_findings)} suspicious certs",
            type="Phishing: Summary",
            source="PhishingDetector",
            confidence="Medium",
            color="red" if highest_threat in ("Critical", "High Risk") else "orange",
            threat_level=highest_threat,
            raw_data="\n".join(summary_lines),
            tags=["summary", "phishing-detection", "typosquatting"]
        ))

    return findings
