import httpx
import re
import asyncio
from models import IntelligenceFinding

KEYSERVERS = [
    ("keys.openpgp.org", "https://keys.openpgp.org/vks/v1/by-email/{email}"),
    ("keyserver.ubuntu.com", "https://keyserver.ubuntu.com/pks/lookup?op=get&search={email}"),
    ("pgp.mit.edu", "https://pgp.mit.edu/pks/lookup?op=get&search={email}"),
    ("keyring.debian.org", "https://keyring.debian.org/pks/lookup?op=get&search={email}"),
    ("keys.gnupg.net", "https://keys.gnupg.net/pks/lookup?op=get&search={email}"),
]

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

KEY_PATTERNS = {
    "key_id": re.compile(r'(?:Key ID|keyid|KeyID)[:\s]*([A-F0-9]{8,16})', re.IGNORECASE),
    "fingerprint": re.compile(r'(?:Fingerprint|fingerprint)[:\s]*([A-F0-9]{4}(?:\s[A-F0-9]{4}){9,})', re.IGNORECASE),
    "algorithm": re.compile(r'(?:Algorithm|algorithm|algo)[:\s]*(\w+\d*)', re.IGNORECASE),
    "key_size": re.compile(r'(?:Key Size|key.size|keysize|bits)[:\s]*(\d+)', re.IGNORECASE),
    "creation_date": re.compile(r'(?:Created|created|Creation|creation)[:\s]*(\d{4}[-/]\d{2}[-/]\d{2})', re.IGNORECASE),
    "expiration": re.compile(r'(?:Expires|expires|Expiration|expiration)[:\s]*(\d{4}[-/]\d{2}[-/]\d{2})', re.IGNORECASE),
    "revoked": re.compile(r'(?:Revoked|revoked|REVOKED)', re.IGNORECASE),
    "user_id": re.compile(r'(?:User ID|uid|UserID)[:\s]*([^<]*\s*<[^>]+>)', re.IGNORECASE),
    "signatures": re.compile(r'(?:signatures?|Sigs?)[:\s]*(\d+)', re.IGNORECASE),
}

async def check_keyserver(key_name: str, url_template: str, email: str, client: httpx.AsyncClient) -> dict:
    result = {"found": False, "keyserver": key_name, "raw": "", "details": {}}
    url = url_template.format(email=email)
    try:
        resp = await client.get(url, timeout=20.0,
            headers={"User-Agent": UA, "Accept": "text/html,application/pgp-keys,*/*"})
        if resp.status_code == 200 and len(resp.text) > 100:
            text = resp.text
            result["found"] = True
            result["raw"] = text[:2000]
            for key, pat in KEY_PATTERNS.items():
                m = pat.search(text)
                if m:
                    result["details"][key] = m.group(1) if m.groups() else m.group(0)
            if not result["details"]:
                result["details"]["raw_found"] = True
    except Exception:
        pass
    return result

async def fetch_public_key(email: str, client: httpx.AsyncClient) -> str | None:
    try:
        resp = await client.get(
            f"https://keys.openpgp.org/vks/v1/by-email/{email}",
            timeout=15.0,
            headers={"User-Agent": UA, "Accept": "application/pgp-keys"}
        )
        if resp.status_code == 200 and resp.text.startswith("-----BEGIN PGP PUBLIC KEY BLOCK"):
            return resp.text[:2000]
    except Exception:
        pass
    return None

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    email = target.strip().lower()
    if "@" not in email:
        findings.append(IntelligenceFinding(
            entity="Not a valid email",
            type="PGP Discovery Error",
            source="EmailPGPDiscovery",
            confidence="High", color="red", category="General OSINT",
            threat_level="Informational", status="Error",
            tags=["error"]
        ))
        return findings

    for name, url in KEYSERVERS:
        result = await check_keyserver(name, url, email, client)
        if result["found"]:
            details = result["details"]
            key_id = details.get("key_id", "Unknown")
            fingerprint = details.get("fingerprint", "N/A")
            algorithm = details.get("algorithm", "Unknown")
            key_size = details.get("key_size", "Unknown")
            created = details.get("creation_date", "Unknown")
            expires = details.get("expiration", "Never")
            is_revoked = "revoked" in details

            if is_revoked:
                findings.append(IntelligenceFinding(
                    entity=f"REVOKED key found on {name}",
                    type="PGP: Revoked Key",
                    source="EmailPGPDiscovery",
                    confidence="High",
                    color="red",
                    category="Cryptographic Intelligence",
                    threat_level="Elevated Risk",
                    status="Revoked",
                    resolution=f"Keyserver: {name}",
                    tags=["pgp", "revoked", name]
                ))

            findings.append(IntelligenceFinding(
                entity=f"PGP key for {email} on {name}: Key ID {key_id[:16]}",
                type="PGP: Key Discovery",
                source="EmailPGPDiscovery",
                confidence="High",
                color="purple",
                category="Cryptographic Intelligence",
                threat_level="Informational",
                status="Found",
                resolution=f"Key ID: {key_id[:16]}",
                raw_data=f"Keyserver: {name} | Algorithm: {algorithm} | Size: {key_size} | Created: {created} | Expires: {expires} | Revoked: {is_revoked} | Fingerprint: {fingerprint[:50] if fingerprint != 'N/A' else 'N/A'}",
                tags=["pgp", "key-discovery", name.replace(".", "-")]
            ))

            if key_id:
                findings.append(IntelligenceFinding(
                    entity=f"Key ID: {key_id[:16]}",
                    type="PGP: Key ID",
                    source="EmailPGPDiscovery",
                    confidence="High",
                    color="slate",
                    category="Cryptographic Intelligence",
                    threat_level="Informational",
                    tags=["pgp", "key-id"]
                ))

            if fingerprint and fingerprint != "N/A":
                findings.append(IntelligenceFinding(
                    entity=f"Fingerprint: {fingerprint[:60]}",
                    type="PGP: Fingerprint",
                    source="EmailPGPDiscovery",
                    confidence="High",
                    color="slate",
                    category="Cryptographic Intelligence",
                    threat_level="Informational",
                    tags=["pgp", "fingerprint"]
                ))

            if algorithm:
                findings.append(IntelligenceFinding(
                    entity=f"Algorithm: {algorithm}",
                    type="PGP: Algorithm",
                    source="EmailPGPDiscovery",
                    confidence="High",
                    color="slate",
                    category="Cryptographic Intelligence",
                    threat_level="Informational",
                    tags=["pgp", "algorithm"]
                ))

            if key_size:
                try:
                    ks = int(key_size)
                    ks_color = "emerald" if ks >= 4096 else "orange" if ks >= 2048 else "red"
                    findings.append(IntelligenceFinding(
                        entity=f"Key size: {key_size} bits",
                        type="PGP: Key Strength",
                        source="EmailPGPDiscovery",
                        confidence="High",
                        color=ks_color,
                        category="Cryptographic Intelligence",
                        threat_level="Informational",
                        tags=["pgp", "key-strength"]
                    ))
                except ValueError:
                    pass

            if created and created != "Unknown":
                findings.append(IntelligenceFinding(
                    entity=f"Key created: {created}",
                    type="PGP: Creation Date",
                    source="EmailPGPDiscovery",
                    confidence="High",
                    color="slate",
                    category="Cryptographic Intelligence",
                    threat_level="Informational",
                    tags=["pgp", "creation-date"]
                ))

            if expires and expires != "Never":
                findings.append(IntelligenceFinding(
                    entity=f"Key expires: {expires}",
                    type="PGP: Expiration",
                    source="EmailPGPDiscovery",
                    confidence="High",
                    color="orange",
                    category="Cryptographic Intelligence",
                    threat_level="Informational",
                    tags=["pgp", "expiration"]
                ))
            elif not is_revoked:
                findings.append(IntelligenceFinding(
                    entity="No key expiration date set - key never expires",
                    type="PGP: No Expiration",
                    source="EmailPGPDiscovery",
                    confidence="Medium",
                    color="orange",
                    category="Cryptographic Intelligence",
                    threat_level="Informational",
                    tags=["pgp", "no-expiry"]
                ))

            sig_count = details.get("signatures", "0")
            if sig_count:
                findings.append(IntelligenceFinding(
                    entity=f"Signatures on key: {sig_count}",
                    type="PGP: Signature Count",
                    source="EmailPGPDiscovery",
                    confidence="Medium",
                    color="slate",
                    category="Cryptographic Intelligence",
                    threat_level="Informational",
                    tags=["pgp", "signatures"]
                ))

            if "user_id" in details:
                uid = details["user_id"]
                findings.append(IntelligenceFinding(
                    entity=f"User ID: {uid[:100]}",
                    type="PGP: User ID",
                    source="EmailPGPDiscovery",
                    confidence="High",
                    color="slate",
                    category="Cryptographic Intelligence",
                    threat_level="Informational",
                    tags=["pgp", "user-id"]
                ))
                other_emails = re.findall(r'<([^>]+@[^>]+)>', uid)
                for oe in other_emails:
                    if oe.lower() != email:
                        findings.append(IntelligenceFinding(
                            entity=f"Associated email on same key: {oe}",
                            type="PGP: Associated Email",
                            source="EmailPGPDiscovery",
                            confidence="High",
                            color="purple",
                            category="Cryptographic Intelligence",
                            threat_level="Informational",
                            tags=["pgp", "associated-email"]
                        ))
        else:
            findings.append(IntelligenceFinding(
                entity=f"No PGP key found on {name} for {email}",
                type="PGP: No Key",
                source="EmailPGPDiscovery",
                confidence="High",
                color="slate",
                category="Cryptographic Intelligence",
                threat_level="Informational",
                status="Not Found",
                tags=["pgp", "no-key", name.replace(".", "-")]
            ))

    public_key = await fetch_public_key(email, client)
    if public_key:
        findings.append(IntelligenceFinding(
            entity=f"Public key exported from keys.openpgp.org ({len(public_key)} chars)",
            type="PGP: Public Key Export",
            source="EmailPGPDiscovery",
            confidence="High",
            color="slate",
            category="Cryptographic Intelligence",
            threat_level="Informational",
            status="Exported",
            raw_data=public_key[:1000],
            tags=["pgp", "public-key", "export"]
        ))

    total_found = sum(1 for f in findings if f.type == "PGP: Key Discovery")
    findings.append(IntelligenceFinding(
        entity=f"PGP key search complete: {total_found} key(s) found across {len(KEYSERVERS)} keyservers",
        type="PGP: Scan Summary",
        source="EmailPGPDiscovery",
        confidence="High",
        color="purple",
        category="General OSINT",
        threat_level="Informational",
        status=f"{total_found} keys found",
        tags=["pgp", "summary"]
    ))

    return findings
