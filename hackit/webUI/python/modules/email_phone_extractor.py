import httpx
import re
import asyncio
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

PHONE_PATTERNS = {
    "US": (r'\b(\+?1[-.\s]?)?\(?(\d{3})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})\b', 10),
    "UK": (r'\b(\+?44[-.\s]?)?(\d{4})[-.\s]?(\d{3})[-.\s]?(\d{4})\b', 11),
    "DE": (r'\b(\+?49[-.\s]?)?(\d{3,4})[-.\s]?(\d{3,4})[-.\s]?(\d{3,4})\b', 10),
    "FR": (r'\b(\+?33[-.\s]?)?(\d{1})[-.\s]?(\d{2})[-.\s]?(\d{2})[-.\s]?(\d{2})[-.\s]?(\d{2})\b', 10),
    "RU": (r'\b(\+?7[-.\s]?)?(\d{3})[-.\s]?(\d{3})[-.\s]?(\d{2})[-.\s]?(\d{2})\b', 10),
    "IN": (r'\b(\+?91[-.\s]?)?(\d{3})[-.\s]?(\d{3})[-.\s]?(\d{4})\b', 10),
    "BR": (r'\b(\+?55[-.\s]?)?(\d{2})[-.\s]?(\d{4,5})[-.\s]?(\d{4})\b', 11),
    "JP": (r'\b(\+?81[-.\s]?)?(\d{1,3})[-.\s]?(\d{4})[-.\s]?(\d{4})\b', 10),
    "AU": (r'\b(\+?61[-.\s]?)?(\d{1})[-.\s]?(\d{4})[-.\s]?(\d{4})\b', 10),
    "CA": (r'\b(\+?1[-.\s]?)?\(?(\d{3})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})\b', 10),
}

INTERNATIONAL_PATTERN = re.compile(r'\b(\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{2,4}[-.\s]?\d{2,4}\b')

VOIP_PREFIXES = [
    "+1214", "+1305", "+1541", "+1612", "+1708",
    "+1866", "+1877", "+1888", "+1844", "+1855",
    "+44", "+4989", "+331", "+612",
]

COUNTRY_CODES = {
    "1": "US/CA", "44": "UK", "49": "DE", "33": "FR", "7": "RU",
    "91": "IN", "55": "BR", "81": "JP", "61": "AU", "86": "CN",
    "39": "IT", "34": "ES", "31": "NL", "46": "SE", "41": "CH",
    "48": "PL", "30": "GR", "351": "PT", "45": "DK", "47": "NO",
    "358": "FI", "353": "IE", "43": "AT", "32": "BE", "90": "TR",
    "971": "AE", "966": "SA", "972": "IL", "82": "KR", "65": "SG",
    "60": "MY", "66": "TH", "63": "PH", "62": "ID", "92": "PK",
    "880": "BD", "20": "EG", "27": "ZA", "234": "NG", "254": "KE",
}

CARRIER_PATTERNS = {
    "Verizon": [r"^\+?1[-.\s]?(?:20[0-9]|21[0-9]|22[0-9]|23[0-9]|24[0-9]|25[0-9])"],
    "AT&T": [r"^\+?1[-.\s]?(?:8[0-9]{2})"],
    "T-Mobile": [r"^\+?1[-.\s]?(?:3[0-9]{2}|4[0-9]{2}|5[0-9]{2}|6[0-9]{2}|7[0-9]{2}|8[0-9]{2}|9[0-9]{2})"],
    "Vodafone": [r"^\+?44[-.\s]?7[0-9]{3}"],
    "O2": [r"^\+?44[-.\s]?7[0-9]{3}"],
    "EE": [r"^\+?44[-.\s]?7[0-9]{3}"],
    "Three": [r"^\+?44[-.\s]?7[0-9]{3}"],
    "Telefonica": [r"^\+?34[-.\s]?6[0-9]{2}"],
    "Orange": [r"^\+?33[-.\s]?6[0-9]{2}", r"^\+?33[-.\s]?7[0-9]{2}"],
    "SFR": [r"^\+?33[-.\s]?6[0-9]{2}"],
    "Bouygues": [r"^\+?33[-.\s]?6[0-9]{2}"],
    "Deutsche Telekom": [r"^\+?49[-.\s]?17[0-9]"],
    "Vodafone DE": [r"^\+?49[-.\s]?16[0-9]"],
    "Telefonica DE": [r"^\+?49[-.\s]?15[0-9]"],
    "Airtel": [r"^\+?91[-.\s]?9[0-9]{2}", r"^\+?91[-.\s]?8[0-9]{2}"],
    "Jio": [r"^\+?91[-.\s]?7[0-9]{2}", r"^\+?91[-.\s]?6[0-9]{2}"],
    "Vodafone IN": [r"^\+?91[-.\s]?9[0-9]{2}"],
    "SK Telecom": [r"^\+?82[-.\s]?10"],
    "KT": [r"^\+?82[-.\s]?10"],
    "LGU+": [r"^\+?82[-.\s]?10"],
    "SoftBank": [r"^\+?81[-.\s]?70", r"^\+?81[-.\s]?80", r"^\+?81[-.\s]?90"],
    "NTT Docomo": [r"^\+?81[-.\s]?70", r"^\+?81[-.\s]?80", r"^\+?81[-.\s]?90"],
    "KDDI": [r"^\+?81[-.\s]?70", r"^\+?81[-.\s]?80", r"^\+?81[-.\s]?90"],
}

PAGE_PATHS = [
    "/contact", "/contact-us", "/about", "/about-us", "/support",
    "/help", "/team", "/staff", "/directory", "/people",
    "/locations", "/offices", "/partners", "/footer",
]

async def scrape_domain_for_phones(domain: str, client: httpx.AsyncClient) -> list:
    phones = []
    paths_to_check = PAGE_PATHS + [""]
    for path in paths_to_check:
        for proto in ["https", "http"]:
            url = f"{proto}://{domain}{path}"
            try:
                resp = await client.get(url, timeout=10.0,
                    headers={"User-Agent": UA}, follow_redirects=True)
                if resp.status_code == 200 and len(resp.text) > 200:
                    text = resp.text
                    text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL | re.IGNORECASE)
                    text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
                    for country, (pat, _) in PHONE_PATTERNS.items():
                        for m in re.finditer(pat, text):
                            full = m.group(0).strip()
                            if full and len(full) >= 7 and full not in [p["number"] for p in phones]:
                                phones.append({"number": full, "country": country, "source": url, "pattern": f"pattern_{country}"})
                    intl_matches = INTERNATIONAL_PATTERN.findall(text)
                    for m in intl_matches:
                        full = m if isinstance(m, str) else m[0]
                        if full and len(full) >= 8 and full not in [p["number"] for p in phones]:
                            phones.append({"number": full, "country": "International", "source": url, "pattern": "intl"})
            except Exception:
                pass
    return phones[:30]

def validate_phone(number: str) -> dict:
    result = {"valid": True, "issues": []}
    digits = re.sub(r'[^\d]', '', number)
    if len(digits) < 7:
        result["valid"] = False
        result["issues"].append("Too few digits")
    if len(digits) > 15:
        result["issues"].append("More digits than standard")
    if number.count('-') > 4:
        result["issues"].append("Unusual hyphen count")
    return result

def detect_carrier(number: str) -> str:
    for carrier, patterns in CARRIER_PATTERNS.items():
        for pat in patterns:
            if re.match(pat, number):
                return carrier
    return "Unknown"

def detect_voip(number: str) -> bool:
    for prefix in VOIP_PREFIXES:
        if number.startswith(prefix):
            return True
    return False

def extract_country_code(number: str) -> str:
    digits = re.sub(r'[^\d]', '', number)
    if digits.startswith("00"):
        digits = digits[2:]
    if digits.startswith("011"):
        digits = digits[3:]
    for code_len in [3, 2, 1]:
        code = digits[:code_len]
        if code in COUNTRY_CODES:
            return COUNTRY_CODES[code]
    return "Unknown"

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    email = target.strip().lower()
    domain = email

    if "@" in email:
        domain = email.split("@")[1]
    elif email.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(email).netloc

    phones = await scrape_domain_for_phones(domain, client)

    if phones:
        for phone in phones[:20]:
            validation = validate_phone(phone["number"])
            carrier = detect_carrier(phone["number"])
            is_voip = detect_voip(phone["number"])
            country = phone.get("country", extract_country_code(phone["number"]))

            v_color = "emerald" if validation["valid"] else "orange"
            v_threat = "Informational"
            tags = ["phone", "extracted", phone["country"].lower()]
            if is_voip:
                tags.append("voip")
                v_color = "orange"
                v_threat = "Elevated Risk"

            findings.append(IntelligenceFinding(
                entity=f"Phone: {phone['number']} (Country: {country})",
                type="Phone: Number Extraction",
                source="EmailPhoneExtractor",
                confidence="Medium",
                color=v_color,
                category="Contact Intelligence",
                threat_level=v_threat,
                status="Extracted",
                resolution=f"Source: {phone['source']}",
                raw_data=f"Number: {phone['number']} | Country: {country} | Carrier: {carrier} | VoIP: {is_voip} | Source: {phone['source']}",
                tags=tags
            ))

            if carrier != "Unknown":
                findings.append(IntelligenceFinding(
                    entity=f"Carrier: {carrier}",
                    type="Phone: Carrier Detection",
                    source="EmailPhoneExtractor",
                    confidence="Low",
                    color="slate",
                    category="Contact Intelligence",
                    threat_level="Informational",
                    tags=["phone", "carrier", carrier.lower().replace(" ", "-")]
                ))

            if is_voip:
                findings.append(IntelligenceFinding(
                    entity=f"VoIP number detected: {phone['number']}",
                    type="Phone: VoIP Detection",
                    source="EmailPhoneExtractor",
                    confidence="Medium",
                    color="orange",
                    category="Contact Intelligence",
                    threat_level="Elevated Risk",
                    tags=["phone", "voip", "virtual-number"]
                ))

            if not validation["valid"]:
                for issue in validation["issues"]:
                    findings.append(IntelligenceFinding(
                        entity=f"Validation issue for {phone['number']}: {issue}",
                        type="Phone: Validation Issue",
                        source="EmailPhoneExtractor",
                        confidence="Medium",
                        color="orange",
                        category="Contact Intelligence",
                        threat_level="Informational",
                        tags=["phone", "validation"]
                    ))
    else:
        findings.append(IntelligenceFinding(
            entity=f"No phone numbers found on {domain}",
            type="Phone: No Numbers Found",
            source="EmailPhoneExtractor",
            confidence="Medium",
            color="slate",
            category="Contact Intelligence",
            threat_level="Informational",
            status="Not Found",
            tags=["phone", "no-results"]
        ))

    findings.append(IntelligenceFinding(
        entity=f"Phone extraction complete for {domain}: {len(phones)} numbers found",
        type="Phone: Extraction Summary",
        source="EmailPhoneExtractor",
        confidence="Medium",
        color="purple",
        category="General OSINT",
        threat_level="Informational",
        status=f"{len(phones)} numbers",
        raw_data=f"Pages scanned: {len(PAGE_PATHS)} | Numbers found: {len(phones)} | Unique sources: {len(set(p['source'] for p in phones)) if phones else 0}",
        tags=["phone", "summary"]
    ))

    return findings
