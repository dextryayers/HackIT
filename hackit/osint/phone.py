import re
from dataclasses import dataclass
from urllib.request import urlopen, Request
from urllib.error import URLError


@dataclass
class PhoneResult:
    number: str
    carrier: str = ""
    country: str = ""
    line_type: str = ""
    region: str = ""
    reputation: str = ""
    sources: list[str] = None


def validate_phone(number: str) -> tuple[str, str]:
    cleaned = re.sub(r'[^\d+]', '', number)
    if cleaned.startswith('+'):
        return cleaned, "international"
    if cleaned.startswith('0'):
        return cleaned, "local"
    if len(cleaned) >= 10:
        return cleaned, "unknown"
    return number, "invalid"


def check_numverify(phone: str) -> PhoneResult:
    result = PhoneResult(number=phone)
    try:
        url = f"https://numverify.com/php_helper_scripts/phone_api.php?number={phone}"
        req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urlopen(req, timeout=15) as resp:
            import json
            data = json.loads(resp.read())
            result.country = data.get("country_name", "")
            result.carrier = data.get("carrier", "")
            result.line_type = data.get("line_type", "")
            result.region = data.get("location", "")
    except (URLError, OSError, json.JSONDecodeError):
        pass
    return result


def check_phone_reputation(phone: str) -> PhoneResult:
    result = PhoneResult(number=phone)
    try:
        url = f"https://api.phonecheck.io/v1/validate/{phone}"
        req = Request(url, headers={"User-Agent": "HackIT-OSINT/1.0"})
        with urlopen(req, timeout=15) as resp:
            import json
            data = json.loads(resp.read())
            result.reputation = data.get("reputation", "")
    except:
        pass
    return result


def check_phone_social(phone: str) -> PhoneResult:
    result = PhoneResult(number=phone)
    sources_found = []

    services = [
        ("Telegram", f"https://t.me/{phone}"),
        ("WhatsApp", f"https://wa.me/{phone}"),
        ("Signal", f"https://signal.me/{phone}"),
    ]

    for name, url in services:
        try:
            req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
            resp = urlopen(req, timeout=10)
            if resp.status == 200:
                sources_found.append(name)
        except:
            pass

    result.sources = sources_found
    return result


def analyze_phone(number: str) -> dict:
    cleaned, ptype = validate_phone(number)
    if ptype == "invalid":
        return {"error": "Invalid phone number", "number": number}

    results = {}
    results["numverify"] = check_numverify(cleaned)
    results["reputation"] = check_phone_reputation(cleaned)
    results["social"] = check_phone_social(cleaned)

    return {
        "number": cleaned,
        "type": ptype,
        "carrier": results["numverify"].carrier or results["reputation"].carrier,
        "country": results["numverify"].country,
        "line_type": results["numverify"].line_type,
        "region": results["numverify"].region,
        "reputation": results["reputation"].reputation,
        "social_found": results["social"].sources or [],
    }
