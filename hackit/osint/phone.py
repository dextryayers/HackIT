import re
import json
from urllib.request import urlopen, Request
from urllib.error import URLError
from urllib.parse import quote_plus


COUNTRY_CODES = {
    "93": "Afghanistan", "355": "Albania", "213": "Algeria", "376": "Andorra",
    "244": "Angola", "54": "Argentina", "374": "Armenia", "61": "Australia",
    "43": "Austria", "994": "Azerbaijan", "973": "Bahrain", "880": "Bangladesh",
    "32": "Belgium", "501": "Belize", "229": "Benin", "975": "Bhutan",
    "591": "Bolivia", "387": "Bosnia", "267": "Botswana", "55": "Brazil",
    "673": "Brunei", "359": "Bulgaria", "226": "Burkina Faso", "95": "Myanmar",
    "257": "Burundi", "855": "Cambodia", "237": "Cameroon", "1": "US/Canada",
    "238": "Cape Verde", "236": "Central African Republic", "235": "Chad",
    "56": "Chile", "86": "China", "57": "Colombia", "269": "Comoros",
    "242": "Congo", "243": "DR Congo", "506": "Costa Rica", "385": "Croatia",
    "53": "Cuba", "357": "Cyprus", "420": "Czech Republic", "45": "Denmark",
    "253": "Djibouti", "593": "Ecuador", "20": "Egypt", "503": "El Salvador",
    "372": "Estonia", "251": "Ethiopia", "679": "Fiji", "358": "Finland",
    "33": "France", "241": "Gabon", "220": "Gambia", "995": "Georgia",
    "49": "Germany", "233": "Ghana", "30": "Greece", "502": "Guatemala",
    "224": "Guinea", "245": "Guinea-Bissau", "592": "Guyana", "509": "Haiti",
    "504": "Honduras", "852": "Hong Kong", "36": "Hungary", "354": "Iceland",
    "91": "India", "62": "Indonesia", "98": "Iran", "964": "Iraq",
    "353": "Ireland", "972": "Israel", "39": "Italy", "225": "Ivory Coast",
    "81": "Japan", "962": "Jordan", "7": "Kazakhstan", "254": "Kenya",
    "686": "Kiribati", "965": "Kuwait", "996": "Kyrgyzstan", "856": "Laos",
    "371": "Latvia", "961": "Lebanon", "266": "Lesotho", "231": "Liberia",
    "218": "Libya", "423": "Liechtenstein", "370": "Lithuania", "352": "Luxembourg",
    "853": "Macau", "389": "North Macedonia", "261": "Madagascar", "265": "Malawi",
    "60": "Malaysia", "960": "Maldives", "223": "Mali", "356": "Malta",
    "692": "Marshall Islands", "222": "Mauritania", "230": "Mauritius",
    "52": "Mexico", "691": "Micronesia", "373": "Moldova", "377": "Monaco",
    "976": "Mongolia", "382": "Montenegro", "212": "Morocco", "258": "Mozambique",
    "264": "Namibia", "674": "Nauru", "977": "Nepal", "31": "Netherlands",
    "64": "New Zealand", "505": "Nicaragua", "227": "Niger", "234": "Nigeria",
    "850": "North Korea", "47": "Norway", "968": "Oman", "92": "Pakistan",
    "680": "Palau", "970": "Palestine", "507": "Panama", "675": "Papua New Guinea",
    "595": "Paraguay", "51": "Peru", "63": "Philippines", "48": "Poland",
    "351": "Portugal", "974": "Qatar", "40": "Romania", "7": "Russia",
    "250": "Rwanda", "685": "Samoa", "378": "San Marino", "239": "Sao Tome",
    "966": "Saudi Arabia", "221": "Senegal", "381": "Serbia", "248": "Seychelles",
    "232": "Sierra Leone", "65": "Singapore", "421": "Slovakia", "386": "Slovenia",
    "677": "Solomon Islands", "252": "Somalia", "27": "South Africa",
    "82": "South Korea", "211": "South Sudan", "34": "Spain", "94": "Sri Lanka",
    "249": "Sudan", "597": "Suriname", "268": "Eswatini", "46": "Sweden",
    "41": "Switzerland", "963": "Syria", "886": "Taiwan", "992": "Tajikistan",
    "255": "Tanzania", "66": "Thailand", "670": "Timor-Leste", "228": "Togo",
    "690": "Tokelau", "676": "Tonga", "216": "Tunisia", "90": "Turkey",
    "993": "Turkmenistan", "688": "Tuvalu", "256": "Uganda", "380": "Ukraine",
    "971": "United Arab Emirates", "44": "United Kingdom", "598": "Uruguay",
    "998": "Uzbekistan", "678": "Vanuatu", "379": "Vatican", "58": "Venezuela",
    "84": "Vietnam", "967": "Yemen", "260": "Zambia", "263": "Zimbabwe",
}


def validate_phone(number: str) -> tuple:
    cleaned = re.sub(r'[^\d+]', '', number)
    if cleaned.startswith('+'):
        return cleaned, "international"
    if cleaned.startswith('0'):
        try:
            num_only = cleaned[1:]
            for code in sorted(COUNTRY_CODES.keys(), key=len, reverse=True):
                if num_only.startswith(code):
                    return f"+{code}{num_only[len(code):]}", "international"
            return f"0{num_only}", "local"
        except:
            return cleaned, "local"
    if len(cleaned) >= 10:
        return cleaned, "unknown"
    return number, "invalid"


def detect_country(phone: str) -> str:
    num = phone.replace("+", "").replace("-", "").replace(" ", "")
    for code, name in sorted(COUNTRY_CODES.items(), key=lambda x: -len(x[0])):
        if num.startswith(code):
            return name
    return ""


def check_numverify(phone: str) -> dict:
    result = {}
    try:
        url = f"https://numverify.com/php_helper_scripts/phone_api.php?number={phone}"
        req = Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
        })
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            result["country"] = data.get("country_name", "")
            result["carrier"] = data.get("carrier", "")
            result["line_type"] = data.get("line_type", "")
            result["location"] = data.get("location", "")
            country_code = data.get("country_code", "")
            if country_code:
                result["country_code"] = country_code
    except:
        pass
    return result


def check_google_phone(phone: str) -> dict:
    result = {"search_title": "", "mentions": 0, "snippets": []}
    try:
        url = f"https://www.google.com/search?q={quote_plus(phone)}"
        req = Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept-Language": "en-US,en;q=0.9",
        })
        with urlopen(req, timeout=15) as resp:
            html = resp.read().decode('utf-8', errors='ignore')
            title_match = re.search(r'<title>(.*?)</title>', html)
            if title_match:
                result["search_title"] = title_match.group(1).strip()
            count_match = re.search(r'About ([\d,]+) results', html)
            if count_match:
                result["mentions"] = int(count_match.group(1).replace(',', ''))
            snippets = re.findall(r'<span[^>]*class="[^"]*st"[^>]*>(.*?)</span>', html, re.DOTALL)
            for s in snippets[:3]:
                clean = re.sub(r'<[^>]+>', '', s).strip()
                if clean:
                    result["snippets"].append(clean[:200])
    except:
        pass
    return result


def check_social_media_phone(phone: str) -> list:
    found = []
    checks = [
        ("Telegram", f"https://t.me/{phone}"),
        ("WhatsApp", f"https://wa.me/{phone}"),
        ("Viber", f"viber://chat?number={phone}"),
        ("Telegram ID", f"https://t.me/+{phone}"),
    ]
    for name, url in checks:
        try:
            req = Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            })
            resp = urlopen(req, timeout=10)
            if resp.status == 200:
                found.append(name)
        except URLError as e:
            if hasattr(e, 'code') and e.code == 200:
                found.append(name)
        except:
            pass
    return found


def analyze_phone(number: str) -> dict:
    cleaned, ptype = validate_phone(number)
    if ptype == "invalid":
        return {"error": "Invalid phone number", "number": number}

    numverify = check_numverify(cleaned)
    social = check_social_media_phone(cleaned)
    google = check_google_phone(cleaned)

    detected_country = numverify.get("country", "") or detect_country(cleaned)

    return {
        "number": cleaned,
        "type": ptype,
        "carrier": numverify.get("carrier", "Unknown"),
        "country": detected_country,
        "line_type": numverify.get("line_type", "Unknown"),
        "location": numverify.get("location", ""),
        "country_code": numverify.get("country_code", ""),
        "social_found": social,
        "google_mentions": google.get("mentions", 0),
        "google_snippets": google.get("snippets", []),
        "google_search_title": google.get("search_title", ""),
    }
