import subprocess
import json
import re
from dataclasses import dataclass
from urllib.request import urlopen, Request
from urllib.error import URLError


@dataclass
class DomainResult:
    domain: str
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    name_servers: list[str] = None
    org: str = ""
    email: str = ""
    country: str = ""
    mx_records: list[str] = None
    txt_records: list[str] = None
    a_records: list[str] = None
    aaaa_records: list[str] = None
    cname_records: list[str] = None


def check_whois(domain: str) -> dict:
    result = {}
    try:
        output = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=30)
        text = output.stdout

        if "No match for" in text or "NOT FOUND" in text:
            return {"error": "Domain not found", "domain": domain}

        patterns = [
            ("registrar", r"Registrar:\s*(.+?)\n"),
            ("creation_date", r"(?:Creation Date|created|Created on):\s*(.+?)\n"),
            ("expiration_date", r"(?:Registry Expiry Date|Expiration Date|expire|Expiry date):\s*(.+?)\n"),
            ("name_servers", r"Name Server:\s*(.+?)\n"),
            ("org", r"(?:Organization|OrgName|org-name):\s*(.+?)\n"),
            ("email", r"(?:Registrant Email|Email|e-mail):\s*(.+?)\n"),
            ("country", r"(?:Country|Registrant Country):\s*(.+?)\n"),
        ]

        for key, pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                if key == "name_servers":
                    result[key] = [m.strip() for m in matches if m.strip()]
                else:
                    result[key] = matches[0].strip()

    except (subprocess.TimeoutExpired, FileNotFoundError):
        result["error"] = "whois command not available or timed out"
    return result


def check_dns_records(domain: str) -> dict:
    result = {}
    dns_types = {
        "a_records": "A",
        "aaaa_records": "AAAA",
        "mx_records": "MX",
        "txt_records": "TXT",
        "cname_records": "CNAME",
    }

    for key, rtype in dns_types.items():
        try:
            output = subprocess.run(
                ["dig", "+short", domain, rtype],
                capture_output=True, text=True, timeout=15
            )
            if output.stdout.strip():
                records = [line.strip() for line in output.stdout.splitlines() if line.strip()]
                if records:
                    result[key] = records
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    return result


def check_robtex(domain: str) -> dict:
    result = {}
    try:
        req = Request(f"https://www.robtex.com/dns-lookup/{domain}",
                      headers={"User-Agent": "HackIT-OSINT/1.0"})
        with urlopen(req, timeout=15) as resp:
            html = resp.read().decode()
            ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', html)
            if ips:
                result["related_ips"] = list(set(ips))
    except:
        pass
    return result


def analyze_domain(domain: str) -> dict:
    result = {"domain": domain}
    result.update(check_whois(domain))
    result.update(check_dns_records(domain))
    result.update(check_robtex(domain))
    return result
