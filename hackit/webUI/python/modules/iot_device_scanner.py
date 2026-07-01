import httpx
import re
import json
from urllib.parse import urlparse, quote
from typing import List
from models import IntelligenceFinding

IOT_SEARCH_ENGINES = [
    ("Shodan", "https://www.shodan.io/search?query={}"),
    ("Censys", "https://search.censys.io/search?resource=hosts&q={}"),
    ("ZoomEye", "https://www.zoomeye.org/searchResult?q={}"),
    ("Fofa", "https://en.fofa.info/result?qbase64={}"),
    ("Netlas", "https://app.netlas.io/search/?q={}"),
    ("Onyphe", "https://www.onyphe.io/search?q={}"),
    ("BinaryEdge", "https://www.binaryedge.io/search?q={}"),
    ("PublicWWW", "https://publicwww.com/websites/{}"),
]

IOT_DEVICE_PATTERNS = {
    "camera": ["axis", "hikvision", "dahua", "ip camera", "webcam", "cctv", "rtsp", "onvif"],
    "router": ["router", "routeros", "mikrotik", "ubiquiti", "unifi", "cpe", "ap"],
    "printer": ["printer", "print server", "ipp", "lp", "raw printing", "jetdirect"],
    "nas": ["synology", "qnap", "nas", "network storage", "openmediavault", "truenas"],
    "smart_hub": ["smart hub", "smartthings", "home assistant", "hue bridge", "zigbee"],
    "voip": ["sip", "voip", "asterisk", "freepbx", "3cx", "ip phone", "polycom"],
    "building_automation": ["bacnet", "modbus", "knx", "lonworks", "hvac", "bms"],
    "medical": ["hl7", "dicom", "pacs", "medical device", "patient monitor", "infusion"],
    "industrial": ["plc", "scada", "ics", "rtu", "hmi", "siemens", "rockwell"],
    "network": ["switch", "cisco", "juniper", "huawei", "hp switch", "brocade"],
}

DEFAULT_CREDENTIALS = {
    "axis": ("root", "pass"),
    "hikvision": ("admin", "12345"),
    "dahua": ("admin", "admin"),
    "mikrotik": ("admin", ""),
    "ubiquiti": ("ubnt", "ubnt"),
    "synology": ("admin", "admin"),
    "qnap": ("admin", "admin"),
    "cisco": ("cisco", "cisco"),
    "linksys": ("admin", "admin"),
    "netgear": ("admin", "password"),
}

VULNERABLE_VERSIONS = {
    "mikrotik": ["6.x", "6.40", "6.41", "6.42"],
    "axis": ["5.x", "6.x"],
    "hikvision": ["<5.4.0", "<5.5.0"],
    "qnap": ["<4.5.0", "<4.4.0"],
}


async def query_iot_engine(name: str, url_template: str, target: str, client: httpx.AsyncClient) -> dict:
    try:
        url = url_template.format(quote(target))
        resp = await client.get(url, timeout=15.0, headers={"User-Agent": "Mozilla/5.0"}, follow_redirects=True)
        if resp.status_code == 200 and len(resp.text) > 300:
            text = resp.text.lower()
            mentions = text.count(target.lower())
            devices_found = {}
            for device_type, patterns in IOT_DEVICE_PATTERNS.items():
                found = [p for p in patterns if p in text]
                if found:
                    devices_found[device_type] = found
            default_creds_found = {}
            for brand, (user, pwd) in DEFAULT_CREDENTIALS.items():
                if brand in text:
                    default_creds_found[brand] = f"{user}/{pwd}"
            vulnerable = []
            for brand, versions in VULNERABLE_VERSIONS.items():
                if brand in text:
                    vulnerable.append(brand)
            return {
                "name": name,
                "mentions": mentions,
                "devices": devices_found,
                "default_creds": default_creds_found,
                "vulnerable_brands": vulnerable,
            }
    except:
        pass
    return None


async def check_default_credentials(ip: str, client: httpx.AsyncClient) -> list:
    results = []
    for path in ["/", "/login", "/admin", "/setup"]:
        for brand, (user, pwd) in DEFAULT_CREDENTIALS.items():
            try:
                resp = await client.get(
                    f"http://{ip}{path}",
                    timeout=5.0,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                if resp.status_code == 200:
                    results.append({"brand": brand, "path": path, "status": resp.status_code})
            except:
                pass
    return results


async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    all_results = []
    for name, url_template in IOT_SEARCH_ENGINES:
        result = await query_iot_engine(name, url_template, t, client)
        if result:
            all_results.append(result)

    if all_results:
        findings.append(IntelligenceFinding(
            entity=f"IoT scan: {len(all_results)}/{len(IOT_SEARCH_ENGINES)} engines queried",
            type="IoT: Coverage Report",
            source="IoTScanner",
            confidence="High",
            color="slate",
            category="IoT Intelligence",
            threat_level="Informational",
            status="Complete",
            resolution=t,
            tags=["iot", "coverage", "engines"],
        ))

    all_devices = {}
    all_creds = {}
    all_vuln_brands = set()

    for result in all_results:
        if result["mentions"] > 0:
            findings.append(IntelligenceFinding(
                entity=f"{result['name']}: {result['mentions']} IoT mentions for {t}",
                type="IoT: Engine Result",
                source="IoTScanner",
                confidence="Medium",
                color="sky",
                category="IoT Intelligence",
                threat_level="Informational",
                status="Found",
                resolution=t,
                tags=["iot", result['name'].lower().replace(" ", "-")],
            ))

        for dtype, indicators in result.get("devices", {}).items():
            all_devices[dtype] = all_devices.get(dtype, []) + indicators
            findings.append(IntelligenceFinding(
                entity=f"{dtype.replace('_', ' ').title()} detected: {', '.join(indicators[:3])}",
                type=f"IoT: {dtype.replace('_', ' ').title()}",
                source="IoTScanner",
                confidence="Medium",
                color="orange",
                category="IoT Intelligence",
                threat_level="High Risk",
                status="Detected",
                resolution=t,
                tags=["iot", dtype] + indicators[:3],
            ))

        for brand, cred in result.get("default_creds", {}).items():
            all_creds[brand] = cred
            findings.append(IntelligenceFinding(
                entity=f"Default credentials possible: {brand} ({cred})",
                type="IoT: Default Credentials",
                source="IoTScanner",
                confidence="Medium",
                color="red",
                category="IoT Intelligence",
                threat_level="Critical",
                status="Default Creds",
                resolution=t,
                tags=["iot", "default-creds", brand],
            ))

        for brand in result.get("vulnerable_brands", []):
            all_vuln_brands.add(brand)
            findings.append(IntelligenceFinding(
                entity=f"Known vulnerabilities for {brand} devices detected",
                type="IoT: Known Vulnerabilities",
                source="IoTScanner",
                confidence="Medium",
                color="red",
                category="IoT Intelligence",
                threat_level="Critical",
                status="Vulnerable",
                resolution=t,
                tags=["iot", "vulnerability", brand],
            ))

    if all_devices:
        device_summary = ", ".join(f"{d}({len(ind)})" for d, ind in sorted(all_devices.items(), key=lambda x: len(x[1]), reverse=True))
        findings.append(IntelligenceFinding(
            entity=f"Device types detected: {device_summary}",
            type="IoT: Device Inventory",
            source="IoTScanner",
            confidence="Medium",
            color="slate",
            category="IoT Intelligence",
            threat_level="Informational",
            status="Inventoried",
            resolution=t,
            tags=["iot", "inventory"] + list(all_devices.keys()),
        ))

    if all_creds:
        findings.append(IntelligenceFinding(
            entity=f"{len(all_creds)} device brands with default credentials risk",
            type="IoT: Credential Risk Summary",
            source="IoTScanner",
            confidence="Medium",
            color="red",
            category="IoT Intelligence",
            threat_level="Critical",
            status="High Risk",
            resolution=t,
            tags=["iot", "credential-risk", "default"],
        ))

    if not all_results:
        findings.append(IntelligenceFinding(
            entity="No IoT devices found for target",
            type="IoT: Scan Complete",
            source="IoTScanner",
            confidence="Low",
            color="emerald",
            category="IoT Intelligence",
            threat_level="Informational",
            status="Clean",
            resolution=t,
            tags=["iot", "clean"],
        ))

    return findings
