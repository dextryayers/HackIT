import httpx
import asyncio
import socket
import re
from models import IntelligenceFinding

IOT_DEVICE_PATTERNS = {
    "router": {
        "patterns": [r"router", r"routerlogin", r"tplink", r"tp-link", r"dlink", r"d-link",
                     r"netgear", r"linksys", r"asus", r"mikrotik", r"ubiquiti", r"ubnt",
                     r"openwrt", r"dd-wrt", r"tomato", r"pfsense", r"opnsense",
                     r"cisco", r"juniper", r"aruba", r"ruckus", r"meraki"],
        "label": "Router/Firewall"
    },
    "camera": {
        "patterns": [r"camera", r"webcam", r"ipcam", r"cam", r"dvr", r"nvr",
                     r"hikvision", r"dahua", r"axis", r"bosch", r"geovision",
                     r"arecont", r"avigilon", r"pelco", r"vivotek", r"foscam",
                     r"wyze", r"ring", r"nest", r"arlo", r"reolink"],
        "label": "Camera/Surveillance"
    },
    "nas": {
        "patterns": [r"nas", r"synology", r"qnap", r"qnap", r"asustor", r"drobo",
                     r"netapp", r"dell", r"emc", r"trueNas", r"freenas",
                     r"openmediavault", r"unraid", r"wdcloud", r"mycloud"],
        "label": "NAS/Storage"
    },
    "printer": {
        "patterns": [r"printer", r"brother", r"epson", r"hp\s", r"canon", r"ricoh",
                     r"xerox", r"kyocera", r"lexmark", r"konica"],
        "label": "Printer/MFP"
    },
    "industrial": {
        "patterns": [r"plc", r"scada", r"hmi", r"siemens", r"rockwell", r"allen.?bradley",
                     r"modbus", r"bacnet", r"opc.?ua", r"profibus", r"profinet",
                     r"schneider", r"ab.?plc", r"micrologix", r"control.?logix",
                     r"simatic", r"wincc", r"factorytalk"],
        "label": "Industrial Control System"
    },
    "power": {
        "patterns": [r"ups", r"pdu", r"power.?distribution", r"apc\b", r"tripp.?lite",
                     r"cyberpower", r"eaton", r"generac", r"kohler"],
        "label": "Power/Energy"
    },
    "iot": {
        "patterns": [r"esp8266", r"esp32", r"arduino", r"raspberry.?pi", r"rpi\b",
                     r"nodemcu", r"particle", r"photon", r"tessel",
                     r"home.?assistant", r"hassio", r"zigbee", r"zwave",
                     r"sonoff", r"tasmota", r"mqtt"],
        "label": "IoT/Embedded"
    },
    "telecom": {
        "patterns": [r"asterisk", r"freepbx", r"elastix", r"3cx", r"pbx",
                     r"sip.?server", r"voip", r"grandstream", r"polycom",
                     r"yealink", r"cucm", r"freeswitch"],
        "label": "Telecom/VoIP"
    },
}

DEVICE_HTTP_TITLES = {
    "router": ["router", "login", "admin", "status", "tplink", "netgear", "linksys", "asus"],
    "camera": ["webcam", "camera", "ipcam", "dvr", "live view", "liveview", "stream"],
    "nas": ["nas", "synology", "qnap", "diskstation", "filestation", "storage"],
    "printer": ["printer", "hp eprint", "brother", "canon ij", "remote panel"],
    "industrial": ["scada", "plc", "hmi", "factory", "automation", "control"],
    "power": ["ups", "pdu", "apc", "powerchute", "powerpanel"],
    "iot": ["esp", "arduino", "raspberry", "home assistant", "mqtt", "sensor"],
    "telecom": ["asterisk", "freepbx", "pbx", "voip", "sip", "phone system"],
}

DEVICE_DEFAULT_PATHS = [
    "/", "/login", "/admin", "/status", "/config", "/setup",
    "/index.html", "/home.html", "/main.cgi", "/cgi-bin/",
    "/web/", "/camera", "/live", "/view", "/stream",
    "/api/info", "/api/system", "/api/status",
    "/cgi-bin/status", "/cgi-bin/config",
    "/system.html", "/status.html", "/config.html",
]

COMMON_IOT_PORTS = [80, 443, 8080, 8443, 554, 37777, 37778, 8554, 8899, 22, 23, 21]

SERVICE_BANNER_PATTERNS = {
    "OpenSSH": {"label": "SSH Server", "color": "orange"},
    "Apache httpd": {"label": "Web Server (Apache)", "color": "slate"},
    "nginx": {"label": "Web Server (Nginx)", "color": "slate"},
    "lighttpd": {"label": "Web Server (Lighttpd)", "color": "slate"},
    "Microsoft-IIS": {"label": "Web Server (IIS)", "color": "slate"},
    "GoAhead": {"label": "Embedded Web Server (GoAhead)", "color": "orange"},
    "thttpd": {"label": "Embedded Web Server (thttpd)", "color": "orange"},
    "mini_httpd": {"label": "Embedded Web Server (mini_httpd)", "color": "orange"},
    "Boa": {"label": "Embedded Web Server (Boa)", "color": "orange"},
    "RomPager": {"label": "Embedded Web Server (RomPager)", "color": "orange"},
    "Allegro": {"label": "Embedded Web Server (Allegro)", "color": "orange"},
    "micro_httpd": {"label": "Embedded Web Server (micro_httpd)", "color": "orange"},
    "busybox": {"label": "BusyBox httpd", "color": "orange"},
    "Mongoose": {"label": "Embedded Web Server (Mongoose)", "color": "orange"},
    "CherryPy": {"label": "Python Web Server", "color": "slate"},
    "gSOAP": {"label": "gSOAP (Embedded)", "color": "orange"},
    "HP-Chai": {"label": "HP Printer Server", "color": "orange"},
    "HP HTTP": {"label": "HP Printer Server", "color": "orange"},
    "Lexmark": {"label": "Lexmark Printer", "color": "orange"},
    "EPSON": {"label": "Epson Printer", "color": "orange"},
    "CANON": {"label": "Canon Printer", "color": "orange"},
    "Brother": {"label": "Brother Printer", "color": "orange"},
    "Xerox": {"label": "Xerox Printer", "color": "orange"},
    "Ricoh": {"label": "Ricoh Printer", "color": "orange"},
    "AXIS": {"label": "AXIS Camera", "color": "orange"},
    "Hikvision": {"label": "Hikvision Camera", "color": "orange"},
    "Dahua": {"label": "Dahua Camera", "color": "orange"},
    "GoPro": {"label": "GoPro Camera", "color": "orange"},
    "Synology": {"label": "Synology NAS", "color": "orange"},
    "QNAP": {"label": "QNAP NAS", "color": "orange"},
    "NetApp": {"label": "NetApp Storage", "color": "orange"},
    "Drobo": {"label": "Drobo NAS", "color": "orange"},
    "ASUSTOR": {"label": "ASUSTOR NAS", "color": "orange"},
    "Cisco": {"label": "Cisco Device", "color": "orange"},
    "Juniper": {"label": "Juniper Device", "color": "orange"},
    "MikroTik": {"label": "MikroTik Router", "color": "orange"},
    "Ubiquiti": {"label": "Ubiquiti Device", "color": "orange"},
    "TP-LINK": {"label": "TP-Link Device", "color": "orange"},
    "D-Link": {"label": "D-Link Device", "color": "orange"},
    "NETGEAR": {"label": "Netgear Device", "color": "orange"},
    "Linksys": {"label": "Linksys Device", "color": "orange"},
    "ASUS": {"label": "ASUS Device", "color": "orange"},
    "Arris": {"label": "Arris Modem/Router", "color": "orange"},
    "Motorola": {"label": "Motorola Cable Modem", "color": "orange"},
    "Technicolor": {"label": "Technicolor Gateway", "color": "orange"},
    "Zyxel": {"label": "Zyxel Device", "color": "orange"},
    "Huawei": {"label": "Huawei Device", "color": "orange"},
    "ZTE": {"label": "ZTE Device", "color": "orange"},
    "Siemens": {"label": "Siemens Industrial", "color": "orange"},
    "Schneider": {"label": "Schneider Electric", "color": "orange"},
    "Rockwell": {"label": "Rockwell Automation", "color": "orange"},
    "Allen-Bradley": {"label": "Allen-Bradley PLC", "color": "orange"},
    "Modbus": {"label": "Modbus Device", "color": "orange"},
    "BACnet": {"label": "BACnet Device", "color": "orange"},
    "Omron": {"label": "Omron Industrial", "color": "orange"},
    "Mitsubishi": {"label": "Mitsubishi Electric", "color": "orange"},
    "FANUC": {"label": "FANUC Robot", "color": "orange"},
    "ABB": {"label": "ABB Industrial", "color": "orange"},
    "Honeywell": {"label": "Honeywell Controller", "color": "orange"},
    "Johnson": {"label": "Johnson Controls", "color": "orange"},
    "Tridium": {"label": "Tridium Niagara", "color": "orange"},
}


def _ip_to_int(ip_str: str) -> int:
    parts = ip_str.split(".")
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])


def _check_private_ip(ip_str: str) -> bool:
    try:
        ip_int = _ip_to_int(ip_str)
        if _ip_to_int("10.0.0.0") <= ip_int <= _ip_to_int("10.255.255.255"):
            return True
        if _ip_to_int("172.16.0.0") <= ip_int <= _ip_to_int("172.31.255.255"):
            return True
        if _ip_to_int("192.168.0.0") <= ip_int <= _ip_to_int("192.168.255.255"):
            return True
        if ip_str.startswith("127."):
            return True
    except Exception:
        pass
    return False


async def _fetch_title(html: str) -> str:
    m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
    return m.group(1).strip() if m else ""


async def _probe_device(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    base = f"https://{target}" if not target.startswith("http") else target

    try:
        resp = await client.get(base, follow_redirects=True, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"})
        headers = dict(resp.headers)
        server = headers.get("server", "")
        html = resp.text[:100000] if hasattr(resp, 'text') else ""
        title = await _fetch_title(html)

        matched_patterns = {}
        for device_type, info in IOT_DEVICE_PATTERNS.items():
            for pattern in info["patterns"]:
                if re.search(pattern, server, re.IGNORECASE) or \
                   re.search(pattern, html, re.IGNORECASE) or \
                   re.search(pattern, title, re.IGNORECASE):
                    matched_patterns[device_type] = info["label"]
                    break

        if title:
            for dtype, keywords in DEVICE_HTTP_TITLES.items():
                for kw in keywords:
                    if kw in title.lower():
                        matched_patterns[dtype] = f"Device Type: {dtype.title()}"
                        break

        for banner_key, banner_info in SERVICE_BANNER_PATTERNS.items():
            if banner_key.lower() in server.lower():
                findings.append(IntelligenceFinding(
                    entity=banner_info["label"],
                    type="Device Service Banner",
                    source="DeviceSearch",
                    confidence="High",
                    color=banner_info["color"],
                    threat_level="Standard Target",
                    status="Detected",
                    resolution=server,
                    raw_data=f"Server banner: {server}",
                    tags=["device", "banner", banner_key.lower().replace(" ", "-")]
                ))

        for dtype, label in matched_patterns.items():
            findings.append(IntelligenceFinding(
                entity=label,
                type=f"Device Detection: {label}",
                source="DeviceSearch",
                confidence="High" if server and any(p in server.lower() for p in IOT_DEVICE_PATTERNS[dtype]["patterns"]) else "Medium",
                color="orange",
                threat_level="Elevated Risk",
                status="Identified",
                resolution=base,
                raw_data=f"Device type: {label}, Server: {server}, Title: {title}",
                tags=["device", "iot", dtype, label.lower().replace(" ", "-")]
            ))

        if server:
            findings.append(IntelligenceFinding(
                entity=f"Server: {server[:200]}",
                type="Device Fingerprint (Server Header)",
                source="DeviceSearch",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Fingerprinted",
                raw_data=server[:500],
                tags=["device", "fingerprint"]
            ))

        if title:
            findings.append(IntelligenceFinding(
                entity=f"Page Title: {title[:200]}",
                type="Device Fingerprint (Title)",
                source="DeviceSearch",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                raw_data=title[:500],
                tags=["device", "fingerprint"]
            ))

        x_power = headers.get("x-powered-by", "")
        if x_power:
            findings.append(IntelligenceFinding(
                entity=f"X-Powered-By: {x_power[:100]}",
                type="Device Technology",
                source="DeviceSearch",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                raw_data=x_power[:500],
                tags=["device", "tech"]
            ))

        if "x-application-context" in headers:
            findings.append(IntelligenceFinding(
                entity=f"App Context: {headers['x-application-context']}",
                type="Device Technology",
                source="DeviceSearch",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                raw_data=headers.get("x-application-context", "")[:500],
                tags=["device", "tech"]
            ))

        www_auth = headers.get("www-authenticate", "")
        if www_auth:
            findings.append(IntelligenceFinding(
                entity=f"Auth: {www_auth[:200]}",
                type="Device Authentication Required",
                source="DeviceSearch",
                confidence="High",
                color="red",
                threat_level="Standard Target",
                status="Auth Required",
                raw_data=www_auth[:500],
                tags=["device", "auth"]
            ))

    except httpx.ConnectError:
        findings.append(IntelligenceFinding(
            entity=target,
            type="Device Probe (Connection Refused)",
            source="DeviceSearch",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status="Unreachable",
            raw_data=f"Could not connect to {target}:443",
            tags=["device", "unreachable"]
        ))
    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"Probe error: {str(e)[:100]}",
            type="DeviceSearch Error",
            source="DeviceSearch",
            confidence="Low",
            color="red",
            threat_level="Informational",
            raw_data=str(e)[:200],
            tags=["error"]
        ))

    return findings


async def _check_shodan_style(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        loop = asyncio.get_event_loop()
        try:
            ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(target))
        except Exception:
            return []

        url = f"https://internetdb.shodan.io/{ip}"
        resp = await client.get(url, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            ports = data.get("ports", [])
            vulns = data.get("vulns", [])
            cpes = data.get("cpes", [])
            hostnames = data.get("hostnames", [])

            iot_ports = {80, 443, 8080, 8443, 554, 37777, 37778, 8554, 8899, 23, 21, 161, 502, 44818}
            for port in ports:
                if port in iot_ports:
                    findings.append(IntelligenceFinding(
                        entity=f"{ip}:{port} (IoT/Industrial Port)",
                        type="Device Port (IoT/ICS)",
                        source="DeviceSearch",
                        confidence="High",
                        color="red",
                        threat_level="Elevated Risk",
                        status="Open",
                        resolution=f"Port {port}",
                        raw_data=f"Port {port} open on {ip} - potential IoT/ICS device",
                        tags=["device", "iot", "port"]
                    ))

            for cpe in cpes:
                cpe_lower = cpe.lower()
                for pattern, label in [("router", "Router"), ("camera", "Camera"),
                                        ("storage", "NAS/Storage"), ("printer", "Printer"),
                                        ("plc", "PLC"), ("scada", "SCADA"),
                                        ("embedded", "Embedded Device"),
                                        ("firewall", "Firewall"), ("switch", "Switch"),
                                        ("access_point", "Access Point"),
                                        ("modem", "Modem"), ("gateway", "Gateway"),
                                        ("phone", "VoIP Phone"), ("video", "Video Device")]:
                    if pattern in cpe_lower:
                        findings.append(IntelligenceFinding(
                            entity=f"{label}: {cpe[:100]}",
                            type="Device Identification (CPE)",
                            source="DeviceSearch",
                            confidence="High",
                            color="orange",
                            threat_level="Standard Target",
                            status="Identified",
                            raw_data=f"CPE: {cpe}",
                            tags=["device", pattern]
                        ))
                        break

            for vuln in vulns:
                findings.append(IntelligenceFinding(
                    entity=f"{vuln} on {ip}",
                    type="Device Vulnerability",
                    source="DeviceSearch",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    status="Vulnerable",
                    raw_data=f"Vulnerability {vuln} affects {ip}",
                    tags=["device", "cve", "vulnerability"]
                ))

            if ports:
                findings.append(IntelligenceFinding(
                    entity=f"{len(ports)} ports open on {ip}",
                    type="Device Open Ports Summary",
                    source="DeviceSearch",
                    confidence="High",
                    color="purple",
                    threat_level="Standard Target",
                    raw_data=f"Ports: {', '.join(map(str, sorted(ports)))}",
                    tags=["device", "ports", "summary"]
                ))

    except Exception:
        pass
    return findings


async def _check_default_paths(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    base = f"https://{target}" if not target.startswith("http") else target

    for path in DEVICE_DEFAULT_PATHS:
        try:
            url = f"{base.rstrip('/')}{path}"
            resp = await client.get(url, timeout=5.0,
                headers={"User-Agent": "Mozilla/5.0",
                         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"})
            if resp.status_code == 200 and path not in ("/", "/index.html"):
                html = resp.text[:3000].lower()
                device_signals = []
                for dtype, info in IOT_DEVICE_PATTERNS.items():
                    for pattern in info["patterns"]:
                        if re.search(pattern, html, re.IGNORECASE):
                            device_signals.append(info["label"])
                            break

                if device_signals:
                    findings.append(IntelligenceFinding(
                        entity=f"{' / '.join(set(device_signals))} on {path}",
                        type="Device Panel (Path)",
                        source="DeviceSearch",
                        confidence="Medium",
                        color="orange",
                        threat_level="Elevated Risk",
                        status="Discovered",
                        resolution=url,
                        raw_data=f"Path {path} returned 200 with device indicators",
                        tags=["device", "panel"]
                    ))

        except Exception:
            continue
    return findings


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    target = target.strip().lower()
    if target.startswith("http"):
        from urllib.parse import urlparse
        target = urlparse(target).netloc

    probe_findings = await _probe_device(target, client)
    findings.extend(probe_findings)

    shodan_findings = await _check_shodan_style(target, client)
    findings.extend(shodan_findings)

    path_findings = await _check_default_paths(target, client)
    findings.extend(path_findings)

    device_count = sum(1 for f in findings if "Device Detection" in f.type or "Device Port" in f.type)
    vuln_count = sum(1 for f in findings if "Vulnerability" in f.type or f.type == "Device Vulnerability")
    port_count = sum(1 for f in findings if "Port" in f.type)

    if device_count > 0 or vuln_count > 0 or port_count > 0:
        findings.append(IntelligenceFinding(
            entity=f"Device Search Complete: {device_count} devices, {vuln_count} vulns, {port_count} open ports",
            type="Device Search Summary",
            source="DeviceSearch",
            confidence="High",
            color="red" if vuln_count > 0 else ("orange" if device_count > 0 else "slate"),
            threat_level="High Risk" if vuln_count > 0 else ("Elevated Risk" if device_count > 0 else "Standard Target"),
            status="Complete",
            resolution=f"{len(findings)} total findings",
            raw_data=f"Devices: {device_count}, Vulns: {vuln_count}, Ports: {port_count}",
            tags=["device", "summary"]
        ))

    return findings
