import os, sys, subprocess, json, asyncio, time
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent.parent.parent  # hackit/
WIRELESS = BASE / "wireless"
WEBLOCAL = WIRELESS / "weblocal"

sys.path.insert(0, str(WIRELESS))
sys.path.insert(0, str(WIRELESS.parent))  # hackit/

try:
    import importlib
    # Import from hackit.wireless.executor to avoid name collision
    mod = importlib.import_module("hackit.wireless.executor")
    HackITWirelessExecutor = mod.HackITWirelessExecutor
    EXECUTOR = HackITWirelessExecutor()
    from hackit.wireless.engine_bridge import EngineBridge
    BRIDGE = EXECUTOR.bridge
except Exception as e:
    EXECUTOR = None
    BRIDGE = None


ATTACKS = {
    "deauth": {
        "label": "Deauth Attack",
        "desc": "Send 802.11 deauthentication frames to disconnect clients from an AP",
        "icon": "zap",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "bssid", "label": "BSSID", "type": "text", "placeholder": "AA:BB:CC:DD:EE:FF"},
            {"name": "station", "label": "Station MAC", "type": "text", "optional": True, "placeholder": "FF:FF:FF:FF:FF:FF"},
            {"name": "count", "label": "Packet count", "type": "number", "default": "10", "optional": True},
            {"name": "reason", "label": "Reason code", "type": "number", "default": "7", "optional": True},
        ],
        "cmd": "deauth {iface} {bssid} {station} --count {count} --reason {reason}"
    },
    "beacon-flood": {
        "label": "Beacon Flood",
        "desc": "Flood the airwaves with fake beacon frames to confuse clients",
        "icon": "radio",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "ssid", "label": "SSID name", "type": "text", "default": "FreeWiFi"},
            {"name": "count", "label": "Frame count", "type": "number", "default": "500", "optional": True},
            {"name": "wpa2", "label": "WPA2 flag", "type": "checkbox", "optional": True},
        ],
        "cmd": "beacon-flood {iface} --ssid {ssid} --count {count} --wpa2"
    },
    "probe-flood": {
        "label": "Probe Flood",
        "desc": "Flood probe requests to overwhelm APs and monitoring tools",
        "icon": "activity",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "count", "label": "Frame count", "type": "number", "default": "1000", "optional": True},
            {"name": "random-mac", "label": "Random source MAC", "type": "checkbox", "optional": True},
        ],
        "cmd": "probe-flood {iface} --count {count} --random-mac"
    },
    "eviltwin": {
        "label": "Evil Twin",
        "desc": "Clone a legitimate SSID and broadcast a rogue AP with captive portal",
        "icon": "copy",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "ssid", "label": "Target SSID to clone", "type": "text"},
            {"name": "channel", "label": "Channel", "type": "number", "default": "6", "optional": True},
            {"name": "captive", "label": "Captive portal", "type": "checkbox", "optional": True},
        ],
        "cmd": "eviltwin {iface} {ssid} --channel {channel} --captive"
    },
    "rogue": {
        "label": "Rogue AP",
        "desc": "Broadcast a fake access point with custom SSID",
        "icon": "wifi",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "ssid", "label": "SSID name", "type": "text", "default": "FreeWiFi"},
            {"name": "channel", "label": "Channel", "type": "number", "default": "6", "optional": True},
        ],
        "cmd": "rogue {iface} --ssid {ssid} --channel {channel}"
    },
    "arp-spoof": {
        "label": "ARP Spoof",
        "desc": "Poison ARP cache of target and gateway to intercept traffic",
        "icon": "share-2",
        "params": [
            {"name": "target", "label": "Target IP", "type": "text", "placeholder": "192.168.1.100"},
            {"name": "gateway", "label": "Gateway IP", "type": "text", "placeholder": "192.168.1.1"},
            {"name": "timeout", "label": "Timeout (sec)", "type": "number", "default": "120", "optional": True},
        ],
        "cmd": "arp-spoof {target} {gateway} --timeout {timeout}"
    },
    "handshake": {
        "label": "Handshake Capture",
        "desc": "Capture WPA/WPA2 4-way handshake by deauthenticating a client",
        "icon": "shield",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "bssid", "label": "BSSID", "type": "text", "placeholder": "AA:BB:CC:DD:EE:FF"},
            {"name": "timeout", "label": "Timeout (sec)", "type": "number", "default": "60", "optional": True},
            {"name": "deauth", "label": "Deauth trigger", "type": "checkbox", "optional": True},
        ],
        "cmd": "capture handshake {iface} {bssid} --timeout {timeout} --deauth"
    },
    "pmkid": {
        "label": "PMKID Capture",
        "desc": "Capture PMKID hash from WPA2/WPA3 APs for offline cracking",
        "icon": "key",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "bssid", "label": "BSSID (optional)", "type": "text", "optional": True},
            {"name": "timeout", "label": "Timeout (sec)", "type": "number", "default": "30", "optional": True},
        ],
        "cmd": "capture pmkid {iface} {bssid} --timeout {timeout}"
    },
    "wps-pixie": {
        "label": "WPS PixieDust",
        "desc": "PixieDust attack against WPS-enabled AP to recover PIN",
        "icon": "unlock",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "bssid", "label": "BSSID", "type": "text", "placeholder": "AA:BB:CC:DD:EE:FF"},
            {"name": "timeout", "label": "Timeout (sec)", "type": "number", "default": "180", "optional": True},
        ],
        "cmd": "wps pixie {iface} {bssid} --timeout {timeout}"
    },
    "wps-bruteforce": {
        "label": "WPS Bruteforce",
        "desc": "Bruteforce WPS PIN of a target AP",
        "icon": "hash",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "bssid", "label": "BSSID", "type": "text", "placeholder": "AA:BB:CC:DD:EE:FF"},
            {"name": "start", "label": "Start PIN", "type": "text", "optional": True},
        ],
        "cmd": "wps bruteforce {iface} {bssid} --start {start}"
    },
    "wep-arp": {
        "label": "WEP ARP Replay",
        "desc": "Capture ARP packets and replay to generate WEP IVs",
        "icon": "repeat",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "bssid", "label": "BSSID", "type": "text", "placeholder": "AA:BB:CC:DD:EE:FF"},
            {"name": "count", "label": "Packet count", "type": "number", "default": "5000", "optional": True},
        ],
        "cmd": "wep arp-replay {iface} {bssid} --count {count}"
    },
    "wep-chopchop": {
        "label": "WEP ChopChop",
        "desc": "Decrypt WEP packets byte-by-byte without the key",
        "icon": "scissors",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "bssid", "label": "BSSID", "type": "text", "placeholder": "AA:BB:CC:DD:EE:FF"},
        ],
        "cmd": "wep chopchop {iface} {bssid}"
    },
    "crack": {
        "label": "WPA Cracking",
        "desc": "Dictionary attack against captured handshake/PMKID hash",
        "icon": "terminal",
        "params": [
            {"name": "hashfile", "label": "Hash file (.hc22000)", "type": "text"},
            {"name": "wordlist", "label": "Wordlist path", "type": "text"},
            {"name": "rules", "label": "Rules file", "type": "text", "optional": True},
        ],
        "cmd": "crack {hashfile} {wordlist} --rules {rules}"
    },
    "crawl": {
        "label": "AP Scan",
        "desc": "Scan all access points in range with detailed info",
        "icon": "search",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "timeout", "label": "Timeout (sec)", "type": "number", "default": "15", "optional": True},
            {"name": "band", "label": "Band", "type": "select", "options": ["2ghz", "5ghz", "both"], "optional": True},
        ],
        "cmd": "crawl {iface} --timeout {timeout} --band {band}"
    },
    "client-hunt": {
        "label": "Client Hunt",
        "desc": "Enumerate clients connected to a target AP",
        "icon": "users",
        "params": [
            {"name": "iface", "label": "Interface", "type": "text", "default": "wlan0"},
            {"name": "bssid", "label": "BSSID", "type": "text", "placeholder": "AA:BB:CC:DD:EE:FF"},
            {"name": "timeout", "label": "Timeout (sec)", "type": "number", "default": "30", "optional": True},
        ],
        "cmd": "client-hunt {iface} {bssid} --timeout {timeout}"
    },
}


def _exec_cmd(cmd: str) -> dict:
    proc = subprocess.run(
        ["python3", "-c", cmd],
        capture_output=True, text=True, timeout=120
    )
    return {"stdout": proc.stdout, "stderr": proc.stderr, "code": proc.returncode}


def _detect_ifaces() -> list:
    if EXECUTOR:
        return EXECUTOR.detect_wireless_adapters()
    return []


def _list_plugins(typ: str = "") -> list:
    plugin_dir = WIRELESS / "plugins" / typ / "scripts"
    if plugin_dir.exists():
        return sorted(f.stem for f in plugin_dir.glob("*.lua" if typ == "lua" else "*.rb"))
    return []
