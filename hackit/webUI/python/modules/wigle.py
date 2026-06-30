import httpx
import asyncio
import json
import re
from datetime import datetime
from typing import List, Optional
from models import IntelligenceFinding

WIGLE_API_BASE = "https://api.wigle.net/api/v2"
WIGLE_SEARCH_URL = f"{WIGLE_API_BASE}/network/search"

async def wigle_search(query: str, client: httpx.AsyncClient) -> Optional[dict]:
    try:
        params = {}
        if re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', query):
            params["ip"] = query
        elif re.match(r'^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$', query):
            params["netid"] = query
        elif re.match(r'^[0-9a-fA-F]{12}$', query):
            params["netid"] = ":".join(query[i:i+2] for i in range(0, 12, 2))
        else:
            params["ssid"] = query

        resp = await client.get(WIGLE_SEARCH_URL, params=params, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return None

async def wigle_network_details(netid: str, client: httpx.AsyncClient) -> Optional[dict]:
    try:
        url = f"{WIGLE_API_BASE}/network/{netid}"
        resp = await client.get(url, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return None

async def wigle_statistics(query: str, client: httpx.AsyncClient) -> Optional[dict]:
    try:
        url = f"{WIGLE_API_BASE}/stats/network"
        params = {"ssid": query} if not re.match(r'^[0-9.]+$', query) else {"ip": query}
        resp = await client.get(url, params=params, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return None

WIFI_ENCRYPTION_TYPES = {
    "WPA2": ["wpa2", "ccmp", "rsn"],
    "WPA3": ["wpa3", "sae", "owe"],
    "WPA": ["wpa", "tkip"],
    "WEP": ["wep"],
    "Open": ["open", "none", ""],
}

WIFI_VENDORS = {
    "00:00:00": "Xerox",
    "00:01:02": "3Com",
    "00:01:03": "AMD",
    "00:01:05": "Cisco",
    "00:01:0C": "Cisco",
    "00:01:24": "Dell",
    "00:02:2D": "Intel",
    "00:03:93": "Apple",
    "00:04:23": "Netgear",
    "00:05:5D": "HP",
    "00:06:5B": "D-Link",
    "00:0C:29": "VMware",
    "00:0E:35": "Huawei",
    "00:14:22": "Dell",
    "00:15:17": "Huawei",
    "00:15:5D": "Microsoft",
    "00:16:36": "Raspberry Pi",
    "00:17:88": "Huawei",
    "00:18:F8": "Samsung",
    "00:1A:11": "Google",
    "00:1C:B3": "Cisco-Linksys",
    "00:1E:4C": "Samsung",
    "00:1F:01": "Panasonic",
    "00:1F:1F": "ZTE",
    "00:1F:45": "Zyxel",
    "00:1F:90": "Nokia",
    "00:1F:C6": "HTC",
    "00:22:69": "Nintendo",
    "00:23:7D": "Motorola",
    "00:23:DF": "Sony",
    "00:24:FE": "LG",
    "00:25:9C": "Hon Hai",
    "00:25:90": "Apple",
    "00:26:08": "Aruba",
    "00:26:5E": "Ruckus",
    "00:26:75": "Netgear",
    "00:26:AB": "Asus",
}

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip()

    search_results = await wigle_search(t, client)
    stats_results = await wigle_statistics(t, client)

    if search_results:
        total = search_results.get("totalResults", 0)
        results = search_results.get("results", [])
        if total > 0:
            findings.append(IntelligenceFinding(
                entity=f"WiGLE search returned {total} networks",
                type="WiGLE: Search Summary",
                source="WiGLE",
                confidence="Medium",
                color="slate",
                status=f"{total} networks found",
                resolution=t,
                tags=["wigle", "wifi", "search"]
            ))

            for network in results[:15]:
                ssid = network.get("ssid", "Hidden")
                netid = network.get("netid", "")
                encryption = network.get("encryption", "Unknown")
                channel = network.get("channel", "?")
                trilat = network.get("trilat", "")
                trilong = network.get("trilong", "")
                firsttime = network.get("firsttime", "")
                lasttime = network.get("lasttime", "")

                findings.append(IntelligenceFinding(
                    entity=f"Network: {ssid} ({netid}) on ch.{channel} - {encryption}",
                    type="WiGLE: Network",
                    source="WiGLE",
                    confidence="Medium",
                    color="slate",
                    status=f"Chan {channel}",
                    resolution=t,
                    tags=["wigle", "wifi", ssid]
                ))

                if netid:
                    oui = netid[:8]
                    vendor = WIFI_VENDORS.get(oui, "")
                    if vendor:
                        findings.append(IntelligenceFinding(
                            entity=f"Vendor OUI: {oui} -> {vendor}",
                            type="WiGLE: Vendor Identification",
                            source="WiGLE",
                            confidence="Medium",
                            color="slate",
                            status=f"Vendor: {vendor}",
                            resolution=t,
                            tags=["wigle", "vendor", vendor]
                        ))

                if trilat and trilong:
                    findings.append(IntelligenceFinding(
                        entity=f"Location: {trilat}, {trilong}",
                        type="WiGLE: Geolocation",
                        source="WiGLE",
                        confidence="Medium",
                        color="slate",
                        status="Positioned",
                        resolution=t,
                        tags=["wigle", "geo"]
                    ))

    if stats_results:
        findings.append(IntelligenceFinding(
            entity="WiGLE statistics available",
            type="WiGLE: Statistics",
            source="WiGLE",
            confidence="Low",
            color="slate",
            status="Retrieved",
            resolution=t,
            tags=["wigle", "wifi", "statistics"]
        ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity="No WiGLE data found",
            type="WiGLE: Complete",
            source="WiGLE",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Not Found",
            resolution=t,
            tags=["wigle", "empty"]
        ))

    return findings
