import httpx
import socket
import asyncio
import math
from models import IntelligenceFinding
from urllib.parse import urlparse

WIGLE_API = "https://api.wigle.net/api/v2"

ENCRYPTION_TYPES = {
    "[WPA2-CCMP][ESS]": "WPA2 (AES)",
    "[WPA2-TKIP][ESS]": "WPA2 (TKIP)",
    "[WPA2-CCMP][WPA-PSK][ESS]": "WPA2/WPA Mixed",
    "[WPA-PSK-CCMP][ESS]": "WPA (AES)",
    "[WPA-PSK-TKIP][ESS]": "WPA (TKIP)",
    "[WEP][ESS]": "WEP",
    "[ESS]": "Open (No Encryption)",
    "[WPA2-EAP-CCMP][ESS]": "WPA2 Enterprise (AES)",
    "[WPA-EAP-TKIP][ESS]": "WPA Enterprise (TKIP)",
    "[WPA2-CCMP][WPS][ESS]": "WPA2 + WPS",
    "[WPA2-PSK-CCMP][WPS][ESS]": "WPA2-PSK + WPS",
    "[WPA2-CCMP][WPA-PSK-CCMP][WPS][ESS]": "WPA2/WPA + WPS",
    "[WPS][ESS]": "WPS Enabled",
    "[WPA2-CCMP][WPA-PSK-CCMP][ESS]": "WPA2/WPA Mixed",
    "[WPA2-PSK-CCMP][ESS]": "WPA2-PSK (AES)",
    "[WPA2-PSK-TKIP][ESS]": "WPA2-PSK (TKIP)",
}

MANUFACTURER_OUI = {}

OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"


def oui_to_manufacturer(bssid: str) -> str:
    if not bssid or len(bssid) < 8:
        return "Unknown"
    prefix = bssid[:8].upper().replace(":", "").replace("-", "")
    return MANUFACTURER_OUI.get(prefix, "Unknown")


async def load_oui_database(client: httpx.AsyncClient):
    global MANUFACTURER_OUI
    if MANUFACTURER_OUI:
        return
    try:
        resp = await client.get(OUI_URL, timeout=30.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        if resp.status_code == 200:
            for line in resp.text.split("\n"):
                if "(hex)" in line:
                    parts = line.split("(hex)")
                    if len(parts) >= 2:
                        oui = parts[0].strip().replace("-", "")
                        mfr = parts[1].strip()
                        if oui and mfr:
                            MANUFACTURER_OUI[oui] = mfr
    except Exception:
        pass


async def resolve_coords(target: str, client: httpx.AsyncClient) -> tuple | None:
    try:
        loop = asyncio.get_event_loop()
        ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(target))
        resp = await client.get(
            f"http://ip-api.com/json/{ip}?fields=lat,lon,country,city,org",
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
        )
        if resp.status_code == 200:
            data = resp.json()
            lat = data.get("lat")
            lon = data.get("lon")
            if lat and lon:
                return (lat, lon)
    except Exception:
        pass
    return None


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    try:
        await load_oui_database(client)

        lat_lon = await resolve_coords(domain, client)

        if not lat_lon:
            findings.append(IntelligenceFinding(
                entity=domain,
                type="WiGLE Geolocation",
                source="WiGLE",
                confidence="Low",
                color="slate",
                status="Could not geolocate target",
                resolution="Target IP geolocation failed",
            ))
            findings.append(IntelligenceFinding(
                entity=domain,
                type="WiGLE Search",
                source="WiGLE",
                confidence="Low",
                color="slate",
                status="No wireless data available",
            ))
            return findings

        lat, lon = lat_lon
        findings.append(IntelligenceFinding(
            entity=f"Geolocated {domain} at {lat:.4f}, {lon:.4f}",
            type="WiGLE Geolocation",
            source="WiGLE",
            confidence="Medium",
            color="blue",
            status="Coordinates resolved via IP geolocation",
            resolution=f"{lat:.4f}, {lon:.4f}",
        ))

        networks_found = None
        used_radius = None

        for radius_km in [1, 3, 8]:
            try:
                lat_delta = radius_km / 111.0
                cos_lat = abs(math.cos(math.radians(lat)))
                lon_delta = radius_km / (111.0 * cos_lat) if cos_lat > 0.01 else radius_km / 111.0

                params = {
                    "latrange1": lat - lat_delta,
                    "latrange2": lat + lat_delta,
                    "longrange1": lon - lon_delta,
                    "longrange2": lon + lon_delta,
                }

                resp = await client.get(
                    f"{WIGLE_API}/network/search",
                    params=params,
                    timeout=25.0,
                    headers={
                        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                        "Accept": "application/json",
                    },
                )

                if resp.status_code == 200:
                    data = resp.json()
                    results = data.get("results", [])
                    if results:
                        networks_found = results
                        used_radius = radius_km
                        total_results = data.get("totalResults", len(results))
                        break
                elif resp.status_code in (401, 403):
                    findings.append(IntelligenceFinding(
                        entity="WiGLE API authentication required",
                        type="WiGLE Auth Required",
                        source="WiGLE",
                        confidence="Low",
                        color="orange",
                        status="Free API key needed at wigle.net",
                        resolution="Register at https://wigle.net",
                    ))
                    return findings

            except Exception:
                continue

        if not networks_found:
            if not findings:
                findings.append(IntelligenceFinding(
                    entity=domain,
                    type="WiGLE Search",
                    source="WiGLE",
                    confidence="Low",
                    color="slate",
                    status="No wireless networks found nearby",
                    resolution=f"{lat:.4f}, {lon:.4f}",
                ))
            return findings

        total_networks = len(networks_found)
        total_results_display = total_networks

        if used_radius:
            findings.append(IntelligenceFinding(
                entity=f"{total_networks} wireless networks within ~{used_radius}km of {domain}",
                type="WiGLE Network Summary",
                source="WiGLE",
                confidence="High",
                color="purple",
                status=f"{total_networks} networks",
                resolution=f"{lat:.4f}, {lon:.4f}",
            ))

        ssids_seen = set()
        bssids_seen = set()
        open_networks = 0
        wpa_networks = 0
        wep_networks = 0
        wps_networks = 0
        hidden_networks = 0
        manufacturer_counts = {}

        for net in networks_found[:50]:
            ssid = net.get("ssid", "")
            bssid = net.get("netid", "")
            encryption = net.get("encryption", "")
            qos = net.get("qos", 0)
            frequency = net.get("freq", 0)
            channel = net.get("channel", 0)
            net_lat = net.get("trilat", 0)
            net_lon = net.get("trilong", 0)
            last_updt = net.get("lastupdt", "")
            country = net.get("country", "")
            signal = net.get("signal", 0)

            if not bssid:
                continue
            bssid_clean = bssid.upper().replace(":", "").replace("-", "")
            if bssid_clean in bssids_seen:
                continue
            bssids_seen.add(bssid_clean)

            if ssid:
                ssids_seen.add(ssid)

            is_open = encryption == "[ESS]" or encryption == "" or not encryption
            is_hidden = not ssid or "(Hidden)" in encryption
            has_wps = "WPS" in encryption
            is_wep = "WEP" in encryption
            is_enterprise = "EAP" in encryption

            if is_open:
                open_networks += 1
            elif is_wep:
                wep_networks += 1
            else:
                wpa_networks += 1
            if has_wps:
                wps_networks += 1
            if is_hidden:
                hidden_networks += 1

            mfr = oui_to_manufacturer(bssid)
            manufacturer_counts[mfr] = manufacturer_counts.get(mfr, 0) + 1

            if is_open and not is_hidden:
                color = "red"
            elif is_open:
                color = "orange"
            elif is_wep:
                color = "orange"
            elif has_wps:
                color = "yellow"
            else:
                color = "slate"

            threat = "Elevated Risk" if is_open else (
                "Elevated Risk" if is_wep or has_wps else "Informational"
            )

            loc_str = ""
            if net_lat and net_lon and net_lat != 0 and net_lon != 0:
                loc_str = f"{net_lat:.4f}, {net_lon:.4f}"

            resolution_str = f"BSSID: {bssid}"
            if loc_str:
                resolution_str = f"BSSID: {bssid}, Loc: {loc_str}"

            friendly_enc = ENCRYPTION_TYPES.get(encryption, encryption)
            type_label = f"Wireless Network: {friendly_enc}"

            status_parts = []
            if is_open:
                status_parts.append("Open")
            else:
                status_parts.append("Encrypted")
            if is_hidden:
                status_parts.append("Hidden")
            if has_wps:
                status_parts.append("WPS")
            if is_enterprise:
                status_parts.append("Enterprise")
            status_text = " | ".join(status_parts)

            raw_parts = [
                f"SSID: {ssid or '(hidden)'}",
                f"BSSID: {bssid}",
                f"Encryption: {encryption}",
                f"Channel: {channel}",
                f"Freq: {frequency}MHz",
                f"Signal: {signal}",
                f"QoS: {qos}",
                f"Manufacturer: {mfr}",
                f"Country: {country}",
            ]
            if last_updt:
                raw_parts.append(f"Last Seen: {last_updt}")

            tags_list = ["wireless"]
            if is_open:
                tags_list.append("open-network")
            if is_hidden:
                tags_list.append("hidden-network")
            if has_wps:
                tags_list.append("wps")
            if is_wep:
                tags_list.append("wep")
            if is_enterprise:
                tags_list.append("enterprise")

            findings.append(IntelligenceFinding(
                entity=ssid[:200] if ssid else f"(Hidden AP) {bssid[:16]}",
                type=type_label,
                source="WiGLE",
                confidence="Medium" if ssid else "Low",
                color=color,
                threat_level=threat,
                status=status_text,
                resolution=resolution_str,
                raw_data=", ".join(raw_parts),
                tags=tags_list,
            ))

        for mfr, count in sorted(
            manufacturer_counts.items(), key=lambda x: -x[1]
        )[:10]:
            if mfr != "Unknown" or count >= 3:
                pct = 100 * count / len(bssids_seen)
                entity_text = f"{mfr}: {count} APs ({pct:.0f}%)" if mfr != "Unknown" else f"Unknown: {count} APs ({pct:.0f}%)"
                findings.append(IntelligenceFinding(
                    entity=entity_text,
                    type="WiGLE Manufacturer Distribution",
                    source="WiGLE",
                    confidence="High",
                    color="slate",
                    status="Informational",
                    resolution=f"{lat:.4f}, {lon:.4f}",
                    raw_data=f"Manufacturer: {mfr}, APs: {count}, Pct: {pct:.0f}%",
                ))

        if bssids_seen:
            pct_open = 100 * open_networks / len(bssids_seen)
            pct_wpa = 100 * wpa_networks / len(bssids_seen)
            pct_wep = 100 * wep_networks / len(bssids_seen)

            sec_color = "red" if open_networks > 0 else "emerald"
            sec_threat = "Elevated Risk" if open_networks > 0 else "Informational"

            findings.append(IntelligenceFinding(
                entity=f"{open_networks} open ({pct_open:.0f}%), "
                       f"{wpa_networks} WPA ({pct_wpa:.0f}%), "
                       f"{wep_networks} WEP ({pct_wep:.0f}%), "
                       f"{wps_networks} WPS-enabled",
                type="WiGLE Security Distribution",
                source="WiGLE",
                confidence="High",
                color=sec_color,
                threat_level=sec_threat,
                status=f"{open_networks} open",
                resolution=f"{lat:.4f}, {lon:.4f}",
                raw_data=f"Open: {open_networks}, WPA: {wpa_networks}, "
                         f"WEP: {wep_networks}, WPS: {wps_networks}, "
                         f"Hidden: {hidden_networks}, Total: {len(bssids_seen)}",
            ))

            if hidden_networks > 0:
                findings.append(IntelligenceFinding(
                    entity=f"{hidden_networks} hidden (non-broadcasting) networks detected",
                    type="WiGLE Hidden Networks",
                    source="WiGLE",
                    confidence="Medium",
                    color="orange",
                    threat_level="Elevated Risk",
                    status=f"{hidden_networks} hidden",
                    resolution=f"{lat:.4f}, {lon:.4f}",
                    tags=["wireless", "hidden-network"],
                ))

            findings.append(IntelligenceFinding(
                entity=f"{len(ssids_seen)} unique SSIDs across {len(bssids_seen)} access points",
                type="WiGLE AP Statistics",
                source="WiGLE",
                confidence="High",
                color="purple",
                status=f"{len(bssids_seen)} APs",
                resolution=f"{lat:.4f}, {lon:.4f}",
            ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"WiGLE error: {str(e)[:150]}",
            type="WiGLE Error",
            source="WiGLE",
            confidence="Low",
            color="red",
            status="Error",
        ))

    return findings
