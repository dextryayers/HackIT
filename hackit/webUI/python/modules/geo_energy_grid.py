import re
import asyncio
from module_common import safe_fetch_json, make_finding, is_ip, resolve_ip

ENERGY_SECTOR_PATTERNS = {
    "Utility (Power Grid)": ["power", "electric", "utility", "grid", "energy", "transmission", "distribution"],
    "Oil & Gas": ["oil", "gas", "petroleum", "petro", "pipeline", "refiner", "lng", "upstream", "downstream", "midstream"],
    "Renewable Energy": ["solar", "wind", "renewable", "clean energy", "green energy", "hydro", "geothermal", "biomass"],
    "Nuclear": ["nuclear", "nucle", "atomic", "reactor"],
    "Water Utility": ["water", "wastewater", "aqua", "sewer", "waterworks"],
}

ICS_PROTOCOLS = {
    "Modbus": [502, 5502],
    "DNP3": [20000, 19999],
    "IEC 61850": [102, 2404, 2500],
    "IEC 104": [2404],
    "BACnet": [47808],
    "S7comm (Siemens)": [102],
    "Omron FINS": [9600],
    "EtherNet/IP (CIP)": [44818],
    "PROFINET": [34962, 34963, 34964],
    "OPC DA": [135],
    "OPC UA": [4840],
    "MQTT": [1883, 8883],
    "AMQP": [5671, 5672],
}

SCADA_VENDORS = {
    "Siemens": ["siemens", "sinumerik", "simatic"],
    "Schneider Electric": ["schneider", "modicon", "modbus"],
    "ABB": ["abb", "abb.com"],
    "Rockwell Automation": ["rockwell", "allen-bradley", "allenbradley"],
    "Emerson": ["emerson", "emerson.com"],
    "Honeywell": ["honeywell", "honeywell.com"],
    "Yokogawa": ["yokogawa", "yokogawa.com"],
    "GE Grid": ["ge grid", "ge energy", "general electric"],
    "Mitsubishi Electric": ["mitsubishi electric", "melsec"],
    "Omron": ["omron", "omron.com"],
    "OSIsoft": ["osisoft", "pi system", "osi"],
    "Inductive Automation": ["inductive automation", "ignition"],
}

SMART_GRID_PATTERNS = [
    "smart grid", "smart meter", "smart meter", "AMI", "advanced metering",
    "demand response", "SCADA", "substation", "feeder", "switchgear",
    "transformer", "relay", "breaker", "recloser", "phase", "synchrophasor",
    "PMU", "PDC", "WAMS", "WAMPAC",
]

EV_CHARGING_PATTERNS = {
    "ChargePoint": ["chargepoint.com", "chargepoint"],
    "Tesla Supercharger": ["tesla.com", "teslamotors", "supercharger"],
    "EVgo": ["evgo.com", "evgo"],
    "Electrify America": ["electrifyamerica.com", "electrify-america"],
    "Blink Charging": ["blinkcharging.com", "blink"],
    "EVBox": ["evbox.com", "evbox"],
    "Greenlots": ["greenlots.com", "greenlots"],
    "Ionity": ["ionity.eu", "ionity"],
    "Fastned": ["fastned.com", "fastned"],
    "BP Pulse": ["bppulse.com", "bppulse", "chargemaster"],
}

RENEWABLE_MONITORING = {
    "Solar (SMA)": ["sma.de", "sma", "sunny"],
    "Solar (Enphase)": ["enphase.com", "enphase"],
    "Solar (SolarEdge)": ["solaredge.com", "solaredge"],
    "Solar (Fronius)": ["fronius.com", "fronius"],
    "Wind (Vestas)": ["vestas.com", "vestas"],
    "Wind (Siemens Gamesa)": ["siemensgamesa.com", "siemensgamesa"],
    "Wind (GE Renewable)": ["ge renewable", "gerenewable"],
    "Hydro (Voith)": ["voith.com", "voith"],
    "Hydro (Andritz)": ["andritz.com", "andritz"],
}

async def _resolve_target(target: str) -> tuple:
    if is_ip(target):
        return target, True
    ip = resolve_ip(target)
    if ip:
        return ip, False
    return None, "DNS resolution failed"

async def _check_energy_org(ip: str, client) -> list:
    findings = []
    data = await safe_fetch_json(client, f"https://ipinfo.io/{ip}/json",
        headers={"User-Agent": "Mozilla/5.0"})
    if data:
        org = data.get("org", "").lower()
        for sector, keywords in ENERGY_SECTOR_PATTERNS.items():
            for kw in keywords:
                if kw in org:
                    findings.append(make_finding(
                        entity=sector,
                        ftype="Energy Sector Detection",
                        source="EnergyGridScanner",
                        confidence="High",
                        color="blue",
                        category="Geo / Network OSINT",
                        threat_level="Informational",
                        status="Identified",
                        resolution=ip,
                        raw_data=f"Energy sector: {sector} (keyword '{kw}' in org '{org[:80]}')",
                        tags=["energy", sector.lower().replace(" ", "-").replace("&", "and")]
                    ))
                    break
        for vendor, pats in SCADA_VENDORS.items():
            for p in pats:
                if p in org:
                    findings.append(make_finding(
                        entity=vendor,
                        ftype="SCADA / ICS Vendor",
                        source="EnergyGridScanner",
                        confidence="High",
                        color="orange",
                        category="Geo / Network OSINT",
                        threat_level="Informational",
                        status="Detected",
                        resolution=ip,
                        raw_data=f"SCADA vendor: {vendor} matched in org '{org[:80]}'",
                        tags=["scada", "ics", vendor.lower().replace(" ", "-")]
                    ))
                    break
        for name, pats in EV_CHARGING_PATTERNS.items():
            for p in pats:
                if p in org:
                    findings.append(make_finding(
                        entity=name,
                        ftype="EV Charging Network",
                        source="EnergyGridScanner",
                        confidence="High",
                        color="green",
                        category="Geo / Network OSINT",
                        threat_level="Informational",
                        status="Detected",
                        resolution=ip,
                        raw_data=f"EV charging network: {name}",
                        tags=["ev", "charging", name.lower().replace(" ", "-")]
                    ))
                    break
        for name, pats in RENEWABLE_MONITORING.items():
            for p in pats:
                if p in org:
                    findings.append(make_finding(
                        entity=name,
                        ftype="Renewable Energy Monitoring",
                        source="EnergyGridScanner",
                        confidence="High",
                        color="green",
                        category="Geo / Network OSINT",
                        threat_level="Informational",
                        status="Detected",
                        resolution=ip,
                        raw_data=f"Renewable monitoring: {name}",
                        tags=["renewable", name.lower().replace(" ", "-").replace("(", "").replace(")", "")]
                    ))
                    break

    return findings

async def _check_energy_dns(target: str) -> list:
    findings = []
    try:
        loop = asyncio.get_event_loop()
        try:
            answers = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'TXT'))
            for r in answers:
                txt = str(r).lower()
                for pat in SMART_GRID_PATTERNS:
                    if pat in txt:
                        findings.append(make_finding(
                            entity=f"Smart Grid Indicator: {pat}",
                            ftype="Smart Grid / SCADA DNS",
                            source="EnergyGridScanner",
                            confidence="Medium",
                            color="orange",
                            category="Geo / Network OSINT",
                            threat_level="Informational",
                            status="Suspected",
                            raw_data=f"Smart grid/SCADA pattern '{pat}' in TXT record: {txt[:100]}",
                            tags=["energy", "smart-grid", "scada"]
                        ))
                        break
        except Exception:
            pass
    except Exception:
        pass
    return findings

async def _list_ics_protocols() -> list:
    findings = []
    for proto, ports in ICS_PROTOCOLS.items():
        findings.append(make_finding(
            entity=f"{proto} (ports: {', '.join(str(p) for p in ports)})",
            ftype="ICS/SCADA Protocol Reference",
            source="EnergyGridScanner",
            confidence="Medium",
            color="slate",
            category="Geo / Network OSINT",
            threat_level="Informational",
            status="Referenced",
            raw_data=f"Industrial protocol: {proto}. Default ports: {', '.join(str(p) for p in ports)}",
            tags=["ics", "scada", proto.lower().replace(" ", "-").replace("/", "-")]
        ))
    return findings

async def crawl(target: str, client) -> list:
    findings = []
    target = target.strip().lower()
    if target.startswith("http"):
        from urllib.parse import urlparse
        target = urlparse(target).netloc

    ip, is_ip_flag = await _resolve_target(target)
    if ip is None:
        findings.append(make_finding(entity=f"DNS resolution failed: {target}", ftype="DNS Error", source="EnergyGridScanner", confidence="Low", color="red", category="Geo / Network OSINT", raw_data=str(is_ip_flag)[:200], tags=["error"]))
        return findings

    if not is_ip_flag:
        findings.append(make_finding(entity=f"{target} -> {ip}", ftype="DNS Resolution", source="EnergyGridScanner", confidence="High", color="slate", category="Geo / Network OSINT", threat_level="Informational", status="Resolved", resolution=ip, tags=["dns", "resolution"]))

    findings.extend(await _check_energy_org(ip, client))
    findings.extend(await _check_energy_dns(target))
    findings.extend(await _list_ics_protocols())

    energy_sectors = sum(1 for f in findings if "Energy Sector" in f.type)
    scada = sum(1 for f in findings if "SCADA" in f.type or "ICS" in f.type)
    ev = sum(1 for f in findings if "EV Charging" in f.type)
    renewable = sum(1 for f in findings if "Renewable" in f.type)

    findings.append(make_finding(entity=f"Energy sectors detected: {energy_sectors}", ftype="Energy Sector Count", source="EnergyGridScanner", confidence="Medium", color="purple", category="Geo / Network OSINT", tags=["energy", "summary"]))
    findings.append(make_finding(entity=f"SCADA/ICS vendors: {scada}", ftype="SCADA/ICS Count", source="EnergyGridScanner", confidence="Medium", color="purple", category="Geo / Network OSINT", tags=["energy", "summary"]))
    findings.append(make_finding(entity=f"EV networks: {ev}", ftype="EV Network Count", source="EnergyGridScanner", confidence="Medium", color="purple", category="Geo / Network OSINT", tags=["energy", "summary"]))
    findings.append(make_finding(entity=f"Renewable energy systems: {renewable}", ftype="Renewable Energy Count", source="EnergyGridScanner", confidence="Medium", color="purple", category="Geo / Network OSINT", tags=["energy", "summary"]))
    findings.append(make_finding(entity=f"Target: {target}", ftype="Energy Grid Target", source="EnergyGridScanner", confidence="High", color="slate", category="Geo / Network OSINT", tags=["energy", "target"]))
    findings.append(make_finding(entity=f"Total energy grid findings: {len(findings)}", ftype="Energy Grid Summary", source="EnergyGridScanner", confidence="Medium", color="purple", category="Geo / Network OSINT", tags=["energy", "summary"]))

    return findings
