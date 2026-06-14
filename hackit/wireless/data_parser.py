import json, re, os
from typing import Optional, Any


class DataParser:

    # ── Generic telemetry from Rust/Go engines ──────────────────

    @staticmethod
    def parse_telemetry(raw_line: str) -> Optional[dict]:
        if not raw_line or not raw_line.strip():
            return None
        line = raw_line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                pass
        if line.startswith("[RUST-"):
            return DataParser._parse_rust_protocol(line)
        if line.startswith("[GO-"):
            return DataParser._parse_go_protocol(line)
        if line.startswith("[C-"):
            return DataParser._parse_c_protocol(line)
        return {"raw": line, "event": "unknown"}

    @staticmethod
    def _parse_rust_protocol(line: str) -> dict:
        if "BSSID:" in line:
            return DataParser._parse_beacon(line)
        if "EAPOL" in line or "HANDSHAKE" in line or "handshake" in line:
            return DataParser._parse_eapol(line)
        if "DEAUTH" in line or "deauth" in line:
            return {"event": "deauth", "raw": line}
        if "PROBE" in line:
            return {"event": "probe", "raw": line}
        if "WPA3" in line or "SAE" in line:
            return {"event": "wpa3", "raw": line}
        if "WPS" in line:
            return {"event": "wps", "raw": line}
        if "PMKID" in line:
            return {"event": "pmkid", "raw": line}
        m = re.search(r'HOST:\s*ip=(\S+)\s*mac=(\S+)\s*hostname=(\S+)\s*latency=(\S+)', line)
        if m:
            return {"event": "host", "ip": m.group(1), "mac": m.group(2).upper(),
                    "hostname": m.group(3), "latency": m.group(4)}
        m = re.search(r'PORT OPEN:\s*(\S+)', line)
        if m:
            return {"event": "port_open", "target": m.group(1)}
        return {"event": "rust_log", "raw": line}

    @staticmethod
    def _parse_go_protocol(line: str) -> dict:
        if "SUCCESS" in line or "SUCCESS" in line.upper():
            return {"event": "go_success", "raw": line}
        if "ERROR" in line or "FAILED" in line:
            return {"event": "go_error", "raw": line}
        m = re.search(r'CHANNEL:\s*(\d+)\s+(\d+ MHz)\s+(\S+)\s+RSSI:\s*(-?\d+)', line)
        if m:
            return {"event": "channel", "number": int(m.group(1)), "frequency": m.group(2),
                    "band": m.group(3), "rssi": int(m.group(4))}
        m = re.search(r'Tested:\s*(\d+)\s+passwords.*Rate:\s*([\d.]+)\s+p/s', line)
        if m:
            return {"event": "crack_progress", "tested": int(m.group(1)), "rate": float(m.group(2))}
        m = re.search(r'WPA KEY FOUND:\s*\[\s*(\S+)\s*\]', line)
        if m:
            return {"event": "key_found", "key": m.group(1)}
        return {"event": "go_log", "raw": line}

    @staticmethod
    def _parse_c_protocol(line: str) -> dict:
        return {"event": "c_log", "raw": line}

    # ── Beacon frame parsing ───────────────────────────────────

    @staticmethod
    def _parse_beacon(line: str) -> dict:
        result = {"event": "beacon", "raw": line}
        m = re.search(r'SSID:\s*"([^"]*)"', line)
        if m:
            result["ssid"] = m.group(1)
        m = re.search(r'BSSID:\s*([0-9A-Fa-f:]{17})', line)
        if m:
            result["bssid"] = m.group(1).upper()
        m = re.search(r'CH:\s*(\d+)', line, re.I)
        if m:
            result["channel"] = int(m.group(1))
        m = re.search(r'SIGNAL:\s*(-?\d+)', line, re.I)
        if m:
            result["signal"] = int(m.group(1))
        m = re.search(r'ENCRYPT:\s*(\S+)', line, re.I)
        if m:
            result["encrypt"] = m.group(1)
        m = re.search(r'RATES:\s*\[([^\]]+)\]', line)
        if m:
            result["rates"] = m.group(1).split(",")
        m = re.search(r'WPS:\s*(\S+)', line, re.I)
        if m:
            result["wps"] = m.group(1)
        return result

    @staticmethod
    def _parse_eapol(line: str) -> dict:
        result = {"event": "eapol_handshake", "raw": line}
        m = re.search(r'STEP\s*(\d+)', line, re.I)
        if m:
            step = int(m.group(1))
            result["step"] = step
            MSGS = {1: "ANonce", 2: "SNonce+MIC", 3: "GTK Install", 4: "Confirmed"}
            result["message"] = MSGS.get(step, f"Step {step}")
        m = re.search(r'BSSID:\s*([0-9A-Fa-f:]{17})', line)
        if m:
            result["bssid"] = m.group(1).upper()
        m = re.search(r'STA:\s*([0-9A-Fa-f:]{17})', line, re.I)
        if m:
            result["station"] = m.group(1).upper()
        m = re.search(r'REPLAY:\s*(\S+)', line, re.I)
        if m:
            result["replay_counter"] = m.group(1)
        return result

    # ── Airodump-ng CSV parsing ────────────────────────────────

    @staticmethod
    def parse_airodump_csv(contents: str) -> list[dict]:
        aps = []
        in_aps = False
        in_sta = False
        for line in contents.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("BSSID,"):
                in_aps = True
                in_sta = False
                continue
            if line.startswith("Station MAC,"):
                in_aps = False
                in_sta = True
                continue
            if in_aps:
                parts = DataParser._csv_split(line)
                if len(parts) >= 14:
                    aps.append({
                        "bssid": parts[0].strip().upper(),
                        "first_seen": parts[1].strip(),
                        "last_seen": parts[2].strip(),
                        "channel": parts[3].strip(),
                        "speed": parts[4].strip(),
                        "privacy": parts[5].strip(),
                        "cipher": parts[6].strip(),
                        "auth": parts[7].strip(),
                        "power": parts[8].strip(),
                        "beacons": parts[9].strip(),
                        "iv": parts[10].strip(),
                        "lan_ip": parts[11].strip(),
                        "id_length": parts[12].strip(),
                        "essid": parts[13].strip().strip('"'),
                    })
        return aps

    @staticmethod
    def _csv_split(line: str) -> list[str]:
        parts = []
        current = ""
        in_quotes = False
        for ch in line:
            if ch == '"':
                in_quotes = not in_quotes
            elif ch == ',' and not in_quotes:
                parts.append(current)
                current = ""
            else:
                current += ch
        parts.append(current)
        return parts

    @staticmethod
    def extract_bssid(data: dict) -> Optional[str]:
        if data and data.get("event") == "beacon":
            return data.get("bssid")
        if data and data.get("event") == "eapol_handshake":
            return data.get("bssid")
        return None

    # ── OS command parsers ─────────────────────────────────────

    @staticmethod
    def parse_iw_dev(output: str) -> list[dict]:
        interfaces = []
        curr = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Interface"):
                if curr:
                    interfaces.append(curr)
                curr = {"name": line.split()[-1], "channel": 0, "signal_dbm": -70,
                        "is_monitor": False, "supports_2ghz": True, "supports_5ghz": False}
            elif "mac" in line.lower() and curr:
                parts = line.split()
                if len(parts) >= 2 and len(parts[-1]) == 17:
                    curr["mac"] = parts[-1].upper()
            elif "channel" in line.lower() and curr:
                try:
                    curr["channel"] = int(line.split()[-1])
                except ValueError:
                    pass
            elif "type" in line.lower() and curr:
                curr["is_monitor"] = "monitor" in line.lower()
            elif "txpower" in line.lower() and curr:
                try:
                    curr["txpower"] = int(line.split()[-2]) if len(line.split()) >= 2 else 20
                except ValueError:
                    curr["txpower"] = 20
        if curr:
            interfaces.append(curr)
        return interfaces

    @staticmethod
    def parse_nmcli_wifi(output: str) -> list[dict]:
        aps = []
        for line in output.splitlines():
            parts = line.split(":")
            if len(parts) >= 10:
                aps.append({
                    "ssid": parts[0] or "<hidden>",
                    "bssid": ":".join(parts[1:7]).upper(),
                    "signal": f"{parts[7]}%" if len(parts) > 7 else "0%",
                    "channel": parts[8] if len(parts) > 8 else "?",
                    "security": ":".join(parts[9:]) if len(parts) > 9 else "Unknown",
                })
        return aps

    @staticmethod
    def parse_netsh_wlan(output: str) -> list[dict]:
        aps = []
        current: dict[str, Any] = {}
        for line in output.splitlines():
            line = line.strip()
            if not line:
                if current:
                    aps.append(current)
                    current = {}
                continue
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            key = key.strip().lower()
            val = val.strip()
            if key == "ssid":
                if current and "bssid" in current:
                    aps.append(current)
                current = {"ssid": val or "<hidden>"}
            elif key == "bssid":
                current["bssid"] = val.upper()
            elif "signal" in key:
                try:
                    pct = int(val.replace("%", ""))
                    current["signal"] = f"{int(pct/2)-100} dBm"
                except ValueError:
                    current["signal"] = val
            elif "channel" in key:
                current["channel"] = val
            elif "authentication" in key:
                current["auth"] = val
            elif "cipher" in key:
                current["cipher"] = val
        if current:
            aps.append(current)
        return aps

    @staticmethod
    def parse_tshark_handshake(pcap_path: str) -> list[dict]:
        import subprocess
        try:
            cmd = [
                "tshark", "-r", pcap_path, "-Y", "eapol",
                "-T", "fields",
                "-e", "wlan.sa", "-e", "wlan.da", "-e", "wlan.bssid",
                "-e", "eapol.keydes-info", "-e", "eapol.keydes.replay_counter"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            handshakes = []
            for line in result.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 4:
                    handshakes.append({
                        "station": parts[0].upper() if parts[0] else "",
                        "ap": parts[1].upper() if parts[1] else "",
                        "bssid": parts[2].upper() if parts[2] else "",
                        "key_info": parts[3],
                        "replay_counter": parts[4] if len(parts) > 4 else "",
                    })
            return handshakes
        except (FileNotFoundError, subprocess.CalledProcessError):
            return []

    @staticmethod
    def signal_to_dbm(signal_str: str) -> int:
        try:
            if "dBm" in signal_str:
                return int(signal_str.replace("dBm", "").strip())
            if "%" in signal_str:
                pct = int(signal_str.replace("%", "").strip())
                return int(pct / 2 - 100)
            return int(signal_str)
        except (ValueError, TypeError):
            return -100

    @staticmethod
    def json_pretty(data: Any) -> str:
        return json.dumps(data, indent=2, default=str)
