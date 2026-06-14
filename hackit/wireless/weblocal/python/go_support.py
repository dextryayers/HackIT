"""
Go Engine Support Module — High-level Python API for hackit-worker.

Wraps all Go subcommands with structured output parsing, async helpers,
and real-time streaming for the FastAPI web backend.
"""

import os, re, json, subprocess, asyncio, time
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field, asdict


# ── Data Models ──────────────────────────────────────────────────────

@dataclass
class ChannelInfo:
    number: int
    frequency_mhz: int
    band: str          # "2.4GHz" | "5GHz"
    rssi: int
    noise: int = 0
    utilization: float = 0.0
    ap_count: int = 0


@dataclass
class ScanResult:
    channels: list[ChannelInfo] = field(default_factory=list)
    best_channel: Optional[ChannelInfo] = None
    raw_output: str = ""
    error: str = ""


@dataclass
class CrackProgress:
    tested: int = 0
    total: int = 0
    rate: float = 0.0
    current_password: str = ""
    found: bool = False
    key: str = ""
    ssid: str = ""
    elapsed_sec: float = 0.0


@dataclass
class InterfaceStatus:
    name: str = ""
    type_: str = ""
    mac: str = ""
    channel: int = 0
    frequency: int = 0
    txpower: int = 0
    signal: int = 0
    noise: int = 0
    is_monitor: bool = False
    ssid: str = ""
    bitrate: str = ""


@dataclass
class AdapterInfo:
    name: str
    mac: str
    driver: str
    is_monitor: bool
    channel: int
    frequency: int
    txpower: int
    signal: int
    type_: str
    phy: str = ""


@dataclass
class WpsPinResult:
    pin: str = ""
    candidates: list[str] = field(default_factory=list)
    error: str = ""


@dataclass
class SessionInfo:
    id: str = ""
    bssid: str = ""
    ssid: str = ""
    channel: int = 0
    hash_file: str = ""
    hash_type: str = ""
    created_at: str = ""
    status: str = ""


# ── Go Engine Wrapper ────────────────────────────────────────────────

class GoEngine:
    """High-level wrapper around the hackit-worker binary."""

    def __init__(self, go_bin: Optional[str] = None):
        self._go_bin = go_bin or self._find_go_bin()
        self._ready = self._go_bin is not None and os.path.isfile(self._go_bin)

    @staticmethod
    def _find_go_bin() -> Optional[str]:
        """Auto-discover hackit-worker binary."""
        candidates = [
            Path(__file__).resolve().parent.parent.parent
            / "go_workers" / "hackit-worker",
            Path(__file__).resolve().parent.parent.parent
            / "go_workers" / "bin" / "hackit-worker",
        ]
        for p in candidates:
            if p.is_file():
                return str(p.resolve())
        # Try PATH
        for path_dir in os.environ.get("PATH", "").split(os.pathsep):
            p = Path(path_dir) / "hackit-worker"
            if p.is_file():
                return str(p.resolve())
        return None

    @property
    def ready(self) -> bool:
        return self._ready

    def _run(self, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
        """Run a Go worker command synchronously."""
        if not self._ready:
            raise RuntimeError("Go engine binary not found")
        cmd = [self._go_bin] + list(args)
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )

    async def _run_async(self, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
        """Run a Go worker command asynchronously."""
        if not self._ready:
            raise RuntimeError("Go engine binary not found")
        cmd = [self._go_bin] + list(args)
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            raise
        return subprocess.CompletedProcess(
            args=cmd, returncode=proc.returncode or 0,
            stdout=stdout.decode() if stdout else "",
            stderr=stderr.decode() if stderr else "",
        )

    # ── Scanning ─────────────────────────────────────────────────────

    def scan_dual_band(self, iface: str) -> ScanResult:
        """Scan both 2.4GHz and 5GHz bands, return structured channel data."""
        result = ScanResult()
        try:
            proc = self._run("dual-band", iface)
            result.raw_output = proc.stdout
            result.channels = self._parse_dual_band(proc.stdout)
            if result.channels:
                result.best_channel = max(result.channels, key=lambda c: -c.rssi if c.rssi < 0 else c.rssi)
        except Exception as e:
            result.error = str(e)
        return result

    async def scan_dual_band_async(self, iface: str) -> ScanResult:
        """Async scan both bands."""
        result = ScanResult()
        try:
            proc = await self._run_async("dual-band", iface)
            result.raw_output = proc.stdout
            result.channels = self._parse_dual_band(proc.stdout)
            if result.channels:
                result.best_channel = max(result.channels, key=lambda c: -c.rssi if c.rssi < 0 else c.rssi)
        except Exception as e:
            result.error = str(e)
        return result

    def scan_spectrum(self, iface: str) -> ScanResult:
        """Full spectrum analysis including best channel recommendation."""
        result = ScanResult()
        try:
            proc = self._run("spectrum", iface)
            result.raw_output = proc.stdout
            result.channels = self._parse_dual_band(proc.stdout)
            if result.channels:
                result.best_channel = max(result.channels, key=lambda c: c.utilization if c.utilization else 0)
        except Exception as e:
            result.error = str(e)
        return result

    @staticmethod
    def _parse_dual_band(output: str) -> list[ChannelInfo]:
        """Parse Go dual-band output into structured channel list.

        Expected format:
            Ch 6  | 2437 MHz | 2.4GHz | RSSI: -45
        """
        channels = []
        for line in output.splitlines():
            m = re.search(
                r'Ch\s*(\d+)\s*\|\s*(\d+)\s*MHz\s*\|\s*(\S+)\s*\|\s*RSSI:\s*(-?\d+)',
                line
            )
            if m:
                channels.append(ChannelInfo(
                    number=int(m.group(1)),
                    frequency_mhz=int(m.group(2)),
                    band=m.group(3),
                    rssi=int(m.group(4)),
                ))
        return channels

    # ── Cracking ─────────────────────────────────────────────────────

    def crack_wpa(self, hashfile: str, wordlist: str,
                  on_progress: Optional[callable] = None) -> CrackProgress:
        """Run WPA dictionary crack with optional progress callback."""
        result = CrackProgress()
        try:
            proc = subprocess.Popen(
                [self._go_bin, "crack", hashfile, wordlist],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            for line in proc.stdout:
                result = self._parse_crack_line(line, result)
                if on_progress:
                    on_progress(result)
            proc.wait()
        except Exception as e:
            result.error = str(e)
        return result

    @staticmethod
    def _parse_crack_line(line: str, state: CrackProgress) -> CrackProgress:
        """Parse Go crack output lines."""
        line = line.strip()
        m = re.search(r'\[.*?\]\s*Tested\s*([\d,]+)\s*/\s*([\d,]+)\s*\(([\d.]+)\s*ps\)', line)
        if m:
            state.tested = int(m.group(1).replace(",", ""))
            state.total = int(m.group(2).replace(",", ""))
            state.rate = float(m.group(3))
            return state
        m = re.search(r'\[.*?\]\s*KEY FOUND:\s*(.+)', line)
        if m:
            state.found = True
            state.key = m.group(1).strip()
            return state
        m = re.search(r'KEY FOUND:\s*(.+)', line)
        if m:
            state.found = True
            state.key = m.group(1).strip()
        return state

    # ── Interface Control ────────────────────────────────────────────

    def get_adapter_info(self, iface: str) -> AdapterInfo:
        """Get detailed adapter information."""
        adapter = AdapterInfo(name=iface, mac="", driver="",
                              is_monitor=False, channel=0, frequency=0,
                              txpower=0, signal=0, type_="", phy="")
        try:
            proc = self._run("adapter-info", iface)
            self._parse_adapter_info(proc.stdout, adapter)
        except Exception as e:
            adapter.driver = str(e)
        return adapter

    @staticmethod
    def _parse_adapter_info(output: str, adapter: AdapterInfo):
        for line in output.splitlines():
            l = line.strip()
            if "MAC:" in l:
                adapter.mac = l.split("MAC:")[-1].strip()
            elif "driver:" in l:
                adapter.driver = l.split("driver:")[-1].strip()
            elif "monitor" in l.lower():
                adapter.is_monitor = "yes" in l.lower() or "true" in l.lower()
            elif "channel:" in l:
                try: adapter.channel = int(l.split(":")[-1].strip())
                except: pass
            elif "txpower" in l.lower():
                try: adapter.txpower = int(l.split(":")[-1].strip().replace("dBm",""))
                except: pass
            elif "type:" in l.lower():
                adapter.type_ = l.split(":")[-1].strip()
            elif "phy:" in l.lower():
                adapter.phy = l.split(":")[-1].strip()

    def get_status(self, iface: str) -> InterfaceStatus:
        """Get current interface operational status."""
        status = InterfaceStatus(name=iface)
        try:
            proc = self._run("status", iface)
            for line in proc.stdout.splitlines():
                l = line.strip()
                if "MAC" in l:
                    status.mac = l.split(":")[-1].strip()
                elif "channel" in l.lower():
                    try: status.channel = int(l.split(":")[-1].strip())
                    except: pass
                elif "frequency" in l.lower():
                    try: status.frequency = int(re.search(r'(\d+)', l).group(1))
                    except: pass
                elif "txpower" in l.lower():
                    try: status.txpower = int(re.search(r'(\d+)', l).group(1))
                    except: pass
                elif "signal" in l.lower():
                    try: status.signal = int(re.search(r'(-?\d+)', l).group(1))
                    except: pass
                elif "ssid" in l.lower():
                    status.ssid = l.split(":")[-1].strip()
                elif "monitor" in l.lower():
                    status.is_monitor = "yes" in l.lower() or "true" in l.lower()
        except Exception:
            pass
        return status

    def set_mode(self, iface: str, mode: str) -> tuple[bool, str]:
        """Switch interface mode (monitor/managed)."""
        try:
            proc = self._run("mode", iface, mode)
            ok = proc.returncode == 0 and "error" not in proc.stdout.lower()
            return ok, proc.stdout.strip() or f"Switched {iface} to {mode}"
        except Exception as e:
            return False, str(e)

    def set_channel(self, iface: str, channel: int) -> tuple[bool, str]:
        """Set interface channel."""
        try:
            proc = self._run("channel", iface, str(channel))
            ok = proc.returncode == 0
            return ok, proc.stdout.strip() or f"Channel {channel} set on {iface}"
        except Exception as e:
            return False, str(e)

    def set_txpower(self, iface: str, power: int) -> tuple[bool, str]:
        """Set transmit power in dBm."""
        try:
            proc = self._run("txpower", iface, str(power))
            ok = proc.returncode == 0
            return ok, proc.stdout.strip() or f"TX power set to {power}dBm on {iface}"
        except Exception as e:
            return False, str(e)

    def set_mac(self, iface: str, action: str) -> tuple[bool, str]:
        """Change MAC address (random/restore/<custom_mac>)."""
        try:
            proc = self._run("mac", iface, action)
            ok = proc.returncode == 0
            return ok, proc.stdout.strip() or f"MAC {action} on {iface}"
        except Exception as e:
            return False, str(e)

    # ── WPS ──────────────────────────────────────────────────────────

    def wps_pin(self, bssid: str) -> WpsPinResult:
        """Compute WPS PIN and candidates from BSSID."""
        result = WpsPinResult()
        try:
            proc = self._run("wps-pin", bssid)
            result.pin, result.candidates = self._parse_wps_pin(proc.stdout)
        except Exception as e:
            result.error = str(e)
        return result

    @staticmethod
    def _parse_wps_pin(output: str) -> tuple[str, list[str]]:
        pin = ""
        candidates = []
        for line in output.splitlines():
            l = line.strip()
            if "PIN:" in l.upper():
                pin = l.split(":")[-1].strip()
            elif l.startswith("WPS PIN candidate:"):
                c = l.split(":")[-1].strip()
                if c:
                    candidates.append(c)
            elif l.startswith("Candidates:"):
                parts = l.split(":")[-1].strip()
                if parts:
                    candidates = [c.strip() for c in parts.split(",") if c.strip()]
        return pin, candidates

    # ── WEP ──────────────────────────────────────────────────────────

    def wep_crack(self, pcap_file: str) -> tuple[bool, str]:
        """Crack WEP key from captured pcap."""
        try:
            proc = self._run("wep-crack", pcap_file)
            key = ""
            for line in proc.stdout.splitlines():
                m = re.search(r'KEY\s*(?:FOUND|IS)[:\s]+(.+)', line, re.IGNORECASE)
                if m:
                    key = m.group(1).strip()
            found = bool(key)
            return found, key or proc.stdout.strip()
        except Exception as e:
            return False, str(e)

    # ── Packet Generation ────────────────────────────────────────────

    def packet_gen(self, iface: str, frame_type: str, ssid: str = "HackIT") -> tuple[bool, str]:
        """Generate and inject 802.11 frames.

        Frame types: auth, assoc-req, probe-resp, null-data
        """
        try:
            proc = self._run("packet-gen", iface, frame_type, ssid)
            ok = proc.returncode == 0
            return ok, proc.stdout.strip() or f"{frame_type} frame sent on {iface}"
        except Exception as e:
            return False, str(e)

    # ── Session Management ───────────────────────────────────────────

    def list_sessions(self) -> list[SessionInfo]:
        """List all saved sessions."""
        sessions = []
        try:
            proc = self._run("session")
            sessions = self._parse_sessions(proc.stdout)
        except Exception:
            pass
        return sessions

    def create_session(self, bssid: str, ssid: str, channel: int,
                       filepath: str, hash_type: str) -> tuple[bool, str]:
        """Create a new session."""
        try:
            proc = self._run("session-create", bssid, ssid,
                             str(channel), filepath, hash_type)
            ok = proc.returncode == 0
            return ok, proc.stdout.strip() or f"Session created for {ssid}"
        except Exception as e:
            return False, str(e)

    @staticmethod
    def _parse_sessions(output: str) -> list[SessionInfo]:
        sessions = []
        current = SessionInfo()
        for line in output.splitlines():
            l = line.strip()
            if not l:
                if current.id:
                    sessions.append(current)
                    current = SessionInfo()
                continue
            for prefix, attr in [("ID:", "id"), ("BSSID:", "bssid"),
                                  ("SSID:", "ssid"), ("Channel:", "channel"),
                                  ("Hash:", "hash_file"), ("Type:", "hash_type"),
                                  ("Created:", "created_at"), ("Status:", "status")]:
                if l.startswith(prefix):
                    val = l[len(prefix):].strip()
                    if attr == "channel":
                        try: setattr(current, attr, int(val))
                        except: pass
                    else:
                        setattr(current, attr, val)
                    break
        if current.id:
            sessions.append(current)
        return sessions

    # ── ARP Spoof ────────────────────────────────────────────────────

    def arp_spoof(self, target: str, gateway: str, timeout: int = 120) -> tuple[bool, str]:
        """Launch ARP spoofing attack between target and gateway."""
        try:
            proc = subprocess.run(
                [self._go_bin, "arp-spoof", target, gateway],
                capture_output=True, text=True, timeout=timeout
            )
            ok = proc.returncode == 0
            return ok, proc.stdout.strip() or f"ARP spoof {target} ↔ {gateway}"
        except subprocess.TimeoutExpired:
            return False, "ARP spoof timed out"
        except Exception as e:
            return False, str(e)


# ── Convenience API for Web Backend ──────────────────────────────────

_engine: Optional[GoEngine] = None


def get_engine() -> GoEngine:
    global _engine
    if _engine is None:
        _engine = GoEngine()
    return _engine


async def quick_scan(iface: str = "wlan0", bridge=None) -> dict:
    """Multi-engine quick scan returning structured results for the web UI.

    Args:
        iface: wireless interface name
        bridge: optional EngineBridge instance for Rust engine access
    """
    engine = get_engine()
    aps = {}
    engines_used = []
    errors = []
    engine_outputs: dict[str, str] = {}

    # 1. Python nmcli scan
    try:
        raw = subprocess.check_output(
            ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "dev", "wifi", "list"],
            text=True, timeout=10
        )
        from hackit.wireless.data_parser import DataParser
        for ap in DataParser.parse_nmcli_wifi(raw):
            bssid = ap["bssid"]
            if bssid not in aps:
                try: sig = int(ap.get("signal", "0").replace("%", ""))
                except: sig = 0
                aps[bssid] = {
                    "ssid": ap.get("ssid", "<hidden>"), "bssid": bssid,
                    "channel": ap.get("channel", "?"), "signal": sig,
                    "security": ap.get("security", "?"), "source": "Python (nmcli)"
                }
        engines_used.append("Python (nmcli)")
    except Exception as e:
        errors.append(f"Python: {e}")

    # 2. Go dual-band scan
    try:
        scan = await engine.scan_dual_band_async(iface)
        engine_outputs["Go"] = scan.raw_output[:2000] if scan.raw_output else ""
        if scan.channels:
            engines_used.append("Go")
            for ch in scan.channels:
                for bssid, ap in aps.items():
                    if str(ap.get("channel", "")) == str(ch.number):
                        if "Go" not in ap.get("source", ""):
                            ap["source"] += " + Go"
                        ap["signal_go"] = ch.rssi
                        break
        elif scan.raw_output:
            engines_used.append("Go")
    except Exception as e:
        errors.append(f"Go: {e}")

    # 3. Rust aggressive scan (via bridge if provided)
    if bridge is not None:
        try:
            from hackit.wireless.engine_bridge import EngineBuildError
            try:
                rust_bin = bridge._ensure_rust()
                proc = subprocess.run(
                    [rust_bin, "aggressive-scan", "--interface", iface, "--band", "both"],
                    capture_output=True, text=True, timeout=20
                )
                engine_outputs["Rust"] = proc.stdout[:2000] if proc.stdout else ""
                if proc.stdout:
                    engines_used.append("Rust")
                    for line in proc.stdout.splitlines():
                        if line.strip().startswith("{"):
                            try:
                                ev = json.loads(line)
                                if ev.get("event") == "beacon":
                                    bssid = ev.get("bssid", "").upper()
                                    clean = bssid.replace(":", "")
                                    for ap_bssid, ap in aps.items():
                                        b_clean = ap_bssid.replace("\\:", "").replace(":", "")
                                        if clean and clean == b_clean:
                                            if ev.get("signal"):
                                                ap["signal_rust"] = int(ev["signal"])
                                            if ev.get("encrypt"):
                                                ap["security"] = ev["encrypt"]
                                            if "Rust" not in ap.get("source", ""):
                                                ap["source"] += " + Rust"
                                            break
                            except json.JSONDecodeError:
                                pass
            except EngineBuildError:
                pass
        except Exception as e:
            errors.append(f"Rust: {e}")

    # Clean BSSID display
    for ap in aps.values():
        ap["bssid"] = ap["bssid"].replace("\\:", ":")

    sorted_aps = sorted(aps.values(), key=lambda x: x.get("signal_rust", x.get("signal", 0)), reverse=True)
    return {
        "aps": sorted_aps,
        "count": len(sorted_aps),
        "engines": engines_used,
        "engine_outputs": engine_outputs,
        "errors": errors,
        "status": "ok" if sorted_aps else ("partial" if errors else "empty"),
    }


# ── Utility ──────────────────────────────────────────────────────────

def format_signal_bar(signal: int, is_dbm: bool = True) -> str:
    """Generate a signal strength bar (Unicode)."""
    if is_dbm:
        bars = 5 if signal >= -50 else 4 if signal >= -60 else 3 if signal >= -70 else 2 if signal >= -80 else 1
    else:
        bars = 5 if signal >= 80 else 4 if signal >= 60 else 3 if signal >= 40 else 2 if signal >= 20 else 1
    return "█" * bars + "░" * (5 - bars)


def estimate_distance(signal_dbm: int) -> str:
    """Rough distance estimate from signal strength."""
    if signal_dbm >= -30: return "<5m"
    elif signal_dbm >= -50: return "5-10m"
    elif signal_dbm >= -60: return "10-30m"
    elif signal_dbm >= -70: return "30-50m"
    elif signal_dbm >= -80: return "50-100m"
    else: return "100m+"
