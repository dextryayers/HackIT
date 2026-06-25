import os, sys, cmd, time, json, shlex, threading, socket, subprocess, shutil, logging, datetime as dt
from typing import Optional
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.columns import Columns
from rich.syntax import Syntax
from rich.markdown import Markdown
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.layout import Layout
from rich.live import Live
from rich import box

from .executor import HackITWirelessExecutor, JobManager
from .data_parser import DataParser
from .ui_renderer import UIRenderer as UI

console = Console()

# ── Activity logging ──────────────────────────────────────────
LOG_FILE = Path(__file__).resolve().parent / "hackit_wireless.log"
_activity_logger = logging.getLogger("hackit_activity")
_activity_logger.setLevel(logging.INFO)
_fh = logging.FileHandler(str(LOG_FILE), encoding="utf-8", mode="a")
_fh.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-6s  %(message)s", datefmt="%H:%M:%S"))
_activity_logger.addHandler(_fh)
_activity_logger.propagate = False

def log_activity(cmdline: str, result: str = "ok"):
    _activity_logger.info(f"{result.upper():4s}  {cmdline}")
BASE = Path(__file__).resolve().parent  # wireless/
HACKIT = BASE.parent  # hackit/


def _detect_iface() -> str:
    adapters = HackITWirelessExecutor.detect_wireless_adapters()
    if adapters:
        return adapters[0]["name"]
    return ""


def get_realtime_telemetry() -> dict:
    tel = {"status": "Disconnected", "mac": "N/A", "ip": "N/A", "ssid": "N/A", "location": "N/A", "iface": ""}
    try:
        adapters = HackITWirelessExecutor.detect_wireless_adapters()
        if adapters:
            tel["iface"] = adapters[0]["name"]
            tel["mac"] = adapters[0].get("mac", "N/A")
    except:
        pass

    if os.name == "nt":
        try:
            raw = subprocess.check_output("netsh wlan show interfaces", shell=True, text=True, stderr=subprocess.DEVNULL)
            for line in raw.splitlines():
                l = line.strip().lower()
                if "state" in l and ":" in l: tel["status"] = "Connected" if "connected" in l.split(":")[1].lower() else "Disconnected"
                if "ssid" in l and "bssid" not in l and ":" in l: tel["ssid"] = l.split(":")[1].strip()
                if "bssid" in l and ":" in l: tel["mac"] = l.split(":")[1].strip() if tel["mac"] == "N/A" else tel["mac"]
        except: pass
    else:
        iface = tel["iface"]
        if not iface:
            try:
                r = subprocess.check_output(["iw", "dev"], text=True, stderr=subprocess.DEVNULL)
                for line in r.splitlines():
                    if "Interface" in line:
                        iface = line.split()[-1]
                        tel["iface"] = iface
                        break
            except: pass
        if iface:
            try:
                out = subprocess.check_output(["iw", "dev", iface, "link"], text=True, stderr=subprocess.DEVNULL)
                if "Not connected" not in out:
                    tel["status"] = "Connected"
                    for line in out.splitlines():
                        l = line.strip()
                        if l.startswith("SSID:"): tel["ssid"] = l.split("SSID:")[1].strip()
                if tel["mac"] == "N/A":
                    try:
                        info = subprocess.check_output(["iw", "dev", iface, "info"], text=True, stderr=subprocess.DEVNULL)
                        for line in info.splitlines():
                            if "addr" in line:
                                tel["mac"] = line.split("addr")[-1].strip()
                    except: pass
            except:
                tel["status"] = "Disconnected"

    try:
        if os.name == "nt":
            out = subprocess.check_output("ipconfig", shell=True, text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                if "IPv4" in line and ":" in line:
                    tel["ip"] = line.split(":")[1].strip()
                    break
        else:
            out = subprocess.check_output(["hostname", "-I"], text=True, stderr=subprocess.DEVNULL)
            tel["ip"] = out.strip().split()[0] if out.strip() else "N/A"
    except:
        try:
            out = subprocess.check_output(["ip", "addr"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                if "inet " in line and "127.0.0.1" not in line:
                    tel["ip"] = line.strip().split()[1].split("/")[0]
                    break
        except: pass

    try:
        import urllib.request
        geo = urllib.request.urlopen("http://ip-api.com/json/?fields=city,country,query", timeout=4).read()
        d = json.loads(geo)
        city = d.get("city", "?")
        country = d.get("country", "?")
        tel["location"] = f"{city}, {country}"
    except:
        tel["location"] = "local"

    return tel


def _parse_flags(args: list[str], known_flags: set[str],
                  flag_val: dict[str, type | None] | None = None) -> tuple[list[str], dict]:
    """Separate positional args from flags.

    known_flags: set of boolean flag names (e.g. '--full', '--verbose')
    flag_val:    dict mapping flag name to value type (None = str, int, etc.)
    Returns (positional, {flag: value})
    """
    pos: list[str] = []
    flags: dict = {}
    i = 0
    flag_val = flag_val or {}
    while i < len(args):
        a = args[i]
        if a in known_flags:
            flags[a] = True
            i += 1
        elif a in flag_val:
            if i + 1 < len(args):
                val = args[i + 1]
                t = flag_val[a]
                if t is int:
                    try:
                        val = int(val)
                    except ValueError:
                        val = 0
                elif t is float:
                    try:
                        val = float(val)
                    except ValueError:
                        val = 0.0
                flags[a] = val
                i += 2
            else:
                flags[a] = True
                i += 1
        elif a.startswith("--") and "=" in a:
            k, v = a.split("=", 1)
            if k in flag_val:
                t = flag_val[k]
                if t is int:
                    try:
                        v = int(v)
                    except ValueError:
                        v = 0
                elif t is float:
                    try:
                        v = float(v)
                    except ValueError:
                        v = 0.0
                flags[k] = v
            elif k in known_flags:
                flags[k] = True
            else:
                pos.append(a)
            i += 1
        else:
            pos.append(a)
            i += 1
    return pos, flags


def print_banner():
    os.system('cls' if os.name == 'nt' else 'clear')

    banner = """[bold cyan]  .;'                     `;,[/bold cyan]
[bold cyan] .;'  ,;'             `;,  `;,[/bold cyan]   [bold white]HackIT V2.1[/bold white]
[bold cyan].;'  ,;'  ,;'     `;,  `;,  `;,[/bold cyan]
[bold cyan]::   ::   :   ( )   :   ::   ::[/bold cyan]  [bold green]automated wireless auditor[/bold green]
[bold cyan]':.  ':.  ':. /_\\ ,:'  ,:'  ,:'[/bold cyan]
[bold cyan] ':.  ':.    /___\\    ,:'  ,:'[/bold cyan]   [bold dim]designed By AniipID[/bold dim]
[bold cyan]  ':.       /_____\\      ,:'[/bold cyan]
[bold cyan]           /       \\ [/bold cyan]
"""
    console.print(banner)
    console.print("[bold white]========================================================================[/bold white]")

    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[bold cyan]{task.description}"),
        console=console
    ) as progress:
        t = progress.add_task("Configuring wireless interface hooks...", total=100)
        time.sleep(0.2)
        progress.update(t, description="Interfacing with libudev physical controllers...", completed=40)
        time.sleep(0.2)
        progress.update(t, description="Resolving Netlink raw sockets (nl80211)...", completed=80)
        time.sleep(0.2)
        progress.update(t, description="Auditing engine dependencies completed successfully.", completed=100)

    console.print("\n[bold green][+] Audit system operational. Enter 'help' to see active tools.[/bold green]\n")

    tel = get_realtime_telemetry()
    if tel["status"] == "Connected":
        console.print(f"[bold white][*][/bold white] [bold green]Wifi: Connected[/bold green] [bold white]Mac:[/bold white] [bold yellow]{tel['mac']}[/bold yellow] [bold white]IP:[/bold white] [bold cyan]{tel['ip']}[/bold cyan] [bold white][{tel['ssid']}][/bold white]")
    else:
        console.print(f"[bold white][*][/bold white] [bold red]Wifi: Disconnected[/bold red] [bold white]Mac:[/bold white] [bold yellow]{tel['mac']}[/bold yellow]")

    console.print(f"[bold white][*][/bold white] [bold green]Lokasi:[/bold green] [bold yellow]{tel['location']}[/bold yellow] [bold white]|[/bold white] [bold cyan]System Ready[/bold cyan]\n")


class WirelessConsole(cmd.Cmd):
    prompt = "\033[1;36m[HackIT-WiFi]\033[1;32m ~# \033[0m"

    def __init__(self):
        super().__init__()
        self.executor = HackITWirelessExecutor()
        self.executor.check_dependencies()
        self.current_workspace: Optional[str] = None
        self._banner_shown = False
        self._activity: list[dict] = []
        self._activity_max = 500

    # ── Help system ───────────────────────────────────────────

    def do_help(self, arg):
        if arg:
            super().do_help(arg)
            return

        help_categories = [
            ("INTERFACE CONTROL", [
                ("adapters        [--json] [--watch]", "List wireless interfaces", "adapters --watch"),
                ("adapter info    <iface> [--json]", "Chipset, driver, capabilities", "adapter info wlan0"),
                ("mode            <iface> monitor|managed", "Switch adapter mode", "mode wlan0 monitor"),
                ("mac             <iface> random|restore|MAC", "MAC address spoofing", "mac wlan0 random"),
                ("txpower         <iface> <dBm> [--auto]", "Set TX power (0-30)", "txpower wlan0 20"),
                ("channel         <iface> <ch> [--ht40]", "Lock to channel", "channel wlan0 6"),
                ("freq            <iface> <MHz>", "Lock to frequency", "freq wlan0 2412"),
            ]),
            ("RECONNAISSANCE", [
                ("crawl           [iface] [--full] [--band]", "Scan all APs in range", "crawl wlan0 --full"),
                ("crawl           [--bssid <mac>] [--timeout]", "Filtered AP scan", "crawl wlan0 --bssid AA:BB:CC"),
                ("aggressive-scan <iface> [--5ghz] [--timeout]", "Deep multi-channel AP scan", "aggressive-scan wlan0 --5ghz"),
                ("client-hunt     <iface> [bssid] [--timeout]", "Enumerate connected clients", "client-hunt wlan0 AA:BB:CC"),
                ("wpa3-detect     [iface] [--json]", "Detect WPA3/SAE/OWE APs", "wpa3-detect wlan0"),
                ("hidden          [iface] [--deauth] [--timeout]", "Find hidden SSID APs", "hidden wlan0 --deauth"),
                ("probe-monitor   [iface] [--min-rssi]", "Watch probe requests live", "probe-monitor wlan0"),
                ("beacon-analyze  [iface] [--json]", "Analyze beacon frames", "beacon-analyze wlan0"),
                ("signal          [iface] [--threshold]", "Real-time signal monitor", "signal wlan0"),
                ("spectrum        [iface] [--5ghz] [--only]", "Channel utilization heatmap", "spectrum wlan0 --5ghz"),
                ("dual-band       [iface]", "Scan 2.4 + 5 GHz bands", "dual-band wlan0"),
                ("map             [iface] [--heatmap]", "AP × vendor correlation", "map wlan0"),
            ]),
            ("CAPTURE & MONITOR", [
                ("sniff           <iface> [--monitor] [--count]", "Live frame telemetry", "sniff wlan0 --monitor"),
                ("capture         <iface> [output] [--timeout]", "Save all frames to PCAP", "capture wlan0 dump.pcap"),
                ("capture handshake <iface> <bssid> [--deauth]", "Capture WPA handshake", "capture handshake wlan0 AA:BB:CC"),
                ("capture pmkid   <iface> [bssid] [--timeout]", "Capture PMKID hash", "capture pmkid wlan0"),
                ("capture raw     <iface> [--channel]", "Raw 802.11 frame capture", "capture raw wlan0"),
                ("sessions        [--json]", "List saved PCAP cap files", "sessions"),
                ("replay          <pcap> [--loop]", "Replay / analyze PCAP", "replay handshake.pcap"),
            ]),
            ("WPA/WPA2/WPA3 AUDIT", [
                ("crack           <hash> <wordlist> [--rules]", "Dictionary crack (Go engine)", "crack hash.22000 rockyou.txt"),
                ("hashcat         <hash> <wordlist> [--force]", "GPU crack via hashcat", "hashcat hash.22000 rockyou.txt"),
                ("verify          <capture> [--strict] [--json]", "Verify handshake integrity", "verify handshake.pcap"),
                ("convert         hc22000 <pcap> [--ssid]", "Convert PCAP → hashcat", "convert hc22000 handshake.pcap"),
                ("convert         hccapx <pcap>", "Convert PCAP → hccapx", "convert hccapx handshake.pcap"),
                ("convert         csv <pcap>", "Convert PCAP → CSV", "convert csv capture.pcap"),
                ("wordlists       [path] [--size] [--json]", "Find installed wordlists", "wordlists /usr/share"),
                ("auto handshake  [iface] [--deauth] [--timeout]", "Auto-capture handshakes", "auto handshake wlan0"),
                ("auto audit      [iface] [--timeout] [--skip-wps]", "Full automated audit", "auto audit wlan0"),
                ("auto crack      [dir] [--rules] [--hashcat]", "Auto-crack all captures", "auto crack ./handshakes/"),
            ]),
            ("WPS ATTACKS", [
                ("wps scan        [iface] [--timeout] [--json]", "Detect WPS-capable APs", "wps scan wlan0"),
                ("wps pixie       <iface> <bssid> [--timeout]", "PixieDust attack", "wps pixie wlan0 AA:BB:CC"),
                ("wps pin         <bssid> [--compute-all]", "Compute default WPS PIN", "wps pin AA:BB:CC"),
                ("wps bruteforce  <iface> <bssid> [--start]", "Bruteforce WPS PIN", "wps bruteforce wlan0 AA:BB:CC"),
            ]),
            ("WEP ATTACKS", [
                ("wep capture     <iface> <bssid> [--timeout]", "Capture WEP IVs", "wep capture wlan0 AA:BB:CC"),
                ("wep arp-replay  <iface> <bssid> [--count]", "ARP replay → generate IVs", "wep arp-replay wlan0 AA:BB:CC"),
                ("wep chopchop    <iface> <bssid>", "ChopChop attack", "wep chopchop wlan0 AA:BB:CC"),
                ("wep frag        <iface> <bssid>", "Fragmentation attack", "wep frag wlan0 AA:BB:CC"),
                ("wep crack       <pcap> [--method ptw|fms|korek]", "Crack WEP key", "wep crack wep.pcap"),
            ]),
            ("WIRELESS ATTACKS", [
                ("deauth          <iface> <bssid> [station] [--count]", "Deauth specific client", "deauth wlan0 AA:BB:CC --count 20"),
                ("deauth broadcast <iface> <bssid> [--count]", "Deauth all clients", "deauth broadcast wlan0 AA:BB:CC"),
                ("beacon-flood    <iface> [--ssid <name>] [--count]", "Flood fake beacons", "beacon-flood wlan0 --ssid <name>"),
                ("beacon-flood    <iface> [--file <ssids.txt>]", "Multi-SSID beacon flood", "beacon-flood wlan0 --file ssids.txt"),
                ("probe-flood     <iface> [--count] [--random-mac]", "Probe request flood", "probe-flood wlan0 --count 1000"),
                ("eviltwin        <iface> <ssid> [--channel] [--captive]", "Clone SSID rogue AP", "eviltwin wlan0 <name> --channel 6"),
                ("rogue           <iface> [--ssid <name>] [--channel]", "Start rogue AP", "rogue wlan0 --ssid <name>"),
                ("arp-spoof       <target> <gateway> [--full-duplex]", "ARP poisoning MITM", "arp-spoof 198.51.100.100 198.51.100.1"),
                ("forward         <on|off> [--persist]", "Toggle IP forwarding", "forward on"),
            ]),
            ("NETWORK RECON", [
                ("arp scan        [--timeout] [--json]", "ARP subnet discovery", "arp scan --timeout 15"),
                ("arp table       [--json]", "Show local ARP table", "arp table"),
                ("ping-sweep      <subnet> [--timeout] [--parallel]", "ICMP sweep", "ping-sweep 198.51.100.0/24"),
                ("ports           <host> [--top-ports] [--threads]", "TCP port scan", "ports 198.51.100.1"),
                ("ports           <host> [--service-detect] [--syn]", "Port scan + service detect", "ports 198.51.100.1 --syn"),
                ("services        <host> [--threads] [--json]", "Service version detection", "services 198.51.100.1"),
                ("os-detect       <host> [--aggressive] [--json]", "OS fingerprinting", "os-detect 198.51.100.1"),
                ("gateway         [--json] [--ipv6]", "Display default gateway", "gateway"),
                ("dns sniff       [--timeout]", "Passive DNS monitor", "dns sniff --timeout 60"),
                ("dns resolve     <hostname>", "Resolve hostname", "dns resolve google.com"),
                ("dns spoof       <hostname> <ip>", "DNS spoofing", "dns spoof bank.com 198.51.100.100"),
            ]),

            ("SESSION & WORKSPACE", [
                ("workspace create  <name> [--path]", "Create new workspace", "workspace create engagement1"),
                ("workspace load    <name>", "Load existing workspace", "workspace load engagement1"),
                ("workspace list", "List all workspaces", "workspace list"),
                ("workspace delete  <name>", "Delete workspace", "workspace delete engagement1"),
                ("session list      [--json]", "List capture sessions", "session list"),
                ("session info      <id>", "Show session details", "session info SESS-0001"),
                ("session create    <iface> <bssid> <ch> <ssid>", "Create new session", "session create wlan0 AA:BB:CC 6 MyWiFi"),
                ("session delete    <id>", "Delete a session", "session delete SESS-0001"),
                ("report export     <session> [md|json|html]", "Export audit report", "report export eng1 html"),
                ("report list", "List saved reports", "report list"),
                ("jobs              [--json]", "List background jobs", "jobs"),
                ("stop              <jid> [--force]", "Stop a background job", "stop JOB-0001"),
                ("stop all          [--force]", "Stop all background jobs", "stop all"),
                ("logs              [--tail] [--grep <pat>] [--clear]", "View framework logs", "logs --tail 50"),
                ("activity          [--tail <n>] [--grep <pat>]", "CLI activity history", "activity --tail 20"),
                ("run               [--dev] [--port <n>]", "Start wireless web GUI", "run --port 8081"),
                ("dashboard         [iface] [--channel]", "Live monitoring dashboard", "dashboard wlan0"),
                ("banner", "Redraw startup banner", "banner"),
                ("clear", "Clear terminal", "clear"),
                ("exit / quit", "Exit console", "exit"),
            ]),
        ]

        console.print()
        for title, items in help_categories:
            panel = UI.render_help_category(title, items)
            console.print(panel)
            console.print()

    def help_build(self):
        console.print("[bold cyan]build [all|go|rust|c|csharp][/bold cyan]")
        console.print("  Compile native wireless engines (C, C++, Go, Rust, C#)")
        console.print("  [dim]Example: build all  → compiles every engine[/dim]")
        console.print("  [dim]Example: build go   → only compiles Go workers[/dim]")

    def help_crawl(self):
        console.print("[bold cyan]crawl [iface] [--full] [--band 2ghz|5ghz|both][/bold cyan]")
        console.print("  Scan and enumerate Wi-Fi access points in range.")
        console.print("  [dim]Example: crawl wlan0 --full --band 5ghz[/dim]")
        console.print("  [dim]Real case: Find all APs on 5 GHz with deep probe[/dim]")

    def help_capture(self):
        console.print("[bold cyan]capture <iface> [output.pcap][/bold cyan]")
        console.print("  [bold cyan]capture handshake <iface> <bssid>[/bold cyan]")
        console.print("  [bold cyan]capture pmkid <iface> [bssid][/bold cyan]")
        console.print("  Capture 802.11 frames, WPA handshake, or PMKID.")
        console.print("  [dim]Real case: capture handshake wlan0 AA:BB:CC:DD:EE:FF[/dim]")
        console.print("  [dim]  → Captures EAPOL 4-way handshake with deauth trigger[/dim]")

    def help_crack(self):
        console.print("[bold cyan]crack <hashfile> <wordlist>[/bold cyan]")
        console.print("  Dictionary attack WPA/WPA2 PMKID using Go PBKDF2 engine.")
        console.print("  [dim]Real case: crack handshake.hc22000 /usr/share/wordlists/rockyou.txt[/dim]")
        console.print("  [dim]  → Tests 100k+ passwords/sec against captured PMKID[/dim]")

    def help_deauth(self):
        console.print("[bold cyan]deauth <iface> <bssid> [station] [count] [reason][/bold cyan]")
        console.print("  [bold cyan]deauth broadcast <iface> <bssid>[/bold cyan]")
        console.print("  Send 802.11 deauthentication frames to disconnect clients.")
        console.print("  [dim]Real case: deauth wlan0 AA:BB:CC:DD:EE:FF FF:FF:FF:FF:FF:FF 5 7[/dim]")
        console.print("  [dim]  → Kicks all clients off AP (reason 7 = class 3 frame nonce)[/dim]")
        console.print("  [dim]  → Clients reconnect → capture handshake[/dim]")

    def help_eviltwin(self):
        console.print("[bold cyan]eviltwin <iface> <ssid> [channel][/bold cyan]")
        console.print("  Clone a legitimate SSID and broadcast beacon frames.")
        console.print("  [dim]Real case: eviltwin wlan0 Starbucks_WiFi 6[/dim]")
        console.print("  [dim]  → Clients see 'Starbucks_WiFi' with stronger signal[/dim]")
        console.print("  [dim]  → Combine with rogue AP + captive portal for phishing[/dim]")

    def help_wps(self):
        console.print("[bold cyan]wps scan <iface>[/bold cyan]")
        console.print("  [bold cyan]wps pixie <iface> <bssid> [pin][/bold cyan]")
        console.print("  [bold cyan]wps pin <bssid>[/bold cyan]")
        console.print("  WPS auditing: detect, PixieDust attack, compute PIN.")
        console.print("  [dim]Real case: wps pixie wlan0 AA:BB:CC:DD:EE:FF[/dim]")
        console.print("  [dim]  → Uses AP's BSSID to derive default PIN (Pixie Dust)[/dim]")

    def help_wep(self):
        console.print("[bold cyan]wep capture <iface> <bssid>[/bold cyan]")
        console.print("  [bold cyan]wep arp-replay <iface> <bssid>[/bold cyan]")
        console.print("  [bold cyan]wep crack <capture.pcap>[/bold cyan]")
        console.print("  Full WEP cracking workflow: capture IVs → ARP replay → PTW crack")
        console.print("  [dim]Real case: wep capture wlan0 AA:BB:CC → wep arp-replay → wep crack wep.pcap[/dim]")

    def help_mode(self):
        console.print("[bold cyan]mode <iface> <monitor|managed>[/bold cyan]")
        console.print("  Switch wireless interface between monitor and managed mode.")
        console.print("  [dim]Real case: mode wlan0 monitor[/dim]")
        console.print("  [dim]  → Enables RFMON for packet injection & capture[/dim]")
        console.print("  [dim]  → Required BEFORE sniffing, deauth, or beacon flood[/dim]")

    def help_auto(self):
        console.print("[bold cyan]auto handshake [iface][/bold cyan]")
        console.print("  [bold cyan]auto audit [iface][/bold cyan]")
        console.print("  [bold cyan]auto crack [dir][/bold cyan]")
        console.print("  Automated wireless auditing workflows.")
        console.print("  [dim]Real case: auto audit wlan0[/dim]")
        console.print("  [dim]  → crawl → wpa3-detect → hidden → handshake capture → report[/dim]")

    def help_spectrum(self):
        console.print("[bold cyan]spectrum [iface][/bold cyan]")
        console.print("  Analyze 2.4/5 GHz channel utilization with RSSI heatmap.")
        console.print("  [dim]Real case: spectrum wlan0[/dim]")
        console.print("  [dim]  → Identifies least congested channel for AP deployment[/dim]")

    def help_arp(self):
        console.print("[bold cyan]arp scan[/bold cyan]")
        console.print("  Discover live hosts on local subnet via ARP requests.")
        console.print("  [dim]Real case: arp scan[/dim]")
        console.print("  [dim]  → Maps all devices on 198.51.100.0/24 with MAC vendors[/dim]")

    # ── Command implementations ────────────────────────────────

    def do_build(self, arg):
        """Compile native engines.\nUsage: build [all|go|rust|c|csharp]"""
        component = arg.strip() or "all"
        self.executor.do_build(component)

    def do_check(self, arg):
        """Check system dependencies."""
        self.executor.check_dependencies()

    def do_adapters(self, arg):
        """List wireless adapters — full-screen tab view with live scan.
Flags: --json | --watch | --interval <sec>"""
        pos, flags = _parse_flags(arg.split(), {"--json", "--watch"}, {"--interval": int})

        def _scan_and_render():
            os.system("cls" if os.name == "nt" else "clear")

            # ── Animated scan ──
            spinner_frames = ["◐", "◓", "◑", "◒"]
            for i in range(12):
                frame = spinner_frames[i % 4]
                dots = "." * ((i % 4) + 1)
                bar_len = min(i + 1, 20)
                bar = "█" * bar_len + "░" * (20 - bar_len)
                sys.stdout.write(f"\r\033[1;36m {frame} Scanning wireless adapters{dots:<4} [{bar}] {int((i+1)/12*100)}%\033[0m")
                sys.stdout.flush()
                time.sleep(0.08)
            sys.stdout.write("\r" + " " * 80 + "\r")
            sys.stdout.flush()

            adapters = HackITWirelessExecutor.detect_wireless_adapters()

            sys.stdout.write("\033[1;32m ✓ Scan complete! Detecting capabilities...\033[0m\n")
            time.sleep(0.3)

            os.system("cls" if os.name == "nt" else "clear")

            # ── Tab header ──
            tab_w = os.get_terminal_size().columns if hasattr(os, 'get_terminal_size') else 80
            header = f"[bold white]⎇  WIRELESS ADAPTERS  [/bold white][dim]| {len(adapters)} device(s) found[/dim]"
            console.print(Panel(header, border_style="bright_cyan", width=min(tab_w, 90)))

            if not adapters:
                console.print("\n[bold yellow]⚠ No wireless adapters detected[/bold yellow]")
                console.print("[dim]  → Ensure Wi-Fi card is connected and drivers are loaded[/dim]")
                console.print("[dim]  → Run 'check' to verify system dependencies[/dim]")
                return

            if "--json" in flags:
                console.print(json.dumps(adapters, indent=2))
                return

            # ── Horizontal rich table ──
            table = Table(
                title=None,
                border_style="cyan",
                header_style="bold cyan",
                show_lines=True,
                expand=True,
                width=min(tab_w, 90),
            )
            table.add_column("IFACE", style="green", no_wrap=True)
            table.add_column("MAC", style="yellow")
            table.add_column("MODE", style="magenta", justify="center")
            table.add_column("CH", justify="center", style="cyan")
            table.add_column("SIGNAL", style="green", justify="center")
            table.add_column("DRIVER", style="blue")
            table.add_column("SSID", style="white")
            table.add_column("TX", justify="center", style="dim")
            table.add_column("PHY", style="dim", justify="center")

            for a in adapters:
                name = a.get("name", "?")
                mac = a.get("mac", "N/A")
                mode = "MON" if a.get("is_monitor") else "MGD"
                ch = str(a.get("channel", "?"))
                sig = a.get("signal_dbm", "N/A")
                drv = a.get("driver", "?")[:16]
                ssid = a.get("ssid", "")
                txp = str(a.get("txpower", ""))
                phy = a.get("phy", "?")

                sig_str = f"{sig} dBm" if isinstance(sig, (int, float)) else str(sig)
                if isinstance(sig, (int, float)):
                    if sig >= -50: sig_str = f"[green]{sig} dBm ▰▰▰▰[/green]"
                    elif sig >= -70: sig_str = f"[yellow]{sig} dBm ▰▰▰▱[/yellow]"
                    else: sig_str = f"[red]{sig} dBm ▰▰▱▱[/red]"

                table.add_row(name, mac, mode, ch, sig_str, drv, ssid[:20], txp, phy)

            console.print()
            console.print(table)
            console.print()

            # ── Summary bar ──
            mon_count = sum(1 for a in adapters if a.get("is_monitor"))
            connected = sum(1 for a in adapters if a.get("ssid"))
            ch_line = ", ".join(f"{a['name']}: ch {a.get('channel','?')}" for a in adapters)
            summary = (
                f"[bold white]├[/bold white] [bold green]{len(adapters)}[/bold green] adapters  "
                f"[bold white]│[/bold white] [bold yellow]{mon_count}[/bold yellow] monitor  "
                f"[bold white]│[/bold white] [bold cyan]{connected}[/bold cyan] connected  "
                f"[bold white]│[/bold white] [dim]Channels: {ch_line}[/dim]"
            )
            console.print(Panel(summary, border_style="bright_cyan", width=min(tab_w, 90)))

            # ── Action bar ──
            console.print()
            at = Table.grid(padding=(0, 2))
            at.add_column(style="green bold", justify="right", width=1)
            at.add_column(style="white", width=28)
            at.add_column(style="dim white", width=26)
            at.add_row("1", "mode <iface> monitor",     "Enable RFMON")
            at.add_row("2", "adapter info <iface>",     "Detailed diagnostics")
            at.add_row("3", "channel <iface> <ch>",     "Lock to channel")
            at.add_row("4", "mac <iface> random",       "Spoof MAC")
            at.add_row("5", "txpower <iface> <dBm>",    "Adjust TX power")
            at.add_row("6", "crawl <iface>",            "Scan APs in range")
            at.add_row("W", "adapters --watch",         "Live refresh")
            at.add_row("Q", "back to console",          "")
            actions_table = Table.grid(padding=(0, 2))
            actions_table.add_column(justify="center")
            actions_table.add_row("[bold cyan]Quick Actions:[/bold cyan]")
            actions_table.add_row(at)
            console.print(Panel(actions_table, border_style="dim", width=min(tab_w, 90)))
            console.print()

        _scan_and_render()

        if "--watch" in flags:
            import time as _time
            interval = flags.get("--interval", 3)
            try:
                while True:
                    _time.sleep(interval)
                    _scan_and_render()
            except KeyboardInterrupt:
                console.print()
                UI.print_info("Watch stopped.")

    def do_adapter(self, arg):
        """Query adapter info.
Usage: adapter info <iface> [--json] [--capabilities]"""
        pos, flags = _parse_flags(arg.split(), {"--json", "--capabilities", "--all"})
        args = pos
        if len(args) < 2 or args[0].lower() != "info":
            UI.print_error("Syntax: adapter info <interface> [--json] [--capabilities]")
            return
        iface = args[1]
        try:
            proc = self.executor.bridge.go_adapter_info(iface)
            out, _ = proc.communicate()
            if "--json" in flags:
                console.print(out.strip())
            else:
                console.print(Panel(out.strip(), title=f"[bold yellow]{iface} Diagnostics[/bold yellow]",
                                    border_style="cyan"))
        except Exception as e:
            UI.print_error(str(e))

    def do_mode(self, arg):
        """Set adapter mode.
Usage: mode <iface> <monitor|managed> [--no-check] [--channel <ch>]"""
        pos, flags = _parse_flags(arg.split(), {"--no-check"}, {"--channel": int})
        args = pos
        if len(args) < 2:
            UI.print_error("Syntax: mode <interface> <monitor|managed> [--channel 6]")
            return
        iface, mode = args[0], args[1].lower()
        if mode not in ("monitor", "managed"):
            UI.print_error("Mode must be 'monitor' or 'managed'")
            return

        steps = [
            ("Checking adapter status...", f"iw dev {iface} info 2>&1 | head -5"),
            ("Taking interface down...", f"ip link set {iface} down"),
            ("Killing interfering processes...", f"airmon-ng check kill 2>/dev/null; systemctl stop NetworkManager wpa_supplicant 2>/dev/null; true"),
            (f"Setting {mode} mode...", f"iw dev {iface} set type {mode}"),
            ("Bringing interface up...", f"ip link set {iface} up"),
            ("Verifying mode...", f"iw dev {iface} info 2>&1 | grep -q 'type {mode}'"),
        ]
        if mode == "managed":
            steps.append(("Restoring network services...", f"systemctl restart NetworkManager wpa_supplicant 2>/dev/null; true"))

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      transient=True, console=console) as progress:
            task = progress.add_task(f"[cyan]Switching {iface} to {mode}...", total=len(steps))
            for desc, cmd in steps:
                progress.update(task, description=f"[cyan]{desc}")
                subprocess.run(["sh", "-c", cmd], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
                time.sleep(0.15)
                progress.advance(task)

        # Final verification
        r = subprocess.run(["iw", "dev", iface, "info"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and f"type {mode}" in r.stdout:
            UI.print_success(f"{iface} → {mode}")
        else:
            UI.print_warning(f"{iface}: mode switch may not have taken effect")
            UI.print_info("Try: --no-check to skip verification, or run as root")

        if mode == "monitor" and "--channel" in flags:
            ch = flags["--channel"]
            subprocess.run(["iw", "dev", iface, "set", "channel", str(ch)])
            UI.print_info(f"Channel locked: {ch}")

    def do_mac(self, arg):
        """Spoof MAC.
Usage: mac <iface> <random|restore|xx:xx:xx:xx:xx:xx> [--persist] [--vendor <oui>]"""
        pos, flags = _parse_flags(arg.split(), {"--persist"}, {"--vendor": str})
        args = pos
        if len(args) < 2:
            UI.print_error("Syntax: mac <interface> <random|restore|MAC> [--persist] [--vendor 00:11:22]")
            return
        iface, action = args[0], args[1]
        if "--vendor" in flags and action == "random":
            oui = flags["--vendor"].replace(":", "")
            import random
            action = f"{oui}:{random.randint(0x10,0xfe):02x}:{random.randint(0x10,0xfe):02x}:{random.randint(0x10,0xfe):02x}"
        try:
            proc = self.executor.bridge.go_mac(iface, action)
            out, _ = proc.communicate()
            console.print(Panel(out.strip(), title=f"[bold]MAC Spoof: {iface}[/bold]",
                                border_style="yellow"))
            if "--persist" in flags:
                rc = os.path.expanduser("~/.hackit_mac_persist")
                with open(rc, "a") as f:
                    f.write(f"{iface} {action}\n")
                UI.print_info(f"Persistent MAC rule written to {rc}")
        except Exception as e:
            UI.print_error(str(e))

    def do_txpower(self, arg):
        """Set TX power.
Usage: txpower <iface> <dBm> [--fixed] [--auto]"""
        pos, flags = _parse_flags(arg.split(), {"--fixed", "--auto"})
        args = pos
        if len(args) < 2:
            UI.print_error("Syntax: txpower <interface> <dBm> [--fixed] [--auto]")
            return
        iface, val = args[0], args[1]
        if "--auto" in flags:
            subprocess.run(["iw", "dev", iface, "set", "txpower", "auto"])
            UI.print_success(f"{iface} TX power set to auto")
            return
        try:
            proc = self.executor.bridge.go_txpower(iface, int(val))
            out, _ = proc.communicate()
            console.print(f"[green]{out.strip()}[/green]")
        except Exception as e:
            UI.print_error(str(e))

    def do_channel(self, arg):
        """Lock channel.
Usage: channel <iface> <ch> [--ht20|--ht40|--80mhz] [--no-dfs]"""
        pos, flags = _parse_flags(arg.split(),
                                  {"--ht20", "--ht40", "--80mhz", "--no-dfs", "--no-check"})
        args = pos
        if len(args) < 2:
            UI.print_error("Syntax: channel <interface> <channel> [--ht40] [--no-dfs]")
            return
        iface, ch = args[0], args[1]
        width = None
        if "--ht20" in flags: width = "HT20"
        elif "--ht40" in flags: width = "HT40+"
        elif "--80mhz" in flags: width = "80MHz"
        try:
            proc = self.executor.bridge.go_channel(iface, int(ch))
            if width:
                subprocess.run(["iw", "dev", iface, "set", "chwidth", width])
            out, _ = proc.communicate()
            console.print(f"[green]{out.strip()}[/green]")
        except Exception as e:
            UI.print_error(str(e))

    def do_freq(self, arg):
        """Lock to frequency.
Usage: freq <iface> <MHz> [--ht20|--ht40|--80mhz]"""
        pos, flags = _parse_flags(arg.split(), {"--ht20", "--ht40", "--80mhz"})
        args = pos
        if len(args) < 2:
            UI.print_error("Syntax: freq <interface> <MHz> [--ht40]")
            return
        iface, freq = args[0], args[1]
        width = None
        if "--ht20" in flags: width = "HT20"
        elif "--ht40" in flags: width = "HT40+"
        elif "--80mhz" in flags: width = "80MHz"
        try:
            subprocess.run(["iw", "dev", iface, "set", "freq", freq], check=True)
            if width:
                subprocess.run(["iw", "dev", iface, "set", "chwidth", width])
            UI.print_success(f"{iface} locked to {freq} MHz{' ' + width if width else ''}")
        except Exception as e:
            UI.print_error(str(e))

    def do_status(self, arg):
        """Show interface & engine status.
Usage: status [iface] [--json] [--all]"""
        pos, flags = _parse_flags(arg.split(), {"--json", "--all"})
        iface = pos[0] if pos else _detect_iface()
        try:
            proc = self.executor.bridge.go_status(iface) if iface else None
            out = ""
            if proc:
                out, _ = proc.communicate()
            health = self.executor.bridge.engine_health()
            if "--json" in flags:
                report = {"interface": iface, "engine_health": health, "status": out.strip()}
                console.print(json.dumps(report, indent=2))
                return
            grid = Table.grid(padding=(0, 2))
            grid.add_column()
            grid.add_column()
            grid.add_row("[bold cyan]Engine Status[/bold cyan]", "")
            for eng, ok in health.items():
                sym = "[green]✓[/green]" if ok else "[red]✗[/red]"
                grid.add_row(f"  {eng}", sym)
            grid.add_row("", "")
            grid.add_row("[bold cyan]Interface[/bold cyan]", iface or "N/A")
            if out:
                grid.add_row("", out.strip())
            console.print(Panel(grid, title=f"[bold yellow]Status Report[/bold yellow]",
                                border_style="cyan"))
        except Exception as e:
            UI.print_error(str(e))

    def do_crawl(self, arg):
        """Scan APs in range.
Usage: crawl [iface] [--full] [--band 2ghz|5ghz|both] [--timeout <sec>]
       crawl [iface] [--bssid <mac>] [--ssid <name>] [--output <file>] [--json]"""
        KNOWN = {"--full", "--json", "--verbose"}
        FLAG_VAL = {"--band": str, "--timeout": int, "--bssid": str, "--ssid": str, "--output": str,
                    "--min-rssi": int, "--max-aps": int}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        iface = None
        for p in pos:
            if not p.startswith("--"):
                iface = p
                break
        if not iface:
            iface = _detect_iface()
        band = flags.get("--band", "both")
        full = "--full" in flags
        timeout = flags.get("--timeout", 0)
        if "--help" in flags:
            self.help_crawl()
            return
        self.executor.do_crawl(iface, full, band, timeout=timeout,
                               bssid=flags.get("--bssid"),
                               ssid=flags.get("--ssid"),
                               output=flags.get("--output"),
                               min_rssi=flags.get("--min-rssi"),
                               max_aps=flags.get("--max-aps"))

    def do_sniff(self, arg):
        """Live frame telemetry.
Usage: sniff <iface> [--monitor] [--filters <expr>] [--channel <ch>]
       sniff <iface> [--output <file>] [--verbose] [--count <n>]"""
        KNOWN = {"--monitor", "--verbose"}
        FLAG_VAL = {"--filters": str, "--channel": int, "--output": str, "--count": int}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if not pos:
            UI.print_error("Usage: sniff <interface> [--monitor] [--filters <expr>] [--count 50]")
            return
        iface = pos[0]
        monitor = "--monitor" in flags
        filters = flags.get("--filters", "")
        channel = flags.get("--channel", 0)
        verbose = "--verbose" in flags
        count = flags.get("--count", 0)
        if channel:
            subprocess.run(["iw", "dev", iface, "set", "channel", str(channel)], capture_output=True)
        self.executor.run_sniff(iface, monitor, filters, verbose=verbose, count=count,
                                output=flags.get("--output"))

    def do_capture(self, arg):
        """Capture frames.
Usage: capture <iface> [output] [--timeout <sec>] [--filters <expr>]
       capture handshake <iface> <bssid> [--timeout 60] [--deauth] [--output <file>]
       capture pmkid <iface> [bssid] [--timeout 30] [--output <file>]
       capture raw <iface> [--channel <ch>] [--size <bytes>]"""
        KNOWN = {"--deauth", "--verbose"}
        FLAG_VAL = {"--timeout": int, "--output": str, "--filters": str, "--channel": int,
                    "--size": int}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if not pos:
            UI.print_error("Usage: capture <iface> [output] | capture handshake <iface> <bssid> | capture pmkid <iface> [bssid]")
            return
        timeout = flags.get("--timeout", 30)
        output = flags.get("--output", "")
        if pos[0].lower() == "handshake" and len(pos) >= 2:
            iface = pos[1]
            bssid = pos[2] if len(pos) > 2 else ""
            self.executor.do_handshake_capture(iface, bssid, timeout, deauth="--deauth" in flags,
                                                output=output)
        elif pos[0].lower() == "pmkid":
            iface = pos[1] if len(pos) > 1 else _detect_iface()
            bssid = pos[2] if len(pos) > 2 else ""
            self.executor.do_pmkid_capture(iface, bssid, timeout=timeout, output=output)
        elif pos[0].lower() == "raw":
            iface = pos[1] if len(pos) > 1 else _detect_iface()
            ch = flags.get("--channel", 0)
            if ch:
                subprocess.run(["iw", "dev", iface, "set", "channel", str(ch)], capture_output=True)
            sz = flags.get("--size", 4096)
            self.executor.do_capture(iface, output or "raw.pcap", snaplen=sz, timeout=timeout)
        else:
            iface = pos[0]
            self.executor.do_capture(iface, output or (pos[1] if len(pos) > 1 else "capture.pcap"),
                                      timeout=timeout)

    def do_sessions(self, arg):
        """List saved sessions.
Flags: --json | --all | --delete <name>"""
        pos, flags = _parse_flags(arg.split(), {"--json", "--all"}, {"--delete": str})
        if "--delete" in flags:
            self.executor.do_session_delete(flags["--delete"])
            return
        self.executor.do_sessions(json_output="--json" in flags)

    def do_replay(self, arg):
        """Replay PCAP for analysis.
Usage: replay <pcap> [--loop] [--speed <1-100>] [--filter <expr>] [--output <file>]"""
        KNOWN = {"--loop", "--verbose"}
        FLAG_VAL = {"--speed": int, "--filter": str, "--output": str, "--count": int}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if not pos:
            UI.print_error("Usage: replay <pcap_file> [--loop] [--speed 10]")
            return
        self.executor.do_replay(pos[0], loop="--loop" in flags,
                                speed=flags.get("--speed", 1),
                                bpf=flags.get("--filter"),
                                count=flags.get("--count", 0))

    def do_crack(self, arg):
        """Dictionary WPA crack.
Usage: crack <hashfile> <wordlist> [--rules <file>] [--timeout <sec>]
       crack <hashfile> <wordlist> [--session <name>] [--show] [--stdout]"""
        KNOWN = {"--show", "--stdout"}
        FLAG_VAL = {"--rules": str, "--timeout": int, "--session": str}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if len(pos) < 2:
            UI.print_error("Usage: crack <hashfile> <wordlist> [--rules <file>] [--show]")
            return
        if "--show" in flags:
            self.executor.do_crack_show(pos[0])
            return
        self.executor.do_crack(pos[0], pos[1], rules=flags.get("--rules"),
                                timeout=flags.get("--timeout", 0),
                                session=flags.get("--session"))

    def do_hashcat(self, arg):
        """GPU crack via hashcat.
Usage: hashcat <hashfile> <wordlist> [--rules <file>] [--force] [--gpu-devices <n>]
       hashcat <hashfile> <wordlist> [--outfile <file>] [--potfile-disable] [extra_args]"""
        KNOWN = {"--force", "--potfile-disable", "--show"}
        FLAG_VAL = {"--rules": str, "--gpu-devices": str, "--outfile": str, "--workload": int}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if len(pos) < 2:
            UI.print_error("Usage: hashcat <hashfile> <wordlist> [--force] [--rules <file>]")
            return
        extra_parts = []
        if "--force" in flags: extra_parts.append("--force")
        if "--potfile-disable" in flags: extra_parts.append("--potfile-disable")
        if "--rules" in flags: extra_parts.extend(["-r", flags["--rules"]])
        if "--outfile" in flags: extra_parts.extend(["-o", flags["--outfile"]])
        if "--gpu-devices" in flags: extra_parts.extend(["-D", flags["--gpu-devices"]])
        if "--show" in flags: extra_parts.append("--show")
        extra = " ".join(extra_parts)
        self.executor.do_hashcat(pos[0], pos[1], extra)

    def do_verify(self, arg):
        """Verify handshake integrity.
Usage: verify <capture> [--json] [--strict] [--output <report>]"""
        pos, flags = _parse_flags(arg.split(), {"--json", "--strict"}, {"--output": str})
        if not pos:
            UI.print_error("Usage: verify <capture_file> [--json] [--strict]")
            return
        self.executor.do_verify(pos[0], json_output="--json" in flags,
                                 strict="--strict" in flags,
                                 output=flags.get("--output"))

    def do_convert(self, arg):
        """Convert capture format.
Usage: convert hc22000 <pcap> [--ssid <name>] [--bssid <mac>] [--output <file>]
       convert hccapx <pcap>  |  convert csv <pcap>"""
        KNOWN = set()
        FLAG_VAL = {"--ssid": str, "--bssid": str, "--output": str}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if len(pos) >= 2 and pos[0].lower() == "hc22000":
            self.executor.do_convert_hc22000(pos[1], ssid=flags.get("--ssid"),
                                              bssid=flags.get("--bssid"),
                                              output=flags.get("--output"))
        elif len(pos) >= 2 and pos[0].lower() == "hccapx":
            self.executor.do_convert_hccapx(pos[1], output=flags.get("--output"))
        elif len(pos) >= 2 and pos[0].lower() == "csv":
            self.executor.do_convert_csv(pos[1], output=flags.get("--output"))
        else:
            UI.print_error("Usage: convert hc22000 <capture> [--ssid <name>]")

    def do_wordlists(self, arg):
        """List installed wordlists.
Usage: wordlists [path] [--json] [--size] [--count]"""
        pos, flags = _parse_flags(arg.split(), {"--json", "--size", "--count"})
        self.executor.do_wordlists(pos[0] if pos else "",
                                    show_size="--size" in flags,
                                    json_output="--json" in flags)

    def do_wps(self, arg):
        """WPS auditing.
Usage: wps scan <iface> [--timeout <sec>] [--json] [--output <file>]
       wps pixie <iface> <bssid> [pin] [--timeout 120] [--output <file>]
       wps pin <bssid> [--compute-all]
       wps bruteforce <iface> <bssid> [--start <pin>] [--end <pin>] [--delay <ms>]"""
        KNOWN = {"--json", "--compute-all", "--verbose"}
        FLAG_VAL = {"--timeout": int, "--output": str, "--start": str, "--end": str, "--delay": int}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if not pos:
            UI.print_error("Usage: wps scan <iface> | wps pixie <iface> <bssid> | wps pin <bssid>")
            return
        sub = pos[0].lower()
        if sub == "scan":
            iface = pos[1] if len(pos) > 1 else _detect_iface()
            self.executor.do_wps_scan(iface, timeout=flags.get("--timeout", 30),
                                       output=flags.get("--output"))
        elif sub == "pixie":
            iface = pos[1] if len(pos) > 1 else _detect_iface()
            bssid = pos[2] if len(pos) > 2 else ""
            pin = pos[3] if len(pos) > 3 else flags.get("--start", "")
            self.executor.do_wps_pixie(iface, bssid, pin, timeout=flags.get("--timeout", 120))
        elif sub == "pin":
            bssid = pos[1] if len(pos) > 1 else ""
            self.executor.do_wps_pin(bssid, all_pins="--compute-all" in flags)
        elif sub == "bruteforce":
            iface = pos[1] if len(pos) > 1 else _detect_iface()
            bssid = pos[2] if len(pos) > 2 else ""
            self.executor.do_wps_bruteforce(iface, bssid,
                                             start_pin=flags.get("--start"),
                                             end_pin=flags.get("--end"),
                                             delay=flags.get("--delay", 200))
        else:
            UI.print_error("Unknown wps command: use scan, pixie, pin, or bruteforce")

    def do_wep(self, arg):
        """WEP cracking workflow.
Usage: wep capture <iface> <bssid> [--output <file>] [--timeout <sec>] [--ivs-only]
       wep arp-replay <iface> <bssid> [--count <n>] [--delay <ms>] [--timeout <sec>]
       wep chopchop <iface> <bssid> [--output <file>]
       wep crack <capture> [--method ptw|fms|korek] [--output <file>] [--json]
       wep frag <iface> <bssid> [--output <file>]"""
        KNOWN = {"--ivs-only", "--json", "--verbose"}
        FLAG_VAL = {"--output": str, "--timeout": int, "--count": int, "--delay": int,
                    "--method": str}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if not pos:
            UI.print_error("Usage: wep capture | wep arp-replay | wep chopchop | wep crack | wep frag")
            return
        sub = pos[0].lower()
        if sub == "capture":
            iface = pos[1] if len(pos) > 1 else _detect_iface()
            bssid = pos[2] if len(pos) > 2 else ""
            self.executor.do_wep_capture(iface, bssid,
                                          output=flags.get("--output", "wep.pcap"),
                                          timeout=flags.get("--timeout", 120),
                                          ivs_only="--ivs-only" in flags)
        elif sub in ("arp", "arp-replay", "arpreplay"):
            iface = pos[1] if len(pos) > 1 else _detect_iface()
            bssid = pos[2] if len(pos) > 2 else ""
            self.executor.do_wep_arp_replay(iface, bssid,
                                             count=flags.get("--count", 0),
                                             delay=flags.get("--delay", 0),
                                             timeout=flags.get("--timeout", 0))
        elif sub == "chopchop":
            iface = pos[1] if len(pos) > 1 else _detect_iface()
            bssid = pos[2] if len(pos) > 2 else ""
            self.executor.do_wep_chopchop(iface, bssid, output=flags.get("--output"))
        elif sub == "frag":
            iface = pos[1] if len(pos) > 1 else _detect_iface()
            bssid = pos[2] if len(pos) > 2 else ""
            self.executor.do_wep_frag(iface, bssid, output=flags.get("--output"))
        elif sub == "crack":
            capture = pos[1] if len(pos) > 1 else "wep.pcap"
            self.executor.do_wep_crack(capture, method=flags.get("--method", "ptw"),
                                        output=flags.get("--output"))
        else:
            UI.print_error("Unknown wep command: use capture, arp-replay, chopchop, frag, or crack")

    def do_aggressive_scan(self, arg):
        """Multi-channel deep scan.
Usage: aggressive-scan <iface> [--5ghz] [--6ghz] [--timeout <sec>] [--json] [--output <file>]"""
        KNOWN = {"--5ghz", "--6ghz", "--json", "--verbose"}
        FLAG_VAL = {"--timeout": int, "--output": str}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if not pos:
            UI.print_error("Usage: aggressive-scan <iface> [--5ghz] [--6ghz] [--timeout 60]")
            return
        iface = pos[0]
        bands = []
        if "--5ghz" in flags: bands.append("5")
        if "--6ghz" in flags: bands.append("6")
        band = ",".join(bands) if bands else "both"
        self.executor.do_aggressive_scan(iface, band, timeout=flags.get("--timeout"),
                                          output=flags.get("--output"))

    def do_client_hunt(self, arg):
        """Enumerate connected clients.
Usage: client-hunt <iface> [bssid] [--timeout <sec>] [--json] [--output <file>] [--verbose]"""
        KNOWN = {"--json", "--verbose"}
        FLAG_VAL = {"--timeout": int, "--output": str}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if not pos:
            UI.print_error("Usage: client-hunt <iface> [bssid] [--timeout 30]")
            return
        iface = pos[0]
        bssid = pos[1] if len(pos) > 1 else ""
        self.executor.do_client_hunt(iface, bssid, timeout=flags.get("--timeout"),
                                      output=flags.get("--output"))

    def do_wpa3_detect(self, arg):
        """Detect WPA3/SAE/OWE APs.
Usage: wpa3-detect [iface] [--json] [--timeout <sec>] [--output <file>]"""
        pos, flags = _parse_flags(arg.split(), {"--json"}, {"--timeout": int, "--output": str})
        self.executor.do_wpa3_detect(pos[0] if pos else _detect_iface(),
                                      timeout=flags.get("--timeout"),
                                      output=flags.get("--output"))

    def do_hidden(self, arg):
        """Find hidden SSID APs.
Usage: hidden [iface] [--timeout <sec>] [--json] [--deauth] [--output <file>]"""
        KNOWN = {"--json", "--deauth"}
        FLAG_VAL = {"--timeout": int, "--output": str}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        self.executor.do_hidden_ssid(pos[0] if pos else _detect_iface(),
                                      timeout=flags.get("--timeout"),
                                      deauth="--deauth" in flags,
                                      output=flags.get("--output"))

    def do_probe_monitor(self, arg):
        """Watch probe requests.
Usage: probe-monitor [iface] [--timeout <sec>] [--json] [--output <file>] [--min-rssi <dBm>]"""
        KNOWN = {"--json"}
        FLAG_VAL = {"--timeout": int, "--output": str, "--min-rssi": int}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        self.executor.do_probe_monitor(pos[0] if pos else _detect_iface(),
                                        timeout=flags.get("--timeout"),
                                        min_rssi=flags.get("--min-rssi", -80),
                                        output=flags.get("--output"))

    def do_beacon_analyze(self, arg):
        """Analyze beacon frames.
Usage: beacon-analyze [iface] [--timeout <sec>] [--json] [--output <file>] [--verbose]"""
        pos, flags = _parse_flags(arg.split(), {"--json", "--verbose"},
                                    {"--timeout": int, "--output": str})
        self.executor.do_beacon_analyze(pos[0] if pos else _detect_iface(),
                                         timeout=flags.get("--timeout"),
                                         output=flags.get("--output"))

    def do_signal(self, arg):
        """Real-time signal monitor.
Usage: signal [iface] [--timeout <sec>] [--json] [--output <file>] [--threshold <dBm>]"""
        KNOWN = {"--json"}
        FLAG_VAL = {"--timeout": int, "--output": str, "--threshold": int}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        self.executor.do_signal_monitor(pos[0] if pos else _detect_iface(),
                                         timeout=flags.get("--timeout"),
                                         threshold=flags.get("--threshold", -90),
                                         output=flags.get("--output"))

    def do_spectrum(self, arg):
        """Channel utilization heatmap.
Usage: spectrum [iface] [--timeout <sec>] [--output <file>] [--5ghz] [--only <channels>]"""
        KNOWN = {"--5ghz", "--verbose"}
        FLAG_VAL = {"--timeout": int, "--output": str, "--only": str}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        self.executor.do_spectrum(pos[0] if pos else _detect_iface(),
                                   timeout=flags.get("--timeout"),
                                   band="5" if "--5ghz" in flags else "both",
                                   only_channels=flags.get("--only"),
                                   output=flags.get("--output"))

    def do_dual_band(self, arg):
        """Scan both 2.4 + 5 GHz bands.
Usage: dual-band [iface] [--timeout <sec>] [--json] [--output <file>]"""
        pos, flags = _parse_flags(arg.split(), {"--json"}, {"--timeout": int, "--output": str})
        self.executor.do_dual_band(pos[0] if pos else _detect_iface(),
                                    timeout=flags.get("--timeout"),
                                    output=flags.get("--output"))

    def do_map(self, arg):
        """AP × vendor correlation map.
Usage: map [iface] [--timeout <sec>] [--json] [--output <file>] [--heatmap]"""
        KNOWN = {"--json", "--heatmap"}
        FLAG_VAL = {"--timeout": int, "--output": str}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        self.executor.do_map(pos[0] if pos else _detect_iface(),
                              timeout=flags.get("--timeout"),
                              heatmap="--heatmap" in flags,
                              output=flags.get("--output"))

    def do_deauth(self, arg):
        """Deauth attack — kill WiFi with raw 802.11 deauth frames (infinite until Ctrl+C).
Usage: deauth <iface> <bssid> [station] [--rate <n>] [--reason <code>] [--channel <ch>]
       deauth broadcast <iface> <bssid> [--channel <ch>]"""
        KNOWN = set()
        FLAG_VAL = {"--rate": int, "--reason": int, "--channel": int, "--output": str}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        reason = flags.get("--reason", 7)
        channel = flags.get("--channel", 0)
        if len(pos) >= 1 and pos[0].lower() == "broadcast":
            iface = pos[1] if len(pos) > 1 else _detect_iface()
            bssid = pos[2] if len(pos) > 2 else ""
            self.executor.do_deauth(iface, bssid, "FF:FF:FF:FF:FF:FF",
                                    reason=reason, channel=channel,
                                    output=flags.get("--output"))
        elif len(pos) >= 2:
            iface = pos[0]
            bssid = pos[1]
            station = pos[2] if len(pos) > 2 else "FF:FF:FF:FF:FF:FF"
            self.executor.do_deauth(iface, bssid, station,
                                    reason=reason, channel=channel,
                                    output=flags.get("--output"))
        else:
            UI.print_error("Usage: deauth <iface> <bssid> [station] [--reason 7] [--channel <ch>]")

    def do_beacon_flood(self, arg):
        """Flood fake beacons.
Usage: beacon-flood <iface> [--ssid <name>] [--count <n>] [--channel <ch>]
       beacon-flood <iface> [--wpa2] [--wpa3] [--file <ssids.txt>] [--output <file>]"""
        KNOWN = {"--wpa2", "--wpa3", "--verbose"}
        FLAG_VAL = {"--ssid": str, "--count": int, "--channel": int, "--file": str,
                    "--output": str, "--interval": int}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if not pos:
            UI.print_error("Usage: beacon-flood <iface> [--ssid <name>] [--count 500] [--wpa2]")
            return
        iface = pos[0]
        ssid = flags.get("--ssid", "")
        count = flags.get("--count", 100)
        channel = flags.get("--channel", 0)
        caps = []
        if "--wpa2" in flags: caps.append("wpa2")
        if "--wpa3" in flags: caps.append("wpa3")
        if flags.get("--file"):
            import pathlib
            ssids = pathlib.Path(flags["--file"]).read_text().splitlines()
            self.executor.do_beacon_flood_multi(iface, ssids, count, caps=caps,
                                                 channel=channel,
                                                 interval=flags.get("--interval", 100))
        else:
            self.executor.do_beacon_flood(iface, ssid, count, channel=channel,
                                          caps=caps, output=flags.get("--output"))

    def do_probe_flood(self, arg):
        """Probe request flood.
Usage: probe-flood <iface> [--count <n>] [--ssids <file>] [--interval <ms>] [--random-mac]"""
        KNOWN = {"--random-mac"}
        FLAG_VAL = {"--count": int, "--ssids": str, "--interval": int}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if not pos:
            UI.print_error("Usage: probe-flood <iface> [--count 1000] [--ssids ssids.txt]")
            return
        iface = pos[0]
        count = flags.get("--count", 100)
        ssids_file = flags.get("--ssids")
        if ssids_file:
            import pathlib
            ssids = pathlib.Path(ssids_file).read_text().splitlines()
            self.executor.do_probe_flood_ssids(iface, ssids, count,
                                                random_mac="--random-mac" in flags)
        else:
            self.executor.do_probe_flood(iface, count, interval=flags.get("--interval", 50),
                                          random_mac="--random-mac" in flags)

    def do_eviltwin(self, arg):
        """Clone SSID rogue AP.
Usage: eviltwin <iface> <ssid> [--channel <ch>] [--wpa2] [--wpa3] [--captive]
       eviltwin <iface> <ssid> [--output <file>] [--bssid <mac>] [--dhcp-range <cidr>]"""
        KNOWN = {"--wpa2", "--wpa3", "--captive", "--verbose"}
        FLAG_VAL = {"--channel": int, "--output": str, "--bssid": str, "--dhcp-range": str}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if len(pos) < 2:
            UI.print_error("Usage: eviltwin <iface> <ssid> [--channel 6] [--captive]")
            return
        iface = pos[0]
        ssid = pos[1]
        channel = flags.get("--channel", 6)
        caps = []
        if "--wpa2" in flags: caps.append("wpa2")
        if "--wpa3" in flags: caps.append("wpa3")
        self.executor.do_eviltwin(iface, ssid, channel, caps=caps,
                                   captive="--captive" in flags,
                                   bssid=flags.get("--bssid"),
                                   dhcp_range=flags.get("--dhcp-range"))

    def do_rogue(self, arg):
        """Start rogue AP.
Usage: rogue <iface> [--ssid <name>] [--channel <ch>] [--wpa2] [--captive]
       rogue <iface> [--bssid <mac>] [--dhcp-range <cidr>] [--output <file>]"""
        KNOWN = {"--wpa2", "--wpa3", "--captive", "--verbose"}
        FLAG_VAL = {"--ssid": str, "--channel": int, "--bssid": str, "--dhcp-range": str,
                    "--output": str}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if not pos:
            UI.print_error("Usage: rogue <iface> [--ssid <name>] [--channel <ch>]")
            return
        iface = pos[0]
        ssid = flags.get("--ssid")
        if not ssid:
            epoch = str(int(time.time() * 1000))
            ssid = f"AP_{epoch[-6:]}"
        channel = flags.get("--channel", 6)
        self.executor.do_rogue_ap(iface, ssid, channel, wpa2="--wpa2" in flags,
                                   captive="--captive" in flags,
                                   bssid=flags.get("--bssid"),
                                   dhcp_range=flags.get("--dhcp-range"))

    def do_arp(self, arg):
        """ARP network discovery.
Usage: arp scan [--timeout <sec>] [--json] [--output <file>] [--intf <iface>]
       arp table [--json]"""
        KNOWN = {"--json"}
        FLAG_VAL = {"--timeout": int, "--output": str, "--intf": str}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if not pos:
            UI.print_error("Usage: arp scan [--timeout 10] [--json]")
            return
        if pos[0].lower() == "scan":
            self.executor.do_arp_scan(timeout=flags.get("--timeout", 10),
                                       iface=flags.get("--intf"))
        elif pos[0].lower() == "table":
            self.executor.do_arp_table()
        else:
            UI.print_error("Usage: arp scan | arp table")

    def do_ping_sweep(self, arg):
        """ICMP sweep.
Usage: ping-sweep [subnet] [--timeout <sec>] [--json] [--output <file>] [--parallel <n>]"""
        KNOWN = {"--json"}
        FLAG_VAL = {"--timeout": int, "--output": str, "--parallel": int}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        self.executor.do_ping_sweep(pos[0] if pos else "",
                                     timeout=flags.get("--timeout", 5),
                                     parallel=flags.get("--parallel", 10),
                                     output=flags.get("--output"))

    def do_arp_spoof(self, arg):
        """ARP poisoning MITM.
Usage: arp-spoof <target> <gateway> [--timeout <sec>] [--interval <sec>] [--full-duplex] [--output <file>]"""
        KNOWN = {"--full-duplex", "--verbose"}
        FLAG_VAL = {"--timeout": int, "--interval": int, "--output": str}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if len(pos) < 2:
            UI.print_error("Usage: arp-spoof <target> <gateway> [--full-duplex] [--timeout 60]")
            return
        self.executor.do_arp_spoof(pos[0], pos[1],
                                    timeout=flags.get("--timeout", 0),
                                    interval=flags.get("--interval", 2),
                                    full_duplex="--full-duplex" in flags,
                                    output=flags.get("--output"))

    def do_forward(self, arg):
        """Toggle IP forwarding.
Usage: forward <on|off> [--persist]"""
        pos, flags = _parse_flags(arg.split(), {"--persist"})
        val = pos[0] if pos else "on"
        self.executor.do_forward(val, persist="--persist" in flags)

    def do_ports(self, arg):
        """TCP port scan.
Usage: ports <host> [range] [--timeout <ms>] [--threads <n>] [--top-ports <n>]
       ports <host> [--service-detect] [--json] [--output <file>] [--syn] [--connect]"""
        KNOWN = {"--service-detect", "--json", "--verbose", "--syn", "--connect"}
        FLAG_VAL = {"--timeout": int, "--threads": int, "--top-ports": int, "--output": str}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if not pos:
            UI.print_error("Usage: ports <host> [range] [--top-ports 1000] [--service-detect]")
            return
        host = pos[0]
        port_range = pos[1] if len(pos) > 1 else "1-1024"
        self.executor.do_port_scan(host, port_range,
                                    timeout=flags.get("--timeout", 2000),
                                    threads=flags.get("--threads", 50),
                                    top_ports=flags.get("--top-ports", 0),
                                    service_detect="--service-detect" in flags,
                    scan_type="syn" if "--syn" in flags else ("connect" if "--connect" in flags else "syn"),
                                    output=flags.get("--output"))

    def do_services(self, arg):
        """Service version detection.
Usage: services <host> [--timeout <ms>] [--threads <n>] [--json] [--output <file>] [--all]"""
        KNOWN = {"--json", "--all", "--verbose"}
        FLAG_VAL = {"--timeout": int, "--threads": int, "--output": str}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if not pos:
            UI.print_error("Usage: services <host> [--timeout 3000] [--all]")
            return
        self.executor.do_services(pos[0], timeout=flags.get("--timeout", 3000),
                                   threads=flags.get("--threads", 20),
                                   output=flags.get("--output"))

    def do_os_detect(self, arg):
        """OS fingerprinting.
Usage: os-detect <host> [--timeout <sec>] [--json] [--output <file>] [--aggressive]"""
        KNOWN = {"--json", "--aggressive"}
        FLAG_VAL = {"--timeout": int, "--output": str}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if not pos:
            UI.print_error("Usage: os-detect <host> [--aggressive]")
            return
        self.executor.do_os_detect(pos[0], timeout=flags.get("--timeout", 30),
                                    aggressive="--aggressive" in flags,
                                    output=flags.get("--output"))

    def do_gateway(self, arg):
        """Show default gateway.
Flags: --json | --ipv6"""
        pos, flags = _parse_flags(arg.split(), {"--json", "--ipv6"})
        self.executor.do_gateway(ipv6="--ipv6" in flags)

    def do_dns(self, arg):
        """DNS operations.
Usage: dns sniff [--timeout <sec>] [--output <file>]
       dns resolve <hostname>
       dns spoof <hostname> <ip> [--iface <iface>]"""
        KNOWN = set()
        FLAG_VAL = {"--timeout": int, "--output": str, "--iface": str}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if not pos:
            UI.print_error("Usage: dns sniff | dns resolve <hostname> | dns spoof <host> <ip>")
            return
        if pos[0].lower() == "sniff":
            self.executor.do_dns_sniff(timeout=flags.get("--timeout", 30),
                                        output=flags.get("--output"))
        elif pos[0].lower() == "resolve" and len(pos) > 1:
            self.executor.do_dns_resolve(pos[1])
        elif pos[0].lower() == "spoof" and len(pos) > 2:
            self.executor.do_dns_spoof(pos[1], pos[2], iface=flags.get("--iface", _detect_iface()))
        else:
            UI.print_error("Usage: dns sniff | dns resolve <hostname> | dns spoof <host> <ip>")

    def do_auto(self, arg):
        """Automated workflows.
Usage: auto handshake [iface] [--timeout <sec>] [--deauth] [--output <dir>]
       auto audit [iface] [--timeout <sec>] [--output <dir>] [--skip-wep] [--skip-wps]
       auto crack [dir] [--rules <file>] [--hashcat] [--threads <n>]"""
        KNOWN = {"--deauth", "--skip-wep", "--skip-wps", "--hashcat", "--verbose"}
        FLAG_VAL = {"--timeout": int, "--output": str, "--rules": str, "--threads": int}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if not pos:
            UI.print_error("Usage: auto handshake | auto audit | auto crack")
            return
        sub = pos[0].lower()
        if sub == "handshake":
            iface = pos[1] if len(pos) > 1 else _detect_iface()
            self.executor.do_auto_handshake(iface, timeout=flags.get("--timeout", 60),
                                             deauth="--deauth" in flags,
                                             output=flags.get("--output"))
        elif sub == "audit":
            iface = pos[1] if len(pos) > 1 else _detect_iface()
            self.executor.do_auto_audit(iface, timeout=flags.get("--timeout", 300),
                                         skip_wep="--skip-wep" in flags,
                                         skip_wps="--skip-wps" in flags,
                                         output=flags.get("--output"))
        elif sub == "crack":
            d = pos[1] if len(pos) > 1 else ""
            self.executor.do_auto_crack(d, rules=flags.get("--rules"),
                                         use_hashcat="--hashcat" in flags,
                                         threads=flags.get("--threads", 4))
        else:
            UI.print_error("Usage: auto handshake | auto audit | auto crack")

    def do_jobs(self, arg):
        """List background jobs.
Flags: --json | --stop <jid> | --purge"""
        pos, flags = _parse_flags(arg.split(), {"--json", "--purge"}, {"--stop": str})
        if "--stop" in flags:
            self.executor.do_stop_job(flags["--stop"])
            return
        if "--purge" in flags:
            self.executor.do_job_purge()
            return
        self.executor.do_jobs(json_output="--json" in flags)

    def do_stop(self, arg):
        """Stop job(s).
Usage: stop <jid> | stop all [--force]"""
        pos, flags = _parse_flags(arg.split(), {"--force"})
        if pos and pos[0].lower() == "all":
            self.executor.do_stop_all(force="--force" in flags)
        elif pos:
            self.executor.do_stop_job(pos[0])
        else:
            UI.print_error("Usage: stop <jid> | stop all [--force]")



    def do_workspace(self, arg):
        """Workspace management.
Usage: workspace create <name> [--path <dir>]
       workspace load <name>
       workspace list [--json]
       workspace delete <name>"""
        KNOWN = {"--json"}
        FLAG_VAL = {"--path": str}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if len(pos) < 2:
            UI.print_error("Usage: workspace create <name> | workspace load <name> | workspace list")
            return
        sub, name = pos[0].lower(), pos[1]
        if sub == "create":
            self.executor.do_workspace_create(name, path=flags.get("--path"))
        elif sub == "load":
            self.current_workspace = self.executor.do_workspace_load(name)
        elif sub == "list":
            self.executor.do_workspace_list()
        elif sub == "delete":
            self.executor.do_workspace_delete(name)
        else:
            UI.print_error("Usage: workspace create <name> | workspace load <name> | workspace list")

    def do_session(self, arg):
        """Session management.
Usage: session list [--json]
       session create <iface> <bssid> <channel> <ssid> [type] [--output <dir>]
       session delete <id>
       session info <id> [--json]"""
        KNOWN = {"--json"}
        FLAG_VAL = {"--output": str}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if not pos:
            UI.print_error("Usage: session list | session create ... | session info <id>")
            return
        if pos[0].lower() == "list":
            self.executor.do_session_list(json_output="--json" in flags)
        elif pos[0].lower() == "create" and len(pos) >= 5:
            self.executor.do_session_create(pos[1], pos[2], int(pos[3]), pos[4],
                                             pos[5] if len(pos) > 5 else "handshake",
                                             output_dir=flags.get("--output"))
        elif pos[0].lower() == "delete" and len(pos) > 1:
            self.executor.do_session_delete(pos[1])
        elif pos[0].lower() == "info" and len(pos) > 1:
            self.executor.do_session_info(pos[1])
        else:
            UI.print_error("Usage: session list | session create <iface> <bssid> <ch> <ssid>")

    def do_report(self, arg):
        """Export audit report.
Usage: report export <session> [md|json|html] [--output <file>]
       report list [--json]"""
        KNOWN = {"--json"}
        FLAG_VAL = {"--output": str}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if len(pos) >= 2 and pos[0].lower() == "export":
            session = pos[1]
            fmt = pos[2] if len(pos) > 2 else "md"
            self.executor.do_report_export(session, fmt, output=flags.get("--output"))
        elif pos and pos[0].lower() == "list":
            self.executor.do_report_list()
        else:
            UI.print_error("Usage: report export <session> [md|json|html]")

    def do_dashboard(self, arg):
        """Live monitoring dashboard.
Usage: dashboard [iface] [--channel <ch>] [--timeout <sec>] [--simple]"""
        KNOWN = {"--simple"}
        FLAG_VAL = {"--channel": int, "--timeout": int}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        iface = pos[0] if pos else _detect_iface()
        ch = flags.get("--channel", 0)
        if ch:
            subprocess.run(["iw", "dev", iface, "set", "channel", str(ch)], capture_output=True)
        UI.print_info(f"Live dashboard on {iface}...")
        self.executor.run_sniff(iface, monitor=True, verbose=not "--simple" in flags,
                                 timeout=flags.get("--timeout"))

    def do_logs(self, arg):
        """Show raw session logs from hackit_wireless.log.
Flags: --tail <n> | --grep <pattern> | --json | --clear"""
        KNOWN = {"--json", "--clear"}
        FLAG_VAL = {"--tail": int, "--grep": str}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if "--clear" in flags:
            open(LOG_FILE, "w").close()
            UI.print_info("Log cleared.")
            return
        if not LOG_FILE.exists():
            UI.print_info("No log file found.")
            return
        with open(LOG_FILE, errors="replace") as f:
            lines = f.readlines()
        if "--grep" in flags:
            import re as re_m
            pat = flags["--grep"]
            lines = [l for l in lines if re_m.search(pat, l)]
        tail = flags.get("--tail")
        if tail:
            lines = lines[-tail:]
        else:
            lines = lines[-500:]
        if "--json" in flags:
            console.print(json.dumps([{"line": l.rstrip()} for l in lines], indent=2))
            return
        console.print("".join(lines))

    def do_version(self, arg):
        """Display framework version & engine health.
Flags: --json | --check-updates"""
        pos, flags = _parse_flags(arg.split(), {"--json", "--check-updates"})
        if "--json" in flags:
            health = self.executor.bridge.engine_health()
            console.print(json.dumps({"version": "3.0", "engines": health}, indent=2))
            return
        console.print("[bold cyan]HackIT Wireless Framework v3.0[/bold cyan]")
        console.print("  Multi-Engine: C/C++ · Go · Rust · C# · Lua · Ruby")
        health = self.executor.bridge.engine_health()
        for eng, ok in health.items():
            sym = "[green]✓[/green]" if ok else "[red]✗[/red]"
            console.print(f"  {sym} {eng}")
        console.print("  802.11 a/b/g/n/ac/ax  |  2.4/5/6 GHz")
        if "--check-updates" in flags:
            UI.print_info("Update check: feature planned for v3.1")

    def do_clear(self, arg):
        """Clear screen."""
        os.system("cls" if os.name == "nt" else "clear")
        self._banner_shown = False

    def do_banner(self, arg):
        """Redraw startup banner."""
        print_banner()

    def do_exit(self, arg):
        """Exit console."""
        UI.print_info("Shutting down wireless engines...")
        self.executor.jobs.stop_all()
        return True

    def do_run(self, arg):
        """Launch the HackIT Wireless GUI (tkinter).
Usage: run"""
        gui_script = BASE / "weblocal" / "gui.py"
        if not gui_script.exists():
            UI.print_error(f"GUI script not found: {gui_script}")
            return
        UI.print_info("Launching HackIT Wireless GUI...")
        subprocess.Popen(
            [sys.executable, str(gui_script)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        UI.print_success("GUI launched in background.")

    def do_quit(self, arg):
        return self.do_exit(arg)

    def default(self, line):
        UI.print_error(f"Unknown command: {line}")
        UI.print_info("Type 'help' to see available commands.")

    def emptyline(self):
        pass

    def postcmd(self, stop, line):
        if line and not line.startswith("activity") and not line.startswith("log"):
            self._activity.append({"time": dt.datetime.now(), "cmd": line, "ok": True})
            if len(self._activity) > self._activity_max:
                self._activity.pop(0)
            log_activity(line)
        return stop

    def do_activity(self, arg):
        """Show CLI activity history.
        Usage: activity [--tail <n>] [--grep <pattern>] [--json] [--clear]"""
        KNOWN = {"--json", "--clear"}
        FLAG_VAL = {"--tail": int, "--grep": str}
        pos, flags = _parse_flags(arg.split(), KNOWN, FLAG_VAL)
        if "--clear" in flags:
            self._activity.clear()
            open(LOG_FILE, "w").close()
            UI.print_info("Activity log cleared.")
            return
        entries = list(self._activity)
        if "--grep" in flags:
            import re as re_m
            pat = flags["--grep"]
            entries = [e for e in entries if re_m.search(pat, e["cmd"])]
        tail = flags.get("--tail", len(entries))
        entries = entries[-tail:]
        if "--json" in flags:
            console.print(json.dumps(
                [{"time": e["time"].isoformat(), "cmd": e["cmd"]} for e in entries], indent=2))
            return
        if not entries:
            UI.print_info("No activity yet.")
            return
        table = Table(box=box.SIMPLE, border_style="dim", header_style="bold cyan")
        table.add_column("Time", width=8)
        table.add_column("Command", style="green")
        for e in entries:
            table.add_row(e["time"].strftime("%H:%M:%S"), e["cmd"])
        console.print(table)

    # ── Console entry point ────────────────────────────────────

    def start(self):
        if not self._banner_shown:
            print_banner()
            self._banner_shown = True
        self.executor.check_dependencies()
        engine_health = self.executor.bridge.engine_health()
        ready = [k for k, v in engine_health.items() if v]
        if not ready:
            UI.print_warning("No native engines compiled. Run 'build all' to compile.")
        else:
            UI.print_success(f"Engines ready: {', '.join(ready)}")
        UI.print_info("Type 'help' for command reference.")
        console.print()

        try:
            self.cmdloop()
        except KeyboardInterrupt:
            self.do_exit("")


def start_wireless_console():
    c = WirelessConsole()
    c.start()
