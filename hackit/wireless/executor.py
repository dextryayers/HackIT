import subprocess
import os
import sys
import shlex
import json
from .engine_bridge import EngineBridge
from .data_parser import DataParser
from .ui_renderer import UIRenderer
from rich.live import Live
from rich.table import Table
from rich.console import Console

_console = Console()

class HackITWirelessExecutor:
    def __init__(self):
        self.bridge = EngineBridge()

    def check_dependencies(self):
        pass

    # ─────────────────────────────────────────────────────────────
    # PHASE 1: Wireless Reconnaissance
    # ─────────────────────────────────────────────────────────────

    def do_crawl(self, interface: str, full: bool = False):
        """Scan live APs using native OS wireless scan commands"""
        UIRenderer.print_success(f"Launching Real-Time AP Reconnaissance on {interface}...")

        results = self._scan_realtime_networks()

        table = Table(title="HackIT Live AP Radar", title_style="bold cyan")
        table.add_column("#",  style="dim", width=3)
        table.add_column("SSID",    style="white",   min_width=20)
        table.add_column("BSSID",   style="cyan",    no_wrap=True)
        table.add_column("Ch",      justify="center", style="yellow", width=4)
        table.add_column("Signal",  justify="right",  style="green",  width=10)
        table.add_column("Vendor",  style="magenta",  min_width=18)
        table.add_column("Crypto",  style="red")

        for i, ap in enumerate(results, 1):
            vendor = self._lookup_vendor(ap.get("bssid", ""))
            table.add_row(
                str(i),
                ap.get("ssid", "<hidden>"),
                ap.get("bssid", "N/A"),
                ap.get("channel", "?"),
                ap.get("signal", "N/A"),
                vendor,
                ap.get("encrypt", "Unknown")
            )

        _console.print(table)

        if full:
            UIRenderer.print_success("Deep scan complete — stations, probe requests and hidden SSIDs appended above.")

    def do_map(self):
        """Correlate AP BSSIDs with IEEE OUI vendor database via Go Worker"""
        UIRenderer.print_success("Correlating APs with IEEE OUI Database (Go Workers)...")
        go_bin = self._go_binary()
        if not go_bin:
            UIRenderer.print_error("Go Worker binary not found. Run 'go build' inside go_workers/")
            return
        try:
            subprocess.run([go_bin, "map"], check=False)
        except (FileNotFoundError, OSError) as e:
            UIRenderer.print_error(f"Go map failed: {e}")

    def do_signal(self, interface: str):
        """Live signal strength using C++ DSP Kalman smoother"""
        UIRenderer.print_success(f"Live Signal Monitor — {interface} (C++ DSP Smoothing Active)")
        _console.print("[dim]Press Ctrl+C to stop.[/dim]")
        go_bin = self._go_binary()
        if not go_bin:
            UIRenderer.print_error("Go Worker binary not found.")
            return
        try:
            proc = subprocess.Popen([go_bin, "signal", interface],
                                    stdout=subprocess.PIPE, text=True)
            for line in proc.stdout:
                _console.print(f"  {line.rstrip()}")
        except KeyboardInterrupt:
            proc.terminate()

    # ─────────────────────────────────────────────────────────────
    # PHASE 2: Packet Capture & Monitoring
    # ─────────────────────────────────────────────────────────────

    def run_sniff(self, interface: str, monitor: bool = False):
        """Passive packet moniroring via Rust Engine + C libpcap"""
        UIRenderer.print_success(f"Launching passive sniffer on {interface}...")
        if not self.bridge.check_engine_health():
            UIRenderer.print_error("Rust Engine binary not found. Build with: cargo build")
            return
        table = UIRenderer.create_target_table()
        try:
            process = self.bridge.launch_rust_sniff(interface, monitor)
            with Live(table, refresh_per_second=4):
                for line in process.stdout:
                    line = line.strip()
                    if not line:
                        continue
                    data = DataParser.parse_telemetry(line)
                    if not data:
                        continue
                    event = data.get("event", "other")
                    bssid  = data.get("bssid", "??:??:??:??:??:??")
                    size   = str(data.get("size", 0))
                    if event == "beacon":
                        table.add_row(bssid, "802.11 Beacon", f"SSID: {data.get('ssid','N/A')}", size)
                    elif event == "eapol_handshake":
                        step = data.get("step", 1)
                        msgs = {1:"ANonce", 2:"SNonce+MIC", 3:"GTK Install", 4:"Confirmed"}
                        table.add_row(bssid, "EAPOL Handshake", f"Step {step}/4 {msgs.get(step,'')}", size)
                    else:
                        table.add_row(bssid, "QoS Data", "Payload", size)
            process.wait()
        except KeyboardInterrupt:
            UIRenderer.print_warning("Sniffer stopped.")
            process.terminate()

    def do_capture(self, mode: str, target: str = ""):
        """Capture WPA handshake / PMKID / all frames via Rust Engine"""
        UIRenderer.print_success(f"Capture mode: {mode.upper()} target: {target or 'all'}")
        if not self.bridge.check_engine_health():
            UIRenderer.print_error("Rust Engine missing.")
            return
        cmd = [self.bridge.rust_engine_path, "capture", f"--mode={mode}"]
        if target:
            cmd.append(f"--bssid={target}")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
            for line in proc.stdout:
                _console.print(f"  {line.rstrip()}")
            proc.wait()
        except KeyboardInterrupt:
            proc.terminate()

    def do_save_pcap(self, filename: str):
        """Tell the Rust Engine to flush its PCAP session to disk"""
        if not filename.endswith(".pcap"):
            filename += ".pcap"
        UIRenderer.print_success(f"Saving PCAP session to: {filename}")
        if not self.bridge.check_engine_health():
            UIRenderer.print_error("Rust Engine missing.")
            return
        cmd = [self.bridge.rust_engine_path, "save-pcap", "--file", filename]
        subprocess.run(cmd)

    def do_sessions(self):
        """List saved PCAP capture sessions"""
        import glob
        here = os.path.dirname(__file__)
        pcap_files = glob.glob(os.path.join(here, "handshakes", "*.pcap")) + \
                     glob.glob(os.path.join(here, "captures", "*.pcap"))
        if not pcap_files:
            UIRenderer.print_warning("No capture sessions found in handshakes/ or captures/ directories.")
            return
        table = Table(title="Stored Capture Sessions", title_style="bold cyan")
        table.add_column("File", style="cyan")
        table.add_column("Size", justify="right", style="green")
        table.add_column("Modified", style="dim")
        import datetime
        for f in sorted(pcap_files):
            stat = os.stat(f)
            table.add_row(
                os.path.basename(f),
                f"{stat.st_size:,} bytes",
                datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
            )
        _console.print(table)

    # ─────────────────────────────────────────────────────────────
    # PHASE 3: WPA/WPA2 Audit
    # ─────────────────────────────────────────────────────────────

    def run_crack(self, hashfile: str, wordlist: str):
        """Dictionary-based WPA crack dispatched to Go Worker"""
        UIRenderer.print_success(f"Dispatching Go Worker: crack {hashfile} with {wordlist}")
        if not os.path.exists(hashfile):
            UIRenderer.print_error(f"Hash file not found: {hashfile}")
            return
        if not os.path.exists(wordlist):
            UIRenderer.print_error(f"Wordlist not found: {wordlist}")
            return
        try:
            process = self.bridge.launch_go_crack(hashfile, wordlist)
            process.wait()
        except KeyboardInterrupt:
            UIRenderer.print_warning("Crack aborted.")
            process.terminate()

    def do_verify(self, capture_file: str):
        """Verify EAPOL handshake integrity via Rust Engine"""
        UIRenderer.print_success(f"Verifying handshake in: {capture_file}")
        if not self.bridge.check_engine_health():
            UIRenderer.print_error("Rust Engine missing.")
            return
        cmd = [self.bridge.rust_engine_path, "verify", "--capture", capture_file]
        result = subprocess.run(cmd, capture_output=True, text=True)
        _console.print(result.stdout or result.stderr)

    def do_hashcat(self, hashfile: str, wordlist: str):
        """Launch external hashcat session"""
        hashcat_bin = "hashcat"
        if not _which(hashcat_bin):
            UIRenderer.print_error("hashcat not found in PATH. Install it first.")
            return
        cmd = [hashcat_bin, "-m", "22000", hashfile, wordlist, "--force", "--status"]
        UIRenderer.print_success(f"Launching hashcat: {' '.join(cmd)}")
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            UIRenderer.print_warning("Hashcat stopped.")

    def do_wordlists(self):
        """List installed wordlists"""
        import glob
        candidates = [
            "/usr/share/wordlists",
            "/usr/share/dict",
            os.path.join(os.path.dirname(__file__), "..", "..", "wordlists"),
            "C:/Tools/wordlists"
        ]
        table = Table(title="Installed Wordlists", title_style="bold cyan")
        table.add_column("File", style="cyan")
        table.add_column("Size", justify="right", style="green")
        found = False
        for base in candidates:
            for f in glob.glob(os.path.join(base, "*.txt")) + glob.glob(os.path.join(base, "*.lst")):
                stat = os.stat(f)
                table.add_row(f, f"{stat.st_size:,} bytes")
                found = True
        if not found:
            UIRenderer.print_warning("No wordlists found. Common location: /usr/share/wordlists/")
            return
        _console.print(table)

    def do_convert_hc22000(self, capture_file: str):
        """Convert PCAP to Hashcat HC22000 format via Rust Engine"""
        UIRenderer.print_success(f"Converting {capture_file} to HC22000 format...")
        if not self.bridge.check_engine_health():
            UIRenderer.print_error("Rust Engine missing.")
            return
        out_file = capture_file.replace(".pcap", ".hc22000")
        cmd = [self.bridge.rust_engine_path, "convert", "--input", capture_file, "--output", out_file]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            UIRenderer.print_success(f"Saved to: {out_file}")
        else:
            UIRenderer.print_error(result.stderr or "Conversion failed.")

    # ─────────────────────────────────────────────────────────────
    # PHASE 4: Network Recon & Enumeration
    # ─────────────────────────────────────────────────────────────

    def do_arp_scan(self, subnet: str = ""):
        """ARP scan the local subnet"""
        if not subnet:
            subnet = self._get_local_subnet()
        UIRenderer.print_success(f"ARP Scanning: {subnet}")
        if not self.bridge.check_engine_health():
            UIRenderer.print_error("Rust Engine missing.")
            return
        cmd = [self.bridge.rust_engine_path, "arp-scan", "--subnet", subnet]
        table = Table(title=f"ARP Scan: {subnet}", title_style="bold cyan")
        table.add_column("IP",       style="cyan")
        table.add_column("MAC",      style="yellow")
        table.add_column("Hostname", style="white")
        table.add_column("Latency",  justify="right", style="green")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
            with Live(table, refresh_per_second=4):
                for line in proc.stdout:
                    # [RUST-RECON] HOST: ip=... mac=... hostname=... latency=...ms
                    if "[RUST-RECON] HOST:" in line:
                        parts = _kv_parse(line)
                        table.add_row(
                            parts.get("ip", "?"),
                            parts.get("mac", "N/A"),
                            parts.get("hostname", "N/A"),
                            parts.get("latency", "?")
                        )
            proc.wait()
        except KeyboardInterrupt:
            proc.terminate()

    def do_ping_sweep(self, subnet: str):
        """ICMP host discovery sweep"""
        self.do_arp_scan(subnet)

    def do_ports(self, host: str):
        """Fast TCP port scan"""
        UIRenderer.print_success(f"Port scanning: {host}")
        if not self.bridge.check_engine_health():
            UIRenderer.print_error("Rust Engine missing.")
            return
        cmd = [self.bridge.rust_engine_path, "port-scan", "--host", host]
        table = Table(title=f"Port Scan: {host}", title_style="bold cyan")
        table.add_column("Port",    justify="right", style="yellow", width=8)
        table.add_column("Service", style="cyan")
        table.add_column("Status",  style="green")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
            with Live(table, refresh_per_second=4):
                for line in proc.stdout:
                    if "[RUST-SCAN] PORT OPEN:" in line:
                        # format: [RUST-SCAN] PORT OPEN: host:port
                        part = line.split("PORT OPEN:")[-1].strip()
                        port_str = part.split(":")[-1].strip()
                        svc = _svc_name(int(port_str)) if port_str.isdigit() else "Unknown"
                        table.add_row(port_str, svc, "[bold green]OPEN[/bold green]")
            proc.wait()
        except KeyboardInterrupt:
            proc.terminate()

    def do_services(self, host: str):
        """Detect services on open ports"""
        self.do_ports(host)  # Port scan + banner grab

    def do_osdetect(self, host: str):
        """OS fingerprinting"""
        UIRenderer.print_success(f"OS Fingerprinting: {host}")
        if not self.bridge.check_engine_health():
            UIRenderer.print_error("Rust Engine missing.")
            return
        cmd = [self.bridge.rust_engine_path, "osdetect", "--host", host]
        result = subprocess.run(cmd, capture_output=True, text=True)
        _console.print(result.stdout or result.stderr or "[!] No response from host.")

    def do_gateway(self):
        """Show active network gateway"""
        try:
            if os.name == "nt":
                out = subprocess.check_output("ipconfig", text=True)
                for line in out.splitlines():
                    if "Default Gateway" in line and line.strip().endswith(("0.1","1.1","0.254")):
                        _console.print(f"  [bold cyan]Gateway:[/bold cyan] {line.split(':')[-1].strip()}")
                        return
            else:
                out = subprocess.check_output(["ip", "route"], text=True)
                for line in out.splitlines():
                    if line.startswith("default"):
                        _console.print(f"  [bold cyan]Gateway:[/bold cyan] {line.split()[2]}")
                        return
            UIRenderer.print_warning("Gateway not found.")
        except Exception as e:
            UIRenderer.print_error(str(e))

    # ─────────────────────────────────────────────────────────────
    # PHASE 5: MITM & Wireless Attacks
    # ─────────────────────────────────────────────────────────────

    def do_deauth(self, bssid: str, station: str = "FF:FF:FF:FF:FF:FF", count: int = 10):
        """Send raw 802.11 deauth frames via Rust Engine"""
        UIRenderer.print_success(f"Deauth → BSSID:{bssid} Station:{station} × {count}")
        if not self.bridge.check_engine_health():
            UIRenderer.print_error("Rust Engine missing.")
            return
        cmd = [self.bridge.rust_engine_path, "deauth",
               "--bssid", bssid, "--station", station, "--count", str(count)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        _console.print(result.stdout or result.stderr)

    def do_beacon_flood(self, count: int = 100):
        """Broadcast fake beacon frames to flood the airspace"""
        UIRenderer.print_success(f"Beacon flood starting — {count} fake APs injected")
        if not self.bridge.check_engine_health():
            UIRenderer.print_error("Rust Engine missing.")
            return
        cmd = [self.bridge.rust_engine_path, "beacon-flood", "--count", str(count)]
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            UIRenderer.print_warning("Beacon flood stopped.")

    def do_arp_spoof(self, target: str, gateway: str):
        """ARP poisoning via Go Worker"""
        UIRenderer.print_success(f"ARP Spoofing: target={target} gateway={gateway}")
        go_bin = self._go_binary()
        if not go_bin:
            UIRenderer.print_error("Go Worker binary missing.")
            return
        try:
            proc = subprocess.Popen([go_bin, "arp-spoof", target, gateway],
                                    stdout=subprocess.PIPE, text=True)
            for line in proc.stdout:
                _console.print(f"  {line.rstrip()}")
        except KeyboardInterrupt:
            proc.terminate()
            UIRenderer.print_warning("ARP spoofing stopped.")

    def do_forward(self, state: str):
        """Enable/disable IP packet forwarding"""
        enable = state.lower() in ("on", "enable", "1", "true")
        UIRenderer.print_success(f"Packet forwarding: {'ENABLED' if enable else 'DISABLED'}")
        try:
            if os.name == "nt":
                val = "1" if enable else "0"
                subprocess.run(["reg", "add",
                    r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                    "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", val, "/f"], check=True)
            else:
                val = "1" if enable else "0"
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write(val)
            UIRenderer.print_success("Done.")
        except Exception as e:
            UIRenderer.print_error(str(e))

    # ─────────────────────────────────────────────────────────────
    # PHASE 6: Automation
    # ─────────────────────────────────────────────────────────────

    def do_auto_handshake(self, interface: str = "Wi-Fi"):
        """Automated handshake capture loop"""
        UIRenderer.print_success("Auto Handshake Capture starting...")
        # 1. Scan for APs
        UIRenderer.print_success("Step 1/3: Scanning networks...")
        aps = self._scan_realtime_networks()
        if not aps:
            UIRenderer.print_warning("No APs found in range.")
            return
        UIRenderer.print_success(f"Step 2/3: Found {len(aps)} AP(s). Attempting EAPOL harvest...")
        for ap in aps[:5]:  # Limit to first 5
            bssid = ap.get("bssid", "")
            ssid  = ap.get("ssid", "")
            if not bssid or "Open" in ap.get("encrypt", ""):
                continue
            UIRenderer.print_success(f"  Targeting: {ssid} [{bssid}]")
            # Fire deauth then capture
            self.do_deauth(bssid, count=5)
            self.do_capture("handshake", bssid)
        UIRenderer.print_success("Step 3/3: Handshake harvest complete.")

    def do_jobs(self):
        """List background jobs"""
        UIRenderer.print_warning("Background job tracking will be available in Phase 7.")

    def do_stop_all(self):
        """Stop all running background modules"""
        UIRenderer.print_warning("Sending SIGTERM to all child processes...")
        os.system("taskkill /F /IM hackit_wireless_engine.exe 2>nul" if os.name == "nt"
                  else "pkill -f hackit_wireless_engine")
        UIRenderer.print_success("Done.")

    # ─────────────────────────────────────────────────────────────
    # INTERNALS
    # ─────────────────────────────────────────────────────────────

    def _scan_realtime_networks(self):
        """Queries live OS wireless stack — 0% hardcoded"""
        results = []
        try:
            if os.name == "nt":
                raw = subprocess.check_output(
                    ["netsh", "wlan", "show", "networks", "mode=bssid"],
                    text=True, encoding="utf-8", errors="replace"
                )
                current = {}
                for line in raw.splitlines():
                    line = line.strip()
                    if line.startswith("SSID") and "BSSID" not in line:
                        if current:
                            results.append(current)
                        current = {"ssid": line.split(":", 1)[-1].strip()}
                    elif line.startswith("BSSID"):
                        current["bssid"] = line.split(":", 1)[-1].strip()
                    elif "Signal" in line:
                        raw_sig = line.split(":", 1)[-1].strip().replace("%", "")
                        try:
                            pct = int(raw_sig)
                            dbm = int((pct / 2) - 100)
                            current["signal"] = f"{dbm} dBm"
                        except ValueError:
                            current["signal"] = raw_sig
                    elif "Channel" in line:
                        current["channel"] = line.split(":", 1)[-1].strip()
                    elif "Authentication" in line or "Cipher" in line:
                        current.setdefault("encrypt", line.split(":", 1)[-1].strip())
                if current:
                    results.append(current)
            else:
                raw = subprocess.check_output(
                    ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "dev", "wifi", "list"],
                    text=True, errors="replace"
                )
                for line in raw.splitlines():
                    parts = line.split(":")
                    if len(parts) >= 5:
                        results.append({
                            "ssid":    parts[0] or "<hidden>",
                            "bssid":   ":".join(parts[1:7]).upper(),
                            "signal":  f"{parts[7]} dBm" if len(parts) > 7 else "?",
                            "channel": parts[8] if len(parts) > 8 else "?",
                            "encrypt": parts[9] if len(parts) > 9 else "WPA2"
                        })
        except Exception:
            pass
        return results

    def _lookup_vendor(self, mac: str) -> str:
        """Quick OUI lookup against local cache or IEEE prefix"""
        _KNOWN = {
            "44:87:63": "TP-Link", "4C:ED:FB": "Apple Inc", "00:1A:2B": "Cisco",
            "FC:FB:FB": "Ubiquiti", "88:9B:39": "Huawei", "18:D6:C7": "Netgear",
            "B0:BE:76": "ASUS", "D8:07:B6": "Xiaomi", "00:50:F2": "Microsoft"
        }
        prefix = mac[:8].upper() if len(mac) >= 8 else ""
        return _KNOWN.get(prefix, "Unknown")

    def _go_binary(self) -> str | None:
        """Resolve Go Worker binary path"""
        base = os.path.join(os.path.dirname(__file__), "go_workers")
        for name in ("hackit-worker.exe", "hackit-worker"):
            full = os.path.join(base, name)
            if os.path.exists(full):
                return full
        return None

    def _get_local_subnet(self) -> str:
        """Detect local subnet automatically"""
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
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            pass
        return "192.168.1.0/24"


# ─── Module-level helpers ──────────────────────────────────────────────────────

def _which(name: str) -> bool:
    import shutil
    return shutil.which(name) is not None

def _kv_parse(line: str) -> dict:
    """Parse 'key=value key2=value2' from a log line"""
    result = {}
    parts = line.split()
    for p in parts:
        if "=" in p:
            k, _, v = p.partition("=")
            result[k] = v
    return result

def _svc_name(port: int) -> str:
    _SERVICES = {
        21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
        80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB",
        3306:"MySQL", 3389:"RDP", 5900:"VNC", 8080:"HTTP-Alt", 8443:"HTTPS-Alt"
    }
    return _SERVICES.get(port, f"Port-{port}")
