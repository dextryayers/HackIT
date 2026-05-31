import subprocess
import os

class EngineBridge:
    def __init__(self):
        # High performance self-healing path resolution: check release first, then debug, then custom builds
        base_dir = os.path.dirname(__file__)
        candidate_paths = [
            os.path.join(base_dir, "rust_engine", "target", "release", "hackit_wireless_engine"),
            os.path.join(base_dir, "rust_engine", "target", "debug", "hackit_wireless_engine"),
            os.path.join(base_dir, "rust_engine", "target_custom", "release", "hackit_wireless_engine"),
            os.path.join(base_dir, "rust_engine", "target_custom", "debug", "hackit_wireless_engine"),
        ]
        
        self.rust_engine_path = candidate_paths[0]
        for path in candidate_paths:
            full_path = path + ".exe" if os.name == "nt" else path
            if os.path.exists(full_path):
                self.rust_engine_path = full_path
                break
                
        self.go_worker_path = os.path.join(base_dir, "go_workers", "hackit-worker")
        
    def check_engine_health(self):
        full_path = self.rust_engine_path
        if not full_path.endswith(".exe") and os.name == "nt":
            full_path += ".exe"
        return os.path.exists(full_path)

    def _get_creation_flags(self):
        # Optimization: use High Priority scheduling class under Windows for real-time networking packet processing
        if os.name == "nt":
            return 0x00000080  # HIGH_PRIORITY_CLASS
        return 0

    def launch_rust_sniff(self, interface: str, monitor: bool = False):
        cmd = [self.rust_engine_path, "sniff", "-i", interface]
        if monitor:
            cmd.append("--monitor")
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                creationflags=self._get_creation_flags(), universal_newlines=True)

    def launch_go_crack(self, hashfile: str, wordlist: str):
        worker_bin = self.go_worker_path
        if os.name == "nt":
            worker_bin += ".exe"
        cmd = [worker_bin, "crack", hashfile, wordlist]
        go_dir = os.path.join(os.path.dirname(__file__), "go_workers")
        return subprocess.Popen(cmd, cwd=go_dir, creationflags=self._get_creation_flags())

    def launch_go_mode(self, interface: str, mode: str):
        worker_bin = self.go_worker_path
        if os.name == "nt":
            worker_bin += ".exe"
        cmd = [worker_bin, "mode", interface, mode]
        go_dir = os.path.join(os.path.dirname(__file__), "go_workers")
        return subprocess.Popen(cmd, cwd=go_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                creationflags=self._get_creation_flags(), universal_newlines=True)

    def launch_go_audit(self, ssid: str, bssid: str):
        worker_bin = self.go_worker_path
        if os.name == "nt":
            worker_bin += ".exe"
        cmd = [worker_bin, "audit", ssid, bssid]
        go_dir = os.path.join(os.path.dirname(__file__), "go_workers")
        return subprocess.Popen(cmd, cwd=go_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                creationflags=self._get_creation_flags(), universal_newlines=True)

    def launch_rust_map(self, ssid: str, bssid: str, whitelist_file: str = None):
        cmd = [self.rust_engine_path, "map", "--ssid", ssid, "--bssid", bssid]
        if whitelist_file:
            cmd.extend(["--whitelist", whitelist_file])
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                creationflags=self._get_creation_flags(), universal_newlines=True)

    def launch_go_adapter_info(self, interface: str):
        worker_bin = self.go_worker_path
        if os.name == "nt":
            worker_bin += ".exe"
        cmd = [worker_bin, "adapter-info", interface]
        go_dir = os.path.join(os.path.dirname(__file__), "go_workers")
        return subprocess.Popen(cmd, cwd=go_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                creationflags=self._get_creation_flags(), universal_newlines=True)

    def launch_go_mac(self, interface: str, action: str):
        worker_bin = self.go_worker_path
        if os.name == "nt":
            worker_bin += ".exe"
        cmd = [worker_bin, "mac", interface, action]
        go_dir = os.path.join(os.path.dirname(__file__), "go_workers")
        return subprocess.Popen(cmd, cwd=go_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                creationflags=self._get_creation_flags(), universal_newlines=True)

    def launch_go_txpower(self, interface: str, value: int):
        worker_bin = self.go_worker_path
        if os.name == "nt":
            worker_bin += ".exe"
        cmd = [worker_bin, "txpower", interface, str(value)]
        go_dir = os.path.join(os.path.dirname(__file__), "go_workers")
        return subprocess.Popen(cmd, cwd=go_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                creationflags=self._get_creation_flags(), universal_newlines=True)

    def launch_go_channel(self, interface: str, channel: int):
        worker_bin = self.go_worker_path
        if os.name == "nt":
            worker_bin += ".exe"
        cmd = [worker_bin, "channel", interface, str(channel)]
        go_dir = os.path.join(os.path.dirname(__file__), "go_workers")
        return subprocess.Popen(cmd, cwd=go_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                creationflags=self._get_creation_flags(), universal_newlines=True)

    def launch_go_status(self, interface: str):
        worker_bin = self.go_worker_path
        if os.name == "nt":
            worker_bin += ".exe"
        cmd = [worker_bin, "status", interface]
        go_dir = os.path.join(os.path.dirname(__file__), "go_workers")
        return subprocess.Popen(cmd, cwd=go_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                creationflags=self._get_creation_flags(), universal_newlines=True)

    # ──────────────── New Phase 1-6 Launchers ────────────────────────────────

    def _find_rust_binary(self) -> str | None:
        """Return absolute path to Rust engine binary if it exists, else None."""
        full = self.rust_engine_path
        if os.name == "nt" and not full.endswith(".exe"):
            full += ".exe"
        return full if os.path.exists(full) else None

    def launch_rust_recon(self, iface: str):
        return subprocess.Popen(
            [self.rust_engine_path, "recon", "--iface", iface],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=self._get_creation_flags(), universal_newlines=True)

    def launch_rust_arp_scan(self, subnet: str):
        return subprocess.Popen(
            [self.rust_engine_path, "arp-scan", "--subnet", subnet],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=self._get_creation_flags(), universal_newlines=True)

    def launch_rust_port_scan(self, host: str):
        return subprocess.Popen(
            [self.rust_engine_path, "port-scan", f"--host={host}"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=self._get_creation_flags(), universal_newlines=True)

    def launch_rust_osdetect(self, host: str):
        return subprocess.Popen(
            [self.rust_engine_path, "osdetect", f"--host={host}"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=self._get_creation_flags(), universal_newlines=True)

    def launch_rust_deauth(self, bssid: str, station: str = "FF:FF:FF:FF:FF:FF", count: int = 10):
        return subprocess.Popen(
            [self.rust_engine_path, "deauth",
             "--bssid", bssid, "--station", station, "--count", str(count)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=self._get_creation_flags(), universal_newlines=True)

    def launch_rust_beacon_flood(self, ssid: str, bssid: str, channel: int = 6, count: int = 50):
        return subprocess.Popen(
            [self.rust_engine_path, "beacon-flood",
             "--ssid", ssid, "--bssid", bssid,
             "--channel", str(channel), "--count", str(count)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=self._get_creation_flags(), universal_newlines=True)

    def launch_rust_capture(self, iface: str, output: str = "capture.pcap"):
        return subprocess.Popen(
            [self.rust_engine_path, "capture", f"--iface={iface}", f"--output={output}"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=self._get_creation_flags(), universal_newlines=True)

    def launch_go_arp_spoof(self, target: str, gateway: str):
        worker_bin = self.go_worker_path
        if os.name == "nt":
            worker_bin += ".exe"
        go_dir = os.path.join(os.path.dirname(__file__), "go_workers")
        return subprocess.Popen(
            [worker_bin, "arp-spoof", target, gateway],
            cwd=go_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=self._get_creation_flags(), universal_newlines=True)

