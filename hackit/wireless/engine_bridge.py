import os, sys, subprocess, shutil, json, platform, glob, time, threading
from pathlib import Path
from typing import Optional

BASE = Path(__file__).parent


class EngineBuildError(RuntimeError):
    pass


class EngineBridge:
    def __init__(self):
        self._go_bin: Optional[str] = None
        self._rust_bin: Optional[str] = None
        self._c_lib: Optional[str] = None
        self._cxx_lib: Optional[str] = None
        self._cs_bin: Optional[str] = None
        self._discover_engines()

    # ── Engine discovery ────────────────────────────────────────

    def _discover_engines(self):
        self._go_bin = self._find_go_worker()
        self._rust_bin = self._find_rust_engine()
        self._c_lib = self._find_clib("libhackit_wireless_c")
        self._cxx_lib = self._c_lib  # C++ compiled into same shared lib
        self._cs_bin = self._find_csharp()

    def _find_go_worker(self) -> Optional[str]:
        candidates = [
            BASE / "go_workers" / "hackit-worker",
            BASE / "go_workers" / "hackit-worker.exe",
            BASE / "go_workers" / "bin" / "hackit-worker",
        ]
        for p in candidates:
            if p.exists():
                return str(p)
        if shutil.which("go"):
            return "go_build"  # marker
        return None

    def _find_rust_engine(self) -> Optional[str]:
        for root in [BASE / "rust_engine", BASE / "rust_engine" / "target_custom"]:
            for d in [root / "target" / "release", root / "target" / "debug"]:
                for name in ["hackit_wireless_engine", "hackit_wireless_engine.exe"]:
                    p = d / name
                    if p.exists():
                        return str(p)
        if shutil.which("cargo"):
            return "cargo_build"
        return None

    def _find_clib(self, name: str) -> Optional[str]:
        for d in [BASE / "c_core", BASE / "c_core/build", BASE / "c_core/build/lib"]:
            for ext in [".so", ".a", ".dylib", ".dll"]:
                p = d / f"{name}{ext}"
                if p.exists():
                    return str(p)
        return None

    def _find_csharp(self) -> Optional[str]:
        for name in ["HackItWireless.exe", "HackItWireless.dll"]:
            for sub in ["net6.0", "net8.0", "net9.0", ""]:
                d = BASE / "hackitwireless-cs" / "bin" / "Release"
                if sub: d = d / sub
                p = d / name
                if p.exists():
                    return str(p)
        return None

    def engine_health(self) -> dict:
        return {
            "go": self._go_bin is not None,
            "rust": self._rust_bin is not None,
            "c": self._c_lib is not None,
            "cxx": self._cxx_lib is not None,
            "csharp": self._cs_bin is not None,
        }

    def get_available_engines(self) -> list:
        return [k for k, v in self.engine_health().items() if v]

    # ── Build system ────────────────────────────────────────────

    def build_all(self, progress_callback=None):
        results = {}
        results["go"] = self._build_go(progress_callback)
        results["rust"] = self._build_rust(progress_callback)
        results["c_core"] = self._build_c_core(progress_callback)
        results["csharp"] = self._build_csharp(progress_callback)
        self._discover_engines()
        return results

    def _build_go(self, cb) -> bool:
        if not shutil.which("go"):
            return False
        go_dir = BASE / "go_workers"
        if cb:
            cb("go", "Compiling Go workers...")
        try:
            out_dir = go_dir / "bin"
            out_dir.mkdir(exist_ok=True)
            binary = out_dir / ("hackit-worker.exe" if os.name == "nt" else "hackit-worker")
            subprocess.run(
                ["go", "build", "-ldflags=-s -w", "-o", str(binary), "."],
                cwd=str(go_dir), check=True, capture_output=True, text=True
            )
            os.chmod(binary, 0o755)
            self._go_bin = str(binary)
            return True
        except subprocess.CalledProcessError as e:
            if cb:
                cb("go", f"FAILED: {e.stderr[:200]}")
            return False

    def _build_rust(self, cb) -> bool:
        if not shutil.which("cargo"):
            return False
        rust_dir = BASE / "rust_engine"
        if cb:
            cb("rust", "Compiling Rust engine (release)...")
        try:
            subprocess.run(
                ["cargo", "build", "--release"],
                cwd=str(rust_dir), check=True, capture_output=True, text=True
            )
            self._discover_engines()
            return self._rust_bin is not None
        except subprocess.CalledProcessError as e:
            if cb:
                cb("rust", f"FAILED: {e.stderr[:200]}")
            return False

    def _build_c_core(self, cb) -> bool:
        if not shutil.which("cmake"):
            return False
        c_dir = BASE / "c_core"
        build_dir = c_dir / "build"
        build_dir.mkdir(exist_ok=True)
        if cb:
            cb("c_core", "Building C/C++ core with CMake...")
        try:
            subprocess.run(
                ["cmake", "..", "-DCMAKE_BUILD_TYPE=Release"],
                cwd=str(build_dir), check=True, capture_output=True, text=True
            )
            subprocess.run(
                ["make", "-j$(nproc)"],
                cwd=str(build_dir), check=True, capture_output=True, text=True
            )
            self._discover_engines()
            return self._c_lib is not None or self._cxx_lib is not None
        except subprocess.CalledProcessError as e:
            if cb:
                cb("c_core", f"FAILED: {e.stderr[:200]}")
            return False

    def _build_csharp(self, cb) -> bool:
        if not shutil.which("dotnet"):
            return False
        cs_dir = BASE / "hackitwireless-cs"
        if cb:
            cb("csharp", "Building C# components...")
        try:
            subprocess.run(
                ["dotnet", "build", "-c", "Release"],
                cwd=str(cs_dir), check=True, capture_output=True, text=True
            )
            self._discover_engines()
            return self._cs_bin is not None
        except subprocess.CalledProcessError as e:
            if cb:
                cb("csharp", f"FAILED: {e.stderr[:200]}")
            return False

    # ── Rust engine execution ──────────────────────────────────

    def _ensure_rust(self) -> str:
        if self._rust_bin:
            return self._rust_bin
        if self._build_rust(None):
            if self._rust_bin:
                return self._rust_bin
        raise EngineBuildError("Rust engine not built. Run 'build' first.")

    def rust_sniff(self, iface: str, monitor: bool = False, filters: str = ""):
        cmd = [self._ensure_rust(), "sniff", "-i", iface]
        if monitor:
            cmd.append("--monitor")
        if filters:
            cmd.extend(["--filters", filters])
        return self._popen(cmd)

    def rust_handshake(self, iface: str, bssid: str = "", output: str = "", timeout: int = 30):
        cmd = [self._ensure_rust(), "handshake", "--interface", iface, "--timeout", str(timeout)]
        if bssid:
            cmd.extend(["--bssid", bssid])
        if output:
            cmd.extend(["--output", output])
        return self._popen(cmd)

    def rust_deauth(self, iface: str, bssid: str, station: str = "", count: int = 10, reason: int = 7):
        cmd = [self._ensure_rust(), "deauth", "--interface", iface, "--bssid", bssid, "--count", str(count)]
        if station:
            cmd.extend(["--station", station])
        return self._popen(cmd)

    def rust_beacon_flood(self, iface: str, ssid: str = "", count: int = 50, channel: int = 6):
        cmd = [self._ensure_rust(), "beacon-flood", "--interface", iface, "--count", str(count), "--channel", str(channel)]
        if ssid:
            cmd.extend(["--ssid", ssid])
        return self._popen(cmd)

    def rust_capture(self, iface: str, output: str = "capture.pcap"):
        cmd = [self._ensure_rust(), "capture", "--interface", iface, "--output", output]
        return self._popen(cmd)

    def rust_arp_scan(self, subnet: str):
        return self._popen([self._ensure_rust(), "arp-scan", "--subnet", subnet])

    def rust_arp_spoof(self, target: str, gateway: str):
        return self._popen([self._ensure_rust(), "arp-spoof", "--target", target, "--gateway", gateway])

    def rust_port_scan(self, host: str, ports: str = "1-1024"):
        return self._popen([self._ensure_rust(), "port-scan", "--host", host, "--ports", ports])

    def rust_os_detect(self, host: str):
        return self._popen([self._ensure_rust(), "osdetect", "--host", host])

    def rust_aggressive_scan(self, iface: str, band: str = "both"):
        return self._popen([self._ensure_rust(), "aggressive-scan", "--interface", iface, "--band", band])

    def rust_client_hunt(self, iface: str, bssid: str = ""):
        cmd = [self._ensure_rust(), "client-hunt", "--interface", iface]
        if bssid:
            cmd.extend(["--bssid", bssid])
        return self._popen(cmd)

    def rust_wpa3_detect(self, iface: str):
        return self._popen([self._ensure_rust(), "wpa3-detect", "--interface", iface])

    def rust_probe_flood(self, iface: str, count: int = 100):
        return self._popen([self._ensure_rust(), "probe-flood", "--interface", iface, "--count", str(count)])

    def rust_verify(self, capture_file: str):
        return subprocess.run([self._ensure_rust(), "verify", "--capture", capture_file],
                              capture_output=True, text=True)

    def rust_convert_hc22000(self, input_file: str, output_file: str = ""):
        cmd = [self._ensure_rust(), "convert", "--input", input_file]
        if output_file:
            cmd.extend(["--output", output_file])
        return subprocess.run(cmd, capture_output=True, text=True)

    def rust_wps_scan(self, iface: str):
        return self._popen([self._ensure_rust(), "wps-scan", "--interface", iface])

    def rust_wps_pixie(self, iface: str, bssid: str, pin: str = ""):
        cmd = [self._ensure_rust(), "wps-pixie", "--interface", iface, "--bssid", bssid]
        if pin:
            cmd.extend(["--pin", pin])
        return self._popen(cmd)

    def rust_wep_capture(self, iface: str, bssid: str, output: str = "wep.pcap"):
        return self._popen([self._ensure_rust(), "wep-capture", "--interface", iface, "--bssid", bssid, "--output", output])

    def rust_wep_arp_replay(self, iface: str, bssid: str):
        return self._popen([self._ensure_rust(), "wep-arp-replay", "--interface", iface, "--bssid", bssid])

    def rust_wep_crack(self, capture: str):
        return subprocess.run([self._ensure_rust(), "wep-crack", "--capture", capture], capture_output=True, text=True)

    # ── Go worker execution ────────────────────────────────────

    def _ensure_go(self) -> str:
        if self._go_bin:
            return self._go_bin
        if self._build_go(None):
            if self._go_bin:
                return self._go_bin
        raise EngineBuildError("Go workers not built. Run 'build' first.")

    def _go_run(self, *args) -> subprocess.Popen:
        return self._popen([self._ensure_go()] + list(args))

    def go_crack(self, hashfile: str, wordlist: str):
        return self._go_run("crack", hashfile, wordlist)

    def go_mode(self, iface: str, mode: str):
        return self._go_run("mode", iface, mode)

    def go_adapter_info(self, iface: str):
        return self._go_run("adapter-info", iface)

    def go_mac(self, iface: str, action: str):
        return self._go_run("mac", iface, action)

    def go_txpower(self, iface: str, val: int):
        return self._go_run("txpower", iface, str(val))

    def go_channel(self, iface: str, ch: int):
        return self._go_run("channel", iface, str(ch))

    def go_status(self, iface: str):
        return self._go_run("status", iface)

    def go_dual_band(self, iface: str):
        return self._go_run("dual-band", iface)

    def go_spectrum(self, iface: str):
        return self._go_run("spectrum", iface)

    def go_wps_pin(self, bssid: str):
        return self._go_run("wps-pin", bssid)

    def go_wep_crack(self, pcap: str):
        return self._go_run("wep-crack", pcap)

    def go_packet_gen(self, iface: str, frame_type: str, ssid: Optional[str] = None):
        cmd = ["packet-gen", iface, frame_type]
        if ssid:
            cmd.append(ssid)
        return self._go_run(*cmd)

    def go_session(self):
        return self._go_run("session")

    def go_session_create(self, bssid: str, ssid: str, channel: int, filepath: str, hash_type: str):
        return self._go_run("session-create", bssid, ssid, str(channel), filepath, hash_type)

    def go_arp_spoof(self, target: str, gateway: str):
        return self._go_run("arp-spoof", target, gateway)

    # ── C/C++ native calls ─────────────────────────────────────

    def c_deauth(self, iface: str, bssid: str, station: str, count: int):
        if not self._c_lib:
            raise EngineBuildError("C library not built.")
        return self._popen([self._c_lib, "deauth", iface, bssid, station or "FF:FF:FF:FF:FF:FF", str(count)])

    def c_frame_inject(self, iface: str, frame_type: str, payload: str = ""):
        if not self._c_lib:
            raise EngineBuildError("C library not built.")
        return self._popen([self._c_lib, "frame-inject", iface, frame_type, payload])

    # ── C# execution (Windows) ─────────────────────────────────

    def cs_run(self, *args):
        if not self._cs_bin:
            if os.name != "nt":
                return None
            raise EngineBuildError("C# binary not built.")
        return self._popen([self._cs_bin] + list(args))

    def cs_adapters(self):
        return self.cs_run("adapters")

    def cs_handshake(self, iface: str, bssid: str):
        return self.cs_run("handshake", iface, bssid)

    def cs_deauth(self, iface: str, bssid: str, station: str):
        return self.cs_run("deauth", iface, bssid, station)

    # ── Utility ────────────────────────────────────────────────

    def _popen(self, cmd: list, **kw) -> subprocess.Popen:
        if os.name == "nt":
            kw.setdefault("creationflags", subprocess.CREATE_NEW_PROCESS_GROUP)
        kw.setdefault("stdout", subprocess.PIPE)
        kw.setdefault("stderr", subprocess.STDOUT)
        kw.setdefault("text", True)
        kw.setdefault("bufsize", 1)
        return subprocess.Popen(cmd, **kw)

    def run_command(self, cmd: list, timeout: Optional[int] = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        )

    # ── OUI / Vendor Lookup (native engines) ────────────────────

    def oui_lookup_go(self, mac: str) -> Optional[str]:
        if self._go_bin:
            try:
                r = subprocess.run([self._go_bin, "vendor", mac], capture_output=True, text=True, timeout=5)
                out = r.stdout.strip()
                return out if out else None
            except Exception:
                return None
        return None

    def oui_lookup_rust(self, mac: str) -> Optional[str]:
        if self._rust_bin:
            try:
                r = subprocess.run([self._rust_bin, "oui-lookup", "-m", mac], capture_output=True, text=True, timeout=5)
                out = r.stdout.strip()
                if out:
                    parts = out.split(None, 1)
                    return parts[-1] if len(parts) > 1 else None
                return None
            except Exception:
                return None
        return None

    def oui_lookup_c(self, mac: str) -> Optional[str]:
        if self._c_lib and self._c_lib.endswith(".so"):
            try:
                import ctypes
                lib = ctypes.CDLL(self._c_lib)
                lib.web_oui_lookup.argtypes = [ctypes.c_char_p]
                lib.web_oui_lookup.restype = ctypes.c_char_p
                result = lib.web_oui_lookup(mac.encode())
                return result.decode() if result else None
            except Exception:
                return None
        return None

    def oui_lookup_csharp(self, mac: str) -> Optional[str]:
        if self._cs_bin:
            try:
                dll = Path(self._cs_bin) / "HackItWireless.dll"
                if dll.exists():
                    import clr
                    clr.AddReference(str(dll.with_suffix("")))
                    from HackItWireless import OuiLookup
                    return OuiLookup.Lookup(mac)
            except ImportError:
                # pythonnet not installed — fall through
                pass
        return None

    def oui_lookup_all(self, mac: str) -> dict[str, Optional[str]]:
        return {
            "go": self.oui_lookup_go(mac),
            "rust": self.oui_lookup_rust(mac),
            "c": self.oui_lookup_c(mac),
            "csharp": self.oui_lookup_csharp(mac),
        }
