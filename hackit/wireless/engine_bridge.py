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
        self._c_cli: Optional[str] = None
        self._cxx_lib: Optional[str] = None
        self._cs_bin: Optional[str] = None
        self._ctypes_lib = None
        self._discover_engines()

    # ── Engine discovery ────────────────────────────────────────

    def _discover_engines(self):
        self._go_bin = self._find_go_worker()
        self._rust_bin = self._find_rust_engine()
        self._c_lib = self._find_clib("libhackit_wireless_c")
        self._c_cli = self._find_c_cli()
        self._cxx_lib = self._c_lib  # C++ compiled into same shared lib
        self._cs_bin = self._find_csharp()
        self._ctypes_lib = None

    def _find_c_cli(self) -> Optional[str]:
        for d in [BASE / "c_core", BASE / "c_core/build"]:
            for name in ("hackit-c", "hackit-c.exe"):
                p = d / name
                if p.exists():
                    return str(p)
        return None

    # ── ctypes bindings for the C shared library ────────────────
    def c_lib(self):
        """Lazy-load the C shared library as a ctypes handle with declared signatures."""
        if self._ctypes_lib is not None:
            return self._ctypes_lib
        if not self._c_lib or not self._c_lib.endswith(".so"):
            return None
        try:
            import ctypes

            class CWifiAdapter(ctypes.Structure):
                _fields_ = [
                    ("name", ctypes.c_char * 32),
                    ("mac", ctypes.c_char * 18),
                    ("driver", ctypes.c_char * 32),
                    ("channel", ctypes.c_int),
                    ("signal_dbm", ctypes.c_int),
                    ("is_monitor", ctypes.c_bool),
                    ("supports_2ghz", ctypes.c_bool),
                    ("supports_5ghz", ctypes.c_bool),
                    ("max_tx_power", ctypes.c_int),
                ]

            class CChannelInfo(ctypes.Structure):
                _fields_ = [
                    ("channel", ctypes.c_int),
                    ("frequency_mhz", ctypes.c_int),
                    ("band", ctypes.c_int),
                    ("max_power_dbm", ctypes.c_int),
                ]

            lib = ctypes.CDLL(self._c_lib)
            lib._CWifiAdapter = CWifiAdapter
            lib._CChannelInfo = CChannelInfo

            def _sig(name, argtypes, restype):
                try:
                    fn = getattr(lib, name)
                    fn.argtypes = argtypes
                    fn.restype = restype
                except AttributeError:
                    pass

            u8p = ctypes.POINTER(ctypes.c_uint8)
            _sig("hackit_c_detect_adapters", [ctypes.POINTER(CWifiAdapter), ctypes.c_int], ctypes.c_int)
            _sig("hackit_c_get_supported_channels", [ctypes.c_char_p, ctypes.POINTER(CChannelInfo), ctypes.c_int], ctypes.c_int)
            _sig("hackit_c_set_channel", [ctypes.c_char_p, ctypes.c_int], ctypes.c_bool)
            _sig("hackit_c_set_monitor_mode", [ctypes.c_char_p], ctypes.c_bool)
            _sig("hackit_c_set_managed_mode", [ctypes.c_char_p], ctypes.c_bool)
            _sig("hackit_inject_deauth", [ctypes.c_char_p, u8p, u8p, ctypes.c_uint16], ctypes.c_bool)
            _sig("hackit_inject_beacon", [ctypes.c_char_p, ctypes.c_char_p, u8p, ctypes.c_uint8], ctypes.c_bool)
            _sig("hackit_inject_raw_frame", [ctypes.c_char_p, u8p, ctypes.c_int], ctypes.c_bool)
            _sig("hackit_deauth_burst", [ctypes.c_char_p, u8p, u8p, ctypes.c_int, ctypes.c_int], ctypes.c_bool)
            _sig("hackit_deauth_all_clients", [ctypes.c_char_p, u8p, ctypes.c_int], ctypes.c_bool)
            _sig("hackit_deauth_targeted", [ctypes.c_char_p, u8p, u8p, ctypes.c_int], ctypes.c_bool)
            _sig("hackit_beacon_flood", [ctypes.c_char_p, ctypes.c_char_p, u8p, ctypes.c_uint8, ctypes.c_int], ctypes.c_int)
            _sig("hackit_beacon_flood_random", [ctypes.c_char_p, ctypes.c_int], ctypes.c_int)
            _sig("hackit_wifi_change_mac", [ctypes.c_char_p, ctypes.c_char_p], ctypes.c_bool)
            _sig("hackit_wifi_restore_mac", [ctypes.c_char_p], ctypes.c_bool)
            _sig("hackit_wifi_set_txpower", [ctypes.c_char_p, ctypes.c_int], ctypes.c_bool)
            _sig("hackit_wifi_get_adapter_info", [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int], ctypes.c_bool)
            self._ctypes_lib = lib
            return lib
        except Exception:
            return None

    @staticmethod
    def _mac_bytes(mac: Optional[str]):
        import ctypes
        if not mac:
            return (ctypes.c_uint8 * 6)(*[0xFF] * 6)
        parts = mac.replace("-", ":").split(":")
        try:
            if len(parts) >= 6 and all(parts[i].strip() for i in range(6)):
                return (ctypes.c_uint8 * 6)(*[int(p, 16) & 0xFF for p in parts[:6]])
        except ValueError:
            pass
        return (ctypes.c_uint8 * 6)(*[0xFF] * 6)

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
        # os.path.exists()/Path.exists() can return False for a file that
        # os.scandir() clearly reports, depending on the filesystem. Use
        # scandir as the source of truth and match names case-insensitively.
        targets = {"hackitwirelesscore.dll", "hackitwirelesscore",
                   "hackitwireless.dll", "hackitwireless.exe"}
        search_dirs = [
            BASE / "csharp_core" / "bin" / "Release",
            BASE / "hackitwireless-cs" / "bin" / "Release",
        ]
        for root in search_dirs:
            for candidate_dir in (root, root / "net8.0", root / "net9.0",
                                  root / "net7.0", root / "net6.0"):
                try:
                    with os.scandir(str(candidate_dir)) as it:
                        for entry in it:
                            if entry.name.lower() in targets and entry.is_file():
                                return entry.path
                except OSError:
                    continue
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

    def _cpu_count(self) -> int:
        try:
            return max(1, os.cpu_count() or 1)
        except Exception:
            return 1

    def _build_go(self, cb) -> bool:
        if not shutil.which("go"):
            if cb:
                cb("go", "go toolchain not installed - skipped")
            return False
        go_dir = BASE / "go_workers"
        if cb:
            cb("go", "Compiling Go workers...")
        try:
            out_dir = go_dir / "bin"
            out_dir.mkdir(exist_ok=True)
            binary = out_dir / ("hackit-worker.exe" if os.name == "nt" else "hackit-worker")
            env = dict(os.environ)
            env.setdefault("CGO_ENABLED", "0")
            subprocess.run(
                ["go", "build", "-trimpath", "-ldflags=-s -w", "-o", str(binary), "."],
                cwd=str(go_dir), check=True, capture_output=True, text=True, env=env,
            )
            os.chmod(binary, 0o755)
            self._go_bin = str(binary)
            return True
        except subprocess.CalledProcessError as e:
            if cb:
                cb("go", f"FAILED: {(e.stderr or '')[:200]}")
            return False
        except OSError as e:
            if cb:
                cb("go", f"FAILED: {e}")
            return False

    def _build_rust(self, cb) -> bool:
        if not shutil.which("cargo"):
            if cb:
                cb("rust", "cargo not installed - skipped")
            return False
        rust_dir = BASE / "rust_engine"
        if cb:
            cb("rust", "Compiling Rust engine (release)...")
        # The default feature set links libpcap. Hosts without libpcap-dev fail
        # at link time, so fall back to --no-default-features which builds the
        # raw-socket injector path only.
        attempts = [
            ["cargo", "build", "--release"],
            ["cargo", "build", "--release", "--no-default-features"],
        ]
        last_err = ""
        for argv in attempts:
            try:
                subprocess.run(
                    argv, cwd=str(rust_dir), check=True, capture_output=True, text=True,
                )
                self._discover_engines()
                if self._rust_bin is not None and self._rust_bin != "cargo_build":
                    return True
            except subprocess.CalledProcessError as e:
                last_err = (e.stderr or "")[-300:]
            except OSError as e:
                last_err = str(e)
                break
        if cb:
            cb("rust", f"FAILED: {last_err[-200:] if last_err else 'unknown error'}")
        return False

    def _build_c_core(self, cb) -> bool:
        """Build the C/C++ core.

        Prefers CMake when available, but falls back to the standalone
        Makefile and then a direct gcc invocation so the engine still builds
        on hosts without cmake installed.
        """
        c_dir = BASE / "c_core"
        if not c_dir.exists():
            return False

        have_cmake = shutil.which("cmake") is not None
        have_make = shutil.which("make") is not None
        have_gcc = shutil.which("gcc") is not None or shutil.which("cc") is not None

        if have_cmake:
            if cb:
                cb("c_core", "Building with CMake...")
            build_dir = c_dir / "build"
            build_dir.mkdir(exist_ok=True)
            try:
                subprocess.run(
                    ["cmake", "..", "-DCMAKE_BUILD_TYPE=Release"],
                    cwd=str(build_dir), check=True, capture_output=True, text=True,
                )
                subprocess.run(
                    ["cmake", "--build", ".", "--parallel", str(self._cpu_count())],
                    cwd=str(build_dir), check=True, capture_output=True, text=True,
                )
                self._discover_engines()
                if self._c_lib is not None or self._cxx_lib is not None:
                    return True
            except (subprocess.CalledProcessError, OSError) as e:
                if cb:
                    cb("c_core", f"CMake failed ({(getattr(e, 'stderr', '') or str(e))[:160]}) - trying make...")

        if have_make and (c_dir / "Makefile").exists():
            if cb:
                cb("c_core", "Building with Makefile...")
            try:
                subprocess.run(
                    ["make", f"-j{self._cpu_count()}"],
                    cwd=str(c_dir), check=True, capture_output=True, text=True,
                )
                self._discover_engines()
                if self._c_lib is not None or self._cxx_lib is not None:
                    return True
            except (subprocess.CalledProcessError, OSError) as e:
                if cb:
                    cb("c_core", f"make failed ({(getattr(e, 'stderr', '') or str(e))[:160]}) - trying gcc...")

        if have_gcc:
            if cb:
                cb("c_core", "Building static injectors with gcc...")
            cc = shutil.which("gcc") or shutil.which("cc")
            built_any = False
            for src, out in (
                (c_dir / "deauth_inject.c", c_dir / "deauth-inject"),
                (c_dir / "eviltwin_inject.c", c_dir / "eviltwin-inject"),
            ):
                if not src.exists():
                    continue
                try:
                    subprocess.run(
                        [cc, "-O2", "-static", "-o", str(out), str(src), "-lm"],
                        check=True, capture_output=True, text=True,
                    )
                    os.chmod(out, 0o755)
                    built_any = True
                except (subprocess.CalledProcessError, OSError) as e:
                    if cb:
                        cb("c_core", f"{src.name}: {(getattr(e, 'stderr', '') or str(e))[:120]}")
            self._discover_engines()
            return built_any or self._c_lib is not None

        if cb:
            cb("c_core", "No C toolchain found - skipped")
        return False

    def _dotnet(self) -> Optional[str]:
        found = shutil.which("dotnet")
        if found:
            return found
        for cand in ("/opt/dotnet/dotnet", "/usr/share/dotnet/dotnet"):
            if os.path.exists(cand):
                return cand
        return None

    def _build_csharp(self, cb) -> bool:
        dotnet = self._dotnet()
        if not dotnet:
            if cb:
                cb("csharp", "dotnet SDK not installed - skipped")
            return False
        cs_dir = BASE / "csharp_core"
        if not cs_dir.exists():
            cs_dir = BASE / "hackitwireless-cs"
        if cb:
            cb("csharp", "Building C# components...")
        try:
            subprocess.run(
                [dotnet, "build", "-c", "Release"],
                cwd=str(cs_dir), check=True, capture_output=True, text=True
            )
            self._discover_engines()
            return self._cs_bin is not None
        except subprocess.CalledProcessError as e:
            if cb:
                cb("csharp", f"FAILED: {(e.stderr or '')[:200]}")
            return False
        except OSError as e:
            if cb:
                cb("csharp", f"FAILED: {e}")
            return False

    # ── Rust engine execution ──────────────────────────────────

    def _ensure_rust(self) -> str:
        if self._rust_bin and self._rust_bin not in ("cargo_build",):
            return self._rust_bin
        if self._build_rust(None):
            if self._rust_bin and self._rust_bin not in ("cargo_build",):
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

    def rust_deauth(self, iface: str, bssid: str, station: str = "", reason: int = 7):
        cmd = [self._ensure_rust(), "deauth", "--interface", iface, "--bssid", bssid]
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
        if self._go_bin and self._go_bin not in ("go_build",):
            return self._go_bin
        if self._build_go(None):
            if self._go_bin and self._go_bin not in ("go_build",):
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

    def c_deauth(self, iface: str, bssid: str, station: str = "", count: int = 0, reason: int = 7):
        """Fire deauth frames. count=0 → open stream via the hackit-c CLI;
        count>0 → finite burst via the FFI (returns a bool)."""
        lib = self.c_lib()
        if lib is not None and count > 0:
            b = self._mac_bytes(bssid)
            s = self._mac_bytes(station or "FF:FF:FF:FF:FF:FF")
            return bool(lib.hackit_deauth_burst(iface.encode(), b, s, int(count), 5))
        if self._c_cli:
            st = station or "bcast"
            return self._popen([self._c_cli, "deauth-v1", iface, bssid, st, str(reason)])
        raise EngineBuildError("C core not built. Run 'build c' first.")

    def c_deauth_burst(self, iface: str, bssid: str, station: str = "", count: int = 100, delay_ms: int = 5) -> bool:
        lib = self.c_lib()
        if lib is None:
            raise EngineBuildError("C shared library not loaded.")
        return bool(lib.hackit_deauth_burst(iface.encode(), self._mac_bytes(bssid),
                                            self._mac_bytes(station or "FF:FF:FF:FF:FF:FF"),
                                            int(count), int(delay_ms)))

    def c_deauth_all(self, iface: str, bssid: str, count: int = 100) -> bool:
        lib = self.c_lib()
        if lib is None:
            raise EngineBuildError("C shared library not loaded.")
        return bool(lib.hackit_deauth_all_clients(iface.encode(), self._mac_bytes(bssid), int(count)))

    def c_inject_deauth(self, iface: str, bssid: str, station: str = "", reason: int = 7) -> bool:
        """One deauth frame through FFI — the primitive the executor loops
        over with its own channel-hopping scheduler, so a single call site
        can rotate channels and reason codes from Python."""
        lib = self.c_lib()
        if lib is None:
            raise EngineBuildError("C shared library not loaded.")
        return bool(lib.hackit_inject_deauth(iface.encode(), self._mac_bytes(bssid),
                                             self._mac_bytes(station or "FF:FF:FF:FF:FF:FF"),
                                             int(reason)))

    def c_beacon_flood(self, iface: str, ssid: str, bssid: str = "", count: int = 100, channel: int = 6) -> int:
        lib = self.c_lib()
        if lib is None:
            raise EngineBuildError("C shared library not loaded.")
        b = self._mac_bytes(bssid) if bssid else None
        return int(lib.hackit_beacon_flood(iface.encode(), ssid.encode(), b, int(channel), int(count)))

    def c_beacon_flood_random(self, iface: str, count: int = 100) -> int:
        lib = self.c_lib()
        if lib is None:
            raise EngineBuildError("C shared library not loaded.")
        return int(lib.hackit_beacon_flood_random(iface.encode(), int(count)))

    def c_set_channel(self, iface: str, channel: int) -> bool:
        lib = self.c_lib()
        if lib is None:
            raise EngineBuildError("C shared library not loaded.")
        return bool(lib.hackit_c_set_channel(iface.encode(), int(channel)))

    def c_set_monitor(self, iface: str) -> bool:
        lib = self.c_lib()
        if lib is None:
            raise EngineBuildError("C shared library not loaded.")
        return bool(lib.hackit_c_set_monitor_mode(iface.encode()))

    def c_channels(self, iface: str) -> list:
        lib = self.c_lib()
        if lib is None:
            return []
        Arr = lib._CChannelInfo * 128
        arr = Arr()
        n = lib.hackit_c_get_supported_channels(iface.encode(), arr, 128)
        out = []
        for i in range(max(0, n)):
            out.append({
                "channel": arr[i].channel,
                "frequency_mhz": arr[i].frequency_mhz,
                "band": "5GHz" if arr[i].band else "2.4GHz",
                "max_power_dbm": arr[i].max_power_dbm,
            })
        return out

    def c_frame_inject(self, iface: str, frame_type: str, payload: str = ""):
        if not self._c_cli:
            raise EngineBuildError("C CLI not built. Run 'build c' first.")
        return self._popen([self._c_cli, "beacons", iface, payload or "HackIT_WiFi"])

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
