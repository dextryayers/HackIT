"""Interface mode switching that survives the driver quirks this suite meets.

Two families matter here:

* **mac80211** (`iw`-managed: ath9k, rt2800, mt76, rtl8xxxu, iwlwifi, …) —
  the normal path: down, `iw dev X set type monitor`, up.
* **wext** (legacy out-of-tree Realtek/Ralink builds) — `iw dev X set type`
  fails with EOPNOTSUPP; these need `iwconfig X mode monitor`.

Some drivers rename the interface when the mode changes (airmon-ng's
``wlan0mon``), others keep the same name, and Intel cards require the
interface be down *and* the regulatory domain set before monitor works. This
module normalises all of that behind one call and reports what actually
happened rather than assuming the switch succeeded.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Optional


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _run(argv: list[str], timeout: int = 8) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=timeout,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except (subprocess.SubprocessError, OSError) as exc:
        return 1, "", str(exc)


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def interface_exists(iface: str) -> bool:
    return os.path.exists(f"/sys/class/net/{iface}")


def interface_up(iface: str) -> bool:
    try:
        with open(f"/sys/class/net/{iface}/operstate", "r", encoding="utf-8") as fh:
            return fh.read().strip() != "down"
    except OSError:
        rc, out, _ = _run(["ip", "link", "show", iface])
        return rc == 0 and "UP" in out


def current_mode(iface: str) -> str:
    if not _have("iw"):
        return "unknown"
    rc, out, _ = _run(["iw", "dev", iface, "info"])
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("type "):
            return s.split()[-1].lower()
    return "unknown"


@dataclass
class ModeResult:
    ok: bool
    iface: str
    mode: str
    method: str = ""          # mac80211 | wext | none
    final_iface: str = ""     # interface may be renamed (wlan0 -> wlan0mon)
    message: str = ""


def _driver_for(iface: str) -> str:
    if _have("ethtool"):
        rc, out, _ = _run(["ethtool", "-i", iface])
        for line in out.splitlines():
            if line.strip().lower().startswith("driver:"):
                return line.split(":", 1)[1].strip()
    try:
        return os.path.basename(os.path.realpath(f"/sys/class/net/{iface}/device/driver"))
    except OSError:
        return "?"


def _kill_interfering() -> None:
    """Stop NetworkManager/wpa_supplicant so they don't fight the mode switch."""
    if _have("airmon-ng"):
        _run(["airmon-ng", "check", "kill"], timeout=15)
        return
    # No airmon-ng: try systemd units directly, ignore failures.
    for unit in ("NetworkManager", "wpa_supplicant"):
        if shutil.which("systemctl"):
            _run(["systemctl", "stop", unit], timeout=10)


def _restore_interfering() -> None:
    for unit in ("NetworkManager", "wpa_supplicant"):
        if shutil.which("systemctl"):
            _run(["systemctl", "start", unit], timeout=10)


def set_monitor(iface: str, channel: int = 0, kill_services: bool = True) -> ModeResult:
    """Switch `iface` into monitor mode. Returns what really happened."""
    if not interface_exists(iface):
        return ModeResult(False, iface, "monitor", message=f"{iface} not found")

    needs_root = not is_root()
    if needs_root:
        return ModeResult(
            False, iface, "monitor",
            message="monitor mode requires root/CAP_NET_ADMIN — run with sudo",
        )

    driver = _driver_for(iface)
    if kill_services:
        _kill_interfering()

    # ── 1. bring down ──
    _run(["ip", "link", "set", iface, "down"])

    # ── 2. mac80211 path ──
    method = ""
    rc, _, err = _run(["iw", "dev", iface, "set", "type", "monitor"])
    if rc == 0:
        method = "mac80211"
    else:
        # ── 3. wext fallback for out-of-tree Realtek/Ralink ──
        if _have("iwconfig"):
            rc2, _, _ = _run(["iwconfig", iface, "mode", "monitor"])
            if rc2 == 0:
                method = "wext"
        if not method:
            _run(["ip", "link", "set", iface, "up"])
            if kill_services:
                _restore_interfering()
            hint = ""
            low = driver.lower()
            if low.startswith(("rtw_8822", "rtw_8821", "brcmfmac", "wl")):
                hint = (
                    f" — driver '{driver}' has no monitor mode in mainline; "
                    "use a monitor-capable dongle (ath9k_htc, rt2800usb, mt76x2u, rtl8812au)"
                )
            return ModeResult(
                False, iface, "monitor", method="none",
                message=f"set type monitor failed: {err.strip()[:120]}{hint}",
            )

    # ── 4. up ──
    _run(["ip", "link", "set", iface, "up"])
    time.sleep(0.2)

    # ── 5. confirm + detect rename ──
    final_iface = iface
    actual = current_mode(final_iface)
    if actual != "monitor":
        # Some drivers create wlan0mon / mon0 and leave the original managed.
        for candidate in _find_monitor_ifaces():
            if candidate != final_iface:
                final_iface = candidate
                actual = "monitor"
                break

    if channel:
        _run(["iw", "dev", final_iface, "set", "channel", str(channel)])

    ok = actual == "monitor"
    return ModeResult(
        ok, iface, "monitor", method=method, final_iface=final_iface,
        message="monitor mode active" if ok else
        f"mode switch reported {method} but interface is '{actual}'",
    )


def set_managed(iface: str, restore_services: bool = True) -> ModeResult:
    """Return `iface` to managed mode and restart networking services."""
    if not interface_exists(iface):
        return ModeResult(False, iface, "managed", message=f"{iface} not found")
    if not is_root():
        return ModeResult(
            False, iface, "managed",
            message="requires root/CAP_NET_ADMIN — run with sudo",
        )

    _run(["ip", "link", "set", iface, "down"])
    method = ""
    rc, _, _ = _run(["iw", "dev", iface, "set", "type", "managed"])
    if rc == 0:
        method = "mac80211"
    elif _have("iwconfig"):
        rc2, _, _ = _run(["iwconfig", iface, "mode", "managed"])
        if rc2 == 0:
            method = "wext"
    _run(["ip", "link", "set", iface, "up"])
    if restore_services:
        _restore_interfering()

    actual = current_mode(iface)
    ok = actual in ("managed", "station")
    return ModeResult(ok, iface, "managed", method=method or "none",
                      final_iface=iface,
                      message="managed mode active" if ok else f"mode is '{actual}'")


def _find_monitor_ifaces() -> list[str]:
    out_list: list[str] = []
    if not _have("iw"):
        return out_list
    rc, out, _ = _run(["iw", "dev"])
    current = ""
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("Interface"):
            parts = s.split()
            if len(parts) >= 2:
                current = parts[-1]
        elif s.startswith("type monitor") and current:
            out_list.append(current)
    return out_list


def set_channel(iface: str, channel: int) -> bool:
    if not is_root():
        return False
    rc, _, _ = _run(["iw", "dev", iface, "set", "channel", str(channel)])
    return rc == 0


def set_txpower(iface: str, dbm: float, fixed: bool = False) -> bool:
    if not is_root():
        return False
    argv = ["iw", "dev", iface, "set", "txpower"]
    if fixed:
        argv.append("fixed")
    argv.append(f"{dbm:.1f}")
    rc, _, _ = _run(argv)
    return rc == 0
