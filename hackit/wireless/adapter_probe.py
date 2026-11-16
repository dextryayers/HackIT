"""Wireless adapter capability probing and chipset compatibility.

The probe answers four questions the rest of the suite needs before launching
any attack:

1. Can this adapter go into monitor mode (mac80211 `iw` or legacy wext)?
2. Does the driver support frame injection?
3. Which bands does the radio actually cover (2.4 / 5 / 6 GHz)?
4. Does this chipset have a known-good or known-bad record for the technique
   being attempted (deauth, evil twin, WPS, WEP, PMKID)?

Everything here is read-only. Nothing changes interface state; callers do that
explicitly (see ``mode_helper``).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field, asdict
from typing import Iterable, Optional

# --------------------------------------------------------------------------- #
# Chipset knowledge base
# --------------------------------------------------------------------------- #

# driver name (from `ethtool -i`) -> profile
#   monitor: monitor mode support
#   inject:  frame injection support
#   ap:      soft-AP (hostapd) support
#   bands:   bands the reference hardware exposes
#   notes:   practical guidance for an operator
CHIPSET_DB: dict[str, dict] = {
    # ── Atheros (best-in-class for audits) ──
    "ath9k": {
        "monitor": True, "inject": True, "ap": True,
        "bands": ("2.4", "5"), "vendor": "Atheros",
        "notes": "AR9xxx. Reliable monitor + injection. AR9271 is the reference 2.4 GHz dongle.",
    },
    "ath9k_htc": {
        "monitor": True, "inject": True, "ap": True,
        "bands": ("2.4",), "vendor": "Atheros",
        "notes": "AR9271 USB. Single-band but injection is rock solid.",
    },
    "ath10k": {
        "monitor": True, "inject": False, "ap": True,
        "bands": ("2.4", "5"), "vendor": "Atheros/QCA",
        "notes": "Monitor works; injection depends on firmware. Prefer ath9k for attacks.",
    },
    "ath10k_pci": {
        "monitor": True, "inject": False, "ap": True,
        "bands": ("2.4", "5"), "vendor": "Atheros/QCA",
        "notes": "PCR-based. Monitor only on most firmware builds.",
    },
    "ath11k": {
        "monitor": True, "inject": False, "ap": True,
        "bands": ("2.4", "5", "6"), "vendor": "Qualcomm",
        "notes": "WiFi 6/6E. Monitor works, injection unreliable.",
    },
    "ath6kl": {
        "monitor": True, "inject": True, "ap": True,
        "bands": ("2.4", "5"), "vendor": "Atheros",
        "notes": "AR600x. Solid classic injection card.",
    },
    # ── Ralink / MediaTek ──
    "rt2800usb": {
        "monitor": True, "inject": True, "ap": True,
        "bands": ("2.4", "5"), "vendor": "Ralink",
        "notes": "RT2870/3070. Cheap, works well. Patch for newer kernels helps.",
    },
    "rt2800pci": {
        "monitor": True, "inject": True, "ap": True,
        "bands": ("2.4", "5"), "vendor": "Ralink",
        "notes": "RT2860. Stable monitor/injection.",
    },
    "rt73usb": {
        "monitor": True, "inject": True, "ap": True,
        "bands": ("2.4",), "vendor": "Ralink",
        "notes": "RT2571. Old but reliable 2.4 GHz.",
    },
    "mt7601u": {
        "monitor": True, "inject": False, "ap": True,
        "bands": ("2.4",), "vendor": "MediaTek",
        "notes": "Monitor only on most builds.",
    },
    "mt76x0u": {
        "monitor": True, "inject": True, "ap": True,
        "bands": ("2.4", "5"), "vendor": "MediaTek",
        "notes": "MT7610U. Dual-band injection with recent kernels.",
    },
    "mt76x2u": {
        "monitor": True, "inject": True, "ap": True,
        "bands": ("2.4", "5"), "vendor": "MediaTek",
        "notes": "MT7612U. Best budget dual-band injector.",
    },
    "mt7921u": {
        "monitor": True, "inject": False, "ap": True,
        "bands": ("2.4", "5", "6"), "vendor": "MediaTek",
        "notes": "WiFi 6E USB. Monitor works on kernel >= 5.16.",
    },
    "rtl8188eus": {
        "monitor": True, "inject": True, "ap": True,
        "bands": ("2.4",), "vendor": "Realtek",
        "notes": "Requires out-of-tree 8188eu driver (dkms) for injection.",
    },
    # ── Realtek ──
    "rtw_8822ce": {
        "monitor": True, "inject": True, "ap": True,
        "bands": ("2.4", "5"), "vendor": "Realtek",
        "notes": "RTL8822CE. Monitor + injection verified on 6.x kernels; verified live by injection test.",
    },
    "rtw_8821ce": {
        "monitor": True, "inject": True, "ap": True,
        "bands": ("2.4", "5"), "vendor": "Realtek",
        "notes": "RTL8821CE. Monitor works on 6.x; injection verified by test.",
    },
    "rtw88_8822bu": {
        "monitor": True, "inject": False, "ap": True,
        "bands": ("2.4", "5"), "vendor": "Realtek",
        "notes": "Monitor works, injection firmware-limited.",
    },
    "rtl88x2bu": {
        "monitor": True, "inject": True, "ap": True,
        "bands": ("2.4", "5"), "vendor": "Realtek",
        "notes": "Out-of-tree driver (morrownr). Dual-band injection works.",
    },
    "rtl8812au": {
        "monitor": True, "inject": True, "ap": True,
        "bands": ("2.4", "5"), "vendor": "Realtek",
        "notes": "AirCrack-NG edition. The classic dual-band injector.",
    },
    "rtl8814au": {
        "monitor": True, "inject": True, "ap": True,
        "bands": ("2.4", "5"), "vendor": "Realtek",
        "notes": "4-stream dual-band. Strong capture.",
    },
    "rtl8821au": {
        "monitor": True, "inject": True, "ap": True,
        "bands": ("2.4", "5"), "vendor": "Realtek",
        "notes": "Dual-band, out-of-tree driver required.",
    },
    # ── Intel (mostly monitor-only) ──
    "iwlwifi": {
        "monitor": True, "inject": False, "ap": True,
        "bands": ("2.4", "5", "6"), "vendor": "Intel",
        "notes": "Monitor mode OK, injection blocked by firmware. Sniff-only.",
    },
    "iwl3945": {
        "monitor": True, "inject": False, "ap": True,
        "bands": ("2.4",), "vendor": "Intel",
        "notes": "Legacy. Monitor only.",
    },
    # ── Broadcom ──
    "brcmfmac": {
        "monitor": False, "inject": False, "ap": True,
        "bands": ("2.4", "5"), "vendor": "Broadcom",
        "notes": "SDIO/USB. No monitor path; use nexmon firmware to enable it.",
    },
    "wl": {
        "monitor": False, "inject": False, "ap": False,
        "bands": ("2.4",), "vendor": "Broadcom",
        "notes": "Proprietary STA driver. Not usable for audits.",
    },
    # ── Qualcomm / others ──
    "rtl8187": {
        "monitor": True, "inject": True, "ap": True,
        "bands": ("2.4",), "vendor": "Realtek",
        "notes": "Old but WEP-friendly. Inject reliable.",
    },
    "carl9170": {
        "monitor": True, "inject": True, "ap": True,
        "bands": ("2.4", "5"), "vendor": "Atheros",
        "notes": "AR9170. Dual-band injection.",
    },
}


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class AdapterCapabilities:
    name: str
    phy: str = "?"
    mac: str = "N/A"
    driver: str = "?"
    chipset_vendor: str = "Unknown"
    chipset_model: str = ""
    is_monitor: bool = False
    is_managed: bool = True
    supports_monitor: bool = False
    supports_inject: bool = False
    supports_ap: bool = False
    bands: tuple[str, ...] = ()
    channels: int = 0
    max_txpower: float = 0.0
    current_channel: int = 0
    current_freq: int = 0
    connected_ssid: str = ""
    signal_dbm: int = 0
    notes: str = ""
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["bands"] = list(self.bands)
        return d

    @property
    def dual_band(self) -> bool:
        return "2.4" in self.bands and "5" in self.bands

    @property
    def is_usable_for_attacks(self) -> bool:
        return self.supports_monitor and self.supports_inject

    @property
    def role(self) -> str:
        if self.is_usable_for_attacks and self.dual_band:
            return "DUAL-BAND INJECTOR"
        if self.is_usable_for_attacks:
            return "INJECTOR"
        if self.supports_monitor:
            return "MONITOR-ONLY"
        return "MANAGED ONLY"


# --------------------------------------------------------------------------- #
# Shell helpers
# --------------------------------------------------------------------------- #


def _run(argv: list[str], timeout: int = 5) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=timeout,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except (subprocess.SubprocessError, OSError):
        return 1, "", ""


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


# --------------------------------------------------------------------------- #
# Probe
# --------------------------------------------------------------------------- #


def _list_interfaces() -> list[str]:
    """Return wireless interface names, from `iw dev` with a sysfs fallback."""
    names: list[str] = []
    if _have("iw"):
        rc, out, _ = _run(["iw", "dev"])
        if rc == 0:
            for line in out.splitlines():
                stripped = line.strip()
                if stripped.startswith("Interface"):
                    parts = stripped.split()
                    if len(parts) >= 2:
                        names.append(parts[-1])
    if not names and os.path.isdir("/sys/class/net"):
        for name in sorted(os.listdir("/sys/class/net")):
            if os.path.isdir(f"/sys/class/net/{name}/wireless"):
                names.append(name)
    return names


def _driver_for(iface: str) -> str:
    if _have("ethtool"):
        rc, out, _ = _run(["ethtool", "-i", iface])
        if rc == 0:
            for line in out.splitlines():
                if line.strip().lower().startswith("driver:"):
                    return line.split(":", 1)[1].strip()
    # sysfs walk
    try:
        link = os.path.realpath(f"/sys/class/net/{iface}/device/driver")
        return os.path.basename(link)
    except OSError:
        pass
    return "?"


def _phy_for(iface: str) -> str:
    try:
        return os.path.basename(os.path.realpath(f"/sys/class/net/{iface}/phy80211"))
    except OSError:
        pass
    if _have("iw"):
        rc, out, _ = _run(["iw", "dev", iface, "info"])
        for line in out.splitlines():
            if "wiphy" in line.lower():
                return "phy" + line.split()[-1]
    return "?"


CHANNELS_PER_BAND = {"2.4": 13, "5": 25, "6": 59}


def _estimate_channels(bands: tuple[str, ...] = ()) -> int:
    """Rough channel count when `iw phy` is unavailable (non-root)."""
    bands = bands or ("2.4",)
    return sum(CHANNELS_PER_BAND.get(b, 0) for b in bands)


_FREQ_BANDS = (
    (2400, 2500, "2.4"),
    (4900, 5900, "5"),
    (5925, 7125, "6"),
)


def _band_of(freq_mhz: int) -> Optional[str]:
    for lo, hi, label in _FREQ_BANDS:
        if lo <= freq_mhz <= hi:
            return label
    return None


def _bands_from_phy(iface: str) -> tuple[str, ...]:
    """Query `iw phy` for the bands this radio really supports."""
    if not _have("iw"):
        return ()
    phy = _phy_for(iface)
    if not phy.startswith("phy"):
        return ()
    rc, out, _ = _run(["iw", "phy", phy])
    if rc != 0:
        return ()
    bands: list[str] = []
    for line in out.splitlines():
        lowered = line.strip().lower()
        if lowered.startswith("band "):
            # Handles "Band 1: 2412 - 2472 MHz", "Band 2: 5170 - 5850 MHz",
            # and "Band 4: 5955 - 7115 MHz (6 GHz)"
            numbers = re.findall(r"(\d{4,5})\s*-\s*(\d{4,5})\s*mhz", lowered)
            for lo, hi in numbers:
                label = _band_of((int(lo) + int(hi)) // 2)
                if label and label not in bands:
                    bands.append(label)
            if not numbers and "6 ghz" in lowered and "6" not in bands:
                bands.append("6")
    return tuple(sorted(bands, key=lambda b: {"2.4": 0, "5": 1, "6": 2}[b]))


def _channel_count(iface: str) -> int:
    """Number of channels the radio exposes.

    `iw phy` requires CAP_NET_ADMIN; without root the query returns a usage
    error. Fall back to an estimate derived from the detected bands so the UI
    still shows something meaningful (the exact count needs root).
    """
    if _have("iw"):
        phy = _phy_for(iface)
        if phy.startswith("phy"):
            rc, out, _ = _run(["iw", "phy", phy])
            if rc == 0:
                count = len(re.findall(r"(?m)^\s*\*\s*(\d{1,4})\s*mhz", out))
                if count:
                    return count
    return _estimate_channels()


def _info_fields(iface: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    if not _have("iw"):
        return fields
    rc, out, _ = _run(["iw", "dev", iface, "info"])
    if rc == 0:
        for line in out.splitlines():
            s = line.strip()
            if s.startswith("addr "):
                fields["mac"] = s.split()[-1].upper()
            elif s.startswith("ssid "):
                fields["ssid"] = s.split(None, 1)[-1]
            elif s.startswith("type "):
                fields["type"] = s.split()[-1].lower()
            elif s.startswith("channel "):
                m = re.search(r"channel\s+(\d+)\s+\((\d+)\s*MHz\)", s)
                if m:
                    fields["channel"] = m.group(1)
                    fields["freq"] = m.group(2)
                elif s.split()[-1].isdigit():
                    fields["channel"] = s.split()[-1]
            elif "txpower" in s and s.endswith("dBm"):
                m = re.search(r"(-\d+(?:\.\d+)?)\s*dBm", s)
                if m:
                    fields["txpower"] = m.group(1)
    return fields


def _link_fields(iface: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    if not _have("iw"):
        return fields
    rc, out, _ = _run(["iw", "dev", iface, "link"])
    if rc == 0:
        for line in out.splitlines():
            s = line.strip()
            if s.lower().startswith("ssid:"):
                fields["ssid"] = s.split(":", 1)[1].strip()
            elif s.lower().startswith("freq:"):
                m = re.search(r"(\d+)", s)
                if m:
                    fields["freq"] = m.group(1)
            elif s.lower().startswith("signal:"):
                m = re.search(r"(-?\d+)\s*dBm", s)
                if m:
                    fields["signal"] = m.group(1)
    return fields


def _chipset_from_driver(driver: str) -> tuple[str, dict]:
    """Match the driver name against the knowledge base (longest prefix wins)."""
    driver_l = driver.lower()
    best: tuple[str, dict] = ("", {})
    best_len = 0
    for key, profile in CHIPSET_DB.items():
        if driver_l.startswith(key) and len(key) > best_len:
            best = (key, profile)
            best_len = len(key)
    return best


def probe(iface: str) -> AdapterCapabilities:
    """Full capability probe for one interface."""
    driver = _driver_for(iface)
    info = _info_fields(iface)
    link = _link_fields(iface)

    iface_type = info.get("type", "managed")
    caps = AdapterCapabilities(
        name=iface,
        phy=_phy_for(iface),
        mac=info.get("mac", "N/A"),
        driver=driver,
        is_monitor="monitor" in iface_type,
        is_managed="managed" in iface_type,
        current_channel=int(info["channel"]) if info.get("channel", "").isdigit() else 0,
        current_freq=int(info["freq"]) if info.get("freq", "").isdigit() else 0,
        max_txpower=float(info["txpower"]) if info.get("txpower") else 0.0,
        connected_ssid=link.get("ssid") or info.get("ssid", ""),
        signal_dbm=int(link["signal"]) if link.get("signal") else 0,
    )

    profile_key, profile = _chipset_from_driver(driver)
    if profile:
        caps.chipset_vendor = profile.get("vendor", "Unknown")
        caps.chipset_model = profile_key
        caps.supports_monitor = profile.get("monitor", False)
        caps.supports_inject = profile.get("inject", False)
        caps.supports_ap = profile.get("ap", False)
        caps.bands = tuple(profile.get("bands", ()))
        caps.notes = profile.get("notes", "")
    else:
        caps.warnings.append(
            f"Driver '{driver}' is not in the chipset database; "
            "capabilities inferred from `iw phy` only."
        )

    # Radio capabilities override the static profile when `iw phy` disagrees —
    # the hardware is the source of truth for bands.
    live_bands = _bands_from_phy(iface)
    if live_bands:
        caps.bands = live_bands
    if caps.bands:
        caps.channels = _estimate_channels(caps.bands)
    else:
        caps.channels = _channel_count(iface)

    # The presence of a monitor-capable phy and a raw-socket toolchain does not
    # guarantee injection. If the driver is absent from the DB and the phy
    # advertises software scan, we assume monitor works but injection does not.
    if not profile and "monitor" in iface_type:
        caps.supports_monitor = True

    if not caps.bands:
        caps.warnings.append("Band coverage could not be determined (no `iw phy` data).")

    if caps.supports_monitor and not caps.supports_inject:
        caps.warnings.append(
            "Monitor mode available but frame injection is not — "
            "capture/sniff will work, deauth/evil-twin injection will not."
        )
    if not caps.supports_monitor:
        caps.warnings.append(
            "No monitor mode — this adapter can only observe as a managed client."
        )

    return caps


def probe_all() -> list[AdapterCapabilities]:
    return [probe(name) for name in _list_interfaces()]


# --------------------------------------------------------------------------- #
# Formatting
# --------------------------------------------------------------------------- #


def summary_line(caps: AdapterCapabilities) -> str:
    bands = "+".join(caps.bands) if caps.bands else "?"
    flags = []
    if caps.supports_monitor:
        flags.append("mon")
    if caps.supports_inject:
        flags.append("inject")
    if caps.supports_ap:
        flags.append("ap")
    return (
        f"{caps.name:<10} {caps.driver:<14} {caps.chipset_vendor:<12} "
        f"bands={bands:<10} {'/'.join(flags) or 'none':<18} {caps.role}"
    )


def band_supported(caps: AdapterCapabilities, band: str) -> bool:
    return band in caps.bands


def recommend_for(technique: str, adapters: Iterable[AdapterCapabilities]) -> list[AdapterCapabilities]:
    """Return adapters able to perform `technique`, best first."""
    need_inject = technique in {"deauth", "evil-twin", "beacon-flood", "probe-flood", "wps", "wep"}
    need_monitor = technique in {
        "deauth", "evil-twin", "beacon-flood", "probe-flood", "wps", "wep",
        "handshake", "pmkid", "sniff", "crawl",
    }

    def score(caps: AdapterCapabilities) -> tuple[int, int, int]:
        ok = True
        if need_monitor and not caps.supports_monitor:
            ok = False
        if need_inject and not caps.supports_inject:
            ok = False
        return (
            0 if ok else 1,
            0 if caps.dual_band else 1,
            0 if caps.supports_inject else 1,
        )

    eligible = [c for c in adapters if (c.supports_monitor or not need_monitor)]
    return sorted(eligible, key=score)
