"""Engine discovery, build and execution.

Four engines, one report schema:
  go       — HTTP(S)/HTTP2 load, DNS query rate, UDP echo throughput
  c        — TCP connect / HTTP(S) request measurement, ICMP RTT
  flood    — raw-packet flood, HTTP(S) request flood
  slowloris— socket-holding engine

All speak the same wire protocol on stdout:
  {"type":"progress", ...}  then one {"type":"result", ...}.

Staleness uses a sidecar hash that records platform and machine, because the
binaries are committed and a fresh clone can hand an x86-64 ELF to an ARM host
with identical mtimes.
"""
from __future__ import annotations

import hashlib
import json
import platform
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Optional

MODULE_DIR = Path(__file__).resolve().parent
GO_DIR = MODULE_DIR / "go"
C_DIR = MODULE_DIR / "c"

GO_BIN = GO_DIR / "stresslab"
C_BIN = C_DIR / "stress_engine"
FLOOD_BIN = C_DIR / "flood_engine"
SLOW_BIN = C_DIR / "slowloris"

GO_SRC = GO_DIR / "stresslab.go"
C_SRC = C_DIR / "stress_engine.c"
FLOOD_SRC = C_DIR / "flood_engine.c"
SLOW_SRC = C_DIR / "slowloris.c"

C_HARD_MAX_THREADS = 128
FLOOD_HARD_MAX_THREADS = 256
SLOW_HARD_MAX_SOCKETS = 200000

ProgressCB = Optional[Callable[[Dict[str, Any]], None]]


class EngineError(Exception):
    pass


def _marker(binary: Path) -> Path:
    return binary.with_name(binary.name + ".sha256")


def _fingerprint(src: Path) -> str:
    h = hashlib.sha256(src.read_bytes()).hexdigest()
    extra = hashlib.sha256()
    for sibling in sorted(src.parent.glob("*.h")):
        extra.update(sibling.read_bytes())
    return f"{h}:{extra.hexdigest()[:16]}:{sys.platform}:{platform.machine()}"


def _needs_build(binary: Path, src: Path) -> bool:
    if not binary.is_file():
        return True
    m = _marker(binary)
    if not m.is_file():
        return True
    try:
        return m.read_text(encoding="utf-8").strip() != _fingerprint(src)
    except OSError:
        return True


def _stamp(binary: Path, src: Path) -> None:
    try:
        _marker(binary).write_text(_fingerprint(src), encoding="utf-8")
    except OSError:
        pass


def _make(target: str) -> Path:
    make = shutil.which("make")
    if not make:
        raise EngineError("make not found — install build-essential")
    r = subprocess.run([make, "-C", str(C_DIR), target],
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        raise EngineError(f"C build failed for {target}:\n{r.stderr.strip()}")
    return C_DIR / target


def build_go() -> Path:
    go = shutil.which("go")
    if not go:
        raise EngineError("Go toolchain not found in PATH")
    r = subprocess.run([go, "build", "-o", str(GO_BIN), "."],
                       cwd=str(GO_DIR), capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        raise EngineError(f"Go build failed:\n{r.stderr.strip()}")
    _stamp(GO_BIN, GO_SRC)
    return GO_BIN


def build_c() -> Path:
    p = _make("stress_engine")
    _stamp(p, C_SRC)
    return p


def build_flood() -> Path:
    p = _make("flood_engine")
    _stamp(p, FLOOD_SRC)
    return p


def build_slowloris() -> Path:
    p = _make("slowloris")
    _stamp(p, SLOW_SRC)
    return p


_TABLE = {
    "go": (GO_BIN, GO_SRC, build_go),
    "c": (C_BIN, C_SRC, build_c),
    "flood": (FLOOD_BIN, FLOOD_SRC, build_flood),
    "slowloris": (SLOW_BIN, SLOW_SRC, build_slowloris),
}


def ensure_built(which: str) -> Path:
    if which not in _TABLE:
        raise EngineError(f"unknown engine: {which}")
    binary, src, builder = _TABLE[which]
    if _needs_build(binary, src):
        return builder()
    return binary


def _stream(cmd: list, timeout_s: int, on_progress: ProgressCB) -> Dict[str, Any]:
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, bufsize=1)
    except OSError as exc:
        raise EngineError(f"failed to launch engine: {exc}") from exc

    result: Optional[Dict[str, Any]] = None
    stdout = proc.stdout

    def consume() -> None:
        nonlocal result
        assert stdout is not None
        for line in stdout:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict):
                continue
            if data.get("type") == "progress":
                if on_progress:
                    on_progress(data)
            elif data.get("type") == "result" or "engine" in data:
                result = data

    reader = threading.Thread(target=consume, daemon=True)
    reader.start()
    try:
        assert proc.stderr is not None
        stderr = proc.stderr.read()
        proc.wait(timeout=timeout_s + 30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise EngineError("engine timed out") from None
    reader.join(timeout=5)

    if proc.returncode != 0:
        hint = "\nraw sockets need root or CAP_NET_RAW — run with sudo" if proc.returncode == 3 else ""
        raise EngineError(f"engine exited {proc.returncode}:{(stderr or '').strip()}{hint}")
    if result is None:
        raise EngineError(f"engine produced no final report. stderr:\n{(stderr or '').strip() or '<empty>'}")
    return result


def run_go(url: str, method: str, *, rps: int, workers: int, duration_s: int,
           timeout_ms: int, body: str = "", ramp_s: int = 0, force_close: bool = False,
           mode: str = "http", dns_name: str = "", dns_type: str = "A",
           dns_server: str = "", udp_payload: str = "hackit-ddos-probe",
           udp_echo: bool = True, waf: bool = False,
           on_progress: ProgressCB = None) -> Dict[str, Any]:
    binary = ensure_built("go")
    cmd = [str(binary), "-mode", mode, "-rps", str(rps), "-workers", str(workers),
           "-duration", str(duration_s), "-ramp", str(ramp_s), "-progress-ms", "500"]
    if waf:
        cmd.append("-waf")
    if mode == "http":
        cmd += ["-url", url, "-method", method, "-timeout-ms", str(timeout_ms)]
        if body:
            cmd += ["-body", body]
        if force_close:
            cmd += ["-close"]
    elif mode == "dns":
        cmd += ["-dns-name", dns_name, "-dns-type", dns_type]
        if dns_server:
            cmd += ["-dns-server", dns_server]
    elif mode == "udp":
        cmd += ["-url", url, "-udp-payload", udp_payload]
        if not udp_echo:
            cmd += ["-udp-echo=false"]
    else:
        raise EngineError(f"go mode must be http|dns|udp, got {mode!r}")
    return _stream(cmd, duration_s, on_progress)


def run_c(mode: str, host: str, port: int, *, rps: int, workers: int, duration_s: int,
          path: str = "/", method: str = "GET", body: str = "", tls: bool = False,
          waf: bool = False, on_progress: ProgressCB = None) -> Dict[str, Any]:
    if mode not in ("tcp", "http", "https", "icmp"):
        raise EngineError(f"c mode must be tcp|http|https|icmp, got {mode!r}")
    binary = ensure_built("c")
    threads = max(1, min(workers, C_HARD_MAX_THREADS))
    cmd = [str(binary), mode, host]
    if mode != "icmp":
        cmd.append(str(port))
    cmd += ["--duration", str(duration_s), "--threads", str(threads),
            "--rps", str(rps)]
    if mode in ("http", "https"):
        cmd += ["--path", path, "--method", method.upper()]
        if body:
            cmd += ["--body", body]
        if tls or mode == "https":
            cmd.append("--tls")
        if waf:
            cmd.append("--waf")
    report = _stream(cmd, duration_s, on_progress)
    report["threads"] = threads
    return report


def run_flood(mode: str, host: str, port: int, *, rate: int, threads: int,
              duration_s: int, size: int = 64, spoof: bool = False, path: str = "/",
              method: str = "GET", keepalive: int = 1, rand_path: bool = False,
              read_reply: bool = False, tls: bool = False, waf: bool = False,
              on_progress: ProgressCB = None) -> Dict[str, Any]:
    """Raw-packet flood. `rate` is packets/second; 0 means unthrottled."""
    binary = ensure_built("flood")
    threads = max(1, min(threads, FLOOD_HARD_MAX_THREADS))
    cmd = [str(binary), mode, host]
    if mode != "icmp":
        cmd.append(str(port))
    cmd += ["--duration", str(duration_s), "--threads", str(threads),
            "--rps", str(rate), "--progress-ms", "500"]
    if mode in ("udp", "icmp", "psh", "http", "https"):
        cmd += ["--size", str(size)]
    if spoof:
        cmd.append("--spoof")
    if waf:
        cmd.append("--waf")
    if mode in ("http", "https"):
        cmd += ["--path", path, "--method", method.upper(), "--keepalive", str(keepalive)]
        if rand_path:
            cmd.append("--rand-path")
        if read_reply:
            cmd.append("--read")
        if tls or mode == "https":
            cmd.append("--tls")
    report = _stream(cmd, duration_s, on_progress)
    report["threads"] = threads
    return report


def run_slowloris(host: str, port: int, *, sockets: int, threads: int,
                  duration_s: int, interval_ms: int, path: str = "/",
                  tls: bool = False, waf: bool = False,
                  on_progress: ProgressCB = None) -> Dict[str, Any]:
    binary = ensure_built("slowloris")
    sockets = max(1, min(sockets, SLOW_HARD_MAX_SOCKETS))
    threads = max(1, min(threads, sockets))
    cmd = [str(binary), host, str(port), "--duration", str(duration_s),
           "--sockets", str(sockets), "--threads", str(threads),
           "--interval-ms", str(interval_ms), "--path", path]
    if tls:
        cmd.append("--tls")
    if waf:
        cmd.append("--waf")
    report = _stream(cmd, duration_s, on_progress)
    report["sockets"] = sockets
    return report