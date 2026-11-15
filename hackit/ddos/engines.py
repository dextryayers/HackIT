"""Engine discovery, build and execution for the ddos resilience console.

Three engines, one report schema:
  go     — HTTP(S) load generator (Go stdlib, TLS verified)
  c      — TCP connect / plain-HTTP load generator (C11, pthreads)
  flood  — raw-packet flood engine (C11, raw sockets, optional TLS)

All engines speak the same wire protocol on stdout:
  {"type":"progress", ...}  — periodic snapshot while running
  {"type":"result", ...}    — the final report (last line)

Staleness is tracked with a sidecar hash that also records platform and
machine, because committing the binaries means a fresh clone can hand an
x86-64 ELF to an ARM host with identical mtimes.
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
GO_SRC = GO_DIR / "stresslab.go"
GO_BIN = GO_DIR / "stresslab"
C_DIR = MODULE_DIR / "c"
C_SRC = C_DIR / "stress_engine.c"
C_BIN = C_DIR / "stress_engine"
FLOOD_SRC = C_DIR / "flood_engine.c"
FLOOD_BIN = C_DIR / "flood_engine"

# Must track the C headers and scope.py ceilings.
FLOOD_HARD_MAX_THREADS = 256
C_HARD_MAX_THREADS = 128

ProgressCB = Optional[Callable[[Dict[str, Any]], None]]


class EngineError(Exception):
    pass


def _marker(binary: Path) -> Path:
    return binary.with_name(binary.name + ".sha256")


def _fingerprint(src: Path) -> str:
    digest = hashlib.sha256(src.read_bytes()).hexdigest()
    return f"{digest}:{sys.platform}:{platform.machine()}"


def _needs_build(binary: Path, src: Path) -> bool:
    marker = _marker(binary)
    if not binary.is_file() or not marker.is_file():
        return True
    try:
        return marker.read_text(encoding="utf-8").strip() != _fingerprint(src)
    except OSError:
        return True


def _stamp(binary: Path, src: Path) -> None:
    try:
        _marker(binary).write_text(_fingerprint(src), encoding="utf-8")
    except OSError:
        pass


def build_go() -> Path:
    go = shutil.which("go")
    if not go:
        raise EngineError("Go toolchain not found in PATH — install golang to build the HTTP engine")
    result = subprocess.run(
        [go, "build", "-o", str(GO_BIN), str(GO_SRC)],
        cwd=str(GO_DIR), capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        raise EngineError(f"Go engine build failed:\n{result.stderr.strip()}")
    _stamp(GO_BIN, GO_SRC)
    return GO_BIN


def _build_with_make(target: str) -> Path:
    make = shutil.which("make")
    if not make:
        raise EngineError("make not found — install build-essential")
    result = subprocess.run(
        [make, "-C", str(C_DIR), target],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        raise EngineError(f"C engine build failed:\n{result.stderr.strip()}")
    return C_DIR / target


def build_c() -> Path:
    return _build_with_make("stress_engine")


def build_flood() -> Path:
    try:
        return _build_with_make("flood_engine")
    except EngineError as exc:
        raise EngineError(f"{exc}\n(flood_engine links OpenSSL — apt install libssl-dev)") from exc


def ensure_built(which: str) -> Path:
    table = {
        "go": (GO_BIN, GO_SRC, build_go),
        "c": (C_BIN, C_SRC, build_c),
        "flood": (FLOOD_BIN, FLOOD_SRC, build_flood),
    }
    try:
        binary, src, builder = table[which]
    except KeyError:
        raise EngineError(f"unknown engine: {which}") from None
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

    def consume():
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
        hint = ""
        if proc.returncode == 3:
            hint = "\nraw sockets need root or CAP_NET_RAW — run with sudo"
        raise EngineError(f"engine exited {proc.returncode}:{(stderr or '').strip()}{hint}")
    if result is None:
        raise EngineError(f"engine produced no final report. stderr:\n{(stderr or '').strip() or '<empty>'}")
    return result


def run_go(url: str, method: str, *, rps: int, workers: int, duration_s: int,
           timeout_ms: int, body: str = "", ramp_s: int = 0,
           force_close: bool = False, mode: str = "http",
           dns_name: str = "", dns_type: str = "A", dns_server: str = "",
           udp_payload: str = "hackit-ddos-probe", udp_echo: bool = True,
           on_progress: ProgressCB = None) -> Dict[str, Any]:
    binary = ensure_built("go")
    cmd = [
        str(binary), "-mode", mode, "-rps", str(rps), "-workers", str(workers),
        "-duration", str(duration_s), "-ramp", str(ramp_s), "-progress-ms", "500",
    ]
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
        raise EngineError(f"go engine mode must be http|dns|udp, got {mode!r}")
    return _stream(cmd, duration_s, on_progress)


def run_c(mode: str, host: str, port: int, *, rps: int, workers: int, duration_s: int,
          path: str = "/", method: str = "GET", body: str = "",
          on_progress: ProgressCB = None) -> Dict[str, Any]:
    if mode not in ("tcp", "http"):
        raise EngineError(f"c engine mode must be tcp|http, got {mode!r}")
    binary = ensure_built("c")
    threads = max(1, min(workers, C_HARD_MAX_THREADS))
    cmd = [
        str(binary), mode, host, str(port),
        "--duration", str(duration_s), "--threads", str(threads),
        "--rps", str(rps), "--progress-ms", "500",
    ]
    if mode == "http":
        cmd += ["--path", path, "--method", method.upper()]
        if body:
            cmd += ["--body", body]
    report = _stream(cmd, duration_s, on_progress)
    report["threads"] = threads
    return report


def run_icmp(host: str, *, rps: int, workers: int, duration_s: int,
             on_progress: ProgressCB = None) -> Dict[str, Any]:
    binary = ensure_built("c")
    threads = max(1, min(workers, 64))
    cmd = [
        str(binary), "icmp", host, "--duration", str(duration_s),
        "--threads", str(threads), "--rps", str(rps), "--progress-ms", "500",
    ]
    report = _stream(cmd, duration_s, on_progress)
    report["threads"] = threads
    return report


FLOOD_MODES = frozenset({"syn", "ack", "rst", "fin", "psh", "xmas", "null",
                         "udp", "icmp", "http"})


def run_flood(mode: str, host: str, port: int, *, rate: int, threads: int,
              duration_s: int, size: int = 64, spoof: bool = False,
              path: str = "/", method: str = "GET", keepalive: int = 1,
              rand_path: bool = False, read_reply: bool = False,
              tls: bool = False, on_progress: ProgressCB = None) -> Dict[str, Any]:
    """Raw-packet flood. `rate` is packets/second; 0 means unthrottled."""
    if mode not in FLOOD_MODES:
        raise EngineError(f"flood mode must be one of {sorted(FLOOD_MODES)}, got {mode!r}")
    binary = ensure_built("flood")
    threads = max(1, min(threads, FLOOD_HARD_MAX_THREADS))
    cmd = [
        str(binary), mode, host,
        "--duration", str(duration_s), "--threads", str(threads),
        "--rps", str(rate), "--progress-ms", "500",
    ]
    if mode == "icmp":
        pass
    else:
        cmd.append(str(port))
    if mode in ("udp", "icmp", "psh", "http"):
        cmd += ["--size", str(size)]
    if spoof:
        cmd.append("--spoof")
    if mode == "http":
        cmd += ["--path", path, "--method", method.upper(), "--keepalive", str(keepalive)]
        if rand_path:
            cmd.append("--rand-path")
        if read_reply:
            cmd.append("--read")
        if tls:
            cmd.append("--tls")
    report = _stream(cmd, duration_s, on_progress)
    report["threads"] = threads
    return report