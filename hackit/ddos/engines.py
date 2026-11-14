"""Engine discovery, build and execution for the ddos resilience console.

Two engines, one report schema:
  go  — HTTP(S) load generator (Go stdlib, TLS verified)
  c   — TCP connect / plain-HTTP load generator (C11, pthreads)

Both engines speak the same wire protocol on stdout:
  {"type":"progress", ...}  — periodic snapshot while running
  {"type":"result", ...}    — the final report (last line)
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, Optional

MODULE_DIR = Path(__file__).resolve().parent
GO_DIR = MODULE_DIR / "go"
GO_SRC = GO_DIR / "stresslab.go"
GO_BIN = GO_DIR / "stresslab"
C_DIR = MODULE_DIR / "c"
C_SRC = C_DIR / "stress_engine.c"
C_BIN = C_DIR / "stress_engine"

ProgressCB = Optional[Callable[[Dict[str, Any]], None]]


class EngineError(Exception):
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
    return GO_BIN


def build_c() -> Path:
    make = shutil.which("make")
    cc = shutil.which("cc") or shutil.which("gcc")
    if make:
        result = subprocess.run(
            [make, "-C", str(C_DIR), "stress_engine"],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            raise EngineError(f"C engine build failed:\n{result.stderr.strip()}")
        return C_BIN
    if cc:
        result = subprocess.run(
            [cc, "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror", "-o", str(C_BIN), str(C_SRC), "-pthread"],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            raise EngineError(f"C engine build failed:\n{result.stderr.strip()}")
        return C_BIN
    raise EngineError("No C toolchain found (make/cc/gcc) — install build-essential to build the TCP engine")


def ensure_built(which: str) -> Path:
    if which == "go":
        if GO_BIN.is_file() and GO_BIN.stat().st_mtime >= GO_SRC.stat().st_mtime:
            return GO_BIN
        return build_go()
    if which == "c":
        if C_BIN.is_file() and C_BIN.stat().st_mtime >= C_SRC.stat().st_mtime:
            return C_BIN
        return build_c()
    raise EngineError(f"unknown engine: {which}")


def _stream(cmd: list, timeout_s: int, on_progress: ProgressCB) -> Dict[str, Any]:
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
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

    import threading
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
        raise EngineError(f"engine exited {proc.returncode}:\n{(stderr or '').strip()}")
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
        str(binary),
        "-mode", mode,
        "-rps", str(rps),
        "-workers", str(workers),
        "-duration", str(duration_s),
        "-ramp", str(ramp_s),
        "-progress-ms", "500",
    ]
    if mode == "http":
        cmd += ["-url", url,
                "-method", method,
                "-timeout-ms", str(timeout_ms)]
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
          path: str = "/", on_progress: ProgressCB = None) -> Dict[str, Any]:
    if mode not in ("tcp", "http"):
        raise EngineError(f"c engine mode must be tcp|http, got {mode!r}")
    binary = ensure_built("c")
    threads = min(workers, 128)  # C engine cap, matches HARD_MAX_THREADS
    cmd = [
        str(binary), mode, host, str(port),
        "--duration", str(duration_s),
        "--threads", str(threads),
        "--rps", str(rps),
        "--progress-ms", "500",
    ]
    if mode == "http":
        cmd += ["--path", path]
    report = _stream(cmd, duration_s, on_progress)
    report["threads"] = threads
    return report


def run_icmp(host: str, *, rps: int, workers: int, duration_s: int,
             on_progress: ProgressCB = None) -> Dict[str, Any]:
    binary = ensure_built("c")
    threads = min(workers, 64)
    cmd = [
        str(binary), "icmp", host,
        "--duration", str(duration_s),
        "--threads", str(threads),
        "--rps", str(rps),
        "--progress-ms", "500",
    ]
    report = _stream(cmd, duration_s, on_progress)
    report["threads"] = threads
    return report
