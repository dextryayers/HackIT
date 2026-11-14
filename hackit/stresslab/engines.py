"""Engine discovery, build and execution for stresslab.

Two engines, one report schema:
  go  — HTTP(S) load generator (Go stdlib, TLS verified)
  c   — TCP connect / plain-HTTP load generator (C11, pthreads)
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict

MODULE_DIR = Path(__file__).resolve().parent
GO_DIR = MODULE_DIR / "go"
GO_SRC = GO_DIR / "stresslab.go"
GO_BIN = GO_DIR / "stresslab"
C_DIR = MODULE_DIR / "c"
C_SRC = C_DIR / "stress_engine.c"
C_BIN = C_DIR / "stress_engine"


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


def _parse_report(stdout: str, engine: str) -> Dict[str, Any]:
    for line in reversed(stdout.strip().splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict) and data.get("engine") == engine:
            return data
    raise EngineError(f"{engine} engine produced no parseable report. Output was:\n{stdout.strip() or '<empty>'}")


def run_go(url: str, method: str, *, rps: int, workers: int, duration_s: int, timeout_ms: int) -> Dict[str, Any]:
    binary = ensure_built("go")
    cmd = [
        str(binary),
        "-url", url,
        "-method", method,
        "-rps", str(rps),
        "-workers", str(workers),
        "-duration", str(duration_s),
        "-timeout-ms", str(timeout_ms),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration_s + 30)
    if result.returncode != 0:
        raise EngineError(f"go engine exited {result.returncode}:\n{result.stderr.strip()}")
    return _parse_report(result.stdout, "go")


def run_c(mode: str, host: str, port: int, *, rps: int, workers: int, duration_s: int, path: str = "/") -> Dict[str, Any]:
    if mode not in ("tcp", "http"):
        raise EngineError(f"c engine mode must be tcp|http, got {mode!r}")
    binary = ensure_built("c")
    threads = min(workers, 64)  # C engine cap, matches HARD_MAX_THREADS
    cmd = [
        str(binary), mode, host, str(port),
        "--duration", str(duration_s),
        "--threads", str(threads),
        "--rps", str(rps),
    ]
    if mode == "http":
        cmd += ["--path", path]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration_s + 30)
    if result.returncode != 0:
        raise EngineError(f"c engine exited {result.returncode}:\n{result.stderr.strip()}")
    report = _parse_report(result.stdout, "c")
    report["threads"] = threads
    return report
