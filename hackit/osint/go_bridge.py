"""Bridge to the native OSINT sweep engine (Rust, with Go wrapper binary).

The Rust checker streams one JSON verdict per line:
    RESULT:{...}
    FINAL:{...}
We resolve its path absolutely (relative-to-executable resolution in the old
Go wrapper broke whenever the CLI ran from another directory), build it once
with cargo if missing, and parse the stream incrementally so the CLI can show
live findings.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
from typing import Callable, Optional

ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
RUST_DIR = os.path.join(ENGINE_DIR, "go", "rust_engine")
RUST_BIN = os.path.join(RUST_DIR, "target", "release", "osint_checker")
if os.name == "nt":
    RUST_BIN += ".exe"

_build_lock = threading.Lock()
_build_attempted = False
_build_error = ""


def _ensure_engine() -> tuple[Optional[str], str]:
    """Return (binary_path, error). Builds the Rust engine once if needed."""
    global _build_attempted, _build_error
    if os.path.exists(RUST_BIN):
        return RUST_BIN, ""
    with _build_lock:
        if os.path.exists(RUST_BIN):
            return RUST_BIN, ""
        if _build_attempted:
            return None, _build_error
        _build_attempted = True
        if not shutil.which("cargo"):
            _build_error = "cargo not installed"
            return None, _build_error
        try:
            proc = subprocess.run(
                ["cargo", "build", "--release"],
                cwd=RUST_DIR, capture_output=True, text=True, timeout=300,
            )
            if proc.returncode != 0:
                _build_error = (proc.stderr or proc.stdout or "cargo build failed").strip()[-300:]
                return None, _build_error
        except Exception as exc:
            _build_error = f"build failed: {type(exc).__name__}: {exc}"
            return None, _build_error
    if os.path.exists(RUST_BIN):
        return RUST_BIN, ""
    _build_error = "engine binary missing after build"
    return None, _build_error


def engine_status() -> dict:
    """Describe the active sweep engine without probing anything."""
    path, err = _ensure_engine()
    if path:
        return {"engine": "rust", "path": path, "detail": "native engine ready"}
    return {"engine": "python", "path": "", "detail": err or "rust engine unavailable"}


def check_username(
    username: str,
    proxy: Optional[str] = None,
    retry: int = 1,
    timeout: int = 15,
    workers: int = 50,
    raw: bool = False,
    on_result: Callable[[dict], None] | None = None,
) -> dict:
    """Sweep `username` across the native site list.

    Returns {"username", "results", "summary", "error"}. When `on_result` is
    given it fires for every verdict as it arrives (live stream).
    """
    bin_path, engine_err = _ensure_engine()
    if not bin_path:
        return {"username": username, "results": [], "summary": None, "error": engine_err}

    cmd = [
        bin_path, username,
        "--retry", str(retry), "--timeout", str(timeout), "--workers", str(workers),
    ]
    if proxy:
        cmd.extend(["--proxy", proxy])

    results: list[dict] = []
    summary: dict | None = None
    stderr_tail: list[str] = []

    try:
        proc = subprocess.Popen(
            cmd, cwd=RUST_DIR, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )
    except FileNotFoundError:
        return {"username": username, "results": [], "summary": None,
                "error": f"engine not found: {bin_path}"}
    except Exception as exc:
        return {"username": username, "results": [], "summary": None, "error": str(exc)}

    def _drain_stderr() -> None:
        try:
            for line in proc.stderr:  # type: ignore[union-attr]
                line = line.strip()
                if line:
                    stderr_tail.append(line)
                    del stderr_tail[:-5]
        except Exception:
            pass

    stderr_thread = threading.Thread(target=_drain_stderr, daemon=True)
    stderr_thread.start()

    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.strip()
            if line.startswith("RESULT:"):
                try:
                    item = json.loads(line[7:])
                except json.JSONDecodeError:
                    continue
                results.append(item)
                if on_result:
                    try:
                        on_result(item)
                    except Exception:
                        pass
            elif line.startswith("FINAL:"):
                try:
                    summary = json.loads(line[6:])
                except json.JSONDecodeError:
                    pass
    finally:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        stderr_thread.join(timeout=2)

    if not results and proc.returncode not in (0, None):
        return {"username": username, "results": [], "summary": summary,
                "error": (stderr_tail[-1] if stderr_tail else f"engine exit {proc.returncode}")}

    return {"username": username, "results": results, "summary": summary, "error": ""}
