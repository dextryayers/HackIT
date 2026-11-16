"""Capability-aware command handlers bolted onto the wireless executor.

These wrap ``adapter_probe``, ``mode_helper`` and ``attacks`` with the same
print style the rest of the console uses, and expose the results both to the
interactive shell (``do_caps`` etc. in console.py) and to scripted callers.
"""

from __future__ import annotations

import threading
import time
from typing import Iterable, Optional

from rich.table import Table

from . import adapter_probe, mode_helper
from . import attacks
from .ui_renderer import UIRenderer as UI

try:
    from rich.console import Console
    _console = Console()
except ImportError:  # pragma: no cover
    _console = None


def _render_table(title: str) -> Table:
    table = Table(title=title, border_style="cyan", header_style="bold cyan")
    table.add_column("Interface", style="bold white", no_wrap=True)
    table.add_column("Driver", style="dim")
    table.add_column("Chipset", style="magenta")
    table.add_column("Bands", style="green")
    table.add_column("Inj", justify="center")
    table.add_column("Mon", justify="center")
    table.add_column("AP", justify="center")
    table.add_column("Role", style="yellow")
    return table


def _flag(value: bool) -> str:
    return "[green]Y[/green]" if value else "[red]-[/red]"


def caps_report(json_out: bool = False) -> list[adapter_probe.AdapterCapabilities]:
    adapters = adapter_probe.probe_all()
    if json_out:
        import json
        payload = [a.to_dict() for a in adapters]
        print(json.dumps(payload, indent=2))
        return adapters

    if not adapters:
        UI.print_error("No wireless interfaces detected.")
        return adapters

    table = _render_table("Adapter capabilities")
    for caps in adapters:
        table.add_row(
            caps.name,
            caps.driver,
            f"{caps.chipset_vendor} {caps.chipset_model}".strip(),
            "+".join(caps.bands) or "?",
            _flag(caps.supports_inject),
            _flag(caps.supports_monitor),
            _flag(caps.supports_ap),
            caps.role,
        )
    _console.print(table)

    for caps in adapters:
        if caps.warnings:
            for warning in caps.warnings:
                UI.print_warning(f"{caps.name}: {warning}")
    return adapters


def chipset_detail(iface: str) -> None:
    caps = adapter_probe.probe(iface)
    table = Table(title=f"Interface {iface}", border_style="magenta", show_header=False)
    table.add_column("Field", style="bold cyan")
    table.add_column("Value", style="white")
    table.add_row("Physical radio", caps.phy)
    table.add_row("Driver", caps.driver)
    table.add_row("Chipset", f"{caps.chipset_vendor} {caps.chipset_model}".strip())
    table.add_row("MAC", caps.mac)
    table.add_row("Bands", "+".join(caps.bands) or "unknown")
    table.add_row("Channels (est.)", str(caps.channels))
    table.add_row("Monitor", _flag(caps.supports_monitor))
    table.add_row("Injection", _flag(caps.supports_inject))
    table.add_row("Soft-AP", _flag(caps.supports_ap))
    table.add_row("Current mode", "monitor" if caps.is_monitor else "managed")
    if caps.connected_ssid:
        table.add_row("Connected SSID", caps.connected_ssid)
    if caps.signal_dbm:
        table.add_row("Signal", f"{caps.signal_dbm} dBm")
    if caps.notes:
        table.add_row("Notes", caps.notes)
    _console.print(table)


def switch_mode(iface: str, mode: str, channel: int = 0) -> bool:
    if mode == "monitor":
        result = mode_helper.set_monitor(iface, channel=channel)
    elif mode == "managed":
        result = mode_helper.set_managed(iface)
    else:
        UI.print_error(f"Unknown mode '{mode}' — use monitor or managed")
        return False

    if result.ok:
        suffix = f" (as {result.final_iface})" if result.final_iface != iface else ""
        UI.print_success(f"{iface} → {mode}{suffix} [{result.method}]")
        return True

    UI.print_error(result.message)
    return False


def inject_test(iface: str, frames: int = 20) -> bool:
    caps = adapter_probe.probe(iface)
    if not caps.supports_monitor:
        UI.print_error(
            f"{iface} has no monitor mode — cannot inject. "
            "Use a monitor-capable adapter."
        )
        return False

    if not mode_helper.is_root():
        UI.print_error("injection test requires root — run with sudo")
        return False

    was_monitor = caps.is_monitor
    final_iface = iface
    if not was_monitor:
        result = mode_helper.set_monitor(iface)
        if not result.ok:
            UI.print_error(result.message)
            return False
        final_iface = result.final_iface

    UI.print_info(f"Sending {frames} test beacons on {final_iface} (channel 6)...")
    outcome = attacks.injection_test(final_iface, frames=frames)

    if outcome["injects"]:
        UI.print_success(
            f"Injection confirmed: {outcome['sent']}/{outcome['total']} frames accepted"
        )
    else:
        UI.print_error(
            "No frames accepted — the driver reports monitor mode but silently "
            "drops injected frames (firmware-level block)."
        )

    if not was_monitor:
        mode_helper.set_managed(final_iface)
    return outcome["injects"]


def band_scan(iface: str, band: str = "both", timeout: int = 15) -> list[dict]:
    """Scan for access points without airodump-ng, using `iw dev scan` on a
    managed interface or `iw dev X scan` after switching to managed if needed.
    """
    import json
    import re
    import shutil
    import subprocess

    if not shutil.which("iw"):
        UI.print_error("`iw` not found — install wireless-tools / iw")
        return []

    if band not in ("both", "2.4", "5", "6"):
        UI.print_error("band must be 2.4, 5, 6 or both")
        return []

    UI.print_info(f"Scanning {iface} ({band}) — {timeout}s...")
    try:
        proc = subprocess.run(
            ["iw", "dev", iface, "scan"],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        UI.print_error("scan timed out")
        return []
    except OSError as exc:
        UI.print_error(f"scan failed: {exc}")
        return []

    if proc.returncode != 0:
        UI.print_error(proc.stderr.strip()[:200] or "scan failed")
        return []

    aps: list[dict] = []
    current: Optional[dict] = None
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("BSS "):
            if current:
                aps.append(current)
            # "BSS b2:b9:46:90:db:3a(on wlp2s0) -- associated"
            raw = stripped[4:].split()[0] if len(stripped) > 4 else ""
            bssid = raw.split("(")[0].strip().lower()
            # Drop malformed BSS lines ("BSS load:" from mesh/beacon reports)
            if not _valid_mac(bssid):
                current = None
                continue
            current = {"bssid": bssid, "ssid": "", "channel": 0, "freq": 0,
                       "signal": 0, "band": "", "privacy": False, "wpa3": False}
        elif current is not None:
            if stripped.startswith("freq:"):
                try:
                    freq = int(float(stripped.split()[-1]))
                    current["freq"] = freq
                    if freq < 2500:
                        current["band"] = "2.4"
                    elif freq < 5925:
                        current["band"] = "5"
                    else:
                        current["band"] = "6"
                    current["channel"] = _freq_to_channel(freq)
                except ValueError:
                    pass
            elif stripped.startswith("DS Parameter set:"):
                match = re.search(r"channel\s+(\d+)", stripped)
                if match:
                    current["channel"] = int(match.group(1))
            elif stripped.startswith("signal:"):
                match = re.search(r"(-?\d+(?:\.\d+)?)", stripped)
                if match:
                    current["signal"] = int(float(match.group(1)))
            elif stripped.startswith("SSID:"):
                current["ssid"] = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("RSN:") or stripped.startswith("WPA:"):
                current["privacy"] = True
            elif "Authentication suites: SAE" in stripped:
                current["wpa3"] = True
            elif stripped.startswith("capability:") and "Privacy" in stripped:
                current["privacy"] = True
    if current:
        aps.append(current)

    if band != "both":
        aps = [a for a in aps if a.get("band") == band]

    table = Table(title=f"Access points ({len(aps)})", border_style="green")
    table.add_column("BSSID", style="bold white")
    table.add_column("SSID")
    table.add_column("Ch", justify="right")
    table.add_column("Band", justify="center")
    table.add_column("Signal", justify="right")
    table.add_column("Sec")
    for ap in sorted(aps, key=lambda a: a.get("signal", -100), reverse=True):
        sec = "OPEN"
        if ap.get("wpa3"):
            sec = "WPA3"
        elif ap.get("privacy"):
            sec = "WPA2"
        table.add_row(
            ap["bssid"], ap["ssid"] or "[dim]<hidden>[/dim]",
            str(ap["channel"]), ap.get("band", "?"),
            f"{ap['signal']} dBm", sec,
        )
    _console.print(table)
    return aps


def _valid_mac(mac: str) -> bool:
    import re as _re
    return bool(_re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", mac))


def _freq_to_channel(freq: int) -> int:
    if freq == 2484:
        return 14
    if 2400 <= freq <= 2500:
        return (freq - 2407) // 5
    if 4900 <= freq <= 5900:
        return (freq - 5000) // 5
    if 5925 <= freq <= 7125:
        return (freq - 5950) // 5
    return 0


def deauth_multi(iface: str, bssid: str, stations: Iterable[str], band: str = "both",
                 reason: int = 7, channel: int = 0, duration: float = 0.0) -> dict:
    """Run a dual-band, multi-station deauth campaign with live stats."""
    caps = adapter_probe.probe(iface)
    if not caps.supports_monitor:
        UI.print_error(f"{iface} has no monitor mode — cannot deauth")
        return {}

    bands = ("2.4", "5") if band == "both" else (band,)
    missing = [b for b in bands if b not in caps.bands]
    if missing:
        UI.print_warning(
            f"{iface} does not advertise band(s) {', '.join(missing)} — "
            "those channels will be skipped or fail silently."
        )

    was_monitor = caps.is_monitor
    target_iface = iface
    if not was_monitor:
        result = mode_helper.set_monitor(iface)
        if not result.ok:
            UI.print_error(result.message)
            return {}
        target_iface = result.final_iface

    stations = list(stations) or [attacks.BROADCAST_MAC]
    cfg = attacks.DeauthConfig(
        iface=target_iface, bssid=bssid, stations=stations, reason=reason,
        channel=channel, bands=bands, rotate_reason=True, duration=duration,
    )
    stop = threading.Event()
    last = {"frames": 0}
    started = time.time()

    def on_stats(stats: dict) -> None:
        nonlocal last
        last = stats
        if _console:
            _console.print(
                f"  [cyan]deauth[/cyan] frames={stats['frames']} "
                f"ch={stats['channel']} reason={stats['reason']} "
                f"t={stats['elapsed']}s"
            )

    UI.print_info(
        f"Deauth {bssid} from {target_iface} → {len(stations)} station(s), "
        f"bands={','.join(bands)} — Ctrl+C to stop"
    )
    try:
        outcome = attacks.run_deauth(cfg, on_stats=on_stats, stop_event=stop)
    except KeyboardInterrupt:
        stop.set()
        outcome = {"frames": last.get("frames", 0), "errors": 0,
                   "elapsed": round(time.time() - started, 1), "pps": 0.0}

    if outcome.get("frames"):
        UI.print_success(
            f"Deauth completed: {outcome['frames']} frames "
            f"({outcome.get('pps', 0)}/s) in {outcome['elapsed']}s"
        )
    else:
        UI.print_error(
            "Deauth sent 0 frames — check monitor mode, channel lock and that "
            "the BSSID is actually on air."
        )

    if not was_monitor:
        mode_helper.set_managed(target_iface)
    return outcome
