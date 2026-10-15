#!/usr/bin/env python3
"""HackIt system fetch - neofetch-style host profiler with hacker theme.

Displays the repository ASCII logo next to real host specifications.
All collectors degrade gracefully to "Unknown" when a source is missing.
"""
import click
import getpass
import locale
import os
import platform
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path

try:
    import psutil as _psutil
except Exception:
    _psutil = None

UNKNOWN = "Unknown"
LOGO_FILE = Path(__file__).resolve().parent.parent / "logo.txt"


def _accent_color(name):
    from hackit.ui import (
        _colored, GREEN, RED, CYAN, MAGENTA, YELLOW, B_WHITE, B_GREEN,
        B_RED, B_CYAN, B_MAGENTA, B_YELLOW,
    )
    table = {
        "green": (GREEN, B_GREEN),
        "red": (RED, B_RED),
        "cyan": (CYAN, B_CYAN),
        "magenta": (MAGENTA, B_MAGENTA),
        "yellow": (YELLOW, B_YELLOW),
        "white": (B_WHITE, B_WHITE),
    }
    base, bright = table.get(name, table["green"])
    return base, bright, _colored


def _run(cmd, timeout=2):
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return ""


def _read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _mem():
    """Return (used_mib, total_mib) or (None, None)."""
    if _psutil is not None:
        try:
            vm = _psutil.virtual_memory()
            return vm.used // 1024 // 1024, vm.total // 1024 // 1024
        except Exception:
            pass
    total = avail = None
    for line in _read_text("/proc/meminfo").splitlines():
        if line.startswith("MemTotal:"):
            total = int(line.split()[1]) // 1024
        elif line.startswith("MemAvailable:"):
            avail = int(line.split()[1]) // 1024
    if total is None:
        return None, None
    used = total - (avail or 0)
    return used, total


def _bar(pct, width=12):
    filled = max(0, min(width, int(round(pct / 100 * width))))
    return "#" * filled + "-" * (width - filled)


def _fmt_pair(used, total, unit):
    if used is None or total is None or total <= 0:
        return UNKNOWN
    pct = used / total * 100
    return f"{used} / {total} {unit} [{_bar(pct)}] {pct:.0f}%"


def _cpu_model():
    for line in _read_text("/proc/cpuinfo").splitlines():
        if line.startswith("model name"):
            return line.split(":", 1)[1].strip()
    if _psutil is not None:
        try:
            freq = _psutil.cpu_freq()
            if freq and freq.model_name:
                return freq.model_name
        except Exception:
            pass
    return platform.processor() or UNKNOWN


def _cpu_freq():
    for base in Path("/sys/devices/system/cpu").glob("cpu[0-9]*/cpufreq/scaling_cur_freq"):
        try:
            khz = int(base.read_text().strip())
            if khz > 0:
                return f"{khz / 1000:.0f} MHz"
        except Exception:
            continue
    for line in _read_text("/proc/cpuinfo").splitlines():
        if line.startswith("cpu MHz"):
            try:
                return f"{float(line.split(':')[1]):.0f} MHz"
            except Exception:
                pass
    return UNKNOWN


def _gpu():
    out = _run(["lspci"], timeout=3)
    gpus = []
    for line in out.splitlines():
        if re.search(r"vga|3d controller|display", line, re.I):
            part = line.split(":", 2)
            gpus.append(part[2].strip() if len(part) > 2 else line.strip())
    if gpus:
        return " | ".join(dict.fromkeys(gpus))[:120]
    return UNKNOWN


def _battery():
    for bat in sorted(Path("/sys/class/power_supply").glob("BAT*")):
        cap = (bat / "capacity").read_text().strip() if (bat / "capacity").exists() else ""
        status = (bat / "status").read_text().strip() if (bat / "status").exists() else ""
        if cap.isdigit():
            extra = f" ({status})" if status else ""
            return f"{cap}%{extra} [{_bar(int(cap))}]"
    if _psutil is not None:
        try:
            b = _psutil.sensors_battery()
            if b is not None:
                state = "Charging" if b.power_plugged else "Discharging"
                return f"{b.percent:.0f}% ({state}) [{_bar(b.percent)}]"
        except Exception:
            pass
    return "No battery / Unknown"


def _default_iface():
    for line in _read_text("/proc/net/route").splitlines()[1:]:
        parts = line.split()
        if len(parts) > 1 and parts[1] == "00000000":
            return parts[0]
    return ""


def _local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return UNKNOWN
    finally:
        sock.close()


def _mac(iface):
    if not iface:
        return UNKNOWN
    mac = _read_text(f"/sys/class/net/{iface}/address").strip()
    return mac.upper() if mac else UNKNOWN


def _uptime():
    try:
        secs = float(_read_text("/proc/uptime").split()[0])
    except Exception:
        if _psutil is not None:
            try:
                secs = time.time() - _psutil.boot_time()
            except Exception:
                return UNKNOWN
        else:
            return UNKNOWN
    days, rem = divmod(int(secs), 86400)
    hours, rem = divmod(rem, 3600)
    mins, _ = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    parts.append(f"{mins}m")
    return " ".join(parts)


def _os_name():
    text = _read_text("/etc/os-release")
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return f"{platform.system()} {platform.release()}".strip() or UNKNOWN


def _packages():
    count = _run(["dpkg-query", "-f", "${binary:Package}\n", "-W"], timeout=10)
    if count:
        return str(len(count.splitlines()))
    rpm = _run(["rpm", "-qa"], timeout=10)
    if rpm:
        return str(len(rpm.splitlines()))
    return UNKNOWN


def _processes():
    if _psutil is not None:
        try:
            return str(len(_psutil.pids()))
        except Exception:
            pass
    procs = [p for p in Path("/proc").glob("[0-9]*") if p.is_dir()]
    return str(len(procs)) if procs else UNKNOWN


def collect():
    """Gather all host facts. Keys are stable for --json consumers."""
    try:
        user = getpass.getuser()
    except Exception:
        user = os.environ.get("USER", UNKNOWN)
    host = platform.node() or UNKNOWN

    used_mem, total_mem = _mem()
    try:
        disk = shutil.disk_usage("/")
        disk_str = _fmt_pair(
            (disk.total - disk.free) // 1024 // 1024 // 1024,
            disk.total // 1024 // 1024 // 1024, "GiB",
        )
    except Exception:
        disk_str = UNKNOWN

    try:
        tz = time.tzname[time.daylight] if time.daylight else time.tzname[0]
    except Exception:
        tz = UNKNOWN
    try:
        loc = locale.getdefaultlocale()[0] or UNKNOWN
    except Exception:
        loc = UNKNOWN

    iface = _default_iface()
    cores = os.cpu_count() or 0

    return {
        "user": user,
        "host": host,
        "os": _os_name(),
        "kernel": f"{platform.release()} ({platform.machine()})".strip(),
        "uptime": _uptime(),
        "shell": os.path.basename(os.environ.get("SHELL", "Unknown")),
        "terminal": os.environ.get("TERM_PROGRAM", os.environ.get("TERM", UNKNOWN)),
        "desktop": os.environ.get("XDG_CURRENT_DESKTOP", os.environ.get("DESKTOP_SESSION", UNKNOWN)),
        "session": os.environ.get("XDG_SESSION_TYPE", UNKNOWN),
        "cpu": _cpu_model(),
        "cpu_cores": str(cores) if cores else UNKNOWN,
        "cpu_freq": _cpu_freq(),
        "gpu": _gpu(),
        "memory": _fmt_pair(used_mem, total_mem, "MiB"),
        "disk": disk_str,
        "battery": _battery(),
        "network_interface": iface or UNKNOWN,
        "local_ip": _local_ip(),
        "mac": _mac(iface),
        "packages": _packages(),
        "processes": _processes(),
        "load": " ".join(f"{v:.2f}" for v in os.getloadavg()) if hasattr(os, "getloadavg") else UNKNOWN,
        "locale": loc,
        "timezone": tz or UNKNOWN,
    }


def _rows(info):
    return [
        ("OS", info["os"]),
        ("Kernel", info["kernel"]),
        ("Uptime", info["uptime"]),
        ("Shell", info["shell"]),
        ("Terminal", info["terminal"]),
        ("Desktop", info["desktop"]),
        ("Session", info["session"]),
        ("CPU", f"{info['cpu']} ({info['cpu_cores']}) @ {info['cpu_freq']}"),
        ("GPU", info["gpu"]),
        ("Memory", info["memory"]),
        ("Disk (/)", info["disk"]),
        ("Battery", info["battery"]),
        ("Net IF", f"{info['network_interface']} ({info['local_ip']})"),
        ("MAC", info["mac"]),
        ("Packages", info["packages"]),
        ("Processes", info["processes"]),
        ("Load Avg", info["load"]),
        ("Locale", info["locale"]),
        ("Timezone", info["timezone"]),
    ]


def _load_logo(path):
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        lines = [ln.rstrip() for ln in lines]
        while lines and not lines[0].strip():
            lines.pop(0)
        while lines and not lines[-1].strip():
            lines.pop()
        return lines or ["[logo missing]"]
    except Exception:
        return ["[logo missing]"]


def _info_lines(info, paint_key):
    """Format the spec block. paint_key(key) styles the label."""
    title = f"{info['user']}@{info['host']}"
    lines = [paint_key(None, title), paint_key(None, "-" * len(title))]
    for key, val in _rows(info):
        lines.append(f"{paint_key(key, key + ':')} {val}")
    return lines


def render(info, logo_lines, accent, use_color):
    """Render fixed logo + info side by side, neofetch style."""
    base, bright, colored = _accent_color(accent)

    def paint(text, color):
        return colored(text, color) if use_color else text

    def paint_key(key, text):
        return paint(text, bright)

    width = max((len(ln) for ln in logo_lines), default=0)
    try:
        term_w = shutil.get_terminal_size().columns
    except Exception:
        term_w = 80
    # Narrow terminals: stack logo above specs instead of squeezing.
    if logo_lines and width + 45 > term_w:
        return "\n".join(
            [paint(ln, base) for ln in logo_lines]
            + [""]
            + _info_lines(info, paint_key)
        )
    body = _info_lines(info, paint_key)
    total = max(len(logo_lines), len(body))
    out = []
    for i in range(total):
        left = logo_lines[i] if i < len(logo_lines) else ""
        left = paint(left.ljust(width), base)
        if i < len(body):
            out.append(f"{left}   {body[i]}")
        else:
            out.append(left)
    return "\n".join(out)


@click.command(name="fetch")
@click.option("--no-logo", is_flag=True, help="Show specs without the logo")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable JSON output")
@click.option("--no-color", is_flag=True, help="Disable colored output")
@click.option("--accent", default="green",
              type=click.Choice(["green", "red", "cyan", "magenta", "yellow", "white"]),
              help="Theme accent color")
def sysfetch(no_logo, as_json, no_color, accent):
    """Host profiler - neofetch-style system specs with hacker theme."""
    import json as _json
    info = collect()
    if as_json:
        click.echo(_json.dumps(info, indent=2))
        return
    logo = [] if no_logo else _load_logo(str(LOGO_FILE))
    click.echo(render(info, logo, accent, use_color=not no_color),
               color=not no_color)
