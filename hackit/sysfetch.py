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
        B_RED, B_CYAN, B_MAGENTA, B_YELLOW, DIM, RESET,
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
    return base, bright, DIM + base, RESET, _colored


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


def _battery_level():
    """Return (percent:int|None, state:str)."""
    for bat in sorted(Path("/sys/class/power_supply").glob("BAT*")):
        try:
            cap = (bat / "capacity").read_text().strip() if (bat / "capacity").exists() else ""
            status = (bat / "status").read_text().strip() if (bat / "status").exists() else ""
        except Exception:
            continue
        if cap.isdigit():
            return int(cap), status or UNKNOWN
    if _psutil is not None:
        try:
            b = _psutil.sensors_battery()
            if b is not None:
                state = "Charging" if b.power_plugged else "Discharging"
                return int(b.percent), state
        except Exception:
            pass
    return None, UNKNOWN


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
        tz = time.tzname[time.daylight] if time.daylight else time.tzname[0]
    except Exception:
        tz = UNKNOWN
    try:
        loc = locale.getdefaultlocale()[0] or UNKNOWN
    except Exception:
        loc = UNKNOWN

    iface = _default_iface()
    cores = os.cpu_count() or 0
    used_disk, total_disk = None, None
    try:
        disk = shutil.disk_usage("/")
        used_disk = (disk.total - disk.free) // 1024 // 1024 // 1024
        total_disk = disk.total // 1024 // 1024 // 1024
        disk_str = _fmt_pair(used_disk, total_disk, "GiB")
    except Exception:
        disk_str = UNKNOWN
    batt_pct, batt_state = _battery_level()

    def _pct(used, total):
        if used is None or total is None or total <= 0:
            return None
        return round(used / total * 100)

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
        "memory_used": used_mem,
        "memory_total": total_mem,
        "memory_pct": _pct(used_mem, total_mem),
        "disk": disk_str,
        "disk_used": used_disk,
        "disk_total": total_disk,
        "disk_pct": _pct(used_disk, total_disk),
        "battery": _battery(),
        "battery_pct": batt_pct,
        "battery_state": batt_state,
        "network_interface": iface or UNKNOWN,
        "local_ip": _local_ip(),
        "mac": _mac(iface),
        "packages": _packages(),
        "processes": _processes(),
        "load": " ".join(f"{v:.2f}" for v in os.getloadavg()) if hasattr(os, "getloadavg") else UNKNOWN,
        "locale": loc,
        "timezone": tz or UNKNOWN,
    }


def _level_color(P, pct, mode):
    """Threshold color for a percent. usage: high is bad. charge: high is good."""
    if pct is None:
        return ""
    if mode == "charge":
        return P.good if pct >= 60 else (P.warn if pct >= 25 else P.bad)
    return P.good if pct < 60 else (P.warn if pct < 85 else P.bad)


def _meter(P, pct, mode="usage", width=10):
    if pct is None:
        return UNKNOWN
    filled = max(0, min(width, int(round(pct / 100 * width))))
    bar = "\u2588" * filled + "\u2591" * (width - filled)
    pct_s = f"{pct:.0f}%"
    if P.use_color:
        c = _level_color(P, pct, mode)
        if c:
            bar = f"{c}{bar}{P.reset}"
            pct_s = f"{c}{pct_s}{P.reset}"
    return f"{bar} {pct_s}"


_DENSE = set("@#")
_MID = set("%*+=")
_FAINT = set(":-")


def _logo_line(P, line):
    """Shade logo by character density for depth. Plain chars stay plain."""
    if not P.use_color:
        return line

    def kind(ch):
        if ch in _DENSE:
            return 0
        if ch in _MID:
            return 1
        if ch in _FAINT:
            return 2
        return 3

    runs, cur, cls = [], [], None
    for ch in line:
        k = kind(ch)
        if k != cls:
            if cur:
                runs.append((cls, "".join(cur)))
            cur, cls = [ch], k
        else:
            cur.append(ch)
    if cur:
        runs.append((cls, "".join(cur)))
    cols = (P.bright, P.base, None, None)
    out = []
    for k, s in runs:
        if k == 3:
            out.append(s)
        elif k == 2:
            out.append(f"{P.dim}{s}{P.reset}")
        else:
            out.append(P.colored(s, cols[k]))
    return "".join(out)


def _kv(P, key, val, width=10):
    label = key.ljust(width)
    if P.use_color:
        label = P.colored(label, P.bright)
    return f"{label} {val}"


def _info_lines(info, P):
    """Spec panel grouped in sections. Lines come back fully styled."""
    title = f"{info['user']}@{info['host']}"
    lines = []
    if P.use_color:
        lines.append(P.colored(title, P.bright))
        lines.append(f"{P.dim}{'─' * len(title)}{P.reset}")
    else:
        lines.append(title)
        lines.append("-" * len(title))

    def section(name):
        lines.append(P.colored(f"▸ {name}", P.bright) if P.use_color else f"> {name}")

    def mem_line():
        if info.get("memory_used") is None or info.get("memory_total") is None:
            return UNKNOWN
        return f"{info['memory_used']:,} / {info['memory_total']:,} MiB  " + \
            _meter(P, info.get("memory_pct"))

    def disk_line():
        if info.get("disk_used") is None or info.get("disk_total") is None:
            return UNKNOWN
        return f"{info['disk_used']:,} / {info['disk_total']:,} GiB  " + \
            _meter(P, info.get("disk_pct"))

    def batt_line():
        pct = info.get("battery_pct")
        if pct is None:
            return "No battery"
        state = info.get("battery_state") or UNKNOWN
        return f"{pct}% ({state})  " + _meter(P, pct, mode="charge")

    section("SYSTEM")
    lines.append(_kv(P, "OS", info["os"]))
    lines.append(_kv(P, "Kernel", info["kernel"]))
    lines.append(_kv(P, "Uptime", info["uptime"]))
    lines.append(_kv(P, "Shell", info["shell"]))
    lines.append(_kv(P, "Terminal", info["terminal"]))
    lines.append(_kv(P, "Desktop", info["desktop"]))
    lines.append(_kv(P, "Session", info["session"]))

    section("HARDWARE")
    lines.append(_kv(P, "CPU", f"{info['cpu']} ({info['cpu_cores']}) @ {info['cpu_freq']}"))
    lines.append(_kv(P, "GPU", info["gpu"]))
    lines.append(_kv(P, "Memory", mem_line()))
    lines.append(_kv(P, "Disk (/)", disk_line()))
    lines.append(_kv(P, "Battery", batt_line()))

    section("RUNTIME")
    lines.append(_kv(P, "Packages", info["packages"]))
    lines.append(_kv(P, "Processes", info["processes"]))
    lines.append(_kv(P, "Load Avg", info["load"]))

    section("NETWORK")
    lines.append(_kv(P, "Net IF", f"{info['network_interface']} ({info['local_ip']})"))
    lines.append(_kv(P, "MAC", info["mac"]))

    section("LOCALE")
    lines.append(_kv(P, "Locale", info["locale"]))
    lines.append(_kv(P, "Timezone", info["timezone"]))
    return lines


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


class _Palette:
    pass


def render(info, logo_lines, accent, use_color):
    """Render fixed logo + sectioned spec panel, neofetch style."""
    from hackit.ui import GREEN, YELLOW, RED
    base, bright, dim, reset, colored = _accent_color(accent)
    P = _Palette()
    P.base, P.bright, P.dim, P.reset = base, bright, dim, reset
    P.colored, P.good, P.warn, P.bad = colored, GREEN, YELLOW, RED
    P.use_color = use_color

    body = _info_lines(info, P)
    width = max((len(ln) for ln in logo_lines), default=0)
    try:
        term_w = shutil.get_terminal_size().columns
    except Exception:
        term_w = 80
    if not logo_lines:
        return "\n".join(body)
    # Narrow terminals: centered logo stacked above specs.
    if width + 45 > term_w:
        pad = max(0, (term_w - width) // 2)
        return "\n".join(
            [(" " * pad) + _logo_line(P, ln) for ln in logo_lines]
            + [""]
            + body
        )
    total = max(len(logo_lines), len(body))
    out = []
    for i in range(total):
        raw = logo_lines[i] if i < len(logo_lines) else ""
        left = _logo_line(P, raw.ljust(width))
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
