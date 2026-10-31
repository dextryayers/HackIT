"""Terminal renderer for port scan results.

Design rules:
  * one row per port, aligned on visible width (ANSI and wide glyphs counted)
  * service and version share one column so the eye reads "MySQL 11.8.6"
  * the banner column always belongs to the port beside it
  * no heavy box — a header rule and a footer rule, nothing else
"""

from __future__ import annotations

import re
import shutil
import unicodedata
from typing import Dict, Iterable, List, Optional, Sequence

try:
    from hackit.ui import (
        B_CYAN, B_GREEN, B_RED, B_WHITE, B_YELLOW, BOLD, CYAN,
        DIM, GREEN, MAGENTA, RED, RESET, YELLOW,
    )
except Exception:  # pragma: no cover - ui module optional in isolation
    CSI = "\x1b["
    RESET, BOLD, DIM = CSI + "0m", CSI + "1m", CSI + "2m"
    RED, GREEN, YELLOW, CYAN, MAGENTA = (CSI + f"{n}m" for n in (31, 32, 33, 36, 35))
    B_RED, B_GREEN, B_YELLOW, B_CYAN, B_WHITE = (CSI + f"{n}m" for n in (91, 92, 93, 96, 97))

_ANSI = re.compile(r"\x1b\[[0-9;]*m")

RULE = "─"


def _width(text: str) -> int:
    """Visible width: strip ANSI, count wide glyphs as two cells."""
    plain = _ANSI.sub("", str(text))
    total = 0
    for ch in plain:
        total += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return total


def _pad(text: str, width: int, align: str = "left") -> str:
    gap = max(0, width - _width(text))
    if align == "right":
        return " " * gap + text
    if align == "center":
        left = gap // 2
        return " " * left + text + " " * (gap - left)
    return text + " " * gap


def _clip(text: str, width: int) -> str:
    plain = str(text)
    if _width(plain) <= width:
        return plain
    out = []
    used = 0
    for ch in plain:
        w = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if used + w > width - 1:
            break
        out.append(ch)
        used += w
    return "".join(out) + "…"


def _color(text: str, color: str, bold: bool = False) -> str:
    return f"{color}{BOLD if bold else ''}{text}{RESET}"


def _terminal_width(default: int = 110) -> int:
    try:
        return max(72, min(shutil.get_terminal_size().columns, 160))
    except OSError:
        return default


STATE_STYLE = {
    "open": (B_GREEN, "open"),
    "filtered": (B_YELLOW, "filtered"),
    "closed": (DIM, "closed"),
    "error": (B_RED, "error"),
    "unfiltered": (CYAN, "unfiltered"),
}


def _confidence(value: float) -> str:
    if value <= 0:
        return _color("  —", DIM)
    pct = int(round(value * 100))
    color = B_GREEN if pct >= 90 else GREEN if pct >= 70 else YELLOW if pct >= 50 else RED
    return _color(f"{pct:>3}%", color)


def _service_version(record: Dict, width: int) -> str:
    service = str(record.get("service") or record.get("service_probe") or "").split("|")[0].strip()
    version = str(record.get("version") or "").strip()
    if service.lower() in ("unknown", "none"):
        service = ""
    if version and version in service:
        version = ""
    label = " ".join(x for x in (service, version) if x)
    if not label:
        return _color("—", DIM)
    return _clip(label, width)


def _banner_text(record: Dict, width: int) -> str:
    banner = str(record.get("banner") or "")
    banner = " ".join(banner.replace("\r", " ").replace("\n", " ").split())
    version = str(record.get("version") or "").strip()

    # Keep the banner verbatim — it is the evidence. The version only gets
    # prefixed when the banner does not already carry it.
    if version and banner and version not in banner:
        banner = f"{version}  {banner}"

    if not banner:
        protocol = str(record.get("banner_protocol") or "").strip()
        if protocol:
            return _color(f"<{protocol} decoded, no text>", DIM)
        return _color("—", DIM)

    if record.get("banner_mismatch"):
        banner = "⚠ " + banner
    return _clip(banner, width)


def render_port_table(
    port_results: Sequence[Dict],
    show_risk: bool = False,
    timeline: Optional[Iterable[Dict]] = None,
    open_only: bool = False,
    title: str = "PORT SCAN RESULTS",
    host: str = "",
) -> None:
    """Print the results table. Falls back to plain ASCII when not a TTY."""
    rows = [r for r in (port_results or []) if isinstance(r, dict) and r.get("port")]
    if open_only:
        rows = [r for r in rows if str(r.get("status", "")).lower() == "open"]
    if not rows:
        print(_color("  no results", DIM))
        return
    rows.sort(key=lambda r: (0 if str(r.get("status", "")).lower() == "open" else 1, r.get("port", 0)))

    term = _terminal_width()
    # STATE is noise when every row is open — drop it and give the space to
    # the banner. --all-ports brings it back.
    show_state = any(str(r.get("status", "")).lower() != "open" for r in rows)
    widths = {"port": 10, "state": 9, "service": 24, "protocol": 10, "conf": 5}
    gaps = 2
    active = ["port", "service", "protocol", "conf"]
    if show_state:
        active.insert(1, "state")
    fixed = sum(widths[k] for k in active) + gaps * (len(active) - 1)
    banner_width = max(24, term - fixed - 2)

    labels = {
        "port": "PORT", "state": "STATE", "service": "SERVICE",
        "protocol": "PROTOCOL", "conf": "CONF",
    }
    columns = [
        (labels[k], widths[k], "right" if k == "conf" else "left")
        for k in active
    ] + [("BANNER", banner_width, "left")]
    total_width = sum(w for _, w, _ in columns) + gaps * (len(columns) - 1)

    header = (" " * gaps).join(
        _color(_pad(name, w, align), DIM, bold=True) for name, w, align in columns
    )

    print()
    if title:
        label = title if not host else f"{title} · {host}"
        print("  " + _color(label, B_WHITE, bold=True))
    print("  " + header)
    print("  " + _color(RULE * total_width, DIM))

    for record in rows:
        state = str(record.get("status", "unknown")).lower()
        state_color, state_text = STATE_STYLE.get(state, (DIM, state[:9]))

        conf = record.get("banner_confidence")
        if conf is None:
            conf = record.get("confidence", 0.0)
        try:
            conf = float(conf)
        except (TypeError, ValueError):
            conf = 0.0

        protocol = str(record.get("banner_protocol") or "").strip() or "—"
        if record.get("banner_mismatch"):
            protocol = "~" + protocol
        protocol_color = MAGENTA if record.get("banner_protocol") else DIM

        cells = [
            _color(_pad(f"{record.get('port')}/tcp", widths["port"]), B_WHITE, bold=state == "open"),
            _color(_pad(_service_version(record, widths["service"]), widths["service"]), CYAN),
            _color(_pad(_clip(protocol, widths["protocol"]), widths["protocol"]), protocol_color),
            _pad(_confidence(conf), widths["conf"], "right"),
            _pad(_banner_text(record, banner_width), banner_width),
        ]
        if show_state:
            cells.insert(1, _color(_pad(state_text, widths["state"]), state_color))
        print("  " + (" " * gaps).join(cells))

    print("  " + _color(RULE * total_width, DIM))

    opened = [r for r in rows if str(r.get("status", "")).lower() == "open"]
    protos = sorted({str(r.get("banner_protocol")) for r in opened if r.get("banner_protocol")})
    mismatches = [r for r in opened if r.get("banner_mismatch")]

    summary = f"{len(opened)} open"
    if len(rows) != len(opened):
        summary += f" / {len(rows)} tested"
    if protos:
        summary += "   " + _color("·".join(protos[:8]), CYAN)
    if mismatches:
        summary += f"   {len(mismatches)} on non-standard port" if len(mismatches) > 1 else "   1 on non-standard port"
    print("  " + _color(summary, DIM))
    print()

    if timeline:
        entries = list(timeline)[-10:]
        if entries:
            print(_color("  TIMELINE", B_WHITE, bold=True))
            for entry in entries:
                ts = str(entry.get("time", ""))
                msg = str(entry.get("msg", ""))
                print(_color(f"  {ts:<10} {msg}", DIM))
            print()


def render_engine_matrix(engine_stats: Dict[str, Dict]) -> None:
    """One compact row per engine: name, progress, scanned, open, speed."""
    if not engine_stats:
        return
    print("  " + _color("ENGINES", DIM, bold=True))
    for name, info in sorted(engine_stats.items()):
        status = str(info.get("status", "pending"))
        color = {"running": B_GREEN, "done": CYAN, "error": B_RED}.get(status, YELLOW)
        progress = float(info.get("progress", 0) or 0)
        filled = int(20 * min(progress, 100) / 100)
        bar = "█" * filled + "░" * (20 - filled)
        speed = info.get("rate")
        speed_txt = f"{float(speed):5.0f}/s" if speed else "     "
        line = (
            f"  {_color(_pad(name, 10), B_WHITE)} {_color(bar, color)} "
            f"{progress:5.1f}%   {info.get('ports_scanned', 0):>6} ports   "
            f"{_color(str(info.get('open_found', 0)), B_GREEN):>4} open   {speed_txt}"
        )
        print(line)
    print()
