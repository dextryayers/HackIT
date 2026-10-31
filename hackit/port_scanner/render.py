"""Terminal renderer for port scan results.

Two goals: every column stays aligned regardless of ANSI codes or wide
characters, and the banner column always belongs to the port beside it —
protocol, version and confidence come from the same probe that produced the
banner string.
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

BOX = {
    "tl": "╭", "tr": "╮", "bl": "╰", "br": "╯",
    "h": "─", "v": "│", "lt": "├", "rt": "┤", "tt": "┬", "bt": "┴", "x": "┼",
}


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
    "open": (B_GREEN, "OPEN"),
    "filtered": (B_YELLOW, "FILTERED"),
    "closed": (RED, "CLOSED"),
    "error": (B_RED, "ERROR"),
    "unfiltered": (CYAN, "UNFILTERED"),
}


def _confidence_badge(value: float) -> str:
    if value <= 0:
        return _color("  --", DIM)
    pct = int(round(value * 100))
    if pct >= 90:
        color = B_GREEN
    elif pct >= 70:
        color = GREEN
    elif pct >= 50:
        color = YELLOW
    else:
        color = RED
    return _color(f"{pct:>3}%", color)


def _service_label(record: Dict) -> str:
    service = record.get("service") or record.get("service_probe") or ""
    service = str(service).split("|")[0].strip()
    if not service or service.lower() in ("unknown", "none"):
        service = ""
    return service


def _banner_label(record: Dict, width: int) -> str:
    parts: List[str] = []
    version = str(record.get("version") or "").strip()
    banner = str(record.get("banner") or "")
    banner = " ".join(banner.replace("\r", " ").replace("\n", " ").split())

    # Show the version once: prefix it only when the banner does not carry it.
    if version and (not banner or version not in banner):
        parts.append(version)
    if banner:
        parts.append(banner)

    if not parts:
        evidence = record.get("banner_evidence") or ""
        protocol = record.get("banner_protocol") or ""
        if protocol:
            return _color(f"<{protocol} probe, no text>", DIM)
        if evidence:
            return _color(f"<{evidence}: no banner>", DIM)
        return _color("—", DIM)

    text = " | ".join(parts)
    if record.get("banner_mismatch"):
        text = "⚠ " + text
    return _clip(text, width)


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
    if not rows:
        print(_color("  no results", DIM))
        return
    rows.sort(key=lambda r: (0 if str(r.get("status", "")).lower() == "open" else 1, r.get("port", 0)))
    if open_only:
        rows = [r for r in rows if str(r.get("status", "")).lower() == "open"]

    term = _terminal_width()
    widths = {"port": 10, "state": 8, "service": 14, "protocol": 10, "conf": 5}
    fixed = sum(widths.values()) + 3 * 5 + 4  # 5 gaps of 3 cells + frame padding
    banner_width = max(24, term - fixed)

    header = [
        ("PORT", widths["port"], "left"),
        ("STATE", widths["state"], "left"),
        ("SERVICE", widths["service"], "left"),
        ("PROTOCOL", widths["protocol"], "left"),
        ("CONF", widths["conf"], "right"),
        ("BANNER / VERSION", banner_width, "left"),
    ]

    total_width = sum(w for _, w, _ in header) + 3 * len(header) + 2
    top = BOX["tl"] + BOX["h"] * (total_width - 2) + BOX["tr"]
    bottom = BOX["bl"] + BOX["h"] * (total_width - 2) + BOX["br"]
    sep = BOX["lt"] + BOX["h"] * (total_width - 2) + BOX["rt"]

    label = title if not host else f"{title} — {host}"
    print()
    print(_color(top, B_CYAN))
    print(_color(BOX["v"], B_CYAN) + " " + _pad(_color(label, B_WHITE, bold=True), total_width - 3) + _color(BOX["v"], B_CYAN))
    print(_color(sep, B_CYAN))
    print(
        _color(BOX["v"], B_CYAN)
        + " "
        + "   ".join(_color(_pad(name, w, align), B_WHITE, bold=True) for name, w, align in header)
        + " "
        + _color(BOX["v"], B_CYAN)
    )
    print(_color(sep, B_CYAN))

    for record in rows:
        state = str(record.get("status", "unknown")).lower()
        state_color, state_text = STATE_STYLE.get(state, (DIM, state.upper()[:10]))

        port_text = _color(_pad(f"{record.get('port')}/tcp", widths["port"]), B_WHITE, bold=state == "open")
        state_cell = _color(_pad(state_text, widths["state"]), state_color, bold=state == "open")

        service = _service_label(record) or "—"
        service_cell = _color(_pad(_clip(service, widths["service"]), widths["service"]), CYAN)

        protocol = str(record.get("banner_protocol") or "").strip() or "—"
        if record.get("banner_mismatch"):
            protocol = "⚠ " + protocol
        protocol_cell = _color(_pad(_clip(protocol, widths["protocol"]), widths["protocol"]), MAGENTA if protocol != "—" else DIM)

        conf = record.get("banner_confidence")
        if conf is None:
            conf = record.get("confidence", 0.0)
        try:
            conf = float(conf)
        except (TypeError, ValueError):
            conf = 0.0
        conf_cell = _pad(_confidence_badge(conf), widths["conf"], "right")

        banner_cell = _pad(_banner_label(record, banner_width), banner_width)

        print(
            _color(BOX["v"], B_CYAN)
            + " "
            + port_text
            + "   "
            + state_cell
            + "   "
            + service_cell
            + "   "
            + protocol_cell
            + "   "
            + conf_cell
            + "   "
            + banner_cell
            + " "
            + _color(BOX["v"], B_CYAN)
        )

    print(_color(bottom, B_CYAN))

    opened = [r for r in rows if str(r.get("status", "")).lower() == "open"]
    protos = sorted({str(r.get("banner_protocol")) for r in opened if r.get("banner_protocol")})
    mismatches = [r for r in opened if r.get("banner_mismatch")]
    summary = f"  {len(opened)} open / {len(rows)} tested"
    if protos:
        summary += "  ·  " + ", ".join(protos[:8])
    if mismatches:
        summary += f"  ·  {len(mismatches)} protocol/port mismatch"
    print(_color(summary, DIM))

    if timeline:
        entries = list(timeline)[-10:]
        if entries:
            print()
            print(_color("  TIMELINE", B_WHITE, bold=True))
            for entry in entries:
                ts = str(entry.get("time", ""))
                msg = str(entry.get("msg", ""))
                print(_color(f"  {ts:<10} {msg}", DIM))
    print()


def render_engine_matrix(engine_stats: Dict[str, Dict]) -> None:
    """One row per engine: progress, ports, open, speed."""
    if not engine_stats:
        return
    print(_color("  ENGINES", B_WHITE, bold=True))
    for name, info in sorted(engine_stats.items()):
        status = str(info.get("status", "pending"))
        color = {"running": B_GREEN, "done": CYAN, "error": B_RED}.get(status, YELLOW)
        progress = float(info.get("progress", 0) or 0)
        filled = int(24 * min(progress, 100) / 100)
        bar = "█" * filled + "░" * (24 - filled)
        line = (
            f"  {_color(name.ljust(10), B_WHITE)} {_color(bar, color)} "
            f"{progress:5.1f}%  scanned={info.get('ports_scanned', 0):<6} "
            f"open={_color(str(info.get('open_found', 0)), B_GREEN)}"
        )
        print(line)
    print()
