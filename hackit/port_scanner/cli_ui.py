"""Presentation layer for the port scanner CLI.

Everything that touches the terminal lives here so ``__init__.py`` can stay a
command and this module can be reused by tests. Two rules:

* alignment is computed from the data, never guessed;
* colour is applied through ``hackit.ui`` so ``--no-color`` keeps working.
"""
from __future__ import annotations

import shutil
import sys
from typing import Dict, Iterable, List, Optional, Sequence

from hackit.ui import (
    B_CYAN, B_GREEN, B_MAGENTA, B_RED, B_WHITE, B_YELLOW,
    CYAN, DIM, GREEN, MAGENTA, RED, WHITE, YELLOW, _colored,
)

RULE = "─"
GUTTER = "  "

SEVERITY_STYLE = {
    "critical": (B_RED, "CRIT"),
    "high": (B_RED, "HIGH"),
    "medium": (B_YELLOW, "MED "),
    "low": (CYAN, "LOW "),
    "info": (DIM, "INFO"),
}

STATE_STYLE = {
    "open": (B_GREEN, "open"),
    "closed": (DIM, "closed"),
    "filtered": (YELLOW, "filtered"),
    "error": (RED, "error"),
}


def width(default: int = 78) -> int:
    try:
        return max(60, min(shutil.get_terminal_size((100, 24)).columns, 140))
    except OSError:
        return default


def emit(text: str = "") -> None:
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def clear_line() -> None:
    sys.stdout.write("\r" + " " * (width() - 1) + "\r")
    sys.stdout.flush()


def paint(text: str, colour: str, bold: bool = False) -> str:
    return _colored(str(text), colour, bold=bold)


def rule(char: str = RULE, indent: str = GUTTER) -> None:
    emit(indent + paint(char * (width() - len(indent) - 2), DIM))


def title(text: str, subtitle: str = "") -> None:
    head = paint(text.upper(), B_WHITE, bold=True)
    if subtitle:
        head += paint("  " + subtitle, DIM)
    emit()
    emit(GUTTER + head)


def section(text: str, subtitle: str = "") -> None:
    emit()
    emit(GUTTER + paint(text.upper(), B_CYAN, bold=True)
         + (paint("  " + subtitle, DIM) if subtitle else ""))
    rule()


def note(text: str) -> None:
    emit(GUTTER + paint(text, DIM))


def warn(text: str) -> None:
    emit(GUTTER + paint("! ", YELLOW) + paint(text, YELLOW))


def error(text: str) -> None:
    emit(GUTTER + paint("! ", RED) + paint(text, B_RED))


def ok(text: str) -> None:
    emit(GUTTER + paint("✓ ", B_GREEN) + paint(text, GREEN))


def field(label: str, value: str, label_width: int = 10) -> None:
    emit(GUTTER + paint(label.ljust(label_width), DIM) + str(value))


def header(target: str, address: str, ports_label: str, engine: str,
           profile: str, nse_label: str, workers: int, timeout_ms: int) -> None:
    """Run header: what is being scanned and with what."""
    emit()
    emit(GUTTER + paint("HackIT", B_CYAN, bold=True)
         + paint(" · port scanner", DIM))
    rule()
    field("target", paint(target, B_WHITE, bold=True)
          + (paint("  (" + address + ")", DIM) if address and address != target else ""))
    field("ports", ports_label)
    field("engine", engine)
    field("profile", profile)
    field("nse", nse_label)
    field("timing", "%d workers · %dms probe timeout" % (workers, timeout_ms))
    rule()


def live_open(record: Dict) -> None:
    """One line per open port, printed the moment it is confirmed."""
    port = record.get("port", 0)
    service = str(record.get("service") or "unknown")
    version = str(record.get("version") or "")
    label = (service + (" " + version if version else "")).strip()
    confidence = record.get("confidence") or record.get("banner_confidence") or 0.0
    try:
        confidence = int(round(float(confidence) * 100))
    except (TypeError, ValueError):
        confidence = 0
    emit(GUTTER + paint("+ ", B_GREEN)
         + paint(("%d/tcp" % port).ljust(10), B_WHITE, bold=True)
         + paint(label[:34].ljust(34), CYAN)
         + paint("conf %d%%" % confidence, DIM))


def progress(scanned: int, total: int, elapsed: float) -> None:
    if total <= 0:
        return
    pct = min(100.0, scanned * 100.0 / total)
    rate = scanned / elapsed if elapsed > 0 else 0.0
    bar_width = 28
    filled = int(bar_width * pct / 100.0)
    bar = "█" * filled + "░" * (bar_width - filled)
    sys.stdout.write("\r" + GUTTER + paint(bar, CYAN) + " "
                     + paint("%5.1f%%" % pct, B_WHITE) + " "
                     + paint("%d/%d ports · %.0f p/s" % (scanned, total, rate), DIM))
    sys.stdout.flush()


def finish_progress() -> None:
    clear_line()


def results_table(records: Sequence[Dict], host: str = "", show_all: bool = False,
                  show_risk: bool = False) -> None:
    """Aligned results table; the only place column widths are decided."""
    rows = [r for r in records if isinstance(r, dict) and r.get("port")]
    if not show_all:
        rows = [r for r in rows if str(r.get("status", "")).lower() == "open"]
    if not rows:
        section("results", host)
        note("no open ports")
        return

    rows.sort(key=lambda r: (0 if str(r.get("status", "")).lower() == "open" else 1,
                             r.get("port", 0)))

    show_state = show_all and any(
        str(r.get("status", "")).lower() != "open" for r in rows)

    columns: List[str] = ["port"]
    if show_state:
        columns.append("state")
    columns += ["service", "protocol", "conf", "banner"]
    if show_risk:
        columns.append("risk")

    headers = {
        "port": "PORT", "state": "STATE", "service": "SERVICE",
        "protocol": "PROTO", "conf": "CONF", "banner": "BANNER", "risk": "RISK",
    }
    widths = {
        "port": 9, "state": 9, "service": 26, "protocol": 12,
        "conf": 5, "risk": 5,
    }
    fixed = sum(widths[c] for c in columns if c != "banner")
    gaps = 2 * (len(columns) - 1)
    banner_width = max(20, width() - len(GUTTER) - fixed - gaps - 2)

    def cell(value: str, size: int, colour: str = "", bold: bool = False,
             align: str = "left") -> str:
        text = str(value)[:size]
        text = text.rjust(size) if align == "right" else text.ljust(size)
        return paint(text, colour, bold=bold) if colour else text

    section("results", host)

    head = []
    for column in columns:
        size = banner_width if column == "banner" else widths[column]
        align = "right" if column in ("conf", "risk") else "left"
        head.append(cell(headers[column], size, DIM, align=align))
    emit(GUTTER + (" " * 2).join(head))

    for record in rows:
        state = str(record.get("status", "unknown")).lower()
        state_colour, state_text = STATE_STYLE.get(state, (DIM, state[:9]))

        confidence = record.get("banner_confidence")
        if confidence is None:
            confidence = record.get("confidence", 0.0)
        try:
            confidence = int(round(float(confidence) * 100))
        except (TypeError, ValueError):
            confidence = 0

        protocol = str(record.get("banner_protocol") or "").strip()
        if record.get("banner_mismatch"):
            protocol = "~" + protocol
        protocol = protocol or "—"

        service = str(record.get("service") or "unknown")
        version = str(record.get("version") or "").strip()
        if version and version.lower() not in ("unknown", "-"):
            service = service + " " + version

        banner = record.get("banner") or ""
        banner = " ".join(str(banner).split())
        if not banner:
            banner = record.get("banner_evidence") or ""

        cells = [cell("%d/tcp" % record.get("port", 0), widths["port"], B_WHITE,
                      bold=state == "open")]
        if show_state:
            cells.append(cell(state_text, widths["state"], state_colour))
        cells.append(cell(service, widths["service"], CYAN))
        cells.append(cell(protocol, widths["protocol"],
                          MAGENTA if record.get("banner_protocol") else DIM))
        cells.append(cell("%d%%" % confidence, widths["conf"],
                          B_GREEN if confidence >= 85 else DIM, align="right"))
        cells.append(cell(banner, banner_width, DIM))
        if show_risk:
            score = int(record.get("risk_score") or 0)
            colour = B_RED if score >= 60 else B_YELLOW if score >= 35 else DIM
            cells.append(cell(str(score), widths["risk"], colour, align="right"))
        emit(GUTTER + (" " * 2).join(cells))

    rule()


def nse_findings(results: Sequence, limit: Optional[int] = None,
                 host: str = "") -> int:
    """Render NSE output grouped by port. Returns the number of findings."""
    findings = [r for r in results if getattr(r, "output", None) or getattr(r, "error", None)]
    if not findings:
        return 0

    by_port: Dict[int, List] = {}
    for item in findings:
        by_port.setdefault(item.port, []).append(item)

    total = 0
    for port in sorted(by_port):
        entries = by_port[port]
        entries.sort(key=lambda r: (-_severity_rank(r.severity), r.script))
        label = "%d/tcp" % port if port else "host"
        section("scripts", "%s · %s" % (label, host) if host else label)
        shown = 0
        for entry in entries:
            if limit and shown >= limit:
                note("… %d more" % (len(entries) - shown))
                break
            colour, tag = SEVERITY_STYLE.get(entry.severity, (DIM, "INFO"))
            emit(GUTTER + paint(tag, colour, bold=entry.severity in ("critical", "high"))
                 + "  " + paint(entry.script.ljust(26), B_WHITE)
                 + paint(_first_line(entry), DIM))
            for line in _extra_lines(entry):
                emit(GUTTER + "     " + paint(line, DIM))
            shown += 1
            total += 1
    return total


def _severity_rank(severity: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(severity, 0)


def _first_line(entry) -> str:
    if entry.error:
        return "error: " + entry.error
    for line in entry.output:
        text = " ".join(line.split())
        if text:
            return text[:110]
    return "(no output)"


def _extra_lines(entry) -> List[str]:
    if entry.error:
        return []
    lines = [" ".join(line.split()) for line in entry.output[1:] if line.strip()]
    return lines[:4]


def summary(stats: Dict) -> None:
    """Closing block. Every number here comes from the scan, none are inferred."""
    emit()
    emit(GUTTER + paint("SUMMARY", B_WHITE, bold=True))
    rule()

    open_ports = stats.get("open", 0)
    emit(GUTTER + paint(str(open_ports), B_GREEN, bold=True)
         + paint(" open", DIM)
         + paint("   ·   ", DIM)
         + paint(str(stats.get("filtered", 0)), YELLOW) + paint(" filtered", DIM)
         + paint("   ·   ", DIM)
         + paint(str(stats.get("closed", 0)), DIM) + paint(" closed", DIM)
         + paint("   ·   ", DIM)
         + paint(str(stats.get("probed", 0)), B_WHITE) + paint(" probed", DIM))

    timing = stats.get("elapsed", 0.0)
    rate = stats.get("rate", 0.0)
    line = (paint("elapsed ", DIM) + paint("%.2fs" % timing, B_WHITE)
            + paint("   ·   ", DIM)
            + paint("throughput ", DIM) + paint("%.0f ports/s" % rate, B_WHITE))
    if stats.get("scripts"):
        line += (paint("   ·   ", DIM) + paint("scripts ", DIM)
                 + paint(str(stats["scripts"]), B_WHITE))
    emit(GUTTER + line)

    high_risk = stats.get("high_risk") or []
    if high_risk:
        emit(GUTTER + paint("exposure ", DIM)
             + paint(", ".join(str(p) for p in high_risk[:10]), B_RED, bold=True))

    critical = stats.get("critical_findings", 0)
    if critical:
        emit(GUTTER + paint("findings ", DIM)
             + paint("%d critical/high" % critical, B_RED, bold=True))
    emit()
