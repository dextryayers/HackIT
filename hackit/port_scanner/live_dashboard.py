"""Live scan dashboard.

Renders in place with a fixed frame so the terminal never scrolls mid-scan.
Every value is padded by visible width (ANSI stripped), which the previous
version did not do — colour codes counted as columns and the box drifted.
"""

from __future__ import annotations

import queue
import re
import shutil
import sys
import threading
import time
import unicodedata
from typing import Dict, List, Optional

try:
    from hackit.ui import (
        B_CYAN, B_GREEN, B_RED, B_WHITE, B_YELLOW, CYAN, DIM, GREEN,
        MAGENTA, RED, RESET, YELLOW,
    )
except Exception:  # pragma: no cover
    CSI = "\x1b["
    RESET = CSI + "0m"
    RED, GREEN, YELLOW, CYAN, MAGENTA = (CSI + f"{n}m" for n in (31, 32, 33, 36, 35))
    B_RED, B_GREEN, B_YELLOW, B_CYAN, B_WHITE, DIM = (CSI + f"{n}m" for n in (91, 92, 93, 96, 97, 2))

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_ANSI_HOME = "\x1b[H"
_ANSI_CLEAR_DOWN = "\x1b[J"
_ANSI_HIDE = "\x1b[?25l"
_ANSI_SHOW = "\x1b[?25h"

_SPARK = "▁▂▃▄▅▆▇█"


def _vis(text: str) -> int:
    plain = _ANSI.sub("", str(text))
    return sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 1 for c in plain)


def _pad(text: str, width: int, align: str = "left") -> str:
    gap = max(0, width - _vis(text))
    if align == "right":
        return " " * gap + text
    if align == "center":
        left = gap // 2
        return " " * left + text + " " * (gap - left)
    return text + " " * gap


def _clip(text: str, width: int) -> str:
    text = " ".join(str(text).replace("\r", " ").replace("\n", " ").split())
    if _vis(text) <= width:
        return text
    out, used = [], 0
    for ch in text:
        w = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if used + w > width - 1:
            break
        out.append(ch)
        used += w
    return "".join(out) + "…"


_BOLD = "\x1b[1m"


def _c(text: str, color: str, bold: bool = False) -> str:
    return color + (_BOLD if bold else "") + str(text) + RESET


def _term_width() -> int:
    try:
        return max(80, min(shutil.get_terminal_size().columns, 150))
    except OSError:
        return 100


class Dashboard:
    """Thread-safe in-place dashboard fed by ``update(type, data)``."""

    def __init__(self) -> None:
        self._queue: "queue.Queue[Dict]" = queue.Queue()
        self._running = False
        self._thread: Optional[threading.Thread] = None

        self.engines: Dict[str, Dict] = {}
        self.services: List[Dict] = []
        self.os_info: Dict = {"name": "Detecting…", "confidence": 0}
        self.vulnerabilities: List[Dict] = []
        self.open_count = 0
        self.total_scanned = 0
        self.total_ports = 0
        self.start_time: Optional[float] = None
        self.target = ""
        self.status_line = "initializing"
        self._rate_samples: List[float] = []
        self._last_count = 0
        self._last_rate_time = 0.0
        self._rendered_lines = 0

    # ── lifecycle ────────────────────────────────────────────────

    def start(self, target: str = "", total_ports: int = 0) -> None:
        self._running = True
        self.start_time = time.time()
        self.target = target
        self.total_ports = total_ports
        sys.stdout.write(_ANSI_HIDE)
        sys.stdout.flush()
        self._thread = threading.Thread(target=self._render_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=1.0)
        self._drain_queue()
        self._render(final=True)
        sys.stdout.write(_ANSI_SHOW + "\n")
        sys.stdout.flush()

    # ── ingestion ────────────────────────────────────────────────

    def update(self, msg_type: str, data: Dict) -> None:
        self._queue.put({"type": msg_type, "data": data or {}})

    def _drain_queue(self) -> None:
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                return
            self._process(item.get("type", ""), item.get("data", {}))

    def _process(self, msg_type: str, data: Dict) -> None:
        if msg_type == "engine_status":
            name = data.get("engine", "unknown")
            slot = self.engines.setdefault(name, {
                "status": "running", "ports_scanned": 0, "open_found": 0, "progress": 0.0,
            })
            slot.update({
                "status": data.get("status", slot["status"]),
                "ports_scanned": data.get("ports_scanned", slot["ports_scanned"]),
                "open_found": data.get("open_found", slot["open_found"]),
                "progress": float(data.get("progress", slot["progress"]) or 0),
            })

        elif msg_type == "engine_results":
            name = data.get("engine", "unknown")
            slot = self.engines.setdefault(name, {
                "status": "done", "ports_scanned": 0, "open_found": 0, "progress": 100.0,
            })
            slot["status"] = "done"
            slot["progress"] = 100.0
            slot["ports_scanned"] = data.get("count", slot["ports_scanned"])
            if "open_found" in data:
                slot["open_found"] = data["open_found"]

        elif msg_type == "result":
            port = data.get("port")
            status = str(data.get("status", "")).lower()
            if port:
                self.total_scanned += 1
            if status == "open" and port:
                self.open_count += 1
                self.services.append({
                    "port": port,
                    "service": data.get("service", ""),
                    "version": data.get("version", ""),
                    "protocol": data.get("banner_protocol", ""),
                    "confidence": data.get("banner_confidence", data.get("confidence", 0)),
                    "banner": data.get("banner", ""),
                    "mismatch": bool(data.get("banner_mismatch")),
                    "time": time.time(),
                })
                self.services.sort(key=lambda s: s["port"])

        elif msg_type == "os":
            self.os_info.update(data or {})

        elif msg_type == "vuln":
            if data and data not in self.vulnerabilities:
                self.vulnerabilities.append(data)

        elif msg_type == "status":
            self.status_line = data.get("message", self.status_line)

    # ── rendering ────────────────────────────────────────────────

    def _render_loop(self) -> None:
        while self._running:
            self._drain_queue()
            self._render()
            time.sleep(0.15)

    def _rate(self) -> float:
        now = time.time()
        if self._last_rate_time and now - self._last_rate_time >= 0.5:
            delta = self.total_scanned - self._last_count
            rate = delta / (now - self._last_rate_time)
            self._rate_samples.append(rate)
            if len(self._rate_samples) > 40:
                self._rate_samples.pop(0)
            self._last_count = self.total_scanned
            self._last_rate_time = now
        elif not self._last_rate_time:
            self._last_rate_time = now
        return sum(self._rate_samples) / len(self._rate_samples) if self._rate_samples else 0.0

    def _spark(self) -> str:
        if not self._rate_samples:
            return _SPARK[0] * 16
        peak = max(self._rate_samples) or 1.0
        cells = []
        for value in self._rate_samples[-16:]:
            idx = min(len(_SPARK) - 1, int((value / peak) * (len(_SPARK) - 1)))
            cells.append(_SPARK[idx])
        return "".join(cells).ljust(16)

    def _render(self, final: bool = False) -> None:
        width = _term_width()
        inner = width - 4
        elapsed = time.time() - (self.start_time or time.time())
        rate = self._rate()

        lines: List[str] = []
        push = lines.append

        def row(content: str) -> None:
            push(_c("│", B_CYAN) + " " + _pad(content, inner) + " " + _c("│", B_CYAN))

        def rule(left: str = "├", right: str = "┤") -> None:
            push(_c(left + "─" * (width - 2) + right, B_CYAN))

        push(_c("╭" + "─" * (width - 2) + "╮", B_CYAN))
        title = f" PORTSTORM LIVE — {self.target or 'no target'} "
        row(_c(_pad(title, inner, "center"), B_WHITE, bold=True))
        rule()

        pct = (self.total_scanned / self.total_ports * 100) if self.total_ports else 0.0
        bar_width = max(16, min(40, inner - 62))
        filled = int(bar_width * min(pct, 100) / 100)
        bar = "█" * filled + "░" * (bar_width - filled)
        stats = (
            f"elapsed {elapsed:6.1f}s   rate {rate:6.1f}/s   "
            f"scanned {self.total_scanned}/{self.total_ports or '?'}   "
            f"open {_c(str(self.open_count), B_GREEN)}"
        )
        row(_c(bar, B_GREEN) + " " + _c(stats, DIM))
        row(_c("throughput ", DIM) + _c(self._spark(), CYAN) + "  " + _c(self.status_line[: inner - 40], DIM))
        rule()

        row(_c(" ENGINES", B_WHITE, bold=True))
        if self.engines:
            for name, info in sorted(self.engines.items()):
                status = str(info.get("status", "pending"))
                color = {"running": B_GREEN, "done": CYAN, "error": B_RED}.get(status, YELLOW)
                glyph = {"running": "▶", "done": "✓", "error": "✗"}.get(status, "·")
                progress = float(info.get("progress", 0) or 0)
                cells = max(10, inner - 62)
                fill = int(cells * min(progress, 100) / 100)
                gbar = "█" * fill + "░" * (cells - fill)
                row(
                    "  " + _c(glyph, color) + " " + _c(name.ljust(9), B_WHITE)
                    + " " + _c(gbar, color)
                    + " " + _c(f"{progress:5.1f}%", B_YELLOW)
                    + "  " + _c(f"open {info.get('open_found', 0)}", B_GREEN)
                )
        else:
            row(_c("  (awaiting engine reports…)", DIM))
        rule()

        row(_c(" SERVICES", B_WHITE, bold=True))
        visible_rows = 14 if final else 12
        window = self.services[-visible_rows:]
        if window:
            head = (
                _c(_pad("PORT", 10), B_WHITE)
                + _c(_pad("PROTO", 9), B_WHITE)
                + _c(_pad("SERVICE", 15), B_WHITE)
                + _c(_pad("VERSION", 14), B_WHITE)
                + _c(_pad("CONF", 6, "right"), B_WHITE)
                + "  "
                + _c("BANNER", B_WHITE)
            )
            row("  " + head)
            for svc in window:
                conf = float(svc.get("confidence") or 0)
                conf_color = B_GREEN if conf >= 0.9 else (GREEN if conf >= 0.7 else (YELLOW if conf >= 0.5 else RED))
                banner_room = max(12, inner - 60)
                banner = _clip(svc.get("banner", ""), banner_room)
                mark = _c("⚠", B_YELLOW) + " " if svc.get("mismatch") else ""
                row(
                    "  " + _c(_pad(f"{svc['port']}/tcp", 10), B_WHITE, bold=True)
                    + _c(_pad(_clip(svc.get("protocol") or "—", 9), 9), MAGENTA)
                    + _c(_pad(_clip(svc.get("service") or "—", 15), 15), CYAN)
                    + _c(_pad(_clip(svc.get("version") or "—", 14), 14), GREEN)
                    + _c(_pad(f"{int(conf * 100)}%", 6, "right"), conf_color)
                    + "  " + mark + _c(banner, DIM)
                )
        else:
            row(_c("  (no services detected yet…)", DIM))
        rule()

        os_name = self.os_info.get("name", "Unknown")
        conf = self.os_info.get("confidence", self.os_info.get("accuracy", 0)) or 0
        if conf and conf < 1:
            conf = int(conf * 100)
        if os_name in ("Detecting…", "Detecting...", "Unknown") or not conf:
            # The OS stage is optional; a profile without it must not leave a
            # permanent "Detecting…" row on the final frame.
            if not final:
                row(_c(" OS ", B_WHITE, bold=True) + _c(os_name, DIM))
        else:
            row(_c(" OS ", B_WHITE, bold=True) + _c(f"{os_name} ({int(conf)}%)", GREEN))

        if self.vulnerabilities:
            rule()
            row(_c(f" VULNERABILITIES ({len(self.vulnerabilities)})", B_RED, bold=True))
            for vuln in self.vulnerabilities[-3:]:
                text = str(vuln.get("description") or vuln.get("name") or vuln)
                row("  " + _c("⚠", B_RED) + " " + _c(_clip(text, inner - 6), B_YELLOW))

        push(_c("╰" + "─" * (width - 2) + "╯", B_CYAN))

        frame = _ANSI_HOME + "\n".join(lines) + _ANSI_CLEAR_DOWN
        sys.stdout.write(frame)
        sys.stdout.flush()
        self._rendered_lines = len(lines)
