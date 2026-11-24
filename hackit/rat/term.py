"""Terminal layout primitives shared by the rat menu, live UI and console.

Everything here is ANSI-aware: colour codes cost zero columns, so a padded or
truncated cell lines up with its neighbours no matter how many escapes it
carries. Boxes are built from a single width so two panes drawn side by side
never disagree about the terminal, and every builder clamps to the real
terminal width instead of trusting the caller.

No globals are mutated; each call reads the terminal size fresh.
"""
from __future__ import annotations

import os
import re
import shutil
from typing import Iterable, List, Sequence

from hackit.ui import RESET, _colored

CSI = "\x1b["
DIM = CSI + "2m"
BOLD = CSI + "1m"
RESET_ALL = RESET

_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

MIN_WIDTH = 60
MIN_HEIGHT = 20


class Style:
    """Named colours in one place so panes cannot drift apart."""

    frame = CSI + "36m"
    title = CSI + "96m"
    muted = CSI + "2m"
    ink = CSI + "37m"
    bright = CSI + "97m"
    good = CSI + "92m"
    warn = CSI + "93m"
    bad = CSI + "91m"
    accent = CSI + "95m"


# Short aliases so call sites read as layout, not as colour plumbing.
Frame = Style.frame
Title = Style.title
Dim = Style.muted
Ink = Style.ink
Bright = Style.bright
Good = Style.good
Warn = Style.warn
Bad = Style.bad
Accent = Style.accent


def size() -> tuple[int, int]:
    """(columns, lines), clamped to a floor a box can survive."""
    cols, lines = shutil.get_terminal_size((100, 32))
    # Some CI runners report 0x0; fall back rather than build negative widths.
    if cols <= 0:
        cols = 100
    if lines <= 0:
        lines = 32
    return max(MIN_WIDTH, min(cols, 220)), max(MIN_HEIGHT, min(lines, 80))


def strip(text: str) -> str:
    return _ESCAPE.sub("", text or "")


def vislen(text: str) -> int:
    return len(strip(text))


def trunc(text: str, width: int) -> str:
    """Cut to `width` visible columns, keeping escapes and adding an ellipsis."""
    text = str(text).replace("\n", " ")
    if width <= 0:
        return ""
    if vislen(text) <= width:
        return text
    if width == 1:
        return "…"
    out: List[str] = []
    seen = 0
    index = 0
    while index < len(text) and seen < width - 1:
        if text[index] == "\x1b":
            match = _ESCAPE.match(text, index)
            if match:
                out.append(match.group(0))
                index = match.end()
                continue
        out.append(text[index])
        seen += 1
        index += 1
    out.append("…")
    return "".join(out)


def pad(text: str, width: int, align: str = "left") -> str:
    text = trunc(text, max(0, width))
    gap = max(0, width - vislen(text))
    if align == "right":
        return " " * gap + text
    if align == "center":
        left = gap // 2
        return " " * left + text + " " * (gap - left)
    return text + " " * gap


def rule(width: int, char: str = "─", color: str = "") -> str:
    line = char * max(0, width)
    return _colored(line, color) if color else line


def label(text: str, width: int) -> str:
    """Left column of a key/value row: dim label, always the same width."""
    return _colored(pad(text, width), Style.muted)


def box(
    title: str,
    rows: Sequence[str],
    width: int,
    color: str = Style.frame,
    height: int | None = None,
    title_color: str = Style.title,
) -> List[str]:
    """A framed pane with every line exactly `width` columns wide."""
    width = max(4, width)
    inner = width - 4
    head = trunc(title, max(0, inner))
    top = _colored("┌", color) + " " * 0
    top += _colored(" " + head + " ", title_color)
    top += _colored("─" * max(0, inner - vislen(head) - 1) + "┐", color)
    out = [top]
    wanted = len(rows) if height is None else max(0, height)
    for index in range(wanted):
        body = rows[index] if index < len(rows) else ""
        out.append(_colored("│ ", color) + pad(body, inner) + _colored(" │", color))
    out.append(_colored("└" + "─" * (width - 2) + "┘", color))
    return out


def horizontal(*panes: Sequence[str]) -> List[str]:
    """Join pre-rendered panes left to right, padding to the tallest."""
    if not panes:
        return []
    tallest = max(len(pane) for pane in panes)
    widths = [max(vislen(line) for line in pane) if pane else 0 for pane in panes]
    out: List[str] = []
    for index in range(tallest):
        cells = []
        for pane, width in zip(panes, widths):
            line = pane[index] if index < len(pane) else ""
            cells.append(pad(line, width))
        out.append("".join(cells))
    return out


def table(headers: Sequence[str], rows: Iterable[Sequence[str]], widths: Sequence[int],
          aligns: Sequence[str] | None = None) -> List[str]:
    """Fixed-width columns; a header rule separates it from the rows."""
    aligns = list(aligns or ["left"] * len(widths))
    head = " ".join(pad(_colored(str(h), Style.title), w, a)
                    for h, w, a in zip(headers, widths, aligns))
    out = [head, _colored(" ".join("─" * w for w in widths), Style.muted)]
    for row in rows:
        out.append(" ".join(pad(str(c), w, a) for c, w, a in zip(row, widths, aligns)))
    return out


def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def eprint(text: str = "") -> None:
    print(text)
