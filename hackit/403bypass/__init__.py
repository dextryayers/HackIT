"""403bypass — HTTP 403 / WAF authorization bypass engine.

Thin CLI wrapper around the Go engine in ``go_engine/bypass_engine``. All
request logic lives in Go; this module owns the presentation layer: banner,
results tables, verdict grouping and a compact text export.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any

import click

try:  # colorama is optional; ANSI works natively on modern terminals
    import colorama

    colorama.just_fix_windows_console()
except Exception:  # pragma: no cover - optional dependency
    pass

# --------------------------------------------------------------------------- #
# ANSI palette
# --------------------------------------------------------------------------- #

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
ITALIC = "\x1b[3m"

FG_BLACK = "\x1b[30m"
FG_RED = "\x1b[31m"
FG_GREEN = "\x1b[32m"
FG_YELLOW = "\x1b[33m"
FG_BLUE = "\x1b[34m"
FG_MAGENTA = "\x1b[35m"
FG_CYAN = "\x1b[36m"
FG_WHITE = "\x1b[37m"
FG_GRAY = "\x1b[38;5;245m"
FG_ORANGE = "\x1b[38;5;208m"

BG_NAVY = "\x1b[48;5;17m"
BG_SLATE = "\x1b[48;5;236m"

VERDICT_STYLE = {
    "bypass": (FG_GREEN, "BYPASS"),
    "redirect": (FG_YELLOW, "REDIRECT"),
    "neutral": (FG_CYAN, "NEUTRAL"),
    "soft-200": (FG_MAGENTA, "SOFT-200"),
    "auth-required": (FG_BLUE, "AUTH-401"),
    "blocked": (FG_RED, "BLOCKED"),
    "error5xx": (FG_ORANGE, "5XX"),
    "error": (FG_GRAY, "ERROR"),
}

BOX_WIDTH = 92

VERDICT_ORDER = [
    "bypass",
    "redirect",
    "neutral",
    "soft-200",
    "auth-required",
    "error5xx",
    "blocked",
    "error",
]

ENGINE_VERSION_EXPECTED = "2.0.0"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _supports_unicode() -> bool:
    enc = (sys.stdout.encoding or "").lower()
    return "utf" in enc


def _c(text: str, *styles: str) -> str:
    return "".join(styles) + text + RESET


def _visible_len(text: str) -> int:
    import re

    return len(re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text))


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _visible_len(text))


def _trunc(text: str, width: int) -> str:
    if _visible_len(text) <= width:
        return text
    from re import sub

    plain = sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
    if len(plain) <= width:
        return text
    return plain[: width - 1] + "…"


# --------------------------------------------------------------------------- #
# banner
# --------------------------------------------------------------------------- #

_LOGO = r"""
   ██╗  ██╗ ██████╗ ██████╗        ██╗  ██╗██████╗ ██╗   ██╗██████╗  █████╗ ███████╗███████╗
   ██║  ██║██╔═████╗╚════██╗       ╚██╗██╔╝██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝
   ███████║██║██╔██║ █████╔╝█████╗  ╚███╔╝ ██████╔╝ ╚████╔╝ ██████╔╝███████║███████╗███████╗
   ╚════██║████╔╝██║ ╚═══██╗╚════╝  ██╔██╗ ██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║╚════██║╚════██║
        ██║╚██████╔╝██████╔╝       ██╔╝ ██╗██████╔╝   ██║   ██║     ██║  ██║███████║███████║
        ╚═╝ ╚═════╝ ╚═════╝        ╚═╝  ╚═╝╚═════╝    ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
"""

_TAGLINE = "403 / WAF AUTHORIZATION BYPASS ENGINE"


def print_banner() -> None:
    width = BOX_WIDTH
    bar = "═" * width
    top = _c("╔" + bar + "╗", FG_CYAN)
    bottom = _c("╚" + bar + "╝", FG_CYAN)

    print()
    print(top)
    for line in _LOGO.strip("\n").splitlines():
        print(_c("║", FG_CYAN) + _c(_pad(line, width), BOLD, FG_CYAN) + _c("║", FG_CYAN))
    print(_c("║", FG_CYAN) + _c(_pad("", width), BG_NAVY) + _c("║", FG_CYAN))
    title = _c("  " + _TAGLINE, BOLD, FG_YELLOW)
    print(_c("║", FG_CYAN) + _pad(title, width) + _c("║", FG_CYAN))
    meta = _c(
        "  v3.0 engine   •   1493 techniques   •   similarity + verify scoring",
        DIM,
        FG_GRAY,
    )
    print(_c("║", FG_CYAN) + _pad(meta, width) + _c("║", FG_CYAN))
    print(bottom)
    print()


# --------------------------------------------------------------------------- #
# engine execution
# --------------------------------------------------------------------------- #


@dataclass
class EngineRun:
    data: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    stderr: str = ""
    elapsed: float = 0.0


def _engine_path() -> str:
    base = os.path.join(os.path.dirname(__file__), "go_engine", "bypass_engine")
    if os.name == "nt" and not base.endswith(".exe"):
        base += ".exe"
    return base


def run_engine(target: str, threads: int = 60, timeout: int = 12, insecure: bool = True) -> EngineRun:
    engine = _engine_path()

    if not os.path.exists(engine):
        return EngineRun(error=f"engine missing at {engine}. Build with: cd go_engine && go build")

    if os.name != "nt" and not os.access(engine, os.X_OK):
        try:
            os.chmod(engine, 0o755)
        except OSError:
            pass

    per_req = max(1, int(timeout))
    overall = 60 + per_req * 20  # hard ceiling for the whole sweep

    started = time.time()
    try:
        proc = subprocess.run(
            [engine, "-url", target, "-threads", str(max(1, int(threads))), "-timeout", str(per_req)],
            capture_output=True,
            text=True,
            timeout=overall,
        )
    except subprocess.TimeoutExpired:
        return EngineRun(error=f"engine timed out after {overall}s", elapsed=time.time() - started)
    except OSError as exc:
        return EngineRun(error=f"engine failed to launch: {exc}", elapsed=time.time() - started)

    elapsed = time.time() - started
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip()
        if len(tail) > 400:
            tail = tail[:400] + "…"
        return EngineRun(error=f"engine exited {proc.returncode}: {tail}", stderr=proc.stderr, elapsed=elapsed)

    raw = (proc.stdout or "").strip()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        snippet = raw[:200] if raw else "<empty>"
        return EngineRun(error=f"engine emitted invalid JSON: {snippet}", elapsed=elapsed)

    if "error" in data:
        return EngineRun(error=str(data["error"]), elapsed=elapsed)

    return EngineRun(data=data, elapsed=elapsed)


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #


def _section_header(title: str, subtitle: str = "", color: str = FG_CYAN) -> None:
    width = BOX_WIDTH
    print()
    print(_c("┌" + "─" * width + "┐", color))
    head = _c("  " + BOLD + title, color)
    if subtitle:
        head += _c("   " + DIM + subtitle, FG_GRAY)
    print(_c("│", color) + _pad(_trunc(head, width), width) + _c("│", color))
    print(_c("└" + "─" * width + "┘", color))


def _render_meta(data: dict[str, Any], requested: str) -> None:
    baselines = data.get("baselines") or []
    primary = {}
    for b in baselines:
        if b.get("url") == "original":
            primary = b
            break
    if not primary and baselines:
        primary = baselines[0]

    deny_pages = [b for b in baselines if int(b.get("status_code", 0)) >= 400]
    rows: list[tuple[str, str]] = [
        ("Target", data.get("target", "")),
        ("WAF server", data.get("waf", "Unknown")),
        ("Baseline status", f'{primary.get("status_code", 0)} (len {primary.get("length", 0)})'),
        ("Deny pages seen", str(len(deny_pages))),
        ("Baseline probes", str(len(baselines))),
        ("Requested status", requested),
        ("Payloads", str(len(data.get("results", [])))),
        ("Elapsed", f'{data.get("duration_ms", 0) / 1000:.2f}s'),
    ]
    width = BOX_WIDTH
    for i, (label, value) in enumerate(rows):
        last = i == len(rows) - 1
        glyph = "└" if last else "├"
        left = _c(glyph + "─ ", FG_GRAY) + _c(f"{label:<17}", BOLD, FG_CYAN) + _c("│ ", FG_GRAY)
        plain_left = glyph + "─ " + f"{label:<17}" + "│ "
        room = BOX_WIDTH + 2 - len(plain_left) - 1
        val = _trunc(str(value), room)
        print(left + val)


def _render_summary(results: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.get("verdict", "neutral")] = counts.get(r.get("verdict", "neutral"), 0) + 1

    width = BOX_WIDTH
    print()
    print(_c("┌" + "─" * width + "┐", FG_GRAY))
    print(_c("│", FG_GRAY) + _pad(_c("  VERDICT SUMMARY", BOLD, FG_WHITE), width) + _c("│", FG_GRAY))
    print(_c("├" + "─" * width + "┤", FG_GRAY))
    for verdict in VERDICT_ORDER:
        n = counts.get(verdict, 0)
        if n == 0:
            continue
        color, label = VERDICT_STYLE[verdict]
        bar_units = min(40, max(0, n // max(1, len(results) // 40))) or (1 if n else 0)
        bar = "█" * bar_units
        body = "  " + _c(f"{label:<10}", color) + " " + _c(bar, color) + " " + _c(str(n), BOLD, color)
        print(_c("│", FG_GRAY) + _pad(body, width) + _c("│", FG_GRAY))
    print(_c("└" + "─" * width + "┘", FG_GRAY))
    return counts


def _render_bypass_table(results: list[dict[str, Any]], verify: bool = True) -> None:
    rows = [r for r in results if r.get("verdict") in ("bypass", "redirect", "neutral")]
    if not rows:
        print()
        print(_c("  no open responses — every payload stayed blocked", BOLD, FG_RED))
        return
    expected_verify = bool(verify)
    _section_header("OPEN RESPONSES", f"{len(rows)} technique(s) reached the application layer", FG_GREEN)

    # Fixed-width cells keep every row aligned in any monospace font.
    cols = [
        ("#", 4),
        ("STS", 4),
        ("VERDICT", 9),
        ("METHOD", 7),
        ("LEN", 8),
        ("SIM", 5),
        ("OK", 3),
    ]
    # Table total width == BOX_WIDTH:
    #   1 border + per col (1 + w + 1 + 1 border) + (1 + tech + 1 + 1 border)
    tech_width = BOX_WIDTH + 2 - 4 - sum(w + 3 for _, w in cols)
    if tech_width < 20:
        tech_width = 20

    def fit(value: str, width: int, align: str) -> str:
        value = str(value)
        if len(value) > width:
            value = (value[: width - 1] + "…") if width > 1 else value[:width]
        if align == "right":
            return value.rjust(width)
        if align == "center":
            return value.center(width)
        return value.ljust(width)

    def rule(left: str, mid: str, right: str) -> None:
        segs = ["─" * (w + 2) for _, w in cols] + ["─" * (tech_width + 2)]
        print(_c(left + mid.join(segs) + right, FG_GRAY))

    def row_line(cells: list[tuple[str, str, str, str]]) -> None:
        # cells: (plain_text, align, color, style)
        parts = [_c("│", FG_GRAY)]
        for (text, align, color, style), (_, width) in zip(cells, cols):
            parts.append(" ")
            parts.append(_c(fit(text, width, align), style, color))
            parts.append(" ")
            parts.append(_c("│", FG_GRAY))
        text, align, color, style = cells[-1]
        parts.append(" ")
        parts.append(_c(fit(text, tech_width, align), style, color))
        parts.append(" ")
        parts.append(_c("│", FG_GRAY))
        print("".join(parts))

    def row_plain(cells: list[tuple[str, str, str, str]]) -> None:
        # same layout but the last cell is the technique
        parts = [_c("│", FG_GRAY)]
        for (text, align, color, style), (_, width) in zip(cells[:-1], cols):
            parts.append(" ")
            parts.append(_c(fit(text, width, align), style, color))
            parts.append(" ")
            parts.append(_c("│", FG_GRAY))
        text, align, color, style = cells[-1]
        parts.append(" ")
        parts.append(_c(fit(text, tech_width, align), style, color))
        parts.append(" ")
        parts.append(_c("│", FG_GRAY))
        print("".join(parts))

    rule("┌", "┬", "┐")
    row_plain(
        [(name, "left", FG_WHITE, BOLD) for name, _ in cols]
        + [("TECHNIQUE", "left", FG_WHITE, BOLD)]
    )
    rule("├", "┼", "┤")

    for idx, r in enumerate(rows, 1):
        verdict = r.get("verdict", "neutral")
        color, label = VERDICT_STYLE.get(verdict, (FG_WHITE, verdict.upper()))
        sim = r.get("baseline_similarity") or 0.0
        if r.get("verified") is True:
            ok, ok_color = "Y", FG_GREEN
        elif verdict == "bypass" and expected_verify:
            ok, ok_color = "?", FG_YELLOW
        else:
            ok, ok_color = "-", FG_GRAY
        payload = r.get("payload", "") or ""

        cells = [
            (f"#{idx}", "left", FG_GRAY, ""),
            (str(r.get("status_code", 0)), "left", color, BOLD),
            (label, "left", color, ""),
            (r.get("method", "GET"), "left", FG_WHITE, ""),
            (str(r.get("length", 0)), "right", FG_GRAY, ""),
            (f"{sim:.2f}", "right", FG_GRAY, ""),
            (ok, "center", ok_color, BOLD),
            (payload, "left", FG_WHITE, ""),
        ]
        row_plain(cells)

        def subline(label_text: str, value: str, label_color: str, value_color: str) -> None:
            # 1 wall + 7 lead spaces + label + body + pad + 1 wall == 94
            inner = BOX_WIDTH + 2
            avail = inner - 2 - 7 - len(label_text)
            body = _trunc(value, max(0, avail))
            pad = max(0, inner - 2 - 7 - len(label_text) - len(body))
            print(
                _c("│", FG_GRAY)
                + " " * 7
                + _c(label_text, label_color)
                + _c(body, value_color)
                + " " * pad
                + _c("│", FG_GRAY)
            )

        location = r.get("location")
        if location:
            subline("-> ", location, FG_CYAN, DIM + FG_CYAN)
        title = r.get("title")
        if title:
            subline("title: ", title, FG_MAGENTA, DIM + FG_MAGENTA)

    rule("└", "┴", "┘")


def _render_techniques(results: list[dict[str, Any]], only_success: bool) -> None:
    if only_success:
        return
    rows = [r for r in results if r.get("verdict") not in ("bypass", "redirect", "neutral")]
    if not rows:
        return
    _section_header("BLOCKED / NOISE", f"{len(rows)} attempts rejected — showing technique spread", FG_RED)

    from collections import Counter

    counter: Counter[str] = Counter()
    examples: dict[str, dict[str, Any]] = {}
    for r in rows:
        family = r.get("type", "unknown")
        counter[family] += 1
        examples.setdefault(family, r)

    verdict_w = 11
    count_w = 8
    tech_w = (BOX_WIDTH + 2) - 10 - verdict_w - count_w

    def fit(value: str, width: int, align: str = "left") -> str:
        value = str(value)
        if len(value) > width:
            value = value[: width - 1] + "…"
        return value.rjust(width) if align == "right" else value.ljust(width)

    def rule(left: str, mid: str, right: str) -> None:
        segs = ["─" * (tech_w + 2), "─" * (verdict_w + 2), "─" * (count_w + 2)]
        print(_c(left + mid.join(segs) + right, FG_GRAY))

    def line(cells: list[tuple[str, int, str, str, str]]) -> None:
        parts = [_c("│", FG_GRAY)]
        for text, width, align, color, style in cells:
            parts.append(" " + _c(fit(text, width, align), style, color) + " " + _c("│", FG_GRAY))
        print("".join(parts))

    rule("┌", "┬", "┐")
    line([
        ("TECHNIQUE", tech_w, "left", FG_WHITE, BOLD),
        ("VERDICT", verdict_w, "left", FG_WHITE, BOLD),
        ("HITS", count_w, "right", FG_WHITE, BOLD),
    ])
    rule("├", "┼", "┤")
    for family, count in counter.most_common():
        sample = examples[family]
        verdict = sample.get("verdict", "blocked")
        color, label = VERDICT_STYLE.get(verdict, (FG_RED, verdict.upper()))
        line([
            (family, tech_w, "left", FG_WHITE, ""),
            (label, verdict_w, "left", color, ""),
            (str(count), count_w, "right", FG_GRAY, ""),
        ])
    rule("└", "┴", "┘")
    print()
    print(_c("  run with --verbose to list every rejected payload", DIM, FG_GRAY))


def _render_clusters(data: dict[str, Any]) -> None:
    clusters = data.get("clusters") or []
    if not clusters:
        return
    interesting = [c for c in clusters if not c.startswith(("5", "0"))]
    if not interesting:
        return
    _section_header("RESPONSE CLUSTERS", "distinct server fingerprints observed", FG_YELLOW)

    inner = BOX_WIDTH
    shown = interesting[:15]
    header_txt = "  STATUS    HASH        LENGTH   COUNT    TITLE"
    print(_c("┌" + "─" * BOX_WIDTH + "┐", FG_YELLOW))
    print(_c("│", FG_YELLOW) + _c(header_txt.ljust(inner)[:inner], BOLD, FG_WHITE) + _c("│", FG_YELLOW))
    print(_c("├" + "─" * BOX_WIDTH + "┤", FG_YELLOW))
    for c in shown:
        text = _trunc(str(c), inner - 2)
        print(_c("│", FG_YELLOW) + " " + _c(text.ljust(inner - 2), FG_WHITE) + " " + _c("│", FG_YELLOW))
    if len(interesting) > len(shown):
        note = f"  … {len(interesting) - len(shown)} more"
        print(_c("│", FG_YELLOW) + _c(note.ljust(inner - 2), DIM, FG_GRAY) + " " + _c("│", FG_YELLOW))
    print(_c("└" + "─" * BOX_WIDTH + "┘", FG_YELLOW))


def _render_verbose(results: list[dict[str, Any]]) -> None:
    _section_header("ALL ATTEMPTS", f"{len(results)} payloads", FG_GRAY)
    for r in results:
        verdict = r.get("verdict", "neutral")
        color, label = VERDICT_STYLE.get(verdict, (FG_WHITE, verdict.upper()))
        status = r.get("status_code", 0)
        print(
            _c(f"  {status:>3}", BOLD, color)
            + "  "
            + _c(f"{label:<10}", color)
            + _c(r.get("method", "GET").ljust(8), FG_WHITE)
            + _c(str(r.get("payload", ""))[:110], FG_GRAY)
        )


def _render_footer(data: dict[str, Any], counts: dict[str, int]) -> None:
    bypass_n = counts.get("bypass", 0)
    redirect_n = counts.get("redirect", 0)
    soft_n = counts.get("soft-200", 0)
    confirmed = data.get("confirmed") or []
    confirmed_n = len(confirmed)
    width = BOX_WIDTH
    print()
    print(_c("┌" + "─" * width + "┐", FG_CYAN))
    if bypass_n:
        headline = _c(f"  ✓ AUTHORIZATION BYPASS CONFIRMED — {bypass_n} payload(s) returned 2xx", BOLD, FG_GREEN)
    elif redirect_n:
        headline = _c(f"  ~ REDIRECT RESPONSES ONLY — {redirect_n} 3xx payload(s), inspect Location headers", BOLD, FG_YELLOW)
    elif soft_n:
        headline = _c(f"  ✗ SOFT-200 ONLY — server returns 200 with deny body on {soft_n} payload(s)", BOLD, FG_MAGENTA)
    else:
        headline = _c("  ✗ NO BYPASS — the target enforced authorization on every technique", BOLD, FG_RED)
    print(_c("│", FG_CYAN) + _pad(headline, width) + _c("│", FG_CYAN))
    detail = f"  engine v{data.get('version', '?')}  •  {data.get('waf', 'Unknown')}"
    if bypass_n:
        detail += f"  •  {confirmed_n} re-verified stable"
    print(_c("│", FG_CYAN) + _pad(_c(detail, DIM, FG_GRAY), width) + _c("│", FG_CYAN))
    print(_c("└" + "─" * width + "┘", FG_CYAN))
    print()


# --------------------------------------------------------------------------- #
# JSON export
# --------------------------------------------------------------------------- #


def export_json(data: dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


# --------------------------------------------------------------------------- #
# click command
# --------------------------------------------------------------------------- #


@click.command(name="403bypass")
@click.option("--url", "-u", required=True, help="Target URL returning 403/401 (e.g. https://example.com/admin)")
@click.option("--threads", "-t", default=60, show_default=True, help="Concurrent workers (1-200)")
@click.option("--timeout", default=12, show_default=True, help="Per-request timeout in seconds (1-60)")
@click.option("--verbose", "-v", is_flag=True, help="Print every payload, not just open responses")
@click.option("--only-success", is_flag=True, help="Suppress everything below an open response")
@click.option("--json-out", "-o", default="", help="Also write the raw JSON report to this path")
def run_bypass_cli(
    url: str,
    threads: int,
    timeout: int,
    verbose: bool,
    only_success: bool,
    json_out: str,
) -> None:
    """403 / WAF authorization bypass engine with 1300+ techniques and baseline scoring."""
    print_banner()

    threads = max(1, min(int(threads), 200))
    timeout = max(1, min(int(timeout), 60))

    print(_c("  ▶ target    ", BOLD, FG_CYAN) + _c(url, FG_WHITE))
    print(_c("  ▶ workers   ", BOLD, FG_CYAN) + _c(str(threads), FG_WHITE))
    print(_c("  ▶ timeout   ", BOLD, FG_CYAN) + _c(f"{timeout}s", FG_WHITE))
    print(_c("  ▶ baseline  ", BOLD, FG_CYAN) + _c("5 probes + trigram similarity scoring", DIM, FG_GRAY))
    print()

    run = run_engine(url, threads=threads, timeout=timeout)
    if run.error:
        _section_header("ENGINE ERROR", color=FG_RED)
        print(_c("  " + run.error, BOLD, FG_RED))
        print()
        raise click.exceptions.Exit(1)

    data = run.data
    results: list[dict[str, Any]] = data.get("results", [])

    _render_meta(data, data.get("requested_status", ""))
    counts = _render_summary(results)
    _render_bypass_table(results)

    if verbose:
        _render_verbose(results)
    elif not only_success:
        _render_techniques(results, only_success)

    if not only_success:
        _render_clusters(data)

    _render_footer(data, counts)

    if json_out:
        try:
            export_json(data, json_out)
            print(_c(f"  report written → {json_out}", DIM, FG_GRAY))
        except OSError as exc:
            print(_c(f"  could not write report: {exc}", FG_RED))


# --------------------------------------------------------------------------- #
# direct execution
# --------------------------------------------------------------------------- #


def _main_direct(argv: list[str]) -> None:  # pragma: no cover - manual entry
    if not argv:
        print("usage: python __init__.py --url <target>")
        sys.exit(1)
    if argv[0].startswith("-"):
        run_bypass_cli(argv)
    else:
        run_bypass_cli(["--url", argv[0], *argv[1:]])


if __name__ == "__main__":  # pragma: no cover
    _main_direct(sys.argv[1:])
