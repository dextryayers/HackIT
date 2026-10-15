"""HackIT OSINT v3 — verbose step-by-step progress engine.

Default-verbose: every scan phase announces START, streams live
counters while working, then reports DONE with elapsed time.
Quiet mode (`--quiet`) silences everything except findings + summary.
"""
from __future__ import annotations

import sys
import time
from typing import Callable


class StepLogger:
    """Phase-aware progress printer with elapsed-time accounting."""

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self._phase = ""
        self._t0 = 0.0
        self._count = 0
        self._total = 0
        self.summary: list[dict] = []

    def _out(self, text: str) -> None:
        if not self.verbose:
            return
        sys.stdout.write(text + "\n")
        sys.stdout.flush()

    def phase(self, num: int, total: int, title: str, detail: str = "") -> None:
        self._phase = title
        self._t0 = time.time()
        self._count = 0
        extra = f" — {detail}" if detail else ""
        self._out(f"\n  ┌─ [STEP {num}/{total}] {title}{extra}")

    def tick(self, msg: str = "", total: int = 0) -> None:
        self._count += 1
        if total:
            self._total = total
        if not self.verbose:
            return
        if self._count == 1 or self._count % 25 == 0 or (total and self._count >= total):
            suffix = f"/{total}" if total else ""
            line = f"  │ … {self._phase}: {self._count}{suffix} checked"
            if msg:
                line += f" — {msg[:60]}"
            sys.stdout.write(f"\r{line}{' ' * 10}")
            sys.stdout.flush()

    def done(self, result: str = "") -> None:
        elapsed = time.time() - self._t0 if self._t0 else 0.0
        self.summary.append({"phase": self._phase, "elapsed": round(elapsed, 1), "result": result})
        if not self.verbose:
            return
        sys.stdout.write("\r" + " " * 100 + "\r")
        mark = f" → {result}" if result else ""
        self._out(f"  └─ ✓ {self._phase} done in {elapsed:.1f}s{mark}")

    def note(self, msg: str) -> None:
        self._out(f"  │ {msg}")

    def warn(self, msg: str) -> None:
        self._out(f"  │ ! {msg}")

    def report(self) -> None:
        if not self.verbose or not self.summary:
            return
        total = sum(s["elapsed"] for s in self.summary)
        self._out("\n  ┌── PHASE TIMING ─────────────────────────────┐")
        for s in self.summary:
            self._out(f"  │ {s['phase'][:28]:28s} {s['elapsed']:>6.1f}s  {s['result'][:30]}")
        self._out(f"  │ {'TOTAL':28s} {total:>6.1f}s")
        self._out("  └───────────────────────────────────────────────┘")


def make_step_callback(logger: StepLogger) -> Callable[[str, str], None]:
    def _cb(event: str, msg: str = "") -> None:
        if event == "tick":
            logger.tick(msg)
        elif event == "note":
            logger.note(msg)
        elif event == "warn":
            logger.warn(msg)
    return _cb
