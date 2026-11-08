"""Autopilot orchestrator for HackIt Agent.

Responsible for the "set target → AI runs by itself" contract:

* every pentest phase (recon → osint → js → params → payload → analyse →
  plan → execute → probe → correlate → report) runs without further input
* progress is emitted as structured events and can be hidden / shown
  without stopping the pipeline
* cancellation is cooperative: Ctrl+C in the UI or /autopilot stop stops
  the live subprocesses, not just the Python loop
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

# Ordered pipeline phases as executed by run_pentest.
PHASE_ORDER = [
    "recon", "osint", "js", "param", "payload",
    "analyze", "plan", "execute", "probe", "correlate", "report",
]

# Human labels shown in progress panels.
PHASE_LABELS = {
    "recon": "Recon (ports · subdomains · dir fuzz · tech · waf)",
    "osint": "OSINT footprint",
    "js": "JavaScript analysis",
    "param": "Parameter discovery",
    "payload": "AI payload forge",
    "analyze": "AI analysis",
    "plan": "Attack plan",
    "execute": "Active module execution",
    "probe": "Payload verification",
    "correlate": "Correlation & risk scoring",
    "report": "Report generation",
}

HIDE_ALIASES = {"hide", "hidden", "off", "mute"}
SHOW_ALIASES = {"show", "visible", "on", "unhide"}


@dataclass
class AutopilotEvent:
    phase: str
    message: str
    status: str = "run"  # run | done | error | log
    pct: Optional[int] = None
    module: str = ""
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase,
            "message": self.message,
            "status": self.status,
            "pct": self.pct,
            "module": self.module,
            "ts": self.ts,
        }


class AutopilotController:
    """Thread-safe controller for one background pipeline run."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._running = False
        self._target = ""
        self._started = 0.0
        self._thread: Optional[threading.Thread] = None
        self._cancel = threading.Event()
        self._progress_hidden = False
        self._buffer: List[AutopilotEvent] = []
        self._current_phase = ""
        self._findings = 0
        self._last_state: Optional[Dict[str, Any]] = None

    # -- visibility ------------------------------------------------------

    def set_hidden(self, hidden: bool) -> List[AutopilotEvent]:
        with self._lock:
            self._progress_hidden = bool(hidden)
            if not hidden:
                drained, self._buffer = self._buffer, []
                return drained
            return []

    def is_hidden(self) -> bool:
        with self._lock:
            return self._progress_hidden

    def buffered_count(self) -> int:
        with self._lock:
            return len(self._buffer)

    def emit(self, phase: str, message: str, status: str = "run",
             pct: Optional[int] = None, module: str = "") -> Optional[AutopilotEvent]:
        """Record an event; returns it when visible, else buffers it."""
        event = AutopilotEvent(
            phase=phase, message=message, status=status, pct=pct, module=module
        )
        with self._lock:
            self._current_phase = phase
            if self._progress_hidden:
                self._buffer.append(event)
                if len(self._buffer) > 500:
                    self._buffer = self._buffer[-500:]
                return None
        return event

    # -- lifecycle -------------------------------------------------------

    def is_running(self) -> bool:
        with self._lock:
            return self._running

    def start(self, target: str, run_callable: Callable[..., Any]) -> bool:
        """Start the pipeline in a background thread. Returns False if busy."""
        target = (target or "").strip()
        if not target:
            return False
        with self._lock:
            if self._running:
                return False
            self._running = True
            self._target = target
            self._started = time.time()
            self._cancel.clear()
            self._buffer = []
            self._current_phase = ""
            self._findings = 0
            self._last_state = None
            event = self._cancel

        def _runner() -> None:
            try:
                state = run_callable(target=target, cancel_event=event)
                with self._lock:
                    self._last_state = state if isinstance(state, dict) else None
                    if isinstance(state, dict):
                        self._findings = len(state.get("findings", []) or [])
                    self._running = False
            except Exception as exc:  # noqa: BLE001
                with self._lock:
                    self._last_state = {"error": str(exc)}
                    self._running = False

        self._thread = threading.Thread(target=_runner, daemon=True, name="autopilot")
        self._thread.start()
        return True

    def stop(self) -> bool:
        with self._lock:
            if not self._running:
                return False
            self._cancel.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        with self._lock:
            self._running = False
        return True

    def status(self) -> Dict[str, Any]:
        with self._lock:
            elapsed = int(time.time() - self._started) if self._started else 0
            return {
                "running": self._running,
                "target": self._target,
                "phase": self._current_phase,
                "findings": self._findings,
                "elapsed": elapsed,
                "hidden": self._progress_hidden,
                "buffered": len(self._buffer),
                "state": self._last_state,
            }


def phase_progress_pct(phase: str, done: bool = False) -> Optional[int]:
    """Coarse completion percentage for one pipeline phase."""
    if phase not in PHASE_ORDER:
        return None
    index = PHASE_ORDER.index(phase)
    return int((index + (1 if done else 0)) / len(PHASE_ORDER) * 100)
