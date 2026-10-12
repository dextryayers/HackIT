"""
HackIT Phase 1 shared real-time event bus v2.1 Pro.
Real production code, no simulation.
Provides JSONL streaming for all native bridges with backpressure control.
"""
import json
import queue
import sys
import threading
import time
import uuid
from pathlib import Path

EVENT_TYPES = ("finding", "finding_update", "progress", "stat", "error", "done")

EXIT_OK = 0
EXIT_INPUT_INVALID = 2
EXIT_NETWORK_FAIL = 3
EXIT_TIMEOUT = 4
EXIT_INTERNAL = 5

MAX_QUEUE = 5000
PROGRESS_MIN_INTERVAL_MS = 500
STAT_INTERVAL_MS = 1000
MAX_STDOUT_BYTES = 20 * 1024 * 1024


class EventBus:
    """Thread-safe real-time event bus with overflow to disk."""

    def __init__(self, run_id=None, overflow_path=None):
        self.run_id = run_id or uuid.uuid4().hex[:12]
        self.start_ms = int(time.time() * 1000)
        self.q = queue.Queue(maxsize=MAX_QUEUE)
        self.overflow_path = Path(overflow_path) if overflow_path else None
        self.dropped_to_disk = 0
        self.emitted = 0
        self.bytes_out = 0
        self._lock = threading.Lock()
        self._last_progress_ms = 0
        if self.overflow_path:
            self.overflow_path.parent.mkdir(parents=True, exist_ok=True)

    def elapsed_ms(self):
        return int(time.time() * 1000) - self.start_ms

    def _write_overflow(self, event):
        try:
            if self.overflow_path:
                with open(self.overflow_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event, ensure_ascii=False) + "\n")
                self.dropped_to_disk += 1
        except OSError:
            pass

    def emit(self, event_type, data):
        if event_type not in EVENT_TYPES:
            raise ValueError("invalid event type: %s" % event_type)
        now = int(time.time() * 1000)
        if event_type == "progress":
            with self._lock:
                if now - self._last_progress_ms < PROGRESS_MIN_INTERVAL_MS:
                    return False
                self._last_progress_ms = now
        event = {"type": event_type, "run_id": self.run_id, "elapsed_ms": self.elapsed_ms()}
        event.update(data or {})
        line = json.dumps(event, ensure_ascii=False)
        with self._lock:
            self.emitted += 1
            self.bytes_out += len(line.encode("utf-8", errors="ignore"))
        try:
            self.q.put_nowait(line)
        except queue.Full:
            self._write_overflow(event)
            return False
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
        return True

    def emit_finding(self, module, target_hash, vuln_class, severity, confidence, title, evidence_ref=""):
        return self.emit("finding", {
            "module": module,
            "target_hash": target_hash,
            "vuln_class": vuln_class,
            "severity": severity,
            "confidence": float(confidence),
            "title": title,
            "evidence_ref": evidence_ref,
        })

    def emit_progress(self, done, total, rps=0.0, queue_depth=0, active_workers=0):
        return self.emit("progress", {
            "done": int(done),
            "total": int(total),
            "rps": float(rps),
            "queue_depth": int(queue_depth),
            "active_workers": int(active_workers),
        })

    def emit_stat(self, p50_ms=0, p95_ms=0, timeouts=0, retries=0, extra=None):
        payload = {
            "p50_ms": int(p50_ms),
            "p95_ms": int(p95_ms),
            "timeouts": int(timeouts),
            "retries": int(retries),
            "emitted": self.emitted,
            "dropped_to_disk": self.dropped_to_disk,
        }
        if extra:
            payload.update(extra)
        return self.emit("stat", payload)

    def emit_error(self, code, stage, detail=""):
        return self.emit("error", {
            "code": int(code),
            "stage": stage,
            "detail_redacted": detail[:500],
        })

    def emit_done(self, summary=None, cancelled=False):
        return self.emit("done", {
            "summary": summary or {},
            "cancelled": bool(cancelled),
            "emitted": self.emitted,
            "dropped_to_disk": self.dropped_to_disk,
        })

    def drain(self):
        items = []
        try:
            while True:
                items.append(self.q.get_nowait())
        except queue.Empty:
            pass
        return items
