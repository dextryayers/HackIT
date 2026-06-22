"""
Attack Report Engine — generates detailed analytics after attack.

Tracks: packets sent/rate over time, target responsiveness,
proxy performance, method switching history, and exports to JSON/CSV/HTML.
"""

import json
import os
import time
import csv
import io
from datetime import datetime
from typing import Optional
from collections import deque
from pathlib import Path


class AttackSnapshot:
    def __init__(self, timestamp: float, sent: int = 0, errors: int = 0,
                 rate: int = 0, method: str = "", latency: float = 0,
                 active_workers: int = 0, memory_mb: float = 0):
        self.timestamp = timestamp
        self.sent = sent
        self.errors = errors
        self.rate = rate
        self.method = method
        self.latency = latency
        self.active_workers = active_workers
        self.memory_mb = memory_mb

    def to_dict(self) -> dict:
        return {
            "time": datetime.fromtimestamp(self.timestamp).isoformat(),
            "ts": self.timestamp, "sent": self.sent, "errors": self.errors,
            "rate": self.rate, "method": self.method, "latency_ms": self.latency,
            "workers": self.active_workers,
        }


class ReportEngine:
    def __init__(self, target: str, method: str):
        self.target = target
        self.method = method
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.snapshots: deque[AttackSnapshot] = deque(maxlen=3600)
        self.proxy_switches: list[dict] = []
        self.method_switches: list[tuple[float, str, str]] = []
        self.errors: list[tuple[float, str]] = []
        self.total_sent = 0
        self.total_errors = 0
        self.peak_rate = 0
        self.session_id = os.urandom(4).hex()

    def record(self, sent: int, errors: int, rate: int = 0,
               method: str = "", latency: float = 0, workers: int = 0):
        snap = AttackSnapshot(time.time(), sent, errors, rate,
                              method or self.method, latency, workers)
        self.snapshots.append(snap)
        self.total_sent += sent
        self.total_errors += errors
        if rate > self.peak_rate:
            self.peak_rate = rate

    def record_method_switch(self, old_method: str, new_method: str):
        self.method_switches.append((time.time(), old_method, new_method))

    def record_proxy_switch(self, old_proxy: str, new_proxy: str, reason: str = ""):
        self.proxy_switches.append({
            "time": time.time(), "old": old_proxy, "new": new_proxy, "reason": reason,
        })

    def record_error(self, error: str):
        self.errors.append((time.time(), error))

    def stop(self):
        self.end_time = time.time()

    @property
    def elapsed(self) -> float:
        end = self.end_time or time.time()
        return end - self.start_time

    @property
    def avg_rate(self) -> float:
        if self.elapsed > 0:
            return self.total_sent / self.elapsed
        return 0

    @property
    def current_speed(self) -> int:
        recent = [s for s in self.snapshots
                 if s.timestamp > time.time() - 5]
        if recent:
            return int(sum(s.rate for s in recent) / len(recent))
        return 0

    def to_dict(self) -> dict:
        return {
            "session": self.session_id,
            "target": self.target,
            "method": self.method,
            "start": datetime.fromtimestamp(self.start_time).isoformat(),
            "end": datetime.fromtimestamp(self.end_time).isoformat() if self.end_time else "",
            "elapsed_sec": round(self.elapsed, 2),
            "total_sent": self.total_sent,
            "total_errors": self.total_errors,
            "peak_rate": self.peak_rate,
            "avg_rate": round(self.avg_rate, 2),
            "method_switches": len(self.method_switches),
            "proxy_switches": len(self.proxy_switches),
            "errors": len(self.errors),
            "history": [s.to_dict() for s in self.snapshots],
        }

    def to_json(self, path: Optional[str] = None) -> str:
        data = self.to_dict()
        text = json.dumps(data, indent=2)
        if path:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, 'w') as f:
                f.write(text)
        return text

    def to_csv(self, path: Optional[str] = None) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["timestamp", "sent", "errors", "rate",
                        "method", "workers", "elapsed_sec"])
        for s in self.snapshots:
            writer.writerow([
                datetime.fromtimestamp(s.timestamp).isoformat(),
                s.sent, s.errors, s.rate, s.method,
                s.active_workers, round(s.timestamp - self.start_time, 2),
            ])
        text = output.getvalue()
        if path:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, 'w', newline='') as f:
                f.write(text)
        return text

    def to_html(self, title: str = "Attack Report") -> str:
        html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{title}</title>
<style>
  body {{ font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 40px; }}
  h1 {{ color: #f85149; }}
  .stat {{ display: inline-block; margin: 10px; padding: 15px; background: #161b22;
          border: 1px solid #30363d; border-radius: 6px; min-width: 150px; }}
  .stat label {{ color: #8b949e; font-size: 12px; }}
  .stat .val {{ font-size: 24px; font-weight: bold; color: #58a6ff; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
  th {{ background: #21262d; padding: 8px; text-align: left; }}
  td {{ padding: 8px; border-bottom: 1px solid #21262d; }}
  tr:hover {{ background: #161b22; }}
  .badge {{ padding: 2px 8px; border-radius: 10px; font-size: 11px; }}
  .badge-ok {{ background: #2ea04333; color: #3fb950; }}
  .badge-err {{ background: #f8514933; color: #f85149; }}
</style></head><body>
<h1>🔬 {title}</h1>
<p>Target: <strong>{self.target}</strong> | Method: <strong>{self.method}</strong></p>
<p>Session: {self.session_id} | {datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S')}</p>
<div class="stat"><label>Total Sent</label><div class="val">{self.total_sent:,}</div></div>
<div class="stat"><label>Peak Rate</label><div class="val">{self.peak_rate:,} pps</div></div>
<div class="stat"><label>Avg Rate</label><div class="val">{self.avg_rate:,.0f} pps</div></div>
<div class="stat"><label>Errors</label><div class="val">{self.total_errors}</div></div>
<div class="stat"><label>Elapsed</label><div class="val">{self.elapsed:.1f}s</div></div>
<h2>Timeline</h2>
<table><tr><th>Time</th><th>Sent</th><th>Rate</th><th>Method</th><th>Status</th></tr>"""
        for s in self.snapshots:
            elapsed = s.timestamp - self.start_time
            status = "OK" if s.errors == 0 else "ERR"
            badge = "badge-ok" if s.errors == 0 else "badge-err"
            html += f"<tr><td>{elapsed:.1f}s</td><td>{s.sent}</td><td>{s.rate}</td>"
            html += f"<td>{s.method}</td><td><span class='badge {badge}'>{status}</span></td></tr>"
        html += """</table></body></html>"""
        return html

    def export_all(self, report_dir: str = "reports"):
        base = os.path.join(report_dir, f"attack_{self.session_id}")
        os.makedirs(base, exist_ok=True)
        self.to_json(os.path.join(base, "report.json"))
        self.to_csv(os.path.join(base, "timeline.csv"))
        html = self.to_html(f"DDoS Attack - {self.target}")
        with open(os.path.join(base, "report.html"), 'w') as f:
            f.write(html)
        return base
