"""
Local OSINT scan history.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List


HISTORY_PATH = Path(os.path.expanduser("~")) / ".hackit_osint_history.json"
REPORT_DIR = Path(os.path.expanduser("~")) / ".hackit_osint_reports"


def load_history(limit: int = 10) -> List[Dict[str, object]]:
    try:
        data = json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data[-limit:]
    except Exception:
        pass
    return []


def append_history(result: Dict[str, object]) -> None:
    history = load_history(limit=100)
    summary = result.get("summary", {})
    history.append({
        "time": datetime.now().isoformat(timespec="seconds"),
        "query": result.get("query"),
        "handles": result.get("handles", [])[:10],
        "hits": summary.get("hits", 0),
        "possible": summary.get("possible", 0),
        "checked": summary.get("checked", 0),
    })
    try:
        HISTORY_PATH.write_text(json.dumps(history[-100:], indent=2), encoding="utf-8")
    except Exception:
        pass


def save_auto_report(result: Dict[str, object]) -> str:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    safe_query = "".join(c if c.isalnum() else "_" for c in str(result.get("query", "target"))).strip("_") or "target"
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORT_DIR / f"{safe_query}_{stamp}.json"
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return str(path)
