import json
import os
import time
from dataclasses import dataclass, field
from typing import TypedDict, List, Optional, Dict, Any
from enum import Enum


PERSIST_DIR = os.path.join(os.path.expanduser("~"), ".hackit", "workflow_state")


class Phase(str, Enum):
    INIT = "init"
    RECON = "recon"
    JS = "js"
    PARAM = "param"
    ANALYZE = "analyze"
    PLAN = "plan"
    EXECUTE = "execute"
    CORRELATE = "correlate"
    REPORT = "report"
    DONE = "done"


@dataclass
class Finding:
    id: str = ""
    type: str = ""           # sqli | xss | ssrf | open_redirect | misconfig | etc
    severity: str = "info"   # critical | high | medium | low | info
    target: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    cvss: Optional[float] = None

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type,
            "severity": self.severity,
            "target": self.target,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cvss": self.cvss,
        }


class PentestState(TypedDict):
    target: str
    scope: str
    phase: str
    findings: List[Dict[str, Any]]
    scan_data: Dict[str, Any]
    analysis: str
    attack_plan: str
    risk_score: float
    report_path: Optional[str]
    error: Optional[str]
    messages: List[Dict[str, str]]


def make_initial_state(target: str, scope: str = "active_stealth") -> PentestState:
    return {
        "target": target,
        "scope": scope,
        "phase": Phase.INIT.value,
        "findings": [],
        "scan_data": {},
        "analysis": "",
        "attack_plan": "",
        "risk_score": 0.0,
        "report_path": None,
        "error": None,
        "messages": [],
    }


def persist_state(state: PentestState, suffix: str = "") -> str:
    os.makedirs(PERSIST_DIR, exist_ok=True)
    target_slug = state.get("target", "unknown").replace(".", "_").replace(":", "_")
    ts = time.strftime("%Y%m%d_%H%M%S")
    filename = f"{target_slug}_{state.get('phase', 'init')}_{ts}{suffix}.json"
    path = os.path.join(PERSIST_DIR, filename)
    with open(path, "w") as f:
        json.dump(state, f, indent=2, default=str)
    return path


def load_latest_state(target: str = "") -> Optional[PentestState]:
    if not os.path.exists(PERSIST_DIR):
        return None
    files = os.listdir(PERSIST_DIR)
    if target:
        slug = target.replace(".", "_").replace(":", "_")
        files = [f for f in files if f.startswith(slug)]
    if not files:
        return None
    files.sort(reverse=True)
    latest = os.path.join(PERSIST_DIR, files[0])
    try:
        with open(latest, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def get_persisted_phases(target: str = "") -> List[str]:
    if not os.path.exists(PERSIST_DIR):
        return []
    files = os.listdir(PERSIST_DIR)
    if target:
        slug = target.replace(".", "_").replace(":", "_")
        files = [f for f in files if f.startswith(slug)]
    phases = set()
    for f in files:
        parts = f.split("_")
        if len(parts) >= 2:
            phases.add(parts[-3])  # phase is second-to-last before timestamp
    return list(phases)
