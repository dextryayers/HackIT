import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import TypedDict, List, Optional, Dict, Any
from enum import Enum


PERSIST_DIR = os.path.join(os.path.expanduser("~"), ".hackit", "workflow_state")


def target_slug(target: str) -> str:
    """Build a filesystem-safe identifier from a target URL or host.

    The previous implementation used the raw target, so ``http://host``
    produced a nested ``http_/`` directory that did not exist and every
    persistence call failed.
    """
    value = str(target or "unknown").strip()
    value = re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*://", "", value)
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    value = value.strip("._")
    return value[:90] or "unknown"


class Phase(str, Enum):
    INIT = "init"
    RECON = "recon"
    OSINT = "osint"
    JS = "js"
    PARAM = "param"
    PAYLOAD = "payload"
    ANALYZE = "analyze"
    PLAN = "plan"
    EXECUTE = "execute"
    PROBE = "probe"
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
    osint_data: Dict[str, Any]
    payloads: Dict[str, Any]
    probe_results: List[Dict[str, Any]]
    analysis: str
    attack_plan: str
    risk_score: float
    report_path: Optional[str]
    error: Optional[str]
    analysis_error: str
    plan_error: str
    correlation_error: str
    report_error: str
    messages: List[Dict[str, str]]
    cancelled: bool


def make_initial_state(target: str, scope: str = "active_stealth") -> PentestState:
    return {
        "target": target,
        "scope": scope,
        "phase": Phase.INIT.value,
        "findings": [],
        "scan_data": {},
        "osint_data": {},
        "payloads": {},
        "probe_results": [],
        "analysis": "",
        "attack_plan": "",
        "risk_score": 0.0,
        "report_path": None,
        "error": None,
        "analysis_error": "",
        "plan_error": "",
        "correlation_error": "",
        "report_error": "",
        "messages": [],
        "cancelled": False,
    }


def persist_state(state: PentestState, suffix: str = "") -> str:
    os.makedirs(PERSIST_DIR, exist_ok=True)
    slug = target_slug(state.get("target", "unknown"))
    ts = time.strftime("%Y%m%d_%H%M%S")
    # A short random suffix prevents concurrent nodes from overwriting a file
    # written in the same second.
    unique = uuid.uuid4().hex[:6]
    phase = state.get("phase", "init")
    filename = f"{slug}_{phase}_{ts}_{unique}{suffix}.json"
    path = os.path.join(PERSIST_DIR, filename)
    with open(path, "w") as f:
        json.dump(state, f, indent=2, default=str)
    return path


def _state_files(target: str = "") -> List[str]:
    if not os.path.exists(PERSIST_DIR):
        return []
    names = [name for name in os.listdir(PERSIST_DIR) if name.endswith(".json")]
    if target:
        slug = target_slug(target)
        names = [name for name in names if name.startswith(slug + "_")]
    return [os.path.join(PERSIST_DIR, name) for name in names]


def load_latest_state(target: str = "") -> Optional[PentestState]:
    files = _state_files(target)
    if not files:
        return None
    files.sort(key=lambda path: os.path.getmtime(path), reverse=True)
    try:
        with open(files[0], "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def get_persisted_phases(target: str = "") -> List[str]:
    phases = set()
    for path in _state_files(target):
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError):
            continue
        phase = data.get("phase")
        if phase:
            phases.add(str(phase))
    return sorted(phases)
