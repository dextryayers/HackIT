"""
HackIt Swarm Controller — High-level orchestration interface.
Provides very sharp, high-precision swarm execution with full
vulnerability discovery, verified exploit chains, and professional
pentest-grade reporting.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any, Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from .swarm import SwarmEngine, SWARM_NODE_COUNT, SWARM_MAX_WORKERS
from .brain import AIHyperBrain
from .commands import COMMAND_MODES


class SwarmController:
    """Public interface for the 28-node swarm."""

    def __init__(self):
        self.engine: Optional[SwarmEngine] = None

    def launch(
        self,
        target: str,
        deep: bool = True,
        passive: bool = False,
        full_report: bool = True,
    ) -> Dict[str, Any]:
        """Launch the full swarm against the target."""
        if not target or not isinstance(target, str):
            return {"error": "Target must be a non-empty string (IP or domain)."}
        self.engine = SwarmEngine(target=target, deep=deep, passive=passive)
        result = self.engine.run()
        # Enrich with professional analysis if brain available
        try:
            brain = AIHyperBrain(engine="native", enable_memory=False, announce=False)
            analysis = brain.chat(
                f"Analyze these swarm findings for target {target}:\n"
                f"Findings count: {len(result.get('full_findings', []))}\n"
                f"Attack chains: {len(result.get('attack_chains', []))}\n"
                f"Discovery: {str(result.get('discovery', {}))[:3000]}\n"
                "Provide a concise, high-precision vulnerability assessment with CVSS-style severity rating and exploitation confidence."
            )
            result["ai_analysis"] = analysis
        except Exception:
            pass
        # Save full report
        if full_report:
            result["full_report_path"] = self._save_professional_report(result, target)
        return result

    def _save_professional_report(self, result: Dict[str, Any], target: str) -> str:
        from .swarm import SwarmEngine
        reports_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "reports", "swarm"
        )
        os.makedirs(reports_dir, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        slug = target.replace("://", "_").replace("/", "_")
        path = os.path.join(reports_dir, f"swarm_report_{slug}_{stamp}.json")
        import json
        with open(path, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False, default=str)
        return path


def run_swarm(target: str = "", deep: bool = True, passive: bool = False, full_report: bool = True) -> Dict[str, Any]:
    """One-shot swarm launch."""
    ctrl = SwarmController()
    return ctrl.launch(target=target, deep=deep, passive=passive, full_report=full_report)
