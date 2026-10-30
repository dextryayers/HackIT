"""Autonomous pentest workflow.

LangGraph is used when installed, otherwise a dependency-free sequential
runner executes exactly the same nodes.  Both paths support a ``progress``
callback of the form ``progress(phase, message)`` so the CLI can render live
updates.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any, Callable, Dict, Optional

try:  # optional dependency
    from langgraph.graph import END, START, StateGraph  # type: ignore

    LANGGRAPH_AVAILABLE = True
except Exception:  # noqa: BLE001 - optional dependency
    END = START = None  # type: ignore
    StateGraph = None  # type: ignore
    LANGGRAPH_AVAILABLE = False

from .state import (
    PERSIST_DIR,
    Phase,
    PentestState,
    load_latest_state,
    make_initial_state,
)
from .tools import reset_ai_budget, set_cancel_event, workflow_cancelled
from .nodes import (
    analyze_node,
    correlate_node,
    execute_node,
    js_node,
    osint_node,
    osint_router,
    param_node,
    payload_node,
    plan_node,
    probe_node,
    recon_node,
    recon_router,
    report_node,
)

PHASE_NODE_MAP = {
    Phase.INIT.value: "recon",
    Phase.RECON.value: "osint",
    Phase.OSINT.value: "js",
    Phase.JS.value: "param",
    Phase.PARAM.value: "payload",
    Phase.PAYLOAD.value: "analyze",
    Phase.ANALYZE.value: "plan",
    Phase.PLAN.value: "execute",
    Phase.EXECUTE.value: "probe",
    Phase.PROBE.value: "correlate",
    Phase.CORRELATE.value: "report",
    Phase.REPORT.value: None,
    Phase.DONE.value: None,
}

NODE_SEQUENCE = [
    ("recon", recon_node),
    ("osint", osint_node),
    ("js", js_node),
    ("param", param_node),
    ("payload", payload_node),
    ("analyze", analyze_node),
    ("plan", plan_node),
    ("execute", execute_node),
    ("probe", probe_node),
    ("correlate", correlate_node),
    ("report", report_node),
]

ProgressCallback = Optional[Callable[[str, str], None]]


def _emit(progress: ProgressCallback, phase: str, message: str) -> None:
    if progress is None:
        return
    try:
        progress(phase, message)
    except Exception:  # noqa: BLE001 - UI callbacks must never abort a scan
        pass


def _wrap_node(name: str, node: Callable[[PentestState], Dict[str, Any]],
               progress: ProgressCallback):
    def runner(state: PentestState) -> Dict[str, Any]:
        if workflow_cancelled():
            return {"error": "cancelled", "cancelled": True}
        _emit(progress, name, f"starting {name}")
        started = time.time()
        try:
            update = node(state) or {}
            # A recovered phase must not inherit a previous phase's error.
            update.setdefault("error", "")
        except Exception as exc:  # noqa: BLE001
            update = {
                "error": f"{name}: {exc}",
                "phase": state.get("phase", Phase.INIT.value),
            }
            _emit(progress, name, f"error: {exc}")
        if update.get("error") == "cancelled" or workflow_cancelled():
            update["cancelled"] = True
        elapsed = time.time() - started
        findings = update.get("findings", state.get("findings", []))
        count = len(findings) if isinstance(findings, list) else 0
        phase = update.get("phase", state.get("phase", ""))
        _emit(progress, name, f"{phase} · {elapsed:.1f}s · {count} finding(s)")
        return update

    return runner


def build_graph(progress: ProgressCallback = None):
    """Compile the LangGraph state machine (raises if LangGraph is absent)."""
    if not LANGGRAPH_AVAILABLE:
        raise RuntimeError("langgraph is not installed")

    graph = StateGraph(PentestState)
    nodes = {
        "recon": recon_node,
        "osint": osint_node,
        "js": js_node,
        "param": param_node,
        "payload": payload_node,
        "analyze": analyze_node,
        "plan": plan_node,
        "execute": execute_node,
        "probe": probe_node,
        "correlate": correlate_node,
        "report": report_node,
    }
    for name, node in nodes.items():
        graph.add_node(name, _wrap_node(name, node, progress))

    graph.add_edge(START, "recon")
    graph.add_conditional_edges(
        "recon", recon_router, {"osint": "osint"},
    )
    graph.add_conditional_edges(
        "osint", osint_router, {"js": "js", "payload": "payload"},
    )
    graph.add_edge("js", "param")
    graph.add_edge("param", "payload")
    graph.add_edge("payload", "analyze")
    graph.add_edge("analyze", "plan")
    graph.add_edge("plan", "execute")
    graph.add_edge("execute", "probe")
    graph.add_edge("probe", "correlate")
    graph.add_edge("correlate", "report")
    graph.add_edge("report", END)
    return graph.compile()


def _run_sequential(initial: PentestState, progress: ProgressCallback = None) -> PentestState:
    state: PentestState = dict(initial)  # type: ignore[assignment]
    for name, node in NODE_SEQUENCE:
        if workflow_cancelled():
            state["cancelled"] = True
            _emit(progress, "workflow", "cancelled")
            break
        runner = _wrap_node(name, node, progress)
        update = runner(state)
        merged: Dict[str, Any] = dict(state)
        merged.update(update or {})
        state = merged  # type: ignore[assignment]
        if state.get("cancelled"):
            _emit(progress, "workflow", "cancelled")
            break
    return state


def run_pentest(target: str, scope: str = "active_stealth", resume: bool = False,
                progress: ProgressCallback = None,
                cancel_event: Optional[threading.Event] = None,
                authorized: bool = False) -> PentestState:
    """Run the complete recon -> OSINT -> scan -> payload -> attack -> report flow.

    ``authorized=True`` enables active module execution and payload
    verification.  Callers must only set it for targets they own or have
    explicit written permission to test.
    """
    target = (target or "").strip()
    if not target:
        raise ValueError("target is required")

    initial: PentestState
    if resume:
        saved = load_latest_state(target)
        initial = saved or make_initial_state(target, scope, authorized)  # type: ignore[assignment]
        if saved:
            initial["authorized"] = bool(authorized or initial.get("authorized"))
            _emit(progress, "resume", f"resuming from phase {saved.get('phase', 'init')}")
    else:
        initial = make_initial_state(target, scope, authorized)

    if authorized:
        _emit(progress, "workflow", "active mode enabled: authorized modules and payload probes")

    set_cancel_event(cancel_event)
    reset_ai_budget()
    try:
        if LANGGRAPH_AVAILABLE:
            try:
                graph = build_graph(progress=progress)
                result = graph.invoke(initial)
                return result  # type: ignore[return-value]
            except Exception as exc:  # noqa: BLE001 - degrade to built-in runner
                _emit(progress, "workflow", f"LangGraph unavailable ({exc}); using built-in runner")

        return _run_sequential(initial, progress=progress)
    finally:
        set_cancel_event(None)


def workflow_engine() -> str:
    return "langgraph" if LANGGRAPH_AVAILABLE else "builtin"
