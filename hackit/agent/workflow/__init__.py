import os
import json
from langgraph.graph import StateGraph, START, END

from .state import PentestState, make_initial_state, Phase, load_latest_state, PERSIST_DIR
from .nodes import (
    recon_node,
    js_node,
    param_node,
    analyze_node,
    plan_node,
    execute_node,
    correlate_node,
    report_node,
    recon_router,
)

PHASE_NODE_MAP = {
    Phase.INIT.value: "recon",
    Phase.RECON.value: "js",
    Phase.JS.value: "param",
    Phase.PARAM.value: "analyze",
    Phase.ANALYZE.value: "plan",
    Phase.PLAN.value: "execute",
    Phase.EXECUTE.value: "correlate",
    Phase.CORRELATE.value: "report",
    Phase.REPORT.value: None,
    Phase.DONE.value: None,
}


def build_graph() -> StateGraph:
    graph = StateGraph(PentestState)

    graph.add_node("recon", recon_node)
    graph.add_node("js", js_node)
    graph.add_node("param", param_node)
    graph.add_node("analyze", analyze_node)
    graph.add_node("plan", plan_node)
    graph.add_node("execute", execute_node)
    graph.add_node("correlate", correlate_node)
    graph.add_node("report", report_node)

    graph.add_edge(START, "recon")

    graph.add_conditional_edges(
        "recon",
        recon_router,
        {
            "js": "js",
            "correlate": "correlate",
            "report": "report",
        },
    )

    graph.add_edge("js", "param")
    graph.add_edge("param", "analyze")
    graph.add_edge("analyze", "plan")
    graph.add_edge("plan", "execute")
    graph.add_edge("execute", "correlate")
    graph.add_edge("correlate", "report")
    graph.add_edge("report", END)

    return graph.compile()


def run_pentest(target: str, scope: str = "active_stealth", resume: bool = False) -> PentestState:
    graph = build_graph()

    if resume:
        saved = load_latest_state(target)
        if saved:
            phase = saved.get("phase", Phase.INIT.value)
            next_node = PHASE_NODE_MAP.get(phase)
            if next_node:
                print(f"  Resuming from phase {phase} -> node {next_node}")
                # Re-invoke the graph from the recovered state
                result = graph.invoke(saved)
                return result

    initial = make_initial_state(target, scope)
    result = graph.invoke(initial)
    return result
