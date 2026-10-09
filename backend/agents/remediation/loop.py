"""Remediation-only loop (prompt 05a).

A SMALL graph with just secure_coder → tester → pr_creator and the same
retry routing as the full pipeline. Used by POST /api/remediate and
scripts/remediate_only.py to re-run remediation from a saved
state_after_fix.json without re-scanning. Re-clones the repo when the
original clone is gone (scans delete it at the end).
"""

from __future__ import annotations

import logging
import os
from typing import AsyncGenerator

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph

from ..state import ScanState
from .pr_creator import pr_creator_node
from .secure_coder import secure_coder_node
from .tester import tester_node

logger = logging.getLogger(__name__)


def _route_after_tester(state: ScanState) -> str:
    from ..orchestrator import _route_after_tester as full_route
    return full_route(state)


def build_remediation_graph():
    """secure_coder → tester → (pr_creator | retry secure_coder | END)."""
    graph = StateGraph(ScanState)
    graph.add_node("secure_coder", secure_coder_node)
    graph.add_node("tester", tester_node)
    graph.add_node("pr_creator", pr_creator_node)
    graph.set_entry_point("secure_coder")
    graph.add_edge("secure_coder", "tester")
    graph.add_conditional_edges("tester", _route_after_tester, {
        "pr_creator": "pr_creator",
        "secure_coder": "secure_coder",
        "report_generator": END,
    })
    graph.add_edge("pr_creator", END)
    return graph.compile(checkpointer=MemorySaver())


def _ensure_repo(state: dict, run_id: str) -> dict:
    """Re-clone when the original clone is gone; point state at the clone."""
    repo_path = state.get("repo_path", "")
    if repo_path and os.path.isdir(repo_path):
        return state
    from tools.git_cloner import clone_repo
    repo_url = state.get("repo_url", "")
    if not repo_url:
        raise RuntimeError("remediation needs repo_url (missing from snapshot)")
    dest = clone_repo(repo_url, run_id)
    logger.info("remediation %s: re-cloned %s to %s", run_id, repo_url, dest)
    state["repo_path"] = dest
    return state


def fresh_remediation_state(snapshot: dict, run_id: str,
                            target_hint: str | None = None) -> dict:
    """Reset per-attempt fields so a re-run starts clean."""
    state = dict(snapshot)
    state["scan_id"] = run_id
    state["create_pr"] = True
    if target_hint:
        state["target_hint"] = target_hint
    state["target_vuln"] = None
    state["work_dir"] = ""
    state["code_patch"] = None
    state["attempts"] = 0
    state["feedback"] = []
    state["review"] = None
    state["test_reports"] = {}
    state["test_verdict"] = None
    state["pr_url"] = None
    state["remediation_status"] = "running"
    state["agent_logs"] = []
    return state


async def stream_remediation(state: dict, run_id: str):
    """Yield (node_name, node_output) like the full pipeline's stream."""
    state = _ensure_repo(state, run_id)
    state["scan_id"] = run_id
    graph = build_remediation_graph()
    config = {"configurable": {"thread_id": run_id}}
    async for event in graph.astream(state, config=config):
        node_name, node_output = next(iter(event.items()))
        yield node_name, node_output


async def run_remediation(state: dict, run_id: str) -> dict:
    """Run the small graph to completion; return the accumulated state."""
    accumulated: dict = dict(state)
    async for _, node_output in stream_remediation(state, run_id):
        for key, value in node_output.items():
            if key == "agent_logs":
                accumulated.setdefault("agent_logs", [])
                accumulated["agent_logs"].extend(value)
            else:
                accumulated[key] = value
    return accumulated
