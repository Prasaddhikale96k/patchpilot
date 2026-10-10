"""Remediation-only loop (prompt 05a, reviewer added in prompt 05).

A SMALL graph with just secure_coder → reviewer → tester → pr_creator and
the same retry routing as the full pipeline. Used by POST /api/remediate and
scripts/remediate_only.py to re-run remediation from a saved
state_after_fix.json without re-scanning. Re-clones the repo when the
original clone is gone (scans delete it at the end).
"""

from __future__ import annotations

import logging
from typing import AsyncGenerator

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph

from ..state import ScanState
from .pr_creator import pr_creator_node
from .reviewer import reviewer_node
from .secure_coder import secure_coder_node
from .tester import tester_node

logger = logging.getLogger(__name__)


def _route_after_tester(state: ScanState) -> str:
    from ..orchestrator import _route_after_tester as full_route
    return full_route(state)


def _route_after_reviewer(state: ScanState) -> str:
    from ..orchestrator import _route_after_reviewer as full_route
    return full_route(state)


def _route_after_secure_coder(state: ScanState) -> str:
    from ..orchestrator import _route_after_secure_coder as full_route
    return full_route(state)


def build_remediation_graph(entry_point: str = "secure_coder"):
    """secure_coder → reviewer → tester → (pr_creator | retry | END).

    ``entry_point`` is the resume entry for remediation retries: a retry
    that already holds a validated patch must not pay for SecureCoder (and
    its LLM call) again, so it enters at reviewer/tester/pr_creator with
    the restored work copy. The default preserves the original behaviour.
    """
    if entry_point not in ("secure_coder", "reviewer", "tester", "pr_creator"):
        entry_point = "secure_coder"
    graph = StateGraph(ScanState)
    graph.add_node("secure_coder", secure_coder_node)
    graph.add_node("reviewer", reviewer_node)
    graph.add_node("tester", tester_node)
    graph.add_node("pr_creator", pr_creator_node)
    graph.set_entry_point(entry_point)
    graph.add_conditional_edges("secure_coder", _route_after_secure_coder, {
        "reviewer": "reviewer",
        "secure_coder": "secure_coder",
        "report_generator": END,
    })
    graph.add_conditional_edges("reviewer", _route_after_reviewer, {
        "tester": "tester",
        "secure_coder": "secure_coder",
        "report_generator": END,
    })
    graph.add_conditional_edges("tester", _route_after_tester, {
        "pr_creator": "pr_creator",
        "secure_coder": "secure_coder",
        "report_generator": END,
    })
    graph.add_edge("pr_creator", END)
    return graph.compile(checkpointer=MemorySaver())


def _ensure_repo(state: dict, run_id: str) -> dict:
    """Re-clone when the original clone is gone; point state at the clone."""
    from tools.git_cloner import clone_repo, is_usable_clone
    repo_path = state.get("repo_path", "")
    # A directory is not a clone: Windows cleanup used to leave a bare
    # .git husk behind, and trusting it made every re-run "find nothing".
    if repo_path and is_usable_clone(repo_path):
        return state
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
    state["pr"] = None
    # Opening a PR needs its own explicit consent on a re-run (the caller
    # sets it from the request); never inherited from the original scan.
    state["open_pr"] = False
    state["remediation_status"] = "running"
    state["agent_logs"] = []
    return state


async def stream_remediation(state: dict, run_id: str,
                               entry_point: str = "secure_coder"):
    """Yield (node_name, node_output) like the full pipeline's stream.

    When ``entry_point`` is past SecureCoder, the validated patch saved by
    a previous attempt is re-applied to a fresh clone first, so Reviewer /
    Tester gate the exact same change the earlier run produced. A patch
    that no longer applies (base moved) falls back to SecureCoder.
    """
    from .resume import materialize_work_dir
    state = _ensure_repo(state, run_id)
    state["scan_id"] = run_id
    if entry_point not in ("secure_coder", "reviewer", "tester", "pr_creator"):
        entry_point = "secure_coder"
    if entry_point != "secure_coder" and state.get("_resume_blocks"):
        try:
            work_dir, applied = materialize_work_dir(
                state.get("repo_path", ""), run_id,
                state["_resume_blocks"], state.get("_resume_test_rel", ""),
                state.get("_resume_test_content", ""),
                attempt_no=state.get("attempts", 0) or 0)
            patch = dict(state.get("code_patch") or {})
            patch["diff"] = applied["diff"]
            patch["files_changed"] = applied["files_changed"]
            patch["lines_added"] = applied["lines_added"]
            patch["lines_removed"] = applied["lines_removed"]
            state["work_dir"] = work_dir
            state["code_patch"] = patch
            logger.info("remediation %s: resumed work copy from %s (%s)",
                        run_id, state.get("_resume_source"),
                        entry_point)
        except Exception:
            logger.warning("remediation %s: saved patch no longer applies; "
                           "falling back to SecureCoder", run_id, exc_info=True)
            state["work_dir"] = ""
            state["code_patch"] = None
            state["review"] = None
            state["test_reports"] = {}
            state["test_verdict"] = None
            state.setdefault("agent_logs", []).append(
                "[Resume] Saved patch no longer applies to the current "
                "revision — restarting at SecureCoder.")
            entry_point = "secure_coder"
    # Internal resume keys never reach the graph state / report.
    for key in ("_resume_blocks", "_resume_test_rel",
                "_resume_test_content", "_resume_hash", "_resume_source",
                "_resume_reason"):
        state.pop(key, None)
    graph = build_remediation_graph(entry_point)
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
