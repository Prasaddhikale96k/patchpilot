"""Remediation section of the final report (shared by the full pipeline and
the remediation-only loop, so both report identical evidence).

The section records what actually happened, never what a model claimed:
a diff is "verified" only when the reviewer approved it AND the Docker
tester reproduced the exploit on the original code AND the patched code
passed it with zero regressions. Patches are only ever applied to an
isolated work copy; the user's repository changes only through a PR.
"""

from __future__ import annotations

import os

# outcome values (one per remediation attempt sequence)
NOT_REQUESTED = "not_requested"   # create_pr was off: suggestions only
NOT_ATTEMPTED = "not_attempted"   # requested, but nothing patchable / no clone
PATCH_FAILED = "patch_failed"     # coder ran but produced no applicable patch
VERIFIED = "verified"             # reviewer approved + tester verified
REJECTED = "rejected"             # reviewer never approved within budget
TEST_FAILED = "test_failed"       # approved, but tests did not verify it
ERROR = "error"                   # infrastructure fault (sandbox, LLM down)

_PHASES = ("baseline", "exploit_before", "after")


def _phase_summary(rep: dict) -> dict:
    return {
        "total": rep.get("total", 0),
        "passed": rep.get("passed", 0),
        "failed": rep.get("failed", 0),
        "errors": rep.get("errors", 0),
        "skipped": rep.get("skipped", 0),
        "returncode": rep.get("returncode"),
        "timed_out": bool(rep.get("timed_out")),
        "sandbox": rep.get("sandbox"),
        "duration_s": rep.get("duration_s"),
        "failed_tests": [t.get("name", "") for t in
                         (rep.get("failed_tests") or [])][:20],
        "infra_error": rep.get("infra_error"),
    }


def _pr_not_reached_reason(state: dict, outcome: str) -> str:
    """Actionable reason the PR step was never attempted (no side effects)."""
    if not state.get("create_pr"):
        return "Auto-remediation was not requested for this scan."
    if outcome == VERIFIED:
        return ""
    tests = state.get("test_reports") or {}
    after = tests.get("after") or {}
    failing = [t.get("name", "") for t in (after.get("failed_tests") or [])][:3]
    regressions = sorted(
        set((tests.get("baseline") or {}).get("passed_names", []))
        - set(after.get("passed_names", []))) if after else []
    if outcome == PATCH_FAILED:
        return ("No applicable patch was produced, so no PR was attempted.")
    if outcome == REJECTED:
        return ("The Reviewer never approved a patch within the attempt "
                "budget, so no PR was attempted.")
    if outcome == TEST_FAILED:
        detail = ", ".join(failing) or ", ".join(regressions[:3])
        return ("The patch was not verified"
                + (f" (failing: {detail})" if detail else "")
                + ", so no PR was attempted.")
    if outcome == ERROR:
        return ("Verification hit an infrastructure error (sandbox/timeout), "
                "so no PR was attempted.")
    return "The patch was not verified, so no PR was attempted."


def _artifact_names(scan_id: str) -> list[str]:
    try:
        from tools.run_artifacts import _BASE
        base = _BASE / scan_id
        if not base.is_dir():
            return []
        return sorted(p.name for p in base.iterdir()
                      if p.is_file() and not p.name.endswith(".tmp"))
    except (OSError, ValueError):
        return []


def classify(state: dict) -> str:
    if not state.get("create_pr"):
        return NOT_REQUESTED
    if not state.get("code_patch"):
        # attempts > 0 means the coder ran and could not produce an
        # applicable patch (LLM down, unappliable output): not "not tried".
        return PATCH_FAILED if (state.get("attempts") or 0) > 0 else NOT_ATTEMPTED
    verdict = state.get("test_verdict")
    if verdict == "verified" and (state.get("review") or {}).get("approved"):
        return VERIFIED
    if verdict == "error":
        return ERROR
    if not (state.get("review") or {}).get("approved"):
        return REJECTED
    return TEST_FAILED


def build_remediation_section(state: dict) -> dict:
    """Structured, evidence-only remediation record for the report."""
    outcome = classify(state)
    patch = state.get("code_patch") or {}
    review = state.get("review") or {}
    llm = review.get("llm") or {}
    tests = state.get("test_reports") or {}
    pr = state.get("pr") or {}
    if not pr:
        pr = {"requested": bool(state.get("create_pr")),
              "status": "not_requested" if not state.get("create_pr")
              else "not_reached",
              "url": state.get("pr_url"),
              "reason": _pr_not_reached_reason(state, outcome)}
    regressions = sorted(
        set((tests.get("baseline") or {}).get("passed_names", []))
        - set((tests.get("after") or {}).get("passed_names", []))) \
        if tests.get("after") else []
    return {
        "status": state.get("remediation_status", "skipped"),
        "outcome": outcome,
        "verified": outcome == VERIFIED,
        "applied_to_repository": pr.get("status") == "created",
        "target_vuln": state.get("target_vuln"),
        "attempts": state.get("attempts", 0) or 0,
        "max_attempts": _max_attempts(),
        "patch": ({
            "rationale": patch.get("rationale", ""),
            "diff": patch.get("diff", ""),
            "files_changed": patch.get("files_changed", []),
            "test_file": patch.get("test_file", ""),
            "lines_added": patch.get("lines_added", 0),
            "lines_removed": patch.get("lines_removed", 0),
        } if patch else None),
        "review": ({
            "approved": bool(review.get("approved")),
            "checks": review.get("checks", []),
            "llm_summary": llm.get("summary", ""),
            "llm_issues": llm.get("issues", []),
            "root_cause_fixed": llm.get("root_cause_fixed"),
            "security_score": llm.get("security_score"),
            "feedback_for_coder": review.get("feedback_for_coder", []),
        } if review else None),
        "test_verdict": state.get("test_verdict"),
        "tests": {phase: _phase_summary(tests[phase])
                  for phase in _PHASES if isinstance(tests.get(phase), dict)},
        "regressions": regressions,
        "last_feedback": list(state.get("feedback") or [])[-3:],
        "pr": pr,
        "pr_url": pr.get("url") or state.get("pr_url"),
        "artifacts": _artifact_names(state.get("scan_id", "")),
    }


def _max_attempts() -> int:
    from .fix_queue import max_fix_attempts
    return max_fix_attempts()


def artifact_path(scan_id: str, name: str) -> str | None:
    """Resolve runs/<scan_id>/<name> safely (no traversal, files only)."""
    from tools.run_artifacts import _BASE
    if (not name or name != os.path.basename(name) or name.startswith(".")
            or any(c in scan_id for c in "/\\.:") or not scan_id):
        return None
    candidate = (_BASE / scan_id / name).resolve()
    base = (_BASE / scan_id).resolve()
    if candidate.parent != base or not candidate.is_file():
        return None
    return str(candidate)
