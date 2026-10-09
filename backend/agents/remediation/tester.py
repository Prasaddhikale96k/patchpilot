"""Tester node (prompt 04b): Docker red-green verification.

Baseline (pristine, full suite — run ONCE per scan) → exploit_before
(pristine + only the new exploit test, must FAIL) → after (patched work
copy, full suite, must PASS with zero regressions). Verdicts feed the
retry loop: failed + attempts left → secure_coder with feedback.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess  # nosec B404 - argument list only, never shell=True
import tempfile

logger = logging.getLogger(__name__)

_COPY_IGNORE = shutil.ignore_patterns(
    ".git", "node_modules", ".venv", "__pycache__", ".pytest_cache")


def decide_verdict(baseline: dict, exploit_before: dict,
                   after: dict | None) -> tuple[str, str, list[str]]:
    """Pure verdict logic. Returns (test_verdict, feedback, regressions)."""
    for report, label in ((baseline, "baseline"),
                          (exploit_before, "exploit_before")):
        if (report or {}).get("timed_out"):
            return ("error", f"{label} phase timed out "
                             f"(SANDBOX_TIMEOUT_SECS exceeded).", [])
    reproduced = ((exploit_before.get("failed", 0) or 0)
                  + (exploit_before.get("errors", 0) or 0)) > 0
    if not reproduced:
        return ("failed",
                "Your exploit test does not reproduce the vulnerability on "
                "the original code. Rewrite it so it FAILS on the vulnerable "
                "code.", [])
    if after is None:
        return ("failed",
                "Your exploit test does not reproduce the vulnerability on "
                "the original code. Rewrite it so it FAILS on the vulnerable "
                "code.", [])
    if after.get("timed_out"):
        return ("error", "after phase timed out "
                         "(SANDBOX_TIMEOUT_SECS exceeded).", [])
    regressions = sorted(set(baseline.get("passed_names", []))
                         - set(after.get("passed_names", [])))
    failing = [f["name"] for f in after.get("failed_tests", [])]
    after_bad = (after.get("returncode", 0) != 0
                 or (after.get("failed", 0) or 0) > 0
                 or (after.get("errors", 0) or 0) > 0)
    if after_bad:
        detail = "; ".join(failing) or "no passing tests recorded"
        tail = after.get("output_tail", "")
        return ("failed",
                f"After patch: failing tests: {detail}\nLast output:\n{tail}",
                regressions)
    if regressions:
        return ("failed",
                f"After patch: {len(regressions)} regression(s): "
                f"{'; '.join(regressions[:10])}", regressions)
    return ("verified", "", [])


def _fresh_copy(src: str, name: str) -> str:
    dest = os.path.join(tempfile.mkdtemp(prefix=f"pp-test-{name}-"), name)
    shutil.copytree(src, dest, ignore=_COPY_IGNORE)
    return dest


def _write_test_file(code_dir: str, test_rel: str, content: str) -> None:
    target = os.path.join(code_dir, test_rel)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="") as handle:
        handle.write(content)


def _read_test_content(work_dir: str, test_rel: str, runs_dir: str) -> str:
    for candidate in (os.path.join(work_dir, test_rel),
                      os.path.join(runs_dir, os.path.basename(test_rel))):
        if os.path.isfile(candidate):
            with open(candidate, "r", encoding="utf-8",
                      errors="replace") as handle:
                return handle.read()
    raise RuntimeError(f"exploit test not found: {test_rel}")


def tester_node(state: dict) -> dict:
    """Run baseline / exploit_before / after and record the verdict."""
    from tools.run_artifacts import artifact_dir, save_text
    from tools.sandbox import prepare_image, resolve_sandbox, run_tests
    scan_id = state.get("scan_id", "x")
    repo_path = state.get("repo_path", "")
    work_dir = state.get("work_dir", "")
    code_patch = state.get("code_patch") or {}
    test_rel = code_patch.get("test_file", "")
    logs: list[str] = []

    if not repo_path or not os.path.isdir(repo_path):
        return {"test_verdict": "error",
                "agent_logs": ["[Tester] No repo clone available."]}
    if not work_dir or not os.path.isdir(work_dir) or not test_rel:
        return {"test_verdict": "error",
                "agent_logs": ["[Tester] No patched work copy available."]}

    engine = resolve_sandbox()
    try:
        tag = prepare_image(repo_path) if engine == "docker" else None
    except Exception as exc:
        return {"test_verdict": "error",
                "agent_logs": [f"[Tester] Sandbox image failed: {exc}"]}
    if engine == "docker":
        try:
            proc = subprocess.run(  # nosec B603
                ["docker", "image", "inspect", tag],
                capture_output=True, timeout=30)
            _reused = proc.returncode == 0  # just built or pre-existing
        except Exception:
            _reused = False
        logs.append(f"[Tester] Sandbox: docker (image {tag}, "
                    f"{'reused' if _reused else 'built'})")
    else:
        logs.append("[Tester] Sandbox: venv (Docker unavailable)")

    try:
        test_content = _read_test_content(
            work_dir, test_rel, str(artifact_dir(scan_id)))
    except RuntimeError as exc:
        return {"test_verdict": "error",
                "agent_logs": logs + [f"[Tester] {exc}"]}

    reports = dict(state.get("test_reports") or {})

    # Baseline runs ONLY ONCE per scan, even across retries.
    if "baseline" in reports:
        baseline = reports["baseline"]
        logs.append(f"[Tester] Baseline: reused "
                    f"({baseline.get('passed', 0)}/{baseline.get('total', 0)} "
                    f"passed)")
    else:
        pristine = _fresh_copy(repo_path, "baseline")
        baseline = run_tests(pristine, "baseline", tag, scan_id=scan_id)
        baseline["work_copy"] = pristine
        reports["baseline"] = baseline
        logs.append(f"[Tester] Baseline: {baseline.get('passed', 0)}/"
                    f"{baseline.get('total', 0)} passed")
    save_text(scan_id, "test_baseline.json", _report_json(baseline))

    exploit_dir = _fresh_copy(repo_path, "exploit_before")
    _write_test_file(exploit_dir, test_rel, test_content)
    exploit_before = run_tests(exploit_dir, "exploit_before", tag,
                               selector=test_rel, scan_id=scan_id)
    reports["exploit_before"] = exploit_before
    save_text(scan_id, "test_exploit_before.json",
              _report_json(exploit_before))
    if (exploit_before.get("failed", 0) or 0) + (
            exploit_before.get("errors", 0) or 0) > 0:
        logs.append("[Tester] Exploit on ORIGINAL: FAILED "
                    "(vulnerability reproduced)")
    else:
        logs.append("[Tester] Exploit on ORIGINAL: PASSED "
                    "(does NOT reproduce - bad test)")

    after = None
    reproduced = ((exploit_before.get("failed", 0) or 0)
                  + (exploit_before.get("errors", 0) or 0)) > 0
    if reproduced:
        after = run_tests(work_dir, "after", tag, scan_id=scan_id)
        reports["after"] = after
        save_text(scan_id, "test_after.json", _report_json(after))
        save_text(scan_id, "test_output_after.txt",
                  after.get("output_tail", ""))
        regressions = sorted(set(baseline.get("passed_names", []))
                             - set(after.get("passed_names", [])))
        logs.append(f"[Tester] After patch: {after.get('passed', 0)}/"
                    f"{after.get('total', 0)} passed, "
                    f"{len(regressions)} regressions"
                    f"{' -> VERIFIED' if after.get('returncode', 1) == 0 and not regressions else ''}")

    verdict, feedback, _ = decide_verdict(baseline, exploit_before, after)
    out = {"test_reports": reports, "test_verdict": verdict,
           "agent_logs": logs}
    if feedback:
        out["feedback"] = [feedback]  # replace, never append
    if verdict == "verified":
        out["remediation_status"] = "running"
    elif verdict == "failed":
        out["remediation_status"] = "running"
    else:
        out["remediation_status"] = "failed"
    return out


def _report_json(report: dict) -> str:
    import json as _json
    slim = {k: v for k, v in report.items() if k != "work_copy"}
    return _json.dumps(slim, indent=2)
