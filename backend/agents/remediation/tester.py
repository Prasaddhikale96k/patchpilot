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


def _test_module(test_rel: str) -> str:
    """tests/test_x.py → tests.test_x (pytest junit classname prefix)."""
    return test_rel.replace("\\", "/").removesuffix(".py").replace("/", ".")


def exploit_reproduced(exploit_before: dict) -> bool:
    """The exploit test ran and FAILED an assertion on the original code.

    Only failures count. A junit *error* is a collection/fixture/import
    problem — a broken test, not a demonstrated vulnerability — and used
    to be accepted as reproduction.
    """
    return (exploit_before.get("failed", 0) or 0) > 0


def decide_verdict(baseline: dict, exploit_before: dict,
                   after: dict | None,
                   exploit_test: str | None = None) -> tuple[str, str, list[str]]:
    """Pure verdict logic. Returns (test_verdict, feedback, regressions).

    error    = the evidence is unusable (timeout, sandbox failure, red
               baseline): not the patch's fault, no LLM retry.
    failed   = the patch or its exploit test is wrong: retry with feedback.
    verified = exploit failed on original, whole suite (incl. exploit
               test) passes after, zero regressions.
    """
    for report, label in ((baseline, "baseline"),
                          (exploit_before, "exploit_before")):
        if (report or {}).get("timed_out"):
            return ("error", f"{label} phase timed out "
                             f"(SANDBOX_TIMEOUT_SECS exceeded).", [])
        if (report or {}).get("infra_error"):
            return ("error", f"{label} phase did not run: "
                             f"{report['infra_error']}", [])
    if (baseline.get("failed", 0) or 0) + (baseline.get("errors", 0) or 0) > 0:
        return ("error", "The repository's own test suite already fails on "
                         "the original code, so a fix cannot be verified "
                         "against it.", [])
    reproduced = exploit_reproduced(exploit_before)
    if not reproduced and (exploit_before.get("errors", 0) or 0) > 0:
        return ("failed",
                "Your exploit test errors out (import/fixture/collection "
                "error) instead of failing an assertion. Fix the test so it "
                "runs and FAILS on the vulnerable code:\n"
                f"{exploit_before.get('output_tail', '')[-1500:]}", [])
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
    if after.get("infra_error"):
        return ("error", f"after phase did not run: {after['infra_error']}", [])
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
    if exploit_test:
        module = _test_module(exploit_test)
        if not any(name.startswith(module) or f"{module}::" in name
                   or module.rsplit(".", 1)[-1] in name
                   for name in after.get("passed_names", [])):
            return ("failed", "After patch: the exploit test did not run "
                              "(no passing result recorded for it).", [])
    return ("verified", "", [])


def _fresh_copy(src: str, name: str) -> str:
    dest = os.path.join(tempfile.mkdtemp(prefix=f"pp-test-{name}-"), name)
    shutil.copytree(src, dest, ignore=_COPY_IGNORE)
    return dest


def _cached_baseline(state: dict, repo_path: str) -> dict | None:
    """Baseline run speculatively during the scan (or cached for this
    commit), waiting for an in-flight run. None means: run it here."""
    try:
        from agents.remediation import baseline as _baseline
        return _baseline.get(state.get("repo_url", ""), repo_path)
    except Exception:
        return None


def _write_test_file(code_dir: str, test_rel: str, content: str) -> None:
    # test_rel comes from model output: enforce the repo boundary here too,
    # not only where the patch was first applied.
    from tools.patch_apply import _resolve
    target = _resolve(code_dir, test_rel)
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

    from tools.sandbox import SandboxUnavailable
    try:
        engine = resolve_sandbox()
    except SandboxUnavailable as exc:
        logger.error("tester: %s", exc)
        return {"test_verdict": "error", "remediation_status": "failed",
                "feedback": [str(exc)],
                "agent_logs": [f"[Tester] 🐳 Sandbox unavailable — {exc}"]}
    try:
        tag = prepare_image(repo_path) if engine == "docker" else None
    except Exception as exc:
        logger.error("tester: sandbox image build failed: %s", exc)
        return {"test_verdict": "error", "remediation_status": "failed",
                "agent_logs": [f"[Tester] Sandbox image failed: "
                               f"{str(exc)[-500:]}"]}
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
    def _phase(code_dir: str, phase: str, selector: str | None = None,
               discard: bool = True) -> dict:
        """Run one phase; an exception becomes an infra_error report
        (verdict "error"), and temp copies are always removed."""
        try:
            return run_tests(code_dir, phase, tag, selector=selector,
                             scan_id=scan_id)
        except Exception as exc:  # sandbox died mid-run, image vanished, …
            logger.exception("tester: %s phase crashed (scan %s)", phase, scan_id)
            return {"phase": phase, "total": 0, "passed": 0, "failed": 0,
                    "errors": 0, "skipped": 0, "passed_names": [],
                    "failed_tests": [], "output_tail": "", "timed_out": False,
                    "returncode": None, "sandbox": engine,
                    "infra_error": f"{type(exc).__name__}: {str(exc)[-300:]}"}
        finally:
            if discard:
                shutil.rmtree(os.path.dirname(code_dir), ignore_errors=True)

    if "baseline" in reports:
        baseline = reports["baseline"]
        logs.append(f"[Tester] Baseline: reused "
                    f"({baseline.get('passed', 0)}/{baseline.get('total', 0)} "
                    f"passed)")
    elif _cached_baseline(state, repo_path) is not None:
        baseline = _cached_baseline(state, repo_path)
        reports["baseline"] = baseline
        logs.append(f"[Tester] Baseline: cached for this commit "
                    f"({baseline.get('passed', 0)}/{baseline.get('total', 0)} "
                    f"passed)")
    else:
        baseline = _phase(_fresh_copy(repo_path, "baseline"), "baseline")
        reports["baseline"] = baseline
        logs.append(f"[Tester] Baseline: {baseline.get('passed', 0)}/"
                    f"{baseline.get('total', 0)} passed"
                    + (f" — did not run: {baseline['infra_error']}"
                       if baseline.get("infra_error") else ""))
    save_text(scan_id, "test_baseline.json", _report_json(baseline))

    exploit_dir = _fresh_copy(repo_path, "exploit_before")
    _write_test_file(exploit_dir, test_rel, test_content)
    exploit_before = _phase(exploit_dir, "exploit_before", selector=test_rel)
    reports["exploit_before"] = exploit_before
    save_text(scan_id, "test_exploit_before.json",
              _report_json(exploit_before))
    reproduced = exploit_reproduced(exploit_before)
    if exploit_before.get("infra_error") or exploit_before.get("timed_out"):
        logs.append("[Tester] Exploit on ORIGINAL: did not run "
                    f"({exploit_before.get('infra_error') or 'timed out'})")
    elif reproduced:
        logs.append("[Tester] Exploit on ORIGINAL: FAILED "
                    "(vulnerability reproduced — expected)")
    elif (exploit_before.get("errors", 0) or 0) > 0:
        logs.append("[Tester] Exploit on ORIGINAL: ERRORED "
                    "(broken test, not a reproduction)")
    else:
        logs.append("[Tester] Exploit on ORIGINAL: PASSED "
                    "(does NOT reproduce - bad test)")

    after = None
    baseline_ok = not (baseline.get("infra_error") or baseline.get("timed_out")
                       or (baseline.get("failed", 0) or 0)
                       + (baseline.get("errors", 0) or 0))
    if reproduced and baseline_ok:
        # work_dir belongs to the coder/PR creator: never discard it here.
        after = _phase(work_dir, "after", discard=False)
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

    verdict, feedback, _ = decide_verdict(baseline, exploit_before, after,
                                          exploit_test=test_rel)
    logs.append(f"[Tester] Verdict: {verdict.upper()}"
                + (f" — {feedback.splitlines()[0][:160]}" if feedback else ""))
    logger.info("tester: scan=%s verdict=%s", scan_id, verdict)
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
