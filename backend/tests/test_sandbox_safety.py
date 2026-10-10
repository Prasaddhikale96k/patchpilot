"""Sandbox isolation + tester verdict semantics (no Docker needed).

Pins: no silent fallback to running untrusted tests on the host, a
stopped daemon is detected, the container is locked down, and a test
phase that never ran can never become a passing verification.
"""

from __future__ import annotations

import subprocess

import pytest

from agents import orchestrator
from agents.remediation import tester
from agents.remediation.report import build_remediation_section, classify
from tools import sandbox


@pytest.fixture(autouse=True)
def _reset_probe(monkeypatch):
    monkeypatch.setattr(sandbox, "_DOCKER_OK", None)
    monkeypatch.setattr(sandbox, "_DOCKER_PROBED_AT", 0.0)


class TestEngineResolution:
    def test_stopped_daemon_is_not_available(self, monkeypatch):
        monkeypatch.setattr(subprocess, "run", lambda *a, **k:
                            subprocess.CompletedProcess(a, 1, "", "daemon down"))
        assert sandbox.docker_available() is False

    def test_running_daemon_is_available(self, monkeypatch):
        monkeypatch.setattr(subprocess, "run", lambda *a, **k:
                            subprocess.CompletedProcess(a, 0, "27.1.1\n", ""))
        assert sandbox.docker_available() is True

    @pytest.mark.parametrize("mode", ["auto", "docker", ""])
    def test_no_silent_host_fallback(self, monkeypatch, mode):
        monkeypatch.setenv("SANDBOX", mode)
        monkeypatch.setattr(sandbox, "docker_available", lambda: False)
        with pytest.raises(sandbox.SandboxUnavailable):
            sandbox.resolve_sandbox()

    def test_venv_only_on_explicit_opt_in(self, monkeypatch):
        monkeypatch.setenv("SANDBOX", "venv")
        assert sandbox.resolve_sandbox() == "venv"


class TestContainerHardening:
    def test_run_args_are_locked_down(self):
        args = sandbox.docker_run_args("/code", "/out", "pp-deps-x", "pp-n")
        joined = " ".join(args)
        for flag in ("--network none", "--cap-drop ALL",
                     "--security-opt no-new-privileges", "--read-only",
                     "--pids-limit 256", "--memory 1g"):
            assert flag in joined
        user = args[args.index("--user") + 1]
        assert not user.startswith("0:") and user != "root"
        assert any(a.endswith(":/app") for a in args)
        assert "--privileged" not in args
        assert "docker.sock" not in joined

    def test_docker_infra_exit_code_flags_report(self, monkeypatch, tmp_path):
        monkeypatch.setattr(subprocess, "run", lambda *a, **k:
                            subprocess.CompletedProcess(a, 125, "", "no such image"))
        report = sandbox._run_tests_docker(str(tmp_path), "baseline", "tag",
                                           None, "s1", 30)
        assert report["infra_error"] and "125" in report["infra_error"]


def _rep(passed=(), failed=(), errors=0, **extra):
    rep = {"passed": len(passed), "failed": len(failed), "errors": errors,
           "total": len(passed) + len(failed) + errors,
           "passed_names": list(passed),
           "failed_tests": [{"name": n} for n in failed],
           "returncode": 1 if failed or errors else 0, "timed_out": False,
           "output_tail": "tail"}
    rep.update(extra)
    return rep


class TestStricterVerdicts:
    def test_collection_error_is_not_a_reproduction(self):
        verdict, feedback, _ = tester.decide_verdict(
            _rep(["t::a"]), _rep(errors=1), None)
        assert verdict == "failed"
        assert "errors out" in feedback

    def test_red_baseline_cannot_verify(self):
        verdict, feedback, _ = tester.decide_verdict(
            _rep(["t::a"], failed=["t::b"]), _rep(failed=["x::exploit"]),
            _rep(["t::a", "x::exploit"]))
        assert verdict == "error"

    def test_phase_that_never_ran_is_error_not_pass(self):
        verdict, _, _ = tester.decide_verdict(
            _rep(infra_error="docker could not start"),
            _rep(failed=["x::exploit"]), _rep(["t::a"]))
        assert verdict == "error"

    def test_after_infra_error_is_error(self):
        verdict, _, _ = tester.decide_verdict(
            _rep(["t::a"]), _rep(failed=["x::e"]),
            _rep(infra_error="pytest could not run (exit 4)"))
        assert verdict == "error"

    def test_exploit_test_must_run_after_patch(self):
        verdict, feedback, _ = tester.decide_verdict(
            _rep(["tests.test_a::test_a"]),
            _rep(failed=["tests.test_patchforge_cwe89::test_exploit"]),
            _rep(["tests.test_a::test_a"]),
            exploit_test="tests/test_patchforge_cwe89.py")
        assert verdict == "failed" and "did not run" in feedback

    def test_full_red_green_verifies(self):
        verdict, _, _ = tester.decide_verdict(
            _rep(["tests.test_a::test_a"]),
            _rep(failed=["tests.test_patchforge_cwe89::test_exploit"]),
            _rep(["tests.test_a::test_a",
                  "tests.test_patchforge_cwe89::test_exploit"]),
            exploit_test="tests/test_patchforge_cwe89.py")
        assert verdict == "verified"

    def test_tester_node_without_docker_reports_error(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SANDBOX", "auto")
        monkeypatch.setattr(sandbox, "docker_available", lambda: False)
        (tmp_path / "repo").mkdir()
        (tmp_path / "work").mkdir()
        out = tester.tester_node({
            "scan_id": "s1", "repo_path": str(tmp_path / "repo"),
            "work_dir": str(tmp_path / "work"),
            "code_patch": {"test_file": "tests/test_x.py"}})
        assert out["test_verdict"] == "error"
        assert any("Sandbox unavailable" in l for l in out["agent_logs"])


class TestRouting:
    def test_coder_failure_ends_remediation(self):
        assert orchestrator._route_after_secure_coder(
            {"remediation_status": "failed", "attempts": 0}) == "report_generator"

    def test_coder_patch_apply_failure_retries_within_budget(self, monkeypatch):
        monkeypatch.setenv("MAX_FIX_ATTEMPTS", "3")
        assert orchestrator._route_after_secure_coder(
            {"remediation_status": "failed", "attempts": 1,
             "feedback": ["Patch apply failed: TEST section: no blocks. Fix it."],
             "code_patch": {"diff": "old"}}) == "secure_coder"

    def test_coder_patch_apply_failure_at_max_ends_remediation(self, monkeypatch):
        monkeypatch.setenv("MAX_FIX_ATTEMPTS", "3")
        assert orchestrator._route_after_secure_coder(
            {"remediation_status": "failed", "attempts": 3,
             "feedback": ["Patch apply failed: TEST section: no blocks. Fix it."],
             "code_patch": {"diff": "old"}}) == "report_generator"

    def test_coder_llm_failure_does_not_retry(self, monkeypatch):
        """No retriable marker (LLM down, no clone, no target): a fresh LLM
        call cannot fix it, so the loop ends even with budget left."""
        monkeypatch.setenv("MAX_FIX_ATTEMPTS", "3")
        assert orchestrator._route_after_secure_coder(
            {"remediation_status": "failed", "attempts": 1,
             "feedback": []}) == "report_generator"

    def test_coder_success_goes_to_reviewer(self):
        assert orchestrator._route_after_secure_coder(
            {"remediation_status": "running",
             "code_patch": {"diff": "x"}}) == "reviewer"

    def test_tester_infra_error_does_not_retry_llm(self, monkeypatch):
        monkeypatch.setenv("MAX_FIX_ATTEMPTS", "3")
        assert orchestrator._route_after_tester(
            {"test_verdict": "error", "attempts": 1}) == "report_generator"

    def test_graph_uses_conditional_coder_edge(self):
        graph = orchestrator._graph.get_graph()
        targets = {e.target for e in graph.edges if e.source == "secure_coder"}
        assert targets == {"reviewer", "secure_coder", "report_generator"}


class TestRemediationSection:
    def test_not_requested(self):
        sec = build_remediation_section({"create_pr": False, "scan_id": "x"})
        assert sec["outcome"] == "not_requested"
        assert sec["verified"] is False
        assert sec["applied_to_repository"] is False

    def test_verified_requires_review_and_tests(self):
        base = {"create_pr": True, "code_patch": {"diff": "d"},
                "test_verdict": "verified"}
        assert classify({**base, "review": {"approved": True}}) == "verified"
        assert classify({**base, "review": {"approved": False}}) != "verified"

    def test_patch_failed_vs_not_attempted(self):
        assert classify({"create_pr": True, "attempts": 1}) == "patch_failed"
        assert classify({"create_pr": True, "attempts": 0}) == "not_attempted"

    def test_regressions_and_pr_recorded(self):
        sec = build_remediation_section({
            "create_pr": True, "scan_id": "x", "code_patch": {"diff": "d"},
            "review": {"approved": True}, "test_verdict": "verified",
            "test_reports": {"baseline": {"passed_names": ["a", "b"]},
                             "after": {"passed_names": ["a"]}},
            "pr": {"status": "created", "url": "https://github.com/o/r/pull/1"}})
        assert sec["regressions"] == ["b"]
        assert sec["applied_to_repository"] is True
        assert sec["pr_url"] == "https://github.com/o/r/pull/1"


class TestJunitParsingIsDefensive:
    def test_entity_bomb_is_refused_not_expanded(self, tmp_path):
        bomb = tmp_path / "junit.xml"
        bomb.write_text('<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa">'
                        '<!ENTITY b "&a;&a;&a;&a;">]><testsuite tests="1">'
                        '<testcase name="&b;"/></testsuite>')
        rep = sandbox.parse_junit(str(bomb), "after", "1 passed", 1.0, "docker")
        # falls back to the summary line instead of trusting the XML
        assert rep["passed"] == 1 and rep["passed_names"] == []

    def test_normal_junit_still_parses(self, tmp_path):
        xml = tmp_path / "junit.xml"
        xml.write_text('<testsuites><testsuite tests="2" failures="1" errors="0" '
                       'skipped="0" time="0.1"><testcase classname="t" name="ok"/>'
                       '<testcase classname="t" name="bad"><failure message="x"/>'
                       '</testcase></testsuite></testsuites>')
        rep = sandbox.parse_junit(str(xml), "after", "", 1.0, "docker")
        assert rep["passed"] == 1 and rep["failed"] == 1
        assert rep["passed_names"] == ["t::ok"]
