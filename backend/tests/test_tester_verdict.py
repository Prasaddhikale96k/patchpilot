"""Tests for the tester verdict logic (prompt 04b) with fake reports."""

from __future__ import annotations

from agents.remediation.tester import decide_verdict


def _report(passed_names=(), failed_names=(), returncode=0, timed_out=False,
            tail="output tail"):
    return {
        "passed": len(passed_names),
        "failed": len(failed_names),
        "errors": 0,
        "total": len(passed_names) + len(failed_names),
        "passed_names": list(passed_names),
        "failed_tests": [{"name": n, "message": "boom"} for n in failed_names],
        "output_tail": tail,
        "returncode": returncode,
        "timed_out": timed_out,
    }


class TestDecideVerdict:
    def test_verified_red_to_green(self):
        baseline = _report(passed_names=["t::a", "t::b"])
        before = _report(failed_names=["t::exploit"], returncode=1)
        after = _report(passed_names=["t::a", "t::b", "t::exploit"])
        verdict, feedback, regressions = decide_verdict(baseline, before, after)
        assert verdict == "verified"
        assert feedback == "" and regressions == []

    def test_exploit_not_reproducing(self):
        baseline = _report(passed_names=["t::a"])
        before = _report(passed_names=["t::a", "t::exploit"])  # passes: useless
        verdict, feedback, _ = decide_verdict(baseline, before, None)
        assert verdict == "failed"
        assert "does not reproduce" in feedback

    def test_after_failure_names_tests(self):
        baseline = _report(passed_names=["t::a"])
        before = _report(failed_names=["t::exploit"], returncode=1)
        after = _report(passed_names=["t::a"], failed_names=["t::exploit"],
                        returncode=1)
        verdict, feedback, _ = decide_verdict(baseline, before, after)
        assert verdict == "failed"
        assert "t::exploit" in feedback

    def test_regression_detected(self):
        baseline = _report(passed_names=["t::a", "t::b"])
        before = _report(failed_names=["t::exploit"], returncode=1)
        after = _report(passed_names=["t::b", "t::exploit"])  # t::a regressed
        verdict, feedback, regressions = decide_verdict(baseline, before, after)
        assert verdict == "failed"
        assert regressions == ["t::a"]
        assert "t::a" in feedback

    def test_timeout_is_error(self):
        baseline = _report(passed_names=["t::a"])
        before = _report(failed_names=["t::exploit"], returncode=1)
        after = _report(timed_out=True)
        verdict, feedback, _ = decide_verdict(baseline, before, after)
        assert verdict == "error"
        assert "timed out" in feedback
