"""Tests for tester graph routing (prompt 04b)."""

from __future__ import annotations

import agents.orchestrator as orchestrator


def _state(**overrides):
    base = {"test_verdict": None, "attempts": 1, "create_pr": True,
            "tech_stack": {"languages": ["python"]}, "vulnerabilities": []}
    base.update(overrides)
    return base


class TestRouteAfterTester:
    def test_verified_goes_to_pr_creator(self):
        assert orchestrator._route_after_tester(
            _state(test_verdict="verified")) == "pr_creator"

    def test_failed_with_attempts_left_retries_coder(self, monkeypatch):
        monkeypatch.setenv("MAX_FIX_ATTEMPTS", "3")
        assert orchestrator._route_after_tester(
            _state(test_verdict="failed", attempts=1)) == "secure_coder"

    def test_failed_at_max_attempts_goes_to_report(self, monkeypatch):
        monkeypatch.setenv("MAX_FIX_ATTEMPTS", "3")
        assert orchestrator._route_after_tester(
            _state(test_verdict="failed", attempts=3)) == "report_generator"

    def test_error_with_attempts_left_retries_coder(self, monkeypatch):
        monkeypatch.setenv("MAX_FIX_ATTEMPTS", "3")
        assert orchestrator._route_after_tester(
            _state(test_verdict="error", attempts=2)) == "secure_coder"

    def test_graph_has_new_nodes(self):
        nodes = set(orchestrator._graph.nodes.keys())
        assert {"tester", "pr_creator"} <= nodes
