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

    def test_error_with_attempts_left_ends_at_report(self, monkeypatch):
        """Changed contract: "error" means the sandbox produced no usable
        evidence (Docker down, timeout, red baseline). A new LLM patch
        cannot fix that, so it no longer burns a paid coder retry."""
        monkeypatch.setenv("MAX_FIX_ATTEMPTS", "3")
        assert orchestrator._route_after_tester(
            _state(test_verdict="error", attempts=2)) == "report_generator"

    def test_graph_has_new_nodes(self):
        nodes = set(orchestrator._graph.nodes.keys())
        assert {"tester", "pr_creator"} <= nodes


def _review_state(**overrides):
    base = {"review": None, "attempts": 1}
    base.update(overrides)
    return base


class TestRouteAfterReviewer:
    def test_approved_goes_to_tester(self):
        assert orchestrator._route_after_reviewer(
            _review_state(review={"approved": True})) == "tester"

    def test_rejected_with_attempts_left_retries_coder(self, monkeypatch):
        monkeypatch.setenv("MAX_FIX_ATTEMPTS", "3")
        assert orchestrator._route_after_reviewer(
            _review_state(review={"approved": False},
                          attempts=1)) == "secure_coder"

    def test_rejected_at_max_attempts_goes_to_report(self, monkeypatch):
        monkeypatch.setenv("MAX_FIX_ATTEMPTS", "3")
        assert orchestrator._route_after_reviewer(
            _review_state(review={"approved": False},
                          attempts=3)) == "report_generator"

    def test_missing_review_retries_coder(self, monkeypatch):
        monkeypatch.setenv("MAX_FIX_ATTEMPTS", "3")
        assert orchestrator._route_after_reviewer(
            _review_state(review=None, attempts=0)) == "secure_coder"

    def test_graph_has_reviewer_node(self):
        assert "reviewer" in set(orchestrator._graph.nodes.keys())
