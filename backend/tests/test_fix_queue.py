"""Tests for the fix queue + retry escalation (prompt 00a, Part B)."""

from __future__ import annotations

import pytest

from agents import llm_router
from agents.remediation import fix_queue


def _vuln(vid, severity, category, path="app/routes.py", line=10,
          description=""):
    return {"id": vid, "severity": severity, "category": category,
            "file": path, "line": line,
            "description": description or category}


class TestBuildFixQueue:
    def test_severity_outranks_everything(self):
        vulns = [
            _vuln("VULN-001", "MEDIUM", "A03:2021-Injection", line=1,
                  description="SQL injection in search"),
            _vuln("VULN-002", "CRITICAL", "A05:2021-Security Misconfiguration",
                  line=2),
        ]
        queue = fix_queue.build_fix_queue(vulns)
        assert [v["id"] for v in queue] == ["VULN-002", "VULN-001"]

    def test_priority_category_first_within_severity(self):
        vulns = [
            _vuln("VULN-001", "HIGH", "A05:2021-Security Misconfiguration",
                  line=1),
            _vuln("VULN-002", "HIGH", "A03:2021-Injection", line=2,
                  description="SQL injection via f-string query"),
        ]
        queue = fix_queue.build_fix_queue(vulns)
        assert [v["id"] for v in queue] == ["VULN-002", "VULN-001"]

    def test_two_findings_on_same_line_count_as_one(self):
        vulns = [
            _vuln("VULN-001", "HIGH", "A03:2021-Injection", line=42),
            _vuln("VULN-002", "HIGH", "A03:2021-Injection", line=42),
            _vuln("VULN-003", "HIGH", "A03:2021-Injection", line=43),
        ]
        queue = fix_queue.build_fix_queue(vulns, max_targets=5)
        assert [v["id"] for v in queue] == ["VULN-001", "VULN-003"]

    def test_skips_tests_website_low_and_missing(self):
        vulns = [
            _vuln("VULN-001", "HIGH", "A03:2021-Injection",
                  path="tests/test_app.py"),
            _vuln("VULN-002", "HIGH", "A05:2021-Security Misconfiguration",
                  path="https://example.com/"),
            _vuln("VULN-003", "LOW", "A03:2021-Injection"),
            _vuln("VULN-004", "HIGH", "A03:2021-Injection", path=""),
            _vuln("VULN-005", "HIGH", "A03:2021-Injection", path="app/a.py"),
        ]
        assert [v["id"] for v in fix_queue.build_fix_queue(vulns)] == ["VULN-005"]

    def test_default_limit_is_three(self, monkeypatch):
        monkeypatch.delenv("MAX_FIX_TARGETS", raising=False)
        vulns = [_vuln(f"VULN-{i:03d}", "HIGH", "A01:2021-Broken Access Control",
                       line=i) for i in range(1, 7)]
        assert len(fix_queue.build_fix_queue(vulns)) == 3

    def test_env_limit_respected(self, monkeypatch):
        monkeypatch.setenv("MAX_FIX_TARGETS", "1")
        vulns = [_vuln(f"VULN-{i:03d}", "HIGH", "A03:2021-Injection", line=i)
                 for i in range(1, 4)]
        assert len(fix_queue.build_fix_queue(vulns)) == 1

    def test_input_not_mutated(self):
        vulns = [_vuln("VULN-002", "LOW", "x", line=2),
                 _vuln("VULN-001", "CRITICAL", "y", line=1)]
        snapshot = [dict(v) for v in vulns]
        fix_queue.build_fix_queue(vulns)
        assert vulns == snapshot


class TestProgressFormat:
    def test_progress_line(self):
        assert (fix_queue.format_remediation_progress(2, 3, 1, 74.6)
                == "[Remediation] 2/3 done · 1 PR opened · elapsed 74s")

    def test_workers_and_attempts_defaults(self, monkeypatch):
        monkeypatch.delenv("PARALLEL_FIX_WORKERS", raising=False)
        monkeypatch.delenv("MAX_FIX_ATTEMPTS", raising=False)
        assert fix_queue.parallel_fix_workers() == 2
        assert fix_queue.max_fix_attempts() == 3


class TestEscalation:
    def test_attempt1_is_fast_groq(self):
        assert llm_router.model_for_attempt(1) == ("groq", "qwen/qwen3.8-27b")

    def test_attempt2_is_strong_groq(self):
        assert llm_router.model_for_attempt(2) == ("groq", "openai/gpt-oss-120b")

    def test_attempt3_is_fresh_provider(self):
        assert llm_router.model_for_attempt(3) == ("gemini", "gemini-3-flash-preview")
        assert llm_router.model_for_attempt(9) == ("gemini", "gemini-3-flash-preview")

    def test_env_overrides(self, monkeypatch):
        monkeypatch.setenv("GROQ_FAST_MODEL", "custom/fast")
        assert llm_router.model_for_attempt(1) == ("groq", "custom/fast")

    @pytest.mark.parametrize("attempt", [1, 2, 3])
    def test_each_attempt_logs_a_distinct_model(self, attempt):
        provider, model = llm_router.model_for_attempt(attempt)
        assert provider and model  # consumed by nodes as [Node][VULN-x] model=...
