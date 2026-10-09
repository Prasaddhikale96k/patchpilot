"""Tests for FAST_SCAN shortlisting (pinned cheap model, max 5 vulns)."""

from __future__ import annotations

import agents.orchestrator as orchestrator
from agents.orchestrator import _fast_model_kw, _fast_scan_targets


def _vuln(vid, severity, category="A03:2021-Injection", description="x"):
    return {"id": vid, "file": "a.py", "line": 1, "severity": severity,
            "category": category, "description": description}


class TestFastScanTargets:
    def _seven(self):
        return [_vuln(f"VULN-{i:03d}", sev)
                for i, sev in enumerate(
                    ["LOW", "MEDIUM", "HIGH", "CRITICAL", "HIGH", "MEDIUM",
                     "LOW"], start=1)]

    def test_no_hint_means_inactive(self, monkeypatch):
        monkeypatch.setenv("FAST_SCAN", "1")
        assert _fast_scan_targets(self._seven(), None) is None
        assert _fast_scan_targets(self._seven(), "") is None

    def test_env_off_means_inactive(self, monkeypatch):
        monkeypatch.setenv("FAST_SCAN", "0")
        assert _fast_scan_targets(self._seven(), "CWE-89") is None

    def test_max_five_hint_first_then_severity(self, monkeypatch):
        monkeypatch.setenv("FAST_SCAN", "1")
        vulns = [
            _vuln("VULN-001", "LOW", "A05:2021-Security Misconfiguration",
                  "missing header"),
            _vuln("VULN-002", "MEDIUM", "A05:2021-Security Misconfiguration",
                  "missing header"),
            _vuln("VULN-003", "HIGH", "A05:2021-Security Misconfiguration",
                  "missing header"),
            _vuln("VULN-004", "CRITICAL",
                  "A05:2021-Security Misconfiguration", "missing header"),
            _vuln("VULN-005", "HIGH", "A05:2021-Security Misconfiguration",
                  "missing header"),
            _vuln("VULN-006", "MEDIUM", "A03:2021-Injection",
                  "SQL string via CWE-89"),
            _vuln("VULN-007", "LOW", "A05:2021-Security Misconfiguration",
                  "missing header"),
        ]
        shortlist = _fast_scan_targets(vulns, "CWE-89")
        assert shortlist is not None and len(shortlist) == 5
        assert shortlist[0]["id"] == "VULN-006"  # hint match first
        assert shortlist[1]["id"] == "VULN-004"  # then CRITICAL

    def test_model_kw(self, monkeypatch):
        monkeypatch.setenv("FAST_SCAN", "1")
        shortlist = _fast_scan_targets(self._seven(), "CWE-89")
        assert _fast_model_kw(shortlist) == {"model": "groq:openai/gpt-oss-20b"}
        assert _fast_model_kw(None) == {}

    def test_default_on_without_env(self, monkeypatch):
        monkeypatch.delenv("FAST_SCAN", raising=False)
        assert _fast_scan_targets(self._seven(), "CWE-89") is not None
