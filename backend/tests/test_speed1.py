"""SPEED-1: parallel scan phase equals sequential, failure isolation,
timing wrapper, and the speculative baseline cache."""

from __future__ import annotations

import agents.orchestrator as orchestrator
import agents.remediation.baseline as baseline
from agents.remediation import logic_auditor

LA_FINDING = {"source": "llm-audit", "file": "app/routes.py", "line": 52,
              "severity": "HIGH", "category": "A01:2021-Broken Access Control",
              "description": "CWE-639: IDOR", "code": "x"}


def _setup(monkeypatch, tmp_path, parallel: str):
    import tools.bandit_runner as bandit_runner
    import tools.git_cloner as git_cloner
    import tools.semgrep_runner as semgrep_runner

    monkeypatch.setenv("PARALLEL_AGENTS", parallel)
    monkeypatch.setattr(git_cloner, "clone_repo", lambda *a: str(tmp_path))
    monkeypatch.setattr(git_cloner, "detect_tech_stack",
                        lambda p: {"languages": ["python"]})
    monkeypatch.setattr(bandit_runner, "run_bandit", lambda p: [
        {"source": "bandit", "file": "b.py", "line": 1, "severity": "MEDIUM",
         "description": "bandit finding"}])
    monkeypatch.setattr(semgrep_runner, "run_semgrep", lambda p: [
        {"source": "semgrep", "file": "s.py", "line": 2, "severity": "HIGH",
         "description": "semgrep finding"}])
    monkeypatch.setattr(semgrep_runner, "last_mode", "native")
    monkeypatch.setattr(semgrep_runner, "last_pull", False)
    monkeypatch.setattr(logic_auditor, "audit_repo", lambda p: {
        "findings": [dict(LA_FINDING)], "logs": ["[LogicAuditor] Audited 1 routes"]})


def _full_scan(state):
    """scanner node output merged with the logic_auditor node, like the graph."""
    out = orchestrator._scan_github(state)
    merged = {**state, **out}
    la = logic_auditor.logic_auditor_node(merged)
    merged.update(la)
    return merged


class TestParallelEqualsSequential:
    def test_same_findings_in_same_order(self, monkeypatch, tmp_path):
        state = {"repo_url": "https://github.com/a/b", "scan_id": "t",
                 "tech_stack": {}}
        _setup(monkeypatch, tmp_path, "0")
        seq = _full_scan(dict(state))
        _setup(monkeypatch, tmp_path, "1")
        par = _full_scan(dict(state))
        key = lambda fs: [(f["source"], f["file"], f["line"]) for f in fs]  # noqa: E731
        assert key(par["raw_findings"]) == key(seq["raw_findings"])
        assert [f["source"] for f in par["raw_findings"]] == ["bandit", "semgrep", "llm-audit"]

    def test_parallel_stores_the_audit_for_the_node(self, monkeypatch, tmp_path):
        _setup(monkeypatch, tmp_path, "1")
        out = orchestrator._scan_github({"repo_url": "https://github.com/a/b",
                                         "scan_id": "t"})
        assert out["logic_audit"]["findings"][0]["file"] == "app/routes.py"

    def test_sequential_path_does_not_run_extra_agents(self, monkeypatch, tmp_path):
        _setup(monkeypatch, tmp_path, "0")
        out = orchestrator._scan_github({"repo_url": "https://github.com/a/b",
                                         "scan_id": "t"})
        assert "logic_audit" not in out


class TestFailureIsolation:
    def test_logic_audit_crash_keeps_scanner_findings(self, monkeypatch, tmp_path):
        _setup(monkeypatch, tmp_path, "1")

        def boom(path):
            raise RuntimeError("llm exploded")

        monkeypatch.setattr(logic_auditor, "audit_repo", boom)
        out = orchestrator._scan_github({"repo_url": "https://github.com/a/b",
                                         "scan_id": "t"})
        assert [f["source"] for f in out["raw_findings"]] == ["bandit", "semgrep"]
        assert "ERROR" in out["logic_audit"]["logs"][0]

    def test_secrets_scan_crash_keeps_everything_else(self, monkeypatch, tmp_path):
        import tools.secrets_scan as secrets_scan
        _setup(monkeypatch, tmp_path, "1")
        monkeypatch.setattr(secrets_scan, "run_secrets_scan",
                            lambda p: (_ for _ in ()).throw(OSError("disk")))
        out = orchestrator._scan_github({"repo_url": "https://github.com/a/b",
                                         "scan_id": "t"})
        assert [f["source"] for f in out["raw_findings"]] == ["bandit", "semgrep"]
        assert out["status"] == "analyzing"

    def test_secrets_dedup_against_other_scanners(self, monkeypatch, tmp_path):
        import tools.secrets_scan as secrets_scan
        _setup(monkeypatch, tmp_path, "1")
        monkeypatch.setattr(secrets_scan, "run_secrets_scan", lambda p: [
            {"source": "secrets", "file": "b.py", "line": 2, "severity": "ERROR",
             "description": "dup of bandit"},
            {"source": "secrets", "file": "c.py", "line": 9, "severity": "ERROR",
             "description": "new"}])
        out = orchestrator._scan_github({"repo_url": "https://github.com/a/b",
                                         "scan_id": "t"})
        secrets = [f for f in out["raw_findings"] if f["source"] == "secrets"]
        assert [f["file"] for f in secrets] == ["c.py"]


class TestTimingWrapper:
    def test_records_and_accumulates(self, monkeypatch):
        monkeypatch.setattr("tools.run_artifacts.save_text", lambda *a, **k: None)
        node = orchestrator._timed_node("coder", lambda s: {"agent_logs": ["hi"]})
        first = node({"scan_id": "t"})
        assert first["timings"]["coder"] >= 0
        assert first["agent_logs"][0] == "hi"
        assert first["agent_logs"][-1].startswith("[Timing] coder ")
        second = node({"scan_id": "t", "timings": {"coder": 5.0}})
        assert second["timings"]["coder"] >= 5.0


class TestBaselineCache:
    def test_second_start_does_not_rerun(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BASELINE_CACHE_DIR", str(tmp_path / "cache"))
        monkeypatch.setattr(baseline, "_memory", {})
        monkeypatch.setattr(baseline, "_inflight", {})
        monkeypatch.setattr(baseline, "commit_sha", lambda p: "abc123")
        calls = []

        def fake_run(repo_path, scan_id):
            calls.append(scan_id)
            return {"phase": "baseline", "total": 22, "passed": 22, "failed": 0}

        monkeypatch.setattr(baseline, "_run_baseline", fake_run)
        baseline.start("https://github.com/a/b", str(tmp_path), "s1")
        first = baseline.get("https://github.com/a/b", str(tmp_path))
        baseline.start("https://github.com/a/b", str(tmp_path), "s2")
        second = baseline.get("https://github.com/a/b", str(tmp_path))
        assert first == second and first["passed"] == 22
        assert calls == ["s1"]

    def test_different_commit_is_a_miss(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BASELINE_CACHE_DIR", str(tmp_path / "cache"))
        monkeypatch.setattr(baseline, "_memory", {})
        monkeypatch.setattr(baseline, "_inflight", {})
        monkeypatch.setattr(baseline, "_run_baseline",
                            lambda p, s: {"phase": "baseline", "total": 1, "passed": 1})
        monkeypatch.setattr(baseline, "commit_sha", lambda p: "aaa")
        baseline.start("https://github.com/a/b", str(tmp_path), "s1")
        assert baseline.get("https://github.com/a/b", str(tmp_path)) is not None
        monkeypatch.setattr(baseline, "commit_sha", lambda p: "bbb")
        assert baseline.get("https://github.com/a/b", str(tmp_path)) is None

    def test_infra_errors_are_never_cached(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BASELINE_CACHE_DIR", str(tmp_path / "cache"))
        monkeypatch.setattr(baseline, "_memory", {})
        monkeypatch.setattr(baseline, "_inflight", {})
        monkeypatch.setattr(baseline, "commit_sha", lambda p: "abc")
        monkeypatch.setattr(baseline, "_run_baseline",
                            lambda p, s: {"phase": "baseline", "infra_error": "docker died"})
        baseline.start("https://github.com/a/b", str(tmp_path), "s1")
        assert baseline.get("https://github.com/a/b", str(tmp_path)) is None
