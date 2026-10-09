"""Tests for parallel Semgrep+Bandit execution (prompt 00a, Part B)."""

from __future__ import annotations

import time

import agents.orchestrator as orchestrator


class TestParallelScanners:
    def _scan(self, monkeypatch, tmp_path, bandit_sleep=0.3, semgrep_sleep=0.3):
        import tools.git_cloner as git_cloner
        import tools.bandit_runner as bandit_runner
        import tools.semgrep_runner as semgrep_runner

        monkeypatch.setattr(git_cloner, "clone_repo", lambda *a: str(tmp_path))
        monkeypatch.setattr(git_cloner, "detect_tech_stack",
                            lambda p: {"languages": ["python"]})

        def fake_bandit(path):
            time.sleep(bandit_sleep)
            return [{"source": "bandit", "file": "b.py", "line": 1,
                     "severity": "MEDIUM", "description": "bandit finding"}]

        def fake_semgrep(path):
            time.sleep(semgrep_sleep)
            return [{"source": "semgrep", "file": "s.py", "line": 2,
                     "severity": "HIGH", "description": "semgrep finding"}]

        monkeypatch.setattr(bandit_runner, "run_bandit", fake_bandit)
        monkeypatch.setattr(semgrep_runner, "run_semgrep", fake_semgrep)
        monkeypatch.setattr(semgrep_runner, "last_mode", "native")
        monkeypatch.setattr(semgrep_runner, "last_pull", False)
        start = time.perf_counter()
        result = orchestrator._scan_github({"repo_url": "https://github.com/a/b",
                                            "scan_id": "t"})
        return result, time.perf_counter() - start

    def test_findings_identical_and_ordered(self, monkeypatch, tmp_path):
        result, _ = self._scan(monkeypatch, tmp_path, 0, 0)
        files = [(f["source"], f["file"]) for f in result["raw_findings"]]
        assert files == [("bandit", "b.py"), ("semgrep", "s.py")]

    def test_scanners_overlap_in_time(self, monkeypatch, tmp_path):
        """2 × 0.3 s sleeps must finish well under the 0.6 s sequential floor."""
        result, elapsed = self._scan(monkeypatch, tmp_path)
        assert elapsed < 0.55

    def test_each_scanner_time_is_logged(self, monkeypatch, tmp_path):
        result, _ = self._scan(monkeypatch, tmp_path, 0, 0)
        assert any("Bandit: 1 issues (" in line and line.rstrip().endswith("s)")
                   for line in result["agent_logs"])
        assert any("Semgrep (native): 1 issues (" in line
                   and line.rstrip().endswith("s)")
                   for line in result["agent_logs"])

    def test_semgrep_failure_continues_with_bandit(self, monkeypatch, tmp_path):
        """A dead Semgrep must not sink Bandit findings (prompt 01b)."""
        import tools.git_cloner as git_cloner
        import tools.bandit_runner as bandit_runner
        import tools.semgrep_runner as semgrep_runner

        monkeypatch.setattr(git_cloner, "clone_repo", lambda *a: str(tmp_path))
        monkeypatch.setattr(git_cloner, "detect_tech_stack",
                            lambda p: {"languages": ["python"]})
        monkeypatch.setattr(bandit_runner, "run_bandit", lambda p: [
            {"source": "bandit", "file": "b.py", "line": 1,
             "severity": "MEDIUM", "description": "kept"},
        ])

        def boom(path):
            raise RuntimeError("semgrep is not installed or not on PATH")

        monkeypatch.setattr(semgrep_runner, "run_semgrep", boom)
        result = orchestrator._scan_github({"repo_url": "https://github.com/a/b",
                                            "scan_id": "t"})
        assert result["status"] == "analyzing"
        assert [f["file"] for f in result["raw_findings"]] == ["b.py"]
        assert any("Semgrep failed" in line and "Bandit results" in line
                   for line in result["agent_logs"])

    def test_both_scanners_failing_still_errors(self, monkeypatch, tmp_path):
        import tools.git_cloner as git_cloner
        import tools.bandit_runner as bandit_runner
        import tools.semgrep_runner as semgrep_runner

        monkeypatch.setattr(git_cloner, "clone_repo", lambda *a: str(tmp_path))
        monkeypatch.setattr(git_cloner, "detect_tech_stack",
                            lambda p: {"languages": ["python"]})
        monkeypatch.setattr(bandit_runner, "run_bandit",
                            lambda p: (_ for _ in ()).throw(RuntimeError("bandit down")))

        def boom(path):
            raise RuntimeError("semgrep is not installed or not on PATH")

        monkeypatch.setattr(semgrep_runner, "run_semgrep", boom)
        result = orchestrator._scan_github({"repo_url": "https://github.com/a/b",
                                            "scan_id": "t"})
        assert result["status"] == "error"
        assert any("semgrep" in line.lower() for line in result["agent_logs"])
