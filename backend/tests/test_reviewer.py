"""Tests for the reviewer gate (prompt 05) with fixture diffs."""

from __future__ import annotations

import json
import os

import agents.remediation.reviewer as reviewer
from agents.remediation.reviewer import (
    check_anticcheat,
    check_applied,
    check_rescan,
    check_scope,
    check_syntax,
    reviewer_node,
)

APP_PY = "import os\n\n\ndef search(q):\n    return os.popen('ls ' + q)\n"
APP_FIXED = "import os\nimport subprocess\n\n\ndef search(q):\n    return subprocess.run(['ls', q], capture_output=True)\n"
TEST_NEW = "def test_exploit(client):\n    assert True\n"

TARGET = {"id": "VULN-001", "file": "app.py", "line": 5,
          "severity": "HIGH", "category": "A03:2021-Injection",
          "description": "command injection via os.popen", "cve": None}

SMALL_DIFF = """--- a/app.py
+++ b/app.py
@@ -1,5 +1,6 @@
 import os
+import subprocess
 
 
 def search(q):
-    return os.popen('ls ' + q)
+    return subprocess.run(['ls', q], capture_output=True)
"""


def _trees(tmp_path, work_app=APP_FIXED, extra_base=None, extra_work=None):
    """Build (base, work) fixture trees; return paths."""
    base = tmp_path / "base"
    work = tmp_path / "work"
    (base / "tests").mkdir(parents=True)
    (work / "tests").mkdir(parents=True)
    (base / "app.py").write_text(APP_PY)
    (work / "app.py").write_text(work_app)
    (base / "tests" / "test_old.py").write_text("def test_old():\n    assert True\n")
    (work / "tests" / "test_old.py").write_text("def test_old():\n    assert True\n")
    (work / "tests" / "test_x.py").write_text(TEST_NEW)
    for rel, text in (extra_base or {}).items():
        target = base / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    for rel, text in (extra_work or {}).items():
        target = work / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    return str(base), str(work)


def _patch(files_changed=None, diff=SMALL_DIFF,
           test_file="tests/test_x.py"):
    return {"rationale": "r", "blocks": [],
            "diff": diff, "files_changed": files_changed or
            ["app.py", "tests/test_x.py"],
            "test_file": test_file, "lines_added": 2, "lines_removed": 1}


def _state(base, work, **overrides):
    state = {"scan_id": "rev-test-1", "repo_url": "https://github.com/x/y",
             "repo_path": base, "work_dir": work, "target_vuln": TARGET,
             "code_patch": _patch(), "attempts": 1, "feedback": []}
    state.update(overrides)
    return state


def _isolate_runs(tmp_path, monkeypatch):
    import tools.run_artifacts as ra
    monkeypatch.setattr(ra, "_BASE", tmp_path / "runs")


_LLM_OK = {"approved": True, "root_cause_fixed": True,
           "behaviour_preserved": True, "issues": [],
           "security_score": 9, "summary": "Clean fix."}


def _fake_llm(payload):
    def fake_invoke(messages):
        return type("Reply", (), {"content": json.dumps(payload)})()
    return fake_invoke


class TestApplied:
    def test_present_passes(self, tmp_path):
        base, work = _trees(tmp_path)
        check = check_applied(work, ["app.py", "tests/test_x.py"])
        assert check["passed"] is True

    def test_missing_file_fails(self, tmp_path):
        base, work = _trees(tmp_path)
        check = check_applied(work, ["app.py", "ghost.py"])
        assert check["passed"] is False
        assert "ghost.py" in check["detail"]


class TestSyntax:
    def test_valid_passes(self, tmp_path):
        base, work = _trees(tmp_path)
        assert check_syntax(work, ["app.py"])["passed"] is True

    def test_broken_fails(self, tmp_path):
        base, work = _trees(tmp_path,
                            work_app="def broken(:\n    pass\n")
        check = check_syntax(work, ["app.py"])
        assert check["passed"] is False
        assert "app.py" in check["detail"]


class TestRescan:
    def _finding(self, line, sev="HIGH", rule="python.lang.security.audit.test"):
        return {"source": "semgrep", "file": "app.py", "line": line,
                "severity": sev, "rule_id": rule}

    def test_gone_and_clean_passes(self, tmp_path, monkeypatch):
        base, work = _trees(tmp_path)
        monkeypatch.setattr(
            reviewer, "run_semgrep",
            lambda tree, files=None: [self._finding(5)]
            if tree == base else [])
        monkeypatch.setattr(reviewer, "run_bandit",
                            lambda tree, files=None: [])
        check = check_rescan(work, base, "rev-rescan-1", TARGET, ["app.py"])
        assert check["passed"] is True
        assert "gone" in check["detail"]

    def test_still_present_fails(self, tmp_path, monkeypatch):
        base, work = _trees(tmp_path)
        finding = self._finding(6)
        monkeypatch.setattr(reviewer, "run_semgrep",
                            lambda tree, files=None: [finding])
        monkeypatch.setattr(reviewer, "run_bandit",
                            lambda tree, files=None: [])
        check = check_rescan(work, base, "rev-rescan-2", TARGET, ["app.py"])
        assert check["passed"] is False
        assert "still present" in check["detail"]

    def test_new_high_fails(self, tmp_path, monkeypatch):
        base, work = _trees(tmp_path)
        monkeypatch.setattr(reviewer, "run_semgrep",
                            lambda tree, files=None: []
                            if tree == base else [self._finding(50)])
        monkeypatch.setattr(reviewer, "run_bandit",
                            lambda tree, files=None: [])
        check = check_rescan(work, base, "rev-rescan-3", TARGET, ["app.py"])
        assert check["passed"] is False
        assert "new HIGH" in check["detail"]

    def test_shifted_finding_is_not_new(self, tmp_path, monkeypatch):
        base, work = _trees(tmp_path)
        monkeypatch.setattr(
            reviewer, "run_semgrep",
            lambda tree, files=None: [self._finding(5)]
            if tree == base else [self._finding(12)])
        monkeypatch.setattr(reviewer, "run_bandit",
                            lambda tree, files=None: [])
        # Line 12 is outside ±5 of target line 5 → target counts as gone,
        # but within ±10 with the same rule → not a NEW finding.
        check = check_rescan(work, base, "rev-rescan-4", TARGET, ["app.py"])
        assert check["passed"] is True


class TestScope:
    def test_ok_passes(self, tmp_path):
        base, work = _trees(tmp_path)
        check = check_scope(work, base, TARGET,
                            ["app.py", "tests/test_x.py"],
                            "tests/test_x.py", SMALL_DIFF)
        assert check["passed"] is True

    def test_outsider_fails(self, tmp_path):
        base, work = _trees(tmp_path,
                            extra_work={"other.py": "x = 1\n"})
        check = check_scope(work, base, TARGET,
                            ["app.py", "tests/test_x.py", "other.py"],
                            "tests/test_x.py", SMALL_DIFF)
        assert check["passed"] is False
        assert "other.py" in check["detail"]

    def test_too_many_lines_fails(self, tmp_path):
        base, work = _trees(tmp_path)
        big = "--- a/app.py\n+++ b/app.py\n" + "".join(
            f"@@ -{i},1 +{i},1 @@\n-old{i}\n+new{i}\n" for i in range(1, 45))
        check = check_scope(work, base, TARGET, ["app.py"],
                            "tests/test_x.py", big)
        assert check["passed"] is False
        assert "88" in check["detail"]


class TestAntiCheat:
    def test_clean_passes(self, tmp_path):
        base, work = _trees(tmp_path)
        assert check_anticcheat(
            work, base, ["app.py", "tests/test_x.py"],
            "tests/test_x.py")["passed"] is True

    def test_nosec_fails(self, tmp_path):
        base, work = _trees(tmp_path,
                            extra_work={"app.py": APP_FIXED + "# nosec\n"})
        check = check_anticcheat(work, base, ["app.py"], "tests/test_x.py")
        assert check["passed"] is False
        assert "nosec" in check["detail"]

    def test_modified_existing_test_fails(self, tmp_path):
        base, work = _trees(tmp_path,
                            extra_work={"tests/test_old.py":
                                        "def test_old():\n    assert False\n"})
        check = check_anticcheat(work, base,
                                 ["app.py", "tests/test_x.py"],
                                 "tests/test_x.py")
        assert check["passed"] is False
        assert "test_old.py" in check["detail"]

    def test_commented_route_fails(self, tmp_path):
        base, work = _trees(tmp_path,
                            extra_work={"app.py": APP_FIXED +
                                        "# @app.route('/x')\n"})
        check = check_anticcheat(work, base, ["app.py"], "tests/test_x.py")
        assert check["passed"] is False
        assert "commented-out route" in check["detail"]


class TestNode:
    def test_approve(self, tmp_path, monkeypatch):
        _isolate_runs(tmp_path, monkeypatch)
        base, work = _trees(tmp_path)
        monkeypatch.setattr(reviewer, "run_semgrep",
                            lambda tree, files=None: [])
        monkeypatch.setattr(reviewer, "run_bandit",
                            lambda tree, files=None: [])
        monkeypatch.setattr(reviewer, "invoke_llm", _fake_llm(_LLM_OK))
        result = reviewer_node(_state(base, work))
        assert result["review"]["approved"] is True
        assert result["feedback"] == []
        assert any("APPROVED (score 9/10)" in line
                   for line in result["agent_logs"])
        assert any("Syntax OK" in line or "syntax" in line
                   for line in result["agent_logs"])

    def test_reject_blocker(self, tmp_path, monkeypatch):
        _isolate_runs(tmp_path, monkeypatch)
        base, work = _trees(tmp_path)
        monkeypatch.setattr(reviewer, "run_semgrep",
                            lambda tree, files=None: [])
        monkeypatch.setattr(reviewer, "run_bandit",
                            lambda tree, files=None: [])
        bad = dict(_LLM_OK, approved=False, root_cause_fixed=False,
                   security_score=4,
                   issues=[{"severity": "blocker",
                            "comment": "Still uses shell=True."}],
                   summary="Not fixed.")
        monkeypatch.setattr(reviewer, "invoke_llm", _fake_llm(bad))
        result = reviewer_node(_state(base, work))
        assert result["review"]["approved"] is False
        assert any("shell=True" in line for line in result["feedback"])
        assert any("REJECTED (score 4/10)" in line
                   for line in result["agent_logs"])

    def test_llm_unavailable_rejects(self, tmp_path, monkeypatch):
        _isolate_runs(tmp_path, monkeypatch)
        base, work = _trees(tmp_path)
        monkeypatch.setattr(reviewer, "run_semgrep",
                            lambda tree, files=None: [])
        monkeypatch.setattr(reviewer, "run_bandit",
                            lambda tree, files=None: [])
        from agents.llm_router import LLMUnavailableError

        def boom(messages):
            raise LLMUnavailableError("No AI provider is configured.")
        monkeypatch.setattr(reviewer, "invoke_llm", boom)
        result = reviewer_node(_state(base, work))
        assert result["review"]["approved"] is False
        assert any("REJECTED" in line for line in result["agent_logs"])

    def test_missing_work_copy_rejects(self, tmp_path, monkeypatch):
        _isolate_runs(tmp_path, monkeypatch)
        base, work = _trees(tmp_path)
        result = reviewer_node(_state(base, os.path.join(work, "nope")))
        assert result["review"]["approved"] is False
        assert any("REJECTED (score 0/10)" in line
                   for line in result["agent_logs"])

    def test_deterministic_fail_blocks_despite_llm_ok(self, tmp_path,
                                                      monkeypatch):
        _isolate_runs(tmp_path, monkeypatch)
        base, work = _trees(tmp_path,
                            work_app="def broken(:\n    pass\n")
        monkeypatch.setattr(reviewer, "run_semgrep",
                            lambda tree, files=None: [])
        monkeypatch.setattr(reviewer, "run_bandit",
                            lambda tree, files=None: [])
        monkeypatch.setattr(reviewer, "invoke_llm", _fake_llm(_LLM_OK))
        result = reviewer_node(_state(base, work))
        assert result["review"]["approved"] is False
        assert any("syntax" in line for line in result["feedback"])
