"""Tests for SecureCoder (prompt 03) with a mocked LLM."""

from __future__ import annotations

import os
import shutil

import pytest

from agents.remediation.secure_coder import match_hint, pick_target

APP_PY = '''import sqlite3

USERS = []


def search(q):
    con = sqlite3.connect("x.db")
    cur = con.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{q}'")
    return cur.fetchall()
'''

GOOD_REPLY = """### RATIONALE
The search query interpolates user input into SQL (CWE-89). Parameterizing
it keeps behaviour for legitimate names while closing the injection.

### PATCH
FILE: app.py
<<<<<<< SEARCH
    cur.execute(f"SELECT * FROM users WHERE name = '{q}'")
=======
    cur.execute("SELECT * FROM users WHERE name = ?", (q,))
>>>>>>> REPLACE

### TEST
FILE: tests/test_patchforge_cwe89.py
<<<<<<< SEARCH
=======
def test_sqli_payload_returns_nothing(client):
    resp = client.get("/search", query_string={"q": "' OR '1'='1"})
    assert resp.status_code == 200
    assert resp.get_json() == []
>>>>>>> REPLACE
"""


@pytest.fixture()
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text(APP_PY)
    (root / ".git").mkdir()  # kept for the later PRCreator
    return root


@pytest.fixture()
def isolate_runs(tmp_path, monkeypatch):
    import tools.run_artifacts as ra
    monkeypatch.setattr(ra, "_BASE", tmp_path / "runs")
    yield tmp_path / "runs"


def _state(repo, **overrides):
    vuln = {"id": "VULN-001", "file": "app.py", "line": 7,
            "severity": "HIGH", "category": "A03:2021-Injection",
            "description": "SQL injection via f-string query", "cve": None}
    base = {"scan_id": "t3st0001", "repo_url": "https://github.com/x/y",
            "repo_path": str(repo), "vulnerabilities": [vuln], "patches": [],
            "attempts": 0, "feedback": [], "target_vuln": None,
            "target_hint": None}
    base.update(overrides)
    return base


class TestSecureCoderNode:
    def test_patch_applied_and_test_written(self, repo, isolate_runs,
                                            monkeypatch):
        seen = {}
        import agents.remediation.secure_coder as sc

        def fake_invoke(messages, model=None, hint=None):
            seen["model"] = model
            return type("R", (), {"content": GOOD_REPLY})()

        monkeypatch.setattr(sc, "invoke_llm", fake_invoke)
        result = sc.secure_coder_node(_state(repo))

        assert result["remediation_status"] == "running"
        assert result["attempts"] == 1
        assert result["target_vuln"]["id"] == "VULN-001"
        with open(os.path.join(result["work_dir"], "app.py")) as handle:
            patched = handle.read()
        assert "?" in patched and "f\"SELECT" not in patched
        assert os.path.isfile(os.path.join(
            result["work_dir"], "tests", "test_patchforge_cwe89.py"))
        assert result["code_patch"]["diff"]
        assert any("Target: VULN-001" in line
                   for line in result["agent_logs"])
        assert any("patch applied" in line
                   for line in result["agent_logs"])
        assert seen["model"] and "qwen" in seen["model"]  # attempt-1 model
        shutil.rmtree(result["work_dir"], ignore_errors=True)

    def test_attempt2_uses_stronger_model(self, repo, isolate_runs,
                                          monkeypatch):
        import agents.remediation.secure_coder as sc
        seen = {}

        def fake_invoke(messages, model=None, hint=None):
            seen["model"] = model
            return type("R", (), {"content": GOOD_REPLY})()

        monkeypatch.setattr(sc, "invoke_llm", fake_invoke)
        state = _state(repo)
        state["attempts"] = 1
        result = sc.secure_coder_node(state)
        assert "gpt-oss-120b" in (seen["model"] or "")
        shutil.rmtree(result["work_dir"], ignore_errors=True)

    def test_unparsable_output_fails_cleanly(self, repo, isolate_runs,
                                             monkeypatch):
        import agents.remediation.secure_coder as sc
        monkeypatch.setattr(
            sc, "invoke_llm",
            lambda *a, **k: type("R", (), {"content": "no sections here"})())
        result = sc.secure_coder_node(_state(repo))
        assert result["remediation_status"] == "failed"
        assert any("Repair failed" in line or "failed to apply" in line
                   for line in result["agent_logs"])
        if result.get("work_dir"):
            shutil.rmtree(result["work_dir"], ignore_errors=True)


class TestHintSelection:
    def _two(self):
        sqli = {"id": "VULN-001", "file": "a.py", "line": 1,
                "severity": "MEDIUM", "category": "A03:2021-Injection",
                "description": "SQL injection", "cve": None}
        idor = {"id": "VULN-002", "file": "b.py", "line": 1,
                "severity": "HIGH",
                "category": "A01:2021-Broken Access Control",
                "description": "missing owner check", "cve": None}
        return sqli, idor

    def _two_files(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n")
        (tmp_path / "b.py").write_text("y = 2\n")

    def test_hint_picks_match_despite_lower_severity(self, tmp_path):
        self._two_files(tmp_path)
        sqli, idor = self._two()
        target, matched = pick_target([idor, sqli], str(tmp_path),
                                      hint="CWE-89")
        assert matched is True
        assert target["id"] == "VULN-001"

    def test_hint_by_vuln_id(self, tmp_path):
        self._two_files(tmp_path)
        sqli, idor = self._two()
        target, matched = pick_target([sqli, idor], str(tmp_path),
                                      hint="VULN-001")
        assert matched is True
        assert target["id"] == "VULN-001"

    def test_missed_hint_falls_back_to_severity(self, tmp_path):
        self._two_files(tmp_path)
        sqli, idor = self._two()
        target, matched = pick_target([sqli, idor], str(tmp_path),
                                      hint="CWE-22")
        assert matched is False
        assert target["id"] == "VULN-002"  # highest severity wins

    def test_match_hint_unit(self):
        vuln = {"id": "VULN-003", "category": "A03",
                "description": "path traversal via CWE-22 in download"}
        assert match_hint(vuln, "cwe-22") is True
        assert match_hint(vuln, "VULN-003") is True
        assert match_hint(vuln, "CWE-89") is False
        assert match_hint(vuln, "") is False
