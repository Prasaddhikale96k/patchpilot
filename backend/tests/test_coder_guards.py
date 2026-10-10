"""Parser inheritance, added-lines-only anti-cheat, and the no-op guard."""

from __future__ import annotations

import pytest

from agents.remediation.reviewer import (
    check_anticcheat,
    check_target_changed,
    reviewer_node,
)
from tools.patch_apply import PatchApplyError, parse_blocks

BEFORE = (
    "import subprocess  # nosec B404 - diagnostic\n"
    "\n"
    "\n"
    "def ping(host):\n"
    "    # nosec B602 - host comes from the admin form.\n"
    "    return subprocess.run(f'ping -c 1 {host}', shell=True)  # nosec B602\n"
)
FIXED = (
    "import subprocess\n"
    "\n"
    "\n"
    "def ping(host):\n"
    "    return subprocess.run(['ping', '-c', '1', host], shell=False)\n"
)
TARGET = {"id": "V1", "file": "app.py", "line": 6, "severity": "CRITICAL",
          "category": "CWE-78", "description": "shell=True"}


def _tree(root, name, text):
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "app.py").write_text(text, encoding="utf-8")
    return str(d)


class TestParserInheritsFile:
    def test_second_block_without_file_line_is_kept(self):
        text = (
            "FILE: app.py\n<<<<<<< SEARCH\na\n=======\nb\n>>>>>>> REPLACE\n"
            "<<<<<<< SEARCH\nc\n=======\nd\n>>>>>>> REPLACE\n"
        )
        blocks = parse_blocks(text)
        assert [b.file for b in blocks] == ["app.py", "app.py"]

    def test_unterminated_block_is_an_error_not_silently_dropped(self):
        text = (
            "FILE: app.py\n<<<<<<< SEARCH\na\n=======\nb\n>>>>>>> REPLACE\n"
            "<<<<<<< SEARCH\nc\n=======\nd\n"
        )
        with pytest.raises(PatchApplyError):
            parse_blocks(text)

    def test_first_block_without_file_is_an_error(self):
        with pytest.raises(PatchApplyError):
            parse_blocks("<<<<<<< SEARCH\na\n=======\nb\n>>>>>>> REPLACE\n")


class TestAntiCheatAddedLinesOnly:
    def test_removing_nosec_is_not_cheating(self, tmp_path):
        base = _tree(tmp_path, "base", BEFORE)
        work = _tree(tmp_path, "work", FIXED)
        check = check_anticcheat(work, base, ["app.py"], "tests/test_x.py")
        assert check["passed"] is True

    def test_untouched_existing_nosec_is_not_cheating(self, tmp_path):
        base = _tree(tmp_path, "base", BEFORE)
        work = _tree(tmp_path, "work", BEFORE + "\n\ndef other():\n    return 1\n")
        check = check_anticcheat(work, base, ["app.py"], "tests/test_x.py")
        assert check["passed"] is True

    def test_adding_nosec_is_cheating(self, tmp_path):
        base = _tree(tmp_path, "base", FIXED)
        work = _tree(tmp_path, "work", FIXED + "x = 1  # nosec\n")
        check = check_anticcheat(work, base, ["app.py"], "tests/test_x.py")
        assert check["passed"] is False
        assert "added suppression" in check["detail"]


class TestNoOpGuard:
    def test_comment_and_import_only_change_is_rejected(self, tmp_path):
        base = _tree(tmp_path, "base", BEFORE)
        noop = BEFORE.replace("  # nosec B404 - diagnostic", "").replace(
            "import subprocess", "import re\nimport subprocess")
        work = _tree(tmp_path, "work", noop)
        # The vulnerable call (line 6 -> now 7) is untouched.
        check = check_target_changed(work, base, {**TARGET, "line": 6},
                                     window=1)
        assert check["passed"] is False
        assert "You did not change the vulnerable code at app.py:6" in check["detail"]

    def test_real_fix_passes(self, tmp_path):
        base = _tree(tmp_path, "base", BEFORE)
        work = _tree(tmp_path, "work", FIXED)
        assert check_target_changed(work, base, TARGET)["passed"] is True

    def test_guard_rejects_without_calling_the_llm(self, tmp_path, monkeypatch):
        base = _tree(tmp_path, "base", BEFORE)
        noop = BEFORE.replace("  # nosec B404 - diagnostic", "").replace(
            "import subprocess", "import re\nimport subprocess")
        work = _tree(tmp_path, "work", noop)
        monkeypatch.setenv("SCAN_RUNS_DIR", str(tmp_path / "runs"))

        def boom(*a, **k):  # the Reviewer LLM must not be reached
            raise AssertionError("LLM called for a no-op patch")

        import agents.remediation.reviewer as reviewer
        monkeypatch.setattr(reviewer, "_llm_review", boom)
        out = reviewer_node({
            "scan_id": "t", "repo_path": base, "work_dir": work,
            "target_vuln": {**TARGET, "line": 6},
            "code_patch": {"files_changed": ["app.py"], "diff": "x",
                           "test_file": "tests/test_x.py"},
        })
        assert out["review"]["approved"] is False
        assert out["feedback"] == [
            "You did not change the vulnerable code at app.py:6. "
            "Change that exact code."]


def test_resume_ignores_prior_patch_for_a_different_target_hint():
    from agents.remediation.resume import decide_resume
    prior = {"source_run": "p-r1",
             "target_vuln": {"id": "VULN-002", "category": "CWE-89",
                             "description": "SQL injection via f-string"},
             "code_patch": {"blocks": [], "test_file": "tests/t.py"},
             "attempts": 1, "test_content": ""}
    snap = {"vulnerabilities": [{"id": "VULN-002"}]}
    other = decide_resume(snap, prior, target_hint="CWE-78")
    assert other["resume_from"] == "secure_coder" and other["restored"] == {}
    same = decide_resume(snap, prior, target_hint="CWE-89")
    assert same["resume_from"] != "secure_coder" or same["restored"] != {}
