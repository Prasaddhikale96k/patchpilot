"""Windows console-script resolution (prompt 01b self-heal).

bandit.exe exists in .venv\\Scripts, but the resolvers only looked for the
extensionless name and .venv\\Scripts is not on PATH when the backend is
started via run.ps1 without activation — so repo scans lost all Bandit
findings with "not installed or not on PATH".
"""

from __future__ import annotations

import os
import sys

import pytest

import tools.bandit_runner as bandit_runner
import tools.semgrep_runner as semgrep_runner


@pytest.mark.skipif(os.name != "nt", reason="Windows only")
class TestExeFallback:
    def test_bandit_exe_found_in_venv(self, tmp_path, monkeypatch):
        scripts = tmp_path / "Scripts"
        scripts.mkdir()
        (scripts / "bandit.exe").write_bytes(b"")
        (scripts / "python.exe").write_bytes(b"")
        monkeypatch.setattr(sys, "executable", str(scripts / "python.exe"))
        assert bandit_runner._bandit_bin() == str(scripts / "bandit.exe")

    def test_semgrep_exe_found_in_venv(self, tmp_path, monkeypatch):
        scripts = tmp_path / "Scripts"
        scripts.mkdir()
        (scripts / "semgrep.exe").write_bytes(b"")
        (scripts / "python.exe").write_bytes(b"")
        monkeypatch.setattr(sys, "executable", str(scripts / "python.exe"))
        assert semgrep_runner._semgrep_bin() == str(scripts / "semgrep.exe")
