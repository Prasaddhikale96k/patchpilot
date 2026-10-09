"""Runs Bandit static analysis on a Python repo and returns normalized findings."""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 - argument list only, never shell=True
import sys


def _bandit_bin() -> str:
    """
    Absolute path to bandit: the venv copy if there is one, else whatever is on
    PATH. Resolved rather than invoked by bare name, so an executable planted
    earlier on PATH cannot take its place.
    """
    venv_bin = os.path.join(os.path.dirname(sys.executable), "bandit")
    if os.path.isfile(venv_bin):
        return venv_bin
    if os.name == "nt":
        # Windows console scripts are bandit.exe; extensionless lookup misses
        # them when .venv\Scripts is not on PATH (e.g. run.ps1 without activate).
        venv_exe = venv_bin + ".exe"
        if os.path.isfile(venv_exe):
            return venv_exe
    resolved = shutil.which("bandit")
    if not resolved:
        raise RuntimeError("bandit is not installed or not on PATH")
    return resolved


def _relative(path: str, repo_path: str) -> str:
    """Report paths relative to the repo root. Repos are cloned into a temp
    directory, so the absolute path leaks a meaningless location into reports."""
    if not path:
        return path
    try:
        return os.path.relpath(path, repo_path)
    except ValueError:
        return path


def run_bandit(repo_path: str) -> list[dict]:
    # nosec B603 - resolved executable, fixed argument list, no shell.
    result = subprocess.run(  # nosec B603
        [_bandit_bin(), "-r", repo_path, "-f", "json", "-q"],
        capture_output=True,
        text=True,
        timeout=120,
    )

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    normalized = []
    for issue in data.get("results", []):
        normalized.append({
            "source": "bandit",
            "file": _relative(issue.get("filename", ""), repo_path),
            "line": issue.get("line_number", 0),
            "severity": issue.get("issue_severity", "LOW").upper(),
            "confidence": issue.get("issue_confidence", "LOW").upper(),
            "description": issue.get("issue_text", ""),
            "code": issue.get("code", ""),
            "test_id": issue.get("test_id", ""),
        })

    return normalized
