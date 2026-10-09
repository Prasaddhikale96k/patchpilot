"""Real-Docker sandbox test (prompt 04a). Skipped without a daemon."""

from __future__ import annotations

import os

import pytest

from tools.sandbox import detect_project, docker_available, prepare_image, run_tests

pytestmark = pytest.mark.docker


@pytest.mark.skipif(not docker_available(), reason="Docker unavailable")
def test_tiny_project_one_pass_one_fail(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("")
    (proj / "test_tiny.py").write_text(
        "def test_ok():\n    assert True\n"
        "\n"
        "def test_bad():\n    assert False\n")
    assert detect_project(str(proj)) == "python"
    tag = prepare_image(str(proj))
    assert tag.startswith("pp-deps-")
    report = run_tests(str(proj), "after", tag, scan_id="t")
    assert report["sandbox"] == "docker"
    assert report["timed_out"] is False
    assert report["passed"] == 1 and report["failed"] == 1
    assert report["total"] == 2
    assert any("test_ok" in name for name in report["passed_names"])
    assert any("test_bad" in f["name"] for f in report["failed_tests"])


def test_detect_project_none(tmp_path):
    assert detect_project(str(tmp_path)) is None
    assert os.getenv("SANDBOX", "auto") in ("auto", "docker", "venv")
