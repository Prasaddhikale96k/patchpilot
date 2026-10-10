"""Scanner finding paths: one POSIX, repo-relative form on every OS."""

from __future__ import annotations

import os

import pytest

from tools import bandit_runner, semgrep_runner
from tools.repo_paths import normalize_repo_path


@pytest.fixture()
def repo(tmp_path):
    (tmp_path / "app" / "api").mkdir(parents=True)
    return str(tmp_path)


@pytest.mark.parametrize("raw, expected", [
    ("app\\routes.py", "app/routes.py"),              # Windows relative
    ("app/routes.py", "app/routes.py"),               # POSIX relative
    ("app\\api\\v1\\users.py", "app/api/v1/users.py"),  # nested
    ("./app/routes.py", "app/routes.py"),
    (".github/workflows/ci.yml", ".github/workflows/ci.yml"),  # leading dot kept
    ("app/./api/../routes.py", "app/routes.py"),
])
def test_relative_forms(repo, raw, expected):
    assert normalize_repo_path(raw, repo) == expected


def test_absolute_inside_repo(repo):
    assert normalize_repo_path(os.path.join(repo, "app", "routes.py"), repo) == "app/routes.py"


@pytest.mark.parametrize("raw", [
    "../outside.py", "..\\..\\etc\\passwd", "app/../../x.py", "/etc/passwd", "..",
])
def test_traversal_and_foreign_paths_rejected(repo, raw):
    assert normalize_repo_path(raw, repo) == ""


def test_absolute_outside_repo_rejected(repo, tmp_path_factory):
    other = tmp_path_factory.mktemp("elsewhere") / "secret.py"
    assert normalize_repo_path(str(other), repo) == ""


@pytest.mark.skipif(os.name != "nt", reason="drive letters are Windows-only")
def test_other_drive_rejected(repo):
    drive = "Z:" if not repo.upper().startswith("Z:") else "Y:"
    assert normalize_repo_path(f"{drive}\\x\\app.py", repo) == ""


def test_bandit_windows_absolute_becomes_posix_relative(repo):
    raw = os.path.join(repo, "app", "routes.py")  # what bandit reports
    assert bandit_runner._relative(raw, repo) == "app/routes.py"


def test_semgrep_docker_src_prefix(repo):
    assert semgrep_runner._relative("/src/app/routes.py", repo) == "app/routes.py"


def test_semgrep_and_bandit_agree(repo):
    """Reviewer re-scan compares `file` strings across both scanners."""
    abs_path = os.path.join(repo, "app", "routes.py")
    assert (bandit_runner._relative(abs_path, repo)
            == semgrep_runner._relative(abs_path, repo)
            == semgrep_runner._relative("app\\routes.py", repo))
