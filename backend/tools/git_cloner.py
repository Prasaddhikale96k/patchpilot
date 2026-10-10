"""
Clones a Git repository and detects its tech stack.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess  # nosec B404 - every call below passes an argument list, never shell=True
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


def _git_bin() -> str:
    """
    Absolute path to git.

    Invoking "git" by name resolves through PATH, so anything earlier on the
    path runs instead. Resolve it once and fail with a clear message rather
    than executing whatever is found.
    """
    resolved = shutil.which("git")
    if not resolved:
        raise RuntimeError("git is not installed or not on PATH")
    return resolved


def force_rmtree(path: str) -> bool:
    """Delete a tree, clearing read-only bits on the way. Returns success.

    shutil.rmtree(ignore_errors=True) silently leaves git's read-only pack
    files behind on Windows: every "cleaned up" clone kept its .git, and a
    remediation re-run then trusted that husk as a usable clone.
    """
    import stat

    def _retry(func, target, _exc):
        try:
            os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
            func(target)
        except OSError:
            pass

    if not os.path.exists(path):
        return True
    shutil.rmtree(path, onexc=_retry)
    if os.path.exists(path):
        logger.warning("Could not fully remove %s", path)
        return False
    return True


def is_usable_clone(path: str) -> bool:
    """A checkout with a .git and at least one tracked-tree entry."""
    try:
        entries = os.listdir(path)
    except OSError:
        return False
    return ".git" in entries and any(e != ".git" for e in entries)


def _repo_dest(scan_id: str) -> str:
    return os.path.join(tempfile.gettempdir(), f"vulnsentinel_{scan_id}")


def clone_repo(repo_url: str, scan_id: str) -> str:
    if not repo_url.startswith("https://"):
        raise ValueError("Only https:// repository URLs are supported")

    dest = _repo_dest(scan_id)
    force_rmtree(dest)  # a leftover husk would make `git clone` refuse
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}  # never hang on a credential prompt
    # nosec B603 - fixed argument list, no shell. repo_url is constrained to
    # https:// above, so it cannot be read as a git option.
    subprocess.run(  # nosec B603
        [
            _git_bin(), "clone",
            "--depth", "1",        # shallow — only latest commit
            "--single-branch",     # skip all other branches
            "--no-tags",           # skip tag objects
            "--filter=blob:limit=2m",  # skip individual files > 2 MB
            repo_url, dest,
        ],
        check=True,
        capture_output=True,
        timeout=300,               # 5 minutes — enough for any large repo
        env=env,
    )
    return dest


def cleanup_repo(scan_id: str) -> None:
    """Delete the cloned repo (plus any <dest>_work_* copies) for a scan.

    Never raises."""
    dest = _repo_dest(scan_id)
    try:
        if os.path.isdir(dest):
            if force_rmtree(dest):
                logger.info("Cleaned up cloned repo %s", dest)
        parent = os.path.dirname(dest)
        prefix = os.path.basename(dest) + "_work_"
        for entry in os.listdir(parent):
            if entry.startswith(prefix):
                if force_rmtree(os.path.join(parent, entry)):
                    logger.info("Cleaned up work copy %s", entry)
    except Exception:
        logger.warning("Failed to clean up %s", dest, exc_info=True)


def detect_tech_stack(repo_path: str) -> dict:
    path = Path(repo_path)
    languages = []
    deps: list[str] = []

    if any(path.rglob("*.py")):
        languages.append("python")
    if any(path.rglob("*.js")) or any(path.rglob("*.ts")):
        languages.append("javascript")
    if any(path.rglob("*.go")):
        languages.append("go")
    if any(path.rglob("*.java")):
        languages.append("java")

    req_file = path / "requirements.txt"
    if req_file.exists():
        deps = [l.strip() for l in req_file.read_text().splitlines() if l.strip()]

    pkg_file = path / "package.json"
    if pkg_file.exists():
        try:
            pkg = json.loads(pkg_file.read_text())
            deps += list(pkg.get("dependencies", {}).keys())
        except (json.JSONDecodeError, UnicodeDecodeError):
            logger.warning("Unparseable package.json in %s", repo_path)

    return {"languages": languages, "dependencies": deps}
