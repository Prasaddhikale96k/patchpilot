#!/usr/bin/env python
"""Push a local repo with a one-time token URL (never touches .git/config).

Usage:
    python backend/scripts/git_push.py <repo_dir> <owner/repo> <refspec...>

Builds https://x-access-token:<token>@github.com/<owner>/<repo>.git purely
in memory and pushes the given refspecs (branches and/or tags). The token
is masked in all output and error text.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404 - argument list only, never shell=True
import sys


def _load_token() -> str:
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        from dotenv import load_dotenv
        load_dotenv(os.path.join(backend_dir, ".env"))
    except ImportError:
        pass
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if not token:
        print("git_push: GITHUB_TOKEN missing in backend/.env", file=sys.stderr)
        raise SystemExit(2)
    return token


def _mask(text: str, token: str) -> str:
    return text.replace(token, "ghp_****") if token and text else text


def _git_bin() -> str:
    resolved = shutil.which("git")
    if not resolved:
        raise RuntimeError("git is not installed or not on PATH")
    return resolved


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print("usage: git_push.py <repo_dir> <owner/repo> <refspec...>",
              file=sys.stderr)
        return 2
    repo_dir, slug, refspecs = argv[1], argv[2], argv[3:]
    token = _load_token()
    url = f"https://x-access-token:{token}@github.com/{slug}.git"
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    try:
        proc = subprocess.run(
            [_git_bin(), "-C", repo_dir, "push", url, *refspecs],
            capture_output=True, text=True, timeout=300, env=env)
    except subprocess.TimeoutExpired:
        print("git_push: timed out after 300s", file=sys.stderr)
        return 1
    if proc.stdout:
        sys.stdout.write(_mask(proc.stdout, token))
    if proc.stderr:
        sys.stderr.write(_mask(proc.stderr, token))
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
