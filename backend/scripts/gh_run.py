#!/usr/bin/env python
"""Run a gh CLI command with GITHUB_TOKEN from backend/.env (no login needed).

Usage:
    python backend/scripts/gh_run.py api user --jq .login

Loads GITHUB_TOKEN via python-dotenv and passes it as GH_TOKEN (which gh
honours automatically). Falls back to "C:\\Program Files\\GitHub CLI\\gh.exe"
when gh is not on PATH. The token is masked in all output and error text.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404 - argument list only, never shell=True
import sys

_GH_FALLBACK = r"C:\Program Files\GitHub CLI\gh.exe"


def _load_token() -> str:
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        from dotenv import load_dotenv
        load_dotenv(os.path.join(backend_dir, ".env"))
    except ImportError:
        pass
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if not token:
        print("gh_run: GITHUB_TOKEN missing in backend/.env", file=sys.stderr)
        raise SystemExit(2)
    return token


def _mask(text: str, token: str) -> str:
    return text.replace(token, "ghp_****") if token and text else text


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: gh_run.py <gh args...>", file=sys.stderr)
        return 2
    token = _load_token()
    gh_bin = shutil.which("gh") or _GH_FALLBACK
    if not (shutil.which("gh") or os.path.isfile(gh_bin)):
        print("gh_run: gh CLI not found on PATH nor at " + _GH_FALLBACK,
              file=sys.stderr)
        return 2
    env = {**os.environ, "GH_TOKEN": token, "GITHUB_TOKEN": token}
    try:
        proc = subprocess.run([gh_bin, *argv[1:]], capture_output=True,
                              text=True, timeout=180, env=env)
    except subprocess.TimeoutExpired:
        print("gh_run: timed out after 180s", file=sys.stderr)
        return 1
    if proc.stdout:
        sys.stdout.write(_mask(proc.stdout, token))
    if proc.stderr:
        sys.stderr.write(_mask(proc.stderr, token))
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
