"""Repository-relative path normalisation for scanner findings.

Findings are compared by `file` string (reviewer re-scan, logic auditor,
UI links), so every scanner must emit the same form: POSIX separators,
relative to the repo root, never escaping it. Bandit on Windows used to
emit `app\\routes.py` while Semgrep emitted `app/routes.py`.
"""

from __future__ import annotations

import os
import posixpath


def normalize_repo_path(path: str, repo_path: str) -> str:
    """Return `path` as a forward-slash path relative to `repo_path`.

    Absolute paths are made relative to the repo. Returns "" for anything
    that resolves outside the repository (absolute elsewhere, `..`
    traversal, another drive), so it can never reach an open() or a link.
    Only the path is touched; finding text is left alone.
    """
    if not path:
        return ""
    candidate = path
    if os.path.isabs(candidate) or (len(candidate) > 1 and candidate[1] == ":"):
        try:
            candidate = os.path.relpath(candidate, repo_path)
        except ValueError:  # different drive on Windows
            return ""
    candidate = candidate.replace("\\", "/")
    if candidate.startswith("/"):
        return ""
    normal = posixpath.normpath(candidate)
    if normal in (".", "") or normal == ".." or normal.startswith("../"):
        return ""
    return normal
