"""
Fix queue for the multi-vulnerability remediation loop (prompt 00a).

The remediation workers (secure_coder → reviewer → tester, prompts 03–05)
consume this module; it holds no graph code itself so it is testable alone:

- build_fix_queue(): rank the top MAX_FIX_TARGETS distinct, patchable
  vulnerabilities — severity first, then the demo-critical categories
  (SQLi / broken access control / path traversal / command injection /
  hardcoded secret), deduplicated by (file, line) so two findings on the
  same line count as one target.
- format_remediation_progress(): the websocket progress line emitted after
  each finished vulnerability, e.g.
  "[Remediation] 2/3 done · 1 PR opened · elapsed 74s".
- parallel_fix_workers(): worker count from PARALLEL_FIX_WORKERS (default 2).
"""

from __future__ import annotations

import os

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Categories fixed first: the vulnbank demo set. Matched against the OWASP
# label + description, case-insensitively.
_PRIORITY_KEYWORDS = (
    "sql injection", "sqli", "injection",
    "broken access", "access control", "idor", "insecure direct object",
    "path traversal", "directory traversal",
    "command injection", "os command",
    "hardcoded secret", "hardcoded password", "hardcoded credential",
    "hard-coded",
)

_PATCHABLE_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM")


def _priority_index(vuln: dict) -> int:
    """0 when the finding is in a priority category, else 1."""
    haystack = f"{vuln.get('category', '')} {vuln.get('description', '')}".lower()
    return 0 if any(k in haystack for k in _PRIORITY_KEYWORDS) else 1


def _under_tests(path: str) -> bool:
    parts = (path or "").replace("\\", "/").split("/")
    return "tests" in parts or "test" in parts


def build_fix_queue(vulnerabilities: list[dict],
                    max_targets: int | None = None) -> list[dict]:
    """
    Return up to max_targets (default MAX_FIX_TARGETS=3) distinct targets.

    Skipped: website findings (http file / no file), test-code findings
    (unsafe by design), LOW severity, and duplicates on the same (file,
    line). Ranked by (severity, priority-category, file, line) for a stable
    order. Input order is never mutated.
    """
    limit = max_targets
    if limit is None:
        try:
            limit = max(1, int(os.getenv("MAX_FIX_TARGETS", "3")))
        except ValueError:
            limit = 3

    seen: set[tuple[str, int]] = set()
    candidates: list[dict] = []
    for vuln in vulnerabilities or []:
        if not isinstance(vuln, dict):
            continue
        if (vuln.get("severity") or "").upper() not in _PATCHABLE_SEVERITIES:
            continue
        path = vuln.get("file") or ""
        if not path or path.startswith(("http://", "https://")):
            continue
        if _under_tests(path):
            continue
        key = (path, vuln.get("line", 0))
        if key in seen:
            continue
        seen.add(key)
        candidates.append(vuln)

    candidates.sort(key=lambda v: (
        _SEVERITY_RANK.get((v.get("severity") or "").upper(), 99),
        _priority_index(v),
        v.get("file", ""),
        v.get("line", 0),
    ))
    return candidates[:limit]


def parallel_fix_workers() -> int:
    """Worker count for the fix loop (PARALLEL_FIX_WORKERS, default 2)."""
    try:
        return max(1, int(os.getenv("PARALLEL_FIX_WORKERS", "2")))
    except ValueError:
        return 2


def max_fix_attempts() -> int:
    """Retry budget per vulnerability (MAX_FIX_ATTEMPTS, default 3)."""
    try:
        return max(1, int(os.getenv("MAX_FIX_ATTEMPTS", "3")))
    except ValueError:
        return 3


def format_remediation_progress(done: int, total: int, prs_opened: int,
                                elapsed_s: float) -> str:
    """One websocket progress line after each finished vulnerability."""
    return (f"[Remediation] {done}/{total} done · {prs_opened} "
            f"PR opened · elapsed {int(elapsed_s)}s")
