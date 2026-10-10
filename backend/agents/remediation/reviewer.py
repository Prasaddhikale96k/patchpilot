"""Reviewer node (prompt 05): deterministic gate + LLM review before testing.

Five deterministic checks run first (each reported as {name, passed,
detail}); then a strict senior-AppSec LLM review. The patch is approved
only if every deterministic check passes AND the LLM reports no blocker
AND root_cause_fixed is true. Rejection produces concise bullet feedback
for the coder.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess  # nosec B404 - argument list only, never shell=True
import sys
from pathlib import Path

from ..llm_router import invoke_llm
from tools.bandit_runner import run_bandit
from tools.scan_cache import cached_scan
from tools.semgrep_runner import run_semgrep

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "reviewer.md"

_SEV_NORM = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
             "LOW": "LOW", "ERROR": "HIGH", "WARNING": "MEDIUM",
             "INFO": "LOW"}
_HIGH_CRITICAL = ("HIGH", "CRITICAL")
_MAX_SCOPE_LINES = 40
_RES_CAN_TOL = 5     # target-finding match tolerance (lines)
_NEW_FIND_TOL = 10   # new-finding match tolerance (lines, shifts after patch)

_CHEAT_RES = [
    re.compile(r"#\s*nosec\b"),
    re.compile(r"#\s*nosemgrep\b"),
    re.compile(r"pytest\.skip\s*\("),
    re.compile(r"@pytest\.mark\.skip\b"),
]
_ROUTE_COMMENT_RE = re.compile(
    r"^\s*#.*@(app|bp|router|api|blueprint)\.(route|get|post|put|delete|patch)\b",
    re.IGNORECASE)


def _norm_sev(raw: object) -> str:
    return _SEV_NORM.get(str(raw or "").upper(), "MEDIUM")


def _finding_key(finding: dict) -> tuple:
    return (finding.get("file", ""),
            finding.get("rule_id") or finding.get("test_id") or "",
            _norm_sev(finding.get("severity")))


def _same_finding(a: dict, b: dict, tol: int) -> bool:
    """Same file + same rule with line numbers within tolerance."""
    if a.get("file") != b.get("file"):
        return False
    ra = a.get("rule_id") or a.get("test_id") or ""
    rb = b.get("rule_id") or b.get("test_id") or ""
    if ra != rb:
        return False
    try:
        return abs(int(a.get("line", 0)) - int(b.get("line", 0))) <= tol
    except (TypeError, ValueError):
        return False


def _is_test_file(path: str, test_file: str) -> bool:
    norm = path.replace("\\", "/")
    return norm == test_file.replace("\\", "/") or norm.startswith("tests/")


def check_applied(work_dir: str, files_changed: list[str]) -> dict:
    """1. Every file the patch claims to change exists in the work copy."""
    missing = [f for f in files_changed
               if not os.path.isfile(os.path.join(work_dir, f))]
    if missing:
        return {"name": "patch applied cleanly", "passed": False,
                "detail": f"missing in work copy: {', '.join(missing)}"}
    return {"name": "patch applied cleanly", "passed": True,
            "detail": f"{len(files_changed)} file(s) present"}


def check_syntax(work_dir: str, files_changed: list[str]) -> dict:
    """2. Changed files still parse: py_compile for .py, node --check for .js."""
    failures = []
    node_bin = shutil.which("node")
    for rel in files_changed:
        full = os.path.join(work_dir, rel)
        if rel.endswith(".py"):
            proc = subprocess.run(  # nosec B603
                [sys.executable, "-m", "py_compile", full],
                capture_output=True, text=True, timeout=60)
            if proc.returncode != 0:
                failures.append(f"{rel}: {proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else 'compile error'}")
        elif rel.endswith(".js"):
            if not node_bin:
                failures.append(f"{rel}: node not available for --check")
                continue
            proc = subprocess.run(  # nosec B603
                [node_bin, "--check", full],
                capture_output=True, text=True, timeout=60)
            if proc.returncode != 0:
                failures.append(f"{rel}: {proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else 'syntax error'}")
    if failures:
        return {"name": "syntax", "passed": False,
                "detail": "; ".join(failures)}
    n = sum(1 for f in files_changed if f.endswith((".py", ".js")))
    return {"name": "syntax", "passed": True,
            "detail": f"{n} file(s) compile"}


def _rescan_tree(tree_dir: str, scan_id: str, tree: str,
                 files: list[str]) -> list[dict]:
    """Re-scan changed files in one tree, with per-file-hash caching."""
    present = [f for f in files
               if os.path.isfile(os.path.join(tree_dir, f))]
    if not present:
        return []
    findings: list[dict] = []
    findings += cached_scan(
        f"{scan_id}:{tree}:semgrep", os.path.join(tree_dir, present[0]),
        lambda: run_semgrep(tree_dir, files=present))
    py_files = [f for f in present if f.endswith(".py")]
    if py_files:
        findings += cached_scan(
            f"{scan_id}:{tree}:bandit", os.path.join(tree_dir, py_files[0]),
            lambda: run_bandit(tree_dir, files=py_files))
    return findings


def check_rescan(work_dir: str, repo_path: str, scan_id: str,
                 target: dict, changed_sources: list[str]) -> dict:
    """3. Target finding gone (±5 lines, same file) and no NEW HIGH/CRITICAL."""
    if not changed_sources:
        return {"name": "re-scan", "passed": True,
                "detail": "no changed source files to re-scan"}
    try:
        base = _rescan_tree(repo_path, scan_id, "base", changed_sources)
        work = _rescan_tree(work_dir, scan_id, "work", changed_sources)
    except Exception as exc:
        return {"name": "re-scan", "passed": False,
                "detail": f"re-scan failed: {exc}"}
    tline = int(target.get("line", 0) or 0)
    tfile = target.get("file", "")
    for finding in work:
        if (finding.get("file") == tfile
                and _norm_sev(finding.get("severity")) in _HIGH_CRITICAL):
            try:
                if abs(int(finding.get("line", 0)) - tline) <= _RES_CAN_TOL:
                    return {"name": "re-scan", "passed": False,
                            "detail": f"original finding still present: "
                                      f"{tfile}:{finding.get('line')}"}
            except (TypeError, ValueError):
                continue
    new = [f for f in work
           if _norm_sev(f.get("severity")) in _HIGH_CRITICAL
           and not any(_same_finding(f, b, _NEW_FIND_TOL) for b in base)]
    if new:
        descs = ", ".join(f"{f.get('file')}:{f.get('line')}" for f in new[:5])
        return {"name": "re-scan", "passed": False,
                "detail": f"{len(new)} new HIGH/CRITICAL finding(s): {descs}"}
    return {"name": "re-scan", "passed": True,
            "detail": "original finding gone, no new HIGH/CRITICAL"}


def _hunk_lines_per_file(diff: str) -> dict[str, int]:
    """Count added+removed lines per file from a unified diff."""
    counts: dict[str, int] = {}
    current: str | None = None
    for line in (diff or "").splitlines():
        if line.startswith("+++ b/"):
            current = line[len("+++ b/"):]
            counts.setdefault(current, 0)
        elif current is not None and line.startswith("@@"):
            continue
        elif current is not None and (
                line.startswith("+") and not line.startswith("+++")
                or line.startswith("-") and not line.startswith("---")):
            counts[current] += 1
    return counts


def check_scope(work_dir: str, repo_path: str, target: dict,
                files_changed: list[str], test_file: str,
                diff: str) -> dict:
    """4. Changed sources ⊆ {target file, its local imports} + test file."""
    from .secure_coder import _local_imports
    allowed = {target.get("file", "")}
    try:
        allowed |= set(_local_imports(repo_path, target.get("file", "")))
    except Exception:
        logger.debug("reviewer: import resolution failed", exc_info=True)
    allowed = {a.replace("\\", "/") for a in allowed if a}
    sources = [f for f in files_changed
               if not _is_test_file(f, test_file or "")]
    outsiders = sorted({f for f in sources if f.replace("\\", "/") not in allowed})
    if outsiders:
        return {"name": "scope", "passed": False,
                "detail": f"{len(outsiders)} unrelated file(s) changed: "
                          f"{', '.join(outsiders)}"}
    per_file = _hunk_lines_per_file(diff)
    changed_lines = sum(n for f, n in per_file.items()
                        if not _is_test_file(f, test_file or ""))
    if changed_lines > _MAX_SCOPE_LINES:
        return {"name": "scope", "passed": False,
                "detail": f"{changed_lines} changed source lines "
                          f"(limit {_MAX_SCOPE_LINES})"}
    return {"name": "scope", "passed": True,
            "detail": f"{len(sources)} file(s), {changed_lines} line(s)"}


def _added_lines(before: str, after: str) -> list[tuple[int, str]]:
    """(line number in `after`, text) for every line the patch ADDED."""
    import difflib
    out: list[tuple[int, str]] = []
    matcher = difflib.SequenceMatcher(
        None, before.splitlines(), after.splitlines(), autojunk=False)
    after_lines = after.splitlines()
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag in ("replace", "insert"):
            out.extend((n + 1, after_lines[n]) for n in range(j1, j2))
    return out


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def check_target_changed(work_dir: str, repo_path: str, target: dict,
                         window: int = 3) -> dict:
    """Deterministic no-op guard: the patch must touch the vulnerable code.

    Passes when any changed/inserted/deleted line of the target file falls
    within `window` lines of the finding's line. Removing a suppression
    comment alone or adding an unused import does not count.
    """
    import difflib
    rel = target.get("file", "")
    line = int(target.get("line") or 0)
    before = _read(os.path.join(repo_path, rel)).splitlines()
    after = _read(os.path.join(work_dir, rel)).splitlines()
    matcher = difflib.SequenceMatcher(None, before, after, autojunk=False)
    lo, hi = max(1, line - window), line + window
    for tag, i1, i2, _j1, _j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        # i1..i2 are 0-based old-file positions; an insert has i1 == i2.
        if (i1 + 1) <= hi and max(i2, i1 + 1) >= lo:
            code_changed = [l for l in before[i1:i2] if l.strip() and not
                            l.strip().startswith("#")] or tag == "insert"
            if code_changed:
                return {"name": "vulnerable code changed", "passed": True,
                        "detail": f"{rel} changed near line {line}"}
    return {"name": "vulnerable code changed", "passed": False,
            "detail": (f"You did not change the vulnerable code at "
                       f"{rel}:{line}. Change that exact code.")}


def check_anticcheat(work_dir: str, repo_path: str,
                     files_changed: list[str], test_file: str) -> dict:
    """5. No suppression comments, skipped tests, touched tests, or
    commented-out routes."""
    problems = []
    for rel in files_changed:
        # Only ADDED lines can be cheating: removing a "# nosec" is a good thing.
        added = _added_lines(_read(os.path.join(repo_path, rel)),
                             _read(os.path.join(work_dir, rel)))
        for _n, line_text in added:
            hit = next((p for p in _CHEAT_RES if p.search(line_text)), None)
            if hit:
                problems.append(f"{rel}: added suppression `{hit.pattern}`")
                break
        for n, line_text in added:
            if _ROUTE_COMMENT_RE.match(line_text):
                problems.append(f"{rel}:{n}: commented-out route")
                break
    # Existing tests (other than the new exploit test) must be untouched.
    for root, _dirs, filenames in os.walk(os.path.join(repo_path, "tests")):
        for name in filenames:
            if not name.endswith(".py"):
                continue
            rel = os.path.relpath(os.path.join(root, name),
                                  repo_path).replace("\\", "/")
            if rel == (test_file or "").replace("\\", "/"):
                continue
            base_file = os.path.join(repo_path, rel)
            work_file = os.path.join(work_dir, rel)
            if not os.path.isfile(work_file):
                problems.append(f"{rel}: existing test deleted")
                continue
            try:
                with open(base_file, encoding="utf-8",
                          errors="replace") as fh:
                    before = fh.read()
                with open(work_file, encoding="utf-8",
                          errors="replace") as fh:
                    after = fh.read()
            except OSError:
                continue
            if before != after:
                problems.append(f"{rel}: existing test modified")
    if not os.path.isdir(os.path.join(repo_path, "tests")):
        pass  # repos without a tests/ dir have nothing to protect
    if problems:
        return {"name": "anti-cheat", "passed": False,
                "detail": "; ".join(problems[:5])}
    return {"name": "anti-cheat", "passed": True,
            "detail": "no suppressions, skips, or touched tests"}


def _llm_review(target: dict, diff: str, checks: list[dict],
                scan_id: str) -> dict:
    """Strict senior-AppSec LLM review; always returns the full shape."""
    from ..orchestrator import _parse_json
    from ..llm_router import LLMUnavailableError
    template = _PROMPT_PATH.read_text(encoding="utf-8")
    summary = "; ".join(
        f"{c['name']}: {'PASS' if c['passed'] else 'FAIL'} ({c['detail']})"
        for c in checks)
    import json as _json
    prompt = (f"{template}\n\n## Vulnerability\n"
              f"{_json.dumps(target, indent=2)}\n\n"
              f"## Diff\n{(diff or '')[:6000]}\n\n"
              f"## Deterministic checks\n{summary}\n")
    from tools.run_artifacts import save_text
    save_text(scan_id, "reviewer_prompt.md", prompt)
    fallback = {"approved": False, "root_cause_fixed": False,
                "behaviour_preserved": False, "issues": [],
                "security_score": 0, "summary": "LLM review unavailable."}
    try:
        reply = invoke_llm([{"role": "user", "content": prompt}])
    except LLMUnavailableError as exc:
        fallback["summary"] = f"LLM review unavailable: {exc.reason}"
        return fallback
    raw = getattr(reply, "content", reply)
    parsed = _parse_json(raw if isinstance(raw, str) else str(raw), fallback)
    if not isinstance(parsed, dict):
        return fallback
    review = dict(fallback)
    review.update({k: parsed.get(k, v) for k, v in fallback.items()})
    if not isinstance(review.get("issues"), list):
        review["issues"] = []
    try:
        review["security_score"] = int(review.get("security_score", 0))
    except (TypeError, ValueError):
        review["security_score"] = 0
    return review


def reviewer_node(state: dict) -> dict:
    """Gate the patch before testing: deterministic checks + LLM review."""
    from tools.run_artifacts import save_text
    scan_id = state.get("scan_id", "unknown")
    repo_path = state.get("repo_path", "")
    work_dir = state.get("work_dir", "")
    code_patch = state.get("code_patch") or {}
    target = state.get("target_vuln") or {}
    files_changed = code_patch.get("files_changed", []) or []
    test_file = code_patch.get("test_file", "") or ""
    diff = code_patch.get("diff", "") or ""

    if not target or not work_dir or not os.path.isdir(work_dir):
        check = {"name": "patch applied cleanly", "passed": False,
                 "detail": "no work copy to review"}
        review = {"approved": False, "checks": [check],
                  "llm": {"approved": False, "root_cause_fixed": False,
                          "behaviour_preserved": False, "issues": [],
                          "security_score": 0,
                          "summary": "Nothing to review."},
                  "feedback_for_coder": ["No patch was produced to review."]}
        return {"review": review, "feedback": review["feedback_for_coder"],
                "agent_logs": ["[Reviewer] ❌ patch applied cleanly: "
                               "no work copy to review",
                               "[Reviewer] Verdict: REJECTED (score 0/10)"]}

    guard = check_target_changed(work_dir, repo_path, target)
    if not guard["passed"]:
        # Rejected before any Reviewer LLM call is spent.
        review = {"approved": False, "checks": [guard],
                  "llm": {"approved": False, "root_cause_fixed": False,
                          "behaviour_preserved": False, "issues": [],
                          "security_score": 0,
                          "summary": "Patch left the vulnerable code unchanged."},
                  "feedback_for_coder": [guard["detail"]]}
        from tools.run_artifacts import save_text as _save
        import json as _j
        _save(scan_id, "review.json", _j.dumps(review, indent=2, default=str))
        return {"review": review, "feedback": review["feedback_for_coder"],
                "agent_logs": [f"[Reviewer] FAILED {guard['name']}: "
                               f"{guard['detail']}",
                               "[Reviewer] Verdict: REJECTED (score 0/10, "
                               "no LLM call)"]}

    changed_sources = [f for f in files_changed
                       if not _is_test_file(f, test_file)]
    checks = [
        check_applied(work_dir, files_changed),
        check_syntax(work_dir, files_changed),
        check_rescan(work_dir, repo_path, scan_id, target, changed_sources),
        check_scope(work_dir, repo_path, target, files_changed, test_file,
                    diff),
        check_anticcheat(work_dir, repo_path, files_changed, test_file),
    ]
    llm = _llm_review(target, diff, checks, scan_id)

    blockers = [i for i in llm.get("issues", [])
                if str(i.get("severity", "")).lower() == "blocker"]
    approved = (all(c["passed"] for c in checks)
                and not blockers and bool(llm.get("root_cause_fixed")))
    llm["approved"] = approved

    feedback: list[str] = []
    for check in checks:
        if not check["passed"]:
            feedback.append(f"{check['name']}: {check['detail']}")
    for issue in llm.get("issues", []):
        feedback.append(f"{issue.get('severity', '?')}: "
                        f"{issue.get('comment', '')}")
    if not approved and not feedback:
        feedback = ["LLM could not confirm the root cause is fixed."]

    import json as _json
    review = {"approved": approved, "checks": checks, "llm": llm,
              "feedback_for_coder": feedback}
    save_text(scan_id, "review.json",
              _json.dumps(review, indent=2, default=str))

    verdict = ("APPROVED" if approved else "REJECTED")
    logs = [f"[Reviewer] {'✅' if c['passed'] else '❌'} "
            f"{c['name']}: {c['detail']}" for c in checks]
    logs.append(f"[Reviewer] Verdict: {verdict} "
                f"(score {llm.get('security_score', 0)}/10)")
    return {"review": review, "feedback": feedback, "agent_logs": logs}
