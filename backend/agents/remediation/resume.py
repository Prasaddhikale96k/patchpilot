"""Resume helpers for remediation retries (interrupted-run recovery).

A remediation retry (POST /api/remediate) must NOT restart the full scan
pipeline (orchestrator -> scanner -> ...). It reuses the parent scan's
``state_after_fix.json`` snapshot and, when a previous remediation attempt
(<parent>-rN) already produced a valid patch, resumes from the earliest
phase that genuinely needs to run again instead of discarding the work.

Persisted ``phase`` alone is not trusted: the store row may lag behind the
artifacts actually written (e.g. phase ``secure_coder`` while ``review.json``
already exists). Every decision below compares the snapshot, the event log,
the patch artifacts, the review verdict and the test results.

Only existing graph nodes are reused (secure_coder -> reviewer -> tester ->
pr_creator); this module only decides the entry point and re-materializes a
validated work copy. No second workflow is invented.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

_PARENT_RE = re.compile(r"^(?P<parent>.+)-r(?P<n>\d+)$")

_VALID_ENTRIES = ("secure_coder", "reviewer", "tester", "pr_creator")


def parent_id_for(scan_id: str) -> str:
    """Original scan id for a run id (``d97e9820-r1`` -> ``d97e9820``)."""
    match = _PARENT_RE.fullmatch(scan_id or "")
    return match.group("parent") if match else (scan_id or "")


def is_remediation_id(scan_id: str) -> bool:
    """True for ``<parent>-rN`` remediation attempt ids."""
    return _PARENT_RE.fullmatch(scan_id or "") is not None


def _runs_base() -> Path:
    from tools.run_artifacts import _BASE
    return Path(_BASE)


def list_prior_attempts(parent_id: str, exclude: str | None = None) -> list[tuple[int, Path]]:
    """Existing ``<parent>-rN`` run dirs, oldest first (excluding one id)."""
    base = _runs_base()
    if not base.is_dir():
        return []
    out: list[tuple[int, Path]] = []
    for child in base.iterdir():
        if not child.is_dir():
            continue
        match = _PARENT_RE.fullmatch(child.name)
        if not match or match.group("parent") != parent_id:
            continue
        if child.name == exclude:
            continue
        try:
            out.append((int(match.group("n")), child))
        except ValueError:
            continue
    out.sort(key=lambda item: item[0])
    return out


def _load_json(path: Path) -> dict | list | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _is_safe_rel_file(path: str) -> bool:
    """Syntactic repo-boundary check (mirrors patch_apply._resolve)."""
    if not path or not isinstance(path, str):
        return False
    normalized = (path or "").replace("\\", "/").strip()
    if not normalized or normalized.startswith("/") or ".." in normalized.split("/"):
        return False
    if len(normalized) > 1 and normalized[1] == ":":
        return False
    return True


def validate_blocks(blocks: object) -> bool:
    """A saved patch is reusable only when every block is well-formed."""
    if not isinstance(blocks, list) or not blocks:
        return False
    for block in blocks:
        if not isinstance(block, dict):
            return False
        file = block.get("file")
        search = block.get("search")
        replace = block.get("replace")
        if not _is_safe_rel_file(file if isinstance(file, str) else ""):
            return False
        if not isinstance(search, str) or not isinstance(replace, str):
            return False
        # Empty SEARCH means "create new file" (only valid for the exploit
        # test, never for a source patch). Source blocks must match something.
        if not search.strip() and not (file or "").replace("\\", "/").startswith("tests/"):
            # The exploit test block is not stored in patch_blocks.json
            # (only source blocks are), so an empty SEARCH here is corrupt.
            return False
    # Source patches must touch real source, not only tests.
    sources = [b.get("file", "") for b in blocks if isinstance(b, dict)]
    if not any(not f.replace("\\", "/").startswith("tests/") for f in sources):
        return False
    return True


def patch_hash(diff_text: str) -> str:
    """Bind review/test evidence to the exact patch it was produced from."""
    return hashlib.sha256((diff_text or "").encode("utf-8")).hexdigest()[:16]


def _parse_response_meta(response_text: str) -> tuple[str, str | None]:
    """(rationale, test_rel) from a saved secure_coder_response.md."""
    rationale = ""
    test_rel: str | None = None
    text = response_text or ""
    # RATIONALE section: first ### block.
    match = re.search(r"^###\s*RATIONALE\s*$\n(?P<body>.*?)(?=^###\s*\w+\s*$|\Z)",
                      text, re.MULTILINE | re.DOTALL)
    if match:
        rationale = match.group("body").strip()[:2000]
    match = re.search(r"^###\s*TEST\s*$\n.*?^FILE:\s*(?P<file>.+?)\s*$",
                      text, re.MULTILINE | re.DOTALL)
    if match:
        test_rel = match.group("file").strip().replace("\\", "/")
    return rationale, test_rel


def _test_candidates(attempt_dir: Path) -> list[Path]:
    return sorted(attempt_dir.glob("test_*.py"))


def load_prior_progress(parent_id: str, hint_run_id: str | None = None) -> dict | None:
    """Newest validated prior attempt for ``parent_id`` (or None).

    ``hint_run_id`` (e.g. the interrupted ``d97e9820-r1`` the user clicked
    Retry on) is preferred when it holds a valid patch; otherwise the newest
    valid attempt wins. Validation is syntactic + co-location: review/test
    files only count when they sit next to the patch that produced them, so
    stale approval for a different patch is never accepted.
    """
    attempts = list_prior_attempts(parent_id)
    if hint_run_id and is_remediation_id(hint_run_id):
        hinted = [item for item in attempts if item[1].name == hint_run_id]
        others = [item for item in attempts if item[1].name != hint_run_id]
        # Newest first, but the run the user actually clicked wins ties.
        ordered = sorted(hinted, reverse=True) + sorted(others, reverse=True)
    else:
        ordered = sorted(attempts, reverse=True)

    for _, attempt_dir in ordered:
        progress = _read_attempt(attempt_dir)
        if progress is not None:
            return progress
    return None


def _read_attempt(attempt_dir: Path) -> dict | None:
    blocks = _load_json(attempt_dir / "patch_blocks.json")
    if not validate_blocks(blocks):
        return None
    diff = ""
    try:
        diff = (attempt_dir / "patch.diff").read_text(encoding="utf-8")
    except OSError:
        return None
    if not diff.strip():
        return None
    meta = _load_json(attempt_dir / "scan_meta.json")
    target = (meta or {}).get("target_vuln") if isinstance(meta, dict) else None
    if not isinstance(target, dict) or not target.get("id") or not target.get("file"):
        return None
    attempt_no = 0
    if isinstance(meta, dict):
        try:
            attempt_no = int(meta.get("attempt") or 0)
        except (TypeError, ValueError):
            attempt_no = 0

    response_text = ""
    try:
        response_text = (attempt_dir / "secure_coder_response.md").read_text(
            encoding="utf-8", errors="replace")
    except OSError:
        response_text = ""
    rationale, response_test_rel = _parse_response_meta(response_text)

    test_rel = response_test_rel
    test_content: str | None = None
    candidates = _test_candidates(attempt_dir)
    if test_rel:
        for candidate in candidates:
            # Saved as basename (test_x.py) while the repo path is
            # tests/test_x.py: accept either form from the same directory.
            if candidate.name == Path(test_rel).name:
                try:
                    test_content = candidate.read_text(encoding="utf-8")
                except OSError:
                    test_content = None
                break
    if test_content is None and candidates:
        # Fallback for runs whose response transcript is gone: the single
        # exploit test in the attempt dir belongs to this patch.
        picked = candidates[0]
        test_content = None
        try:
            test_content = picked.read_text(encoding="utf-8")
        except OSError:
            test_content = None
        if test_rel is None:
            test_rel = f"tests/{picked.name}"
    if not test_rel or test_content is None:
        return None

    review = _load_json(attempt_dir / "review.json")
    if not isinstance(review, dict):
        review = None

    test_reports: dict = {}
    for phase, filename in (("baseline", "test_baseline.json"),
                            ("exploit_before", "test_exploit_before.json"),
                            ("after", "test_after.json")):
        loaded = _load_json(attempt_dir / filename)
        if isinstance(loaded, dict) and loaded.get("total") is not None:
            test_reports[phase] = loaded

    files_changed = sorted({b["file"].replace("\\", "/") for b in blocks})
    added = sum(1 for line in diff.splitlines()
                if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in diff.splitlines()
                  if line.startswith("-") and not line.startswith("---"))
    code_patch = {
        "rationale": rationale,
        "blocks": blocks,
        "diff": diff,
        "files_changed": files_changed,
        "test_file": test_rel,
        "lines_added": added,
        "lines_removed": removed,
        "_hash": patch_hash(diff),
    }
    return {
        "source_run": attempt_dir.name,
        "target_vuln": target,
        "code_patch": code_patch,
        "test_content": test_content,
        "review": review,
        "test_reports": test_reports,
        "attempts": max(1, attempt_no),
    }


def decide_resume(snapshot: dict, prior: dict | None,
                  target_hint: str | None = None) -> dict:
    """Earliest phase that genuinely needs to run again.

    Returns ``{"resume_from", "restored", "reason", "source_run"}`` where
    ``restored`` overlays cleanly onto ``fresh_remediation_state`` output.
    Never invents approval or test evidence: unbound or incomplete evidence
    falls back to the earlier phase.
    """
    from agents.remediation.tester import decide_verdict

    if not prior:
        return {"resume_from": "secure_coder", "restored": {},
                "reason": "No validated prior patch; starting at SecureCoder.",
                "source_run": None}

    target = prior["target_vuln"]
    if target_hint:
        from agents.remediation.secure_coder import match_hint
        if not match_hint(target, target_hint):
            return {"resume_from": "secure_coder", "restored": {},
                    "reason": f"Prior patch targets {target.get('id')}, not the "
                              f"requested {target_hint}; starting at SecureCoder.",
                    "source_run": prior["source_run"]}
    snapshot_vulns = snapshot.get("vulnerabilities") or []
    known_ids = {v.get("id") for v in snapshot_vulns if isinstance(v, dict)}
    if target.get("id") not in known_ids:
        return {"resume_from": "secure_coder", "restored": {},
                "reason": f"Prior patch targets {target.get('id')} which is not "
                          "in the current snapshot; starting at SecureCoder.",
                "source_run": prior["source_run"]}

    base_restored = {
        "target_vuln": target,
        "code_patch": prior["code_patch"],
        "attempts": prior["attempts"],
        "_resume_blocks": prior["code_patch"]["blocks"],
        "_resume_test_rel": prior["code_patch"]["test_file"],
        "_resume_test_content": prior["test_content"],
        "_resume_hash": prior["code_patch"].get("_hash"),
        "_resume_source": prior["source_run"],
    }

    review = prior.get("review")
    approved = bool((review or {}).get("approved")) if isinstance(review, dict) else False
    if not isinstance(review, dict) or not review.get("checks"):
        return {"resume_from": "reviewer",
                "restored": base_restored,
                "reason": f"Valid patch from {prior['source_run']} restored; "
                          "no review verdict yet — resuming at Reviewer.",
                "source_run": prior["source_run"]}
    if not approved:
        feedback = review.get("feedback_for_coder") or []
        restored = dict(base_restored)
        restored["feedback"] = list(feedback)[-4:]
        restored["review"] = review
        return {"resume_from": "secure_coder",
                "restored": restored,
                "reason": f"Prior review in {prior['source_run']} rejected the patch; "
                          "returning to SecureCoder with its feedback (bounded loop).",
                "source_run": prior["source_run"]}

    reports = prior.get("test_reports") or {}
    # Only evidence for THIS patch/test counts: the files were co-located
    # with the patch, and the test file name must match the patch's test.
    baseline = reports.get("baseline") if isinstance(reports, dict) else None
    exploit_before = reports.get("exploit_before") if isinstance(reports, dict) else None
    after = reports.get("after") if isinstance(reports, dict) else None
    if not isinstance(baseline, dict) or not isinstance(exploit_before, dict):
        restored = dict(base_restored)
        restored["review"] = review
        if isinstance(baseline, dict):
            restored["test_reports"] = {"baseline": baseline}
        return {"resume_from": "tester",
                "restored": restored,
                "reason": f"Reviewer approved the patch in {prior['source_run']}; "
                          "no test evidence yet — resuming at Tester.",
                "source_run": prior["source_run"]}

    verdict, _, _ = decide_verdict(baseline, exploit_before, after,
                                   exploit_test=prior["code_patch"]["test_file"])
    if verdict == "verified":
        restored = dict(base_restored)
        restored["review"] = review
        restored["test_reports"] = {k: reports[k] for k in ("baseline", "exploit_before", "after")
                                    if isinstance(reports.get(k), dict)}
        restored["test_verdict"] = "verified"
        return {"resume_from": "pr_creator",
                "restored": restored,
                "reason": f"Patch from {prior['source_run']} is already reviewer-approved "
                          "and Docker-verified; continuing to report/PR without rerunning tests.",
                "source_run": prior["source_run"]}

    # Approved but tests failed/inconclusive: Tester owns the verdict and the
    # bounded retry lives in the graph routing — resume there with evidence.
    restored = dict(base_restored)
    restored["review"] = review
    restored["test_reports"] = {k: reports[k] for k in reports if isinstance(reports.get(k), dict)}
    return {"resume_from": "tester",
            "restored": restored,
            "reason": f"Reviewer approved the patch in {prior['source_run']} but test "
                      "evidence is incomplete — resuming at Tester.",
            "source_run": prior["source_run"]}


def materialize_work_dir(repo_path: str, run_id: str, blocks: list[dict],
                         test_rel: str, test_content: str, attempt_no: int = 0) -> tuple[str, dict]:
    """Re-apply saved blocks onto a fresh clone; return (work_dir, applied).

    Raises ``PatchApplyError``/``OSError`` when the base moved or the saved
    patch no longer applies — the caller falls back to SecureCoder.
    """
    from tools.patch_apply import PatchBlock, apply_blocks
    from tools.git_cloner import force_rmtree

    work_dir = f"{repo_path}_work_resume"
    if os.path.isdir(work_dir):
        force_rmtree(work_dir)
    shutil.copytree(repo_path, work_dir,
                    ignore=shutil.ignore_patterns(
                        "node_modules", ".venv", "__pycache__",
                        ".pytest_cache"))
    parsed = [PatchBlock(file=b["file"], search=b["search"], replace=b["replace"])
              for b in blocks]
    applied = apply_blocks(work_dir, parsed)

    from tools.patch_apply import _resolve
    target = _resolve(work_dir, test_rel)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="") as handle:
        handle.write(test_content)
    return work_dir, {"diff": applied.diff, "files_changed": applied.files_changed,
                      "lines_added": applied.lines_added,
                      "lines_removed": applied.lines_removed}
