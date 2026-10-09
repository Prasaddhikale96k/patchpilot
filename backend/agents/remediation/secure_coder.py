"""SecureCoder node (prompt 03): real multi-line patch + exploit test.

Reads the chosen vulnerability, asks the LLM (with model escalation per
attempt) for strict RATIONALE / PATCH / TEST output in SEARCH/REPLACE
format, applies it to a pristine work copy, and persists everything to
backend/runs/<scan_id>/. Reviewer/Tester consume work_dir + code_patch in
later prompts; for now the graph routes secure_coder → report_generator.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
from pathlib import Path

from ..llm_router import invoke_llm, model_for_attempt

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "secure_coder.md"

_IMPORT_RE = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))",
                        re.MULTILINE)
_SECTION_RE = re.compile(
    r"^###\s*(RATIONALE|PATCH|TEST)\s*$\n(?P<body>.*?)(?=^###\s*\w+\s*$|\Z)",
    re.MULTILINE | re.DOTALL,
)

_PATCHABLE = ("CRITICAL", "HIGH", "MEDIUM")


def _read_prompt_template() -> str:
    return _PROMPT_PATH.read_text(encoding="utf-8")


_CWE_KEYWORDS = {
    "CWE-89": ("sql", "sqli", "injection"),
    "CWE-639": ("access control", "broken access", "idor", "owner",
                "authorization"),
    "CWE-22": ("traversal", "path traversal", "directory"),
    "CWE-78": ("command injection", "os command", "shell", "subprocess",
               "ping"),
    "CWE-798": ("hardcoded", "hard-coded", "secret", "password"),
    "CWE-306": ("missing auth", "no auth", "unauthenticated"),
}


def match_hint(vuln: dict, hint: str) -> bool:
    """True when a target_hint (CWE id or VULN id) selects this vuln."""
    needle = (hint or "").upper().strip()
    if not needle:
        return False
    if needle == (vuln.get("id") or "").upper():
        return True
    haystack = f"{vuln.get('category', '')} {vuln.get('description', '')}".upper()
    if needle in haystack:
        return True
    short = needle.replace("CWE-", "")
    for cwe, keywords in _CWE_KEYWORDS.items():
        if needle == cwe or short == cwe.replace("CWE-", ""):
            return any(k.upper() in haystack for k in keywords)
    return False


def pick_target(vulnerabilities: list[dict], repo_path: str,
                hint: str | None = None) -> tuple[dict | None, bool]:
    """Pick the vulnerability to fix. Returns (vuln, hint_matched)."""
    from ..orchestrator import read_source_window
    from .fix_queue import _priority_index

    def _readable(vuln: dict) -> bool:
        path = vuln.get("file") or ""
        if not path or path.startswith(("http://", "https://")):
            return False
        parts = path.replace("\\", "/").split("/")
        if "tests" in parts or "test" in parts:
            return False
        return read_source_window(repo_path, path,
                                  vuln.get("line", 0)) is not None

    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    candidates = [v for v in (vulnerabilities or [])
                  if isinstance(v, dict)
                  and (v.get("severity") or "").upper() in _PATCHABLE
                  and _readable(v)]
    if not candidates:
        return None, False
    if hint:
        for vuln in candidates:
            if match_hint(vuln, hint):
                return vuln, True
    candidates.sort(key=lambda v: (
        sev_rank.get((v.get("severity") or "").upper(), 99),
        _priority_index(v),
        v.get("file", ""),
        v.get("line", 0),
    ))
    return candidates[0], False


def _numbered_source(repo_path: str, rel_file: str, line: int) -> str:
    """Full file with line numbers, or ±80 lines when the file is huge."""
    target = os.path.join(repo_path, rel_file)
    with open(target, "r", encoding="utf-8", errors="replace") as handle:
        lines = handle.read().splitlines()
    if len(lines) > 400 and line:
        start = max(0, line - 1 - 80)
        end = min(len(lines), line + 80)
    else:
        start, end = 0, len(lines)
    return "\n".join(f"{n + 1:>5} | {lines[n]}" for n in range(start, end))


def _local_imports(repo_path: str, rel_file: str, limit: int = 3) -> list[str]:
    """Up to `limit` repo-local modules imported by the vulnerable file."""
    target = os.path.join(repo_path, rel_file)
    try:
        with open(target, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError:
        return []
    found: list[str] = []
    for match in _IMPORT_RE.finditer(text):
        module = (match.group(1) or match.group(2)).split(".")[0]
        if module in ("os", "sys", "json", "re", "flask", "werkzeug"):
            continue
        for candidate in (f"{module}.py", os.path.join(module, "__init__.py"),
                          os.path.join(os.path.dirname(rel_file),
                                       f"{module}.py")):
            full = os.path.join(repo_path, candidate)
            if os.path.isfile(full) and candidate not in found:
                found.append(candidate)
                break
        if len(found) >= limit:
            break
    return found


def _tests_context(repo_path: str) -> tuple[str, str, str]:
    """(tests/ file list, conftest.py content, one example test file)."""
    tests_dir = os.path.join(repo_path, "tests")
    names: list[str] = []
    if os.path.isdir(tests_dir):
        names = sorted(f for f in os.listdir(tests_dir)
                       if f.startswith("test_") and f.endswith(".py"))
    conftest, example = "", ""
    conf_path = os.path.join(tests_dir, "conftest.py")
    if os.path.isfile(conf_path):
        with open(conf_path, "r", encoding="utf-8",
                  errors="replace") as handle:
            conftest = handle.read()[:4000]
    if names:
        with open(os.path.join(tests_dir, names[0]), "r", encoding="utf-8",
                  errors="replace") as handle:
            example = f"# {names[0]}\n" + handle.read()[:4000]
    return ", ".join(names) or "(no tests/)", conftest, example


def _fix_suggester_hint(patches: list, vuln_id: str) -> str:
    for patch in patches or []:
        if isinstance(patch, dict) and patch.get("vuln_id") == vuln_id:
            hint = str(patch.get("explanation", ""))
            if patch.get("patched_code"):
                hint += f"\nSuggested fix:\n{patch['patched_code'][:1500]}"
            return hint
    return "(no matching fix_suggester patch)"


def _split_sections(text: str) -> dict[str, str]:
    sections = {m.group(1): m.group("body").strip()
                for m in _SECTION_RE.finditer(text or "")}
    missing = [name for name in ("RATIONALE", "PATCH", "TEST")
               if name not in sections]
    if missing:
        from tools.patch_apply import PatchApplyError
        raise PatchApplyError(
            f"LLM output is missing sections: {', '.join(missing)}. "
            f"Return ### RATIONALE, ### PATCH and ### TEST exactly.")
    return sections


def _short_desc(vuln: dict) -> str:
    desc = (vuln.get("description") or vuln.get("category") or "").strip()
    return (desc[:90] + "…") if len(desc) > 90 else desc


def secure_coder_node(state: dict) -> dict:
    """Write a real patch + exploit test for the target vulnerability."""
    from tools.patch_apply import PatchApplyError, apply_blocks, parse_blocks
    from tools.run_artifacts import save_text
    from .fix_queue import max_fix_attempts

    scan_id = state.get("scan_id", "unknown")
    repo_path = state.get("repo_path", "")
    max_attempts = max_fix_attempts()
    attempt = state.get("attempts", 0) or 0

    if not repo_path or not os.path.isdir(repo_path):
        return {
            "remediation_status": "failed",
            "agent_logs": ["[SecureCoder] No repo clone available — cannot patch."],
        }

    target = state.get("target_vuln")
    hint_note = ""
    if not target:
        hint = state.get("target_hint")
        target, matched = pick_target(state.get("vulnerabilities", []),
                                      repo_path, hint)
        if hint and not matched:
            hint_note = f" Hint '{hint}' matched nothing — using default selection."
    if not target:
        return {
            "remediation_status": "failed",
            "agent_logs": ["[SecureCoder] No patchable target found." + hint_note],
        }

    logs = [f"[SecureCoder] Target: {target.get('id')} {_short_desc(target)} "
            f"in {target.get('file')}:{target.get('line')}.{hint_note}"]

    # ── Context ──────────────────────────────────────────────────────
    source = _numbered_source(repo_path, target["file"], target.get("line", 0))
    imports = _local_imports(repo_path, target["file"])
    import_texts = []
    for rel in imports:
        with open(os.path.join(repo_path, rel), "r", encoding="utf-8",
                  errors="replace") as handle:
            import_texts.append(f"# --- {rel} ---\n{handle.read()[:3000]}")
    tests_list, conftest, example = _tests_context(repo_path)
    suggester_hint = _fix_suggester_hint(state.get("patches", []),
                                         target.get("id", ""))
    feedback = state.get("feedback", []) or []
    feedback_text = "\n".join(feedback[-4:]) if feedback else "(none yet)"

    prompt = (
        f"{_read_prompt_template()}\n\n"
        f"## Target vulnerability\n{json.dumps(target, indent=2)}\n\n"
        f"## Vulnerable file {target['file']} (numbered)\n{source}\n\n"
        f"## Imported local modules\n{chr(10).join(import_texts) or '(none)'}\n\n"
        f"## Tests layout: {tests_list}\n"
        f"## conftest.py\n{conftest or '(missing)'}\n\n"
        f"## Example test\n{example or '(none)'}\n\n"
        f"## fix_suggester hint\n{suggester_hint}\n\n"
        f"## Previous feedback\n{feedback_text}\n"
    )
    if attempt > 0 and feedback:
        prompt = ("Your previous patch failed. Here is exactly why:\n"
                  f"{feedback_text}\n\nFix the patch AND the test.\n\n" + prompt)
    save_text(scan_id, "secure_coder_prompt.md", prompt)

    # ── LLM (model escalation per attempt, router falls back on failure) ──
    from ..llm_router import LLMUnavailableError
    provider, model = model_for_attempt(attempt + 1)
    logs.append(f"[SecureCoder] Model: {provider}/{model} "
                f"(attempt {attempt + 1}/{max_attempts})")
    messages = [{"role": "user", "content": prompt}]
    try:
        reply = invoke_llm(messages, model=f"{provider}:{model}")
    except LLMUnavailableError as exc:
        save_text(scan_id, "secure_coder_error.txt", exc.reason)
        return {
            "attempts": attempt + 1,
            "target_vuln": target,
            "remediation_status": "failed",
            "agent_logs": logs + [f"[SecureCoder] LLM unavailable: {exc.reason}"],
        }
    raw = getattr(reply, "content", reply)
    raw = raw if isinstance(raw, str) else str(raw)
    save_text(scan_id, "secure_coder_response.md", raw)

    # ── Apply (fresh work copy; ONE self-repair on failure) ──────────
    def _fresh_work_dir() -> str:
        work_dir = f"{repo_path}_work_{attempt + 1}"
        if os.path.isdir(work_dir):
            shutil.rmtree(work_dir, ignore_errors=True)
        shutil.copytree(repo_path, work_dir,
                        ignore=shutil.ignore_patterns(
                            "node_modules", ".venv", "__pycache__",
                            ".pytest_cache"))
        return work_dir

    def _attempt_apply(blocks_text: str, test_text: str,
                       work_dir: str) -> tuple[dict, str]:
        patch_blocks = parse_blocks(blocks_text)
        applied = apply_blocks(work_dir, patch_blocks)
        test_blocks = parse_blocks(test_text)
        if len(test_blocks) != 1 or test_blocks[0].search.strip():
            raise PatchApplyError(
                "TEST section must hold exactly one new-file block "
                "(empty SEARCH).")
        test_rel = test_blocks[0].file
        test_target = os.path.join(work_dir, test_rel)
        os.makedirs(os.path.dirname(test_target), exist_ok=True)
        with open(test_target, "w", encoding="utf-8",
                  newline="") as handle:
            handle.write(test_blocks[0].replace)
        return applied, test_rel

    work_dir = _fresh_work_dir()
    try:
        sections = _split_sections(raw)
        applied, test_rel = _attempt_apply(sections["PATCH"],
                                           sections["TEST"], work_dir)
    except PatchApplyError as exc:
        logs.append(f"[SecureCoder] Patch failed to apply ({exc}); "
                    f"retrying once with the exact error.")
        repair_prompt = (
            f"{prompt}\n\nYour previous output failed to apply with this "
            f"exact error:\n{exc}\n\nReturn the FULL corrected ### RATIONALE, "
            f"### PATCH and ### TEST again.")
        try:
            repair = invoke_llm([{"role": "user", "content": repair_prompt}],
                                model=f"{provider}:{model}")
        except LLMUnavailableError as llm_exc:
            return {
                "attempts": attempt + 1,
                "target_vuln": target,
                "remediation_status": "failed",
                "agent_logs": logs + [f"[SecureCoder] LLM unavailable on repair: "
                                      f"{llm_exc.reason}"],
            }
        repair_raw = getattr(repair, "content", repair)
        repair_raw = repair_raw if isinstance(repair_raw, str) else str(repair_raw)
        save_text(scan_id, "secure_coder_repair_response.md", repair_raw)
        try:
            work_dir = _fresh_work_dir()  # first failure may be partial
            sections = _split_sections(repair_raw)
            applied, test_rel = _attempt_apply(sections["PATCH"],
                                               sections["TEST"], work_dir)
            logs.append("[SecureCoder] Repair output applied cleanly.")
        except PatchApplyError as exc2:
            save_text(scan_id, "secure_coder_error.txt", str(exc2))
            return {
                "attempts": attempt + 1,
                "target_vuln": target,
                "work_dir": work_dir,
                "remediation_status": "failed",
                "agent_logs": logs + [f"[SecureCoder] Repair failed: {exc2}"],
            }

    rationale = sections["RATIONALE"]
    code_patch = {
        "rationale": rationale,
        "blocks": [{"file": b.file, "search": b.search, "replace": b.replace}
                   for b in parse_blocks(sections["PATCH"])],
        "diff": applied.diff,
        "files_changed": applied.files_changed,
        "test_file": test_rel,
        "lines_added": applied.lines_added,
        "lines_removed": applied.lines_removed,
    }
    save_text(scan_id, "patch.diff", applied.diff)
    save_text(scan_id, "patch_blocks.json",
              json.dumps(code_patch["blocks"], indent=2))
    save_text(scan_id, "scan_meta.json", json.dumps({
        "repo_url": state.get("repo_url", ""),
        "scan_id": scan_id,
        "target_vuln": target,
        "attempt": attempt + 1,
        "model": f"{provider}/{model}",
    }, indent=2))
    with open(os.path.join(work_dir, test_rel), "r", encoding="utf-8",
              errors="replace") as handle:
        save_text(scan_id, os.path.basename(test_rel), handle.read())

    logs.append(f"[SecureCoder] Attempt {attempt + 1}/{max_attempts} — patch "
                f"applied (+{applied.lines_added} −{applied.lines_removed}), "
                f"exploit test {test_rel}")
    return {
        "code_patch": code_patch,
        "work_dir": work_dir,
        "attempts": attempt + 1,
        "target_vuln": target,
        "remediation_status": "running",
        "agent_logs": logs,
    }
