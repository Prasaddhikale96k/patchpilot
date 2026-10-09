# PROMPT 03 — State + SecureCoder node (real multi-line patch + exploit test)

Read AGENTS.md. Load skill: secure-patch-writer.

## Why
The existing `fix_suggester_node` produces one-line `original_code → patched_code` suggestions for the report. That's not enough to commit: IDOR / path-traversal fixes need multi-line edits, and we need a regression exploit test. We ADD a new node; we do NOT rewrite fix_suggester.

## Task
1. **State + request**
   - `backend/agents/state.py`: add the new fields from AGENTS.md §3.
   - `_initial_state(repo_url, scan_id=None, create_pr=False)` with safe defaults for every new field.
   - Add `create_pr: bool = False` to the scan request Pydantic model in `main.py`, pass it `start_scan → _run_scan → _initial_state`.
2. **Artifacts + cleanup**
   - New helper `backend/tools/run_artifacts.py`: `artifact_dir(scan_id) -> Path` = `backend/runs/<scan_id>/` (gitignored); `save_text(scan_id, name, text)`.
   - Extend `cleanup_repo(scan_id)` to also delete `<dest>_work_*` directories.
3. **`backend/tools/patch_apply.py`** — SEARCH/REPLACE parser + applier exactly per the skill (exact → whitespace-tolerant match, must match exactly once, path-escape guard, "closest lines" error message, unified diff via difflib). Unit tests: `backend/tests/test_patch_apply.py` (exact, whitespace, ambiguous, missing w/ closest lines, new file, `../../etc/x` rejected).
4. **`backend/agents/remediation/secure_coder.py`** — `secure_coder_node(state) -> dict`:
   - **First attempt → pick `target_vuln`:** highest-severity repo vulnerability whose file exists, not under `tests/`, readable via `read_source_window`; prefer SQLi / broken access control / path traversal / command injection / hardcoded secret (map from OWASP label + description keywords).
   - **Context:** full vulnerable file with line numbers (or ±80 lines if > 400 lines), up to 3 imported local modules (simple import regex), `tests/` file list + `conftest.py` + one example test file, the matching fix_suggester patch as a hint, and previous `feedback` (with last 60 lines of failing test output).
   - **LLM:** reuse `invoke_llm` with template `backend/agents/remediation/prompts/secure_coder.md` (role: senior secure-code engineer; canonical-fixes table from the skill; strict RATIONALE / PATCH / TEST output in SEARCH/REPLACE format; minimal diff; no new deps; exploit test must FAIL on vulnerable code and PASS after the fix; deterministic, no network).
   - **Apply:** copy the pristine clone to `<dest>_work_<attempt>` with `shutil.copytree` — KEEP `.git` (PRCreator commits from here), ignore `node_modules`, `.venv`, `__pycache__`. Apply blocks. On apply failure → ONE self-repair LLM call including the exact apply error.
   - **Return:** `code_patch`, `work_dir`, `attempts+1`, `target_vuln`, `remediation_status="running"`, and `agent_logs` like `[SecureCoder] Target: VULN-003 SQL injection in app/routes.py:42`, `[SecureCoder] Attempt 1/3 — patch applied (+4 −1), exploit test tests/test_patchforge_cwe89.py`.
   - Save prompt/response/diff to the artifacts dir.
5. **Wire it (temporary):** in `build_graph()` add node `secure_coder`; route `fix_suggester → secure_coder` when `state["create_pr"]` and repo scan and there is ≥1 non-website vuln, else → `report_generator`. For now `secure_coder → report_generator` (Reviewer/Tester come next prompts).
6. **Tests:** `backend/tests/test_secure_coder.py` with a monkeypatched `invoke_llm` returning a known-good SQLi patch for a tiny fixture repo → assert the work dir contains the parameterized query and the test file exists.

## Acceptance (paste real outputs)
- `python -m pytest -q` — all old + new tests pass.
- Scan `https://github.com/<me>/vulnbank` with `create_pr=true` via curl:
  `curl -X POST localhost:8000/api/scan -H 'content-type: application/json' -d '{"repo_url":"https://github.com/<me>/vulnbank","create_pr":true}'`
  → show the SecureCoder log lines and the saved diff from `backend/runs/<scan_id>/`.
