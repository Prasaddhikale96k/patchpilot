# PROMPT 05 — Reviewer node (gate before testing)

Read AGENTS.md. Load skill: patch-reviewer.

## Task
1. **Targeted re-scan support:** add an optional `files: list[str] | None = None` parameter to `run_semgrep` and `run_bandit` (backward compatible — existing callers unchanged) so we can scan only changed files.
2. **`backend/agents/remediation/reviewer.py`** — `reviewer_node(state)`:
   - Deterministic checks (report each as `{name, passed, detail}`):
     1. patch applied cleanly
     2. syntax: `python -m py_compile` on each changed .py file (`node --check` for .js)
     3. re-scan changed files → the target finding (same file, ±5 lines, same category) is gone, and no NEW HIGH/CRITICAL finding
     4. scope: changed source files ⊆ {target file, its imported local modules} + the new test file; ≤ 40 changed source lines
     5. anti-cheat: reject `# nosec`, `# nosemgrep`, `pytest.skip`, `@pytest.mark.skip`, deleted/modified existing tests, commented-out routes
   - LLM review via `invoke_llm` + template `prompts/reviewer.md` (role: strict senior AppSec reviewer) returning JSON `{approved, root_cause_fixed, behaviour_preserved, issues:[{severity,comment}], security_score, summary}` parsed with the existing `_parse_json`.
   - Approve only if all deterministic checks pass AND no blocker AND root_cause_fixed.
   - Not approved → `feedback` = concise bullet list for the coder.
   - Logs: `[Reviewer] ✅ Syntax OK`, `[Reviewer] ✅ Semgrep re-scan: original finding gone`, `[Reviewer] ❌ Scope: 3 unrelated files changed`, `[Reviewer] Verdict: APPROVED (score 9/10)`.
3. **Wire final loop:** `secure_coder → reviewer → (approved ? tester : retry/report)`, `tester → (passed ? pr_creator : retry/report)`.
4. **Tests:** unit tests for each deterministic check with tiny fixture diffs; routing tests for the conditional edges (approved / rejected with attempts left / rejected with no attempts left).

## Acceptance
pytest green; a vulnbank scan shows Reviewer checklist lines in the live log; paste them.
