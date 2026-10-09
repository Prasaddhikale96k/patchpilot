---
name: patch-reviewer
description: How the Reviewer agent validates a patch before testing — re-scanning with Semgrep/Bandit, diff-size and scope checks, and an LLM security code review returning a structured verdict. Use when working on backend/app/agents/reviewer.py or reviewer prompts.
---

# Skill: Reviewer agent

The Reviewer is a **gate**: cheap deterministic checks first, LLM review last.

## Deterministic checks (fast, no LLM)
1. **Patch applied cleanly** (from patch_apply result).
2. **Syntax check:** `python -m py_compile <each changed .py file>`; for JS `node --check`.
3. **Re-scan:** run Semgrep + Bandit only on changed files. The target finding (same rule, same file, ±5 lines) must be gone. No NEW high/critical finding introduced.
4. **Scope:** changed files ⊆ {target file, files it imports, the new test file}. Lines changed in source (excluding test) ≤ 40. Otherwise flag "patch too broad".
5. **No cheating:** reject if the patch deletes or skips existing tests, adds `# nosec`, `# nosemgrep`, `pytest.skip`, or comments out the vulnerable route.

## LLM review (structured)
Prompt role: "You are a senior application-security reviewer. Be strict but practical."
Give: finding, rationale, unified diff, the new test.
Schema:
```json
{"approved": true,
 "root_cause_fixed": true,
 "behaviour_preserved": true,
 "issues": [{"severity":"blocker|major|minor","comment":"..."}],
 "security_score": 0-10,
 "summary": "one paragraph for the PR body"}
```
Approve only if no blocker AND root_cause_fixed AND all deterministic checks pass.

## Output
`ReviewVerdict(approved, checks:[{name, passed, detail}], llm: {...}, feedback_for_coder: str)` — the checks list is rendered as a ✅/❌ checklist in the UI and the PR body.

## Routing
- Not approved → append `feedback_for_coder` to `state.feedback`, go back to Coder (if attempts < 3).
- Approved → Tester.
