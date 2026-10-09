---
name: secure-patch-writer
description: How the Coder agent writes minimal, correct security patches using SEARCH/REPLACE blocks, plus a regression exploit test that fails before the fix and passes after. Use when working on backend/app/agents/coder.py, tools/patch_apply.py, coder prompts, or when a patch fails to apply or breaks tests.
---

# Skill: Coder agent (secure patch + exploit test)

## Principles
1. **Minimal diff.** Fix the vulnerability, nothing else. No renames, no reformatting, no new dependencies unless unavoidable.
2. **Preserve behaviour** for legitimate inputs — existing tests must keep passing.
3. **Fix the root cause**, not the symptom (parameterized queries, not string escaping; ownership check, not hiding a button).
4. **Prove it** with an exploit test.

## Context to give the LLM
- Target `Finding` (cwe, message, exploit_scenario).
- Full content of the vulnerable file (if < 400 lines; else ±80 lines around the finding with line numbers).
- Files imported by it that define auth/db helpers (resolve with simple import regex, max 3 files).
- Existing test layout: list `tests/` files + full content of ONE existing test file (so the new test matches style, fixtures like `client`, `app`, `login()` helper).
- Previous attempt feedback (`state.feedback`) if `attempts > 0` — include the failing test output tail (last 60 lines).

## Output format (ask for exactly this, parse strictly)
```
### RATIONALE
<2-5 sentences: what was wrong, why the fix works, CWE id>

### PATCH
FILE: app/routes.py
<<<<<<< SEARCH
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
=======
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
>>>>>>> REPLACE

### TEST
FILE: tests/test_security_patchpilot_<cwe>.py
<<<<<<< SEARCH
=======
<full content of the new test file>
>>>>>>> REPLACE
```
An empty SEARCH section means "create new file".

## patch_apply.py rules
- Parse all `FILE:` + SEARCH/REPLACE blocks with a regex; multiple blocks per file allowed, applied in order.
- Match strategy: (1) exact substring, must occur exactly once; (2) whitespace-normalized line match (strip trailing spaces, normalize tabs); (3) fail with a precise error: `"SEARCH block 2 for app/routes.py not found. Closest lines: 41-44: ..."` — this error goes back to the Coder as feedback.
- Never write outside repo root (resolve path, check `is_relative_to`).
- Produce a unified diff with `difflib.unified_diff` for the UI and PR body; store `Patch(files_changed, diff, rationale, test_file, lines_added, lines_removed)`.

## Canonical fixes (put in the prompt as guidance)
| CWE | Bad | Good |
|---|---|---|
| CWE-89 SQLi | f-string / `%` / `+` in SQL | DB-API placeholders `?`/`%s`, or ORM filter |
| CWE-639 IDOR | `Model.query.get(id)` with no owner check | `if obj.owner_id != current_user.id and not current_user.is_admin: abort(403)` |
| CWE-22 Path traversal | `open(os.path.join(BASE, name))` | `p = (BASE / name).resolve(); if not p.is_relative_to(BASE.resolve()): abort(400)` or `werkzeug.utils.secure_filename` |
| CWE-78 Cmd injection | `os.system(f"ping {host}")`, `shell=True` | `subprocess.run(["ping","-c","1",host], shell=False)` + validation |
| CWE-798 Hardcoded secret | `SECRET_KEY="abc123"` | `os.environ.get("SECRET_KEY")` with safe dev fallback that is random, + `.env.example` |
| CWE-502 Deserialization | `pickle.loads(user_data)` | `json.loads` |

## Exploit test rules
- Uses the project's own test client/fixtures.
- Asserts the **secure** behaviour: e.g. SQLi payload `' OR '1'='1` must NOT return other users' rows; user A requesting `/invoices/<B's id>` must get 403/404; `../../etc/passwd` must get 400/404.
- Must FAIL on the unpatched code and PASS on the patched code — Tester verifies both. If it passes on unpatched code, the test is useless → feedback "exploit test did not reproduce the vulnerability".
- No network, no sleeps, deterministic, < 2s.

## Retry behaviour
On attempt 2+, start the prompt with: "Your previous patch failed. Here is exactly why: ..." and include reviewer issues + test failure tail. Lower temperature to 0.1.
