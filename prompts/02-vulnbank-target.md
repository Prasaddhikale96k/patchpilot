# PROMPT 02 — Build the demo target repo "vulnbank" (separate repo!)

Load skill: demo-target-builder.

## Task
Create a NEW folder OUTSIDE this repo: `../vulnbank/` (it will be its own GitHub repo). Build it exactly per the demo-target-builder skill: Flask + sqlite, 5 realistic planted vulns (CWE-89 SQLi in search, CWE-639 IDOR on /invoices/<id>, CWE-22 path traversal on /download, CWE-798 hardcoded secret, CWE-78 command injection in admin ping), and a GREEN pytest suite (~15 tests incl. the "lazy-fix catcher" tests). No security tests, no hints in comments/README.

Also add `../vulnbank/scripts/verify_vulns.py` (local only, add to .gitignore) that prints EXPLOITABLE for each vuln.

## Acceptance (paste outputs)
- `cd ../vulnbank && python -m pytest -q` → all green
- `python scripts/verify_vulns.py` → 5 × EXPLOITABLE
- `semgrep scan --config auto --json --quiet . ` finds at least SQLi / command injection / secret.
- Give me exact commands to: `git init`, first commit, create GitHub repo `<me>/vulnbank` (via `gh repo create` or website), push, and `git tag pristine && git push --tags`.
Then scan `https://github.com/<me>/vulnbank` with the existing app UI and paste which vulns SentinelAI already finds.
