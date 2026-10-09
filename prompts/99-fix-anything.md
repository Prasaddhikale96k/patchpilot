# PROMPT 99 — Universal debug prompt (use whenever something breaks)

Copy, fill the brackets, paste into OpenCode:

---
Something is broken. Read AGENTS.md and load the relevant skill for this area: [vuln-scanner | secure-patch-writer | sandbox-test-runner | patch-reviewer | agent-orchestrator | github-pr-creator | dashboard-ui].

**What I did:** [exact command / click]
**What I expected:** [...]
**What happened:** [paste FULL error / traceback / screenshot description]
**Run id (if any):** [id] — logs are in data/runs/<id>.events.jsonl and data/runs/<id>/llm/

Rules:
1. First reproduce the bug yourself with a command. Show the output.
2. Find the ROOT cause (explain it in 2-3 lines) before changing code.
3. Make the smallest fix. Don't refactor unrelated code.
4. Add a regression test for this bug if it is testable.
5. Re-run the reproduction + `python -m pytest -q` (and `npm run build` if frontend touched). Paste output.
6. Summarize: root cause, fix, files changed.
---
