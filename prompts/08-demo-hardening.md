# PROMPT 08 — Demo hardening (stage insurance)

Read AGENTS.md.

## Task
1. **Replay:** save every websocket message of a scan to `backend/runs/<scan_id>/events.jsonl`. Add `POST /api/scan/replay/{scan_id}` that creates a new scan id and re-emits the saved messages with the original relative timing (cap gaps at 2 s), with `"replay": true`. Frontend shows a small REPLAY badge. Add a "Replay last successful auto-fix" button on the scan page.
2. **Demo reset script** `backend/scripts/reset_demo.py`: closes open `patchforge/*` PRs on the demo repo and deletes those branches (REST API + token from .env).
3. **Pre-flight check** `backend/scripts/preflight.py`: verifies Docker running, semgrep/bandit installed, LLM reachable (one tiny call), GitHub token valid with push rights on the demo repo, vulnbank tests green. Prints a ✅/❌ checklist. Run it before going on stage.
4. **Timeouts:** per-node soft limits (secure_coder 120 s, tester 300 s), `SCAN_TIMEOUT_SECS=1500`, friendly error messages in the UI.
5. **Docs:** README section "Auto-Remediation (our addition)" with a mermaid diagram of the new graph, setup steps (Docker, GITHUB_TOKEN), and a "What is original vs. what we added" table. Keep CREDITS.md accurate.

## Acceptance
Kill Wi-Fi (or set a wrong GROQ key) → replay still works in the UI. Preflight prints all ✅ on my machine. Paste outputs.
