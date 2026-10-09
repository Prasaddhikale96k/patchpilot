# PROMPT 01 — Understand the codebase + run it locally

Read AGENTS.md fully. Do NOT change any logic in this step.

## Task
1. **Explore first.** Read `backend/main.py`, `backend/agents/state.py`, `backend/agents/orchestrator.py` (focus: `fix_suggester_node`, `build_graph`, `_initial_state`), `backend/agents/llm_router.py`, `backend/tools/git_cloner.py`, `backend/tools/semgrep_runner.py`, `backend/tools/bandit_runner.py`, `frontend/components/vulnsentinel/ScanProgress.tsx`, `frontend/app/scan/page.tsx`, `frontend/app/scan/[id]/page.tsx`, `frontend/lib/ws.ts`, `frontend/lib/api.ts`.
   Write `docs/ARCHITECTURE_NOTES.md` (max 60 lines): data flow, websocket message format, where the cloned repo is deleted, what fix_suggester outputs, and exactly where our new nodes (secure_coder, reviewer, tester, pr_creator) will plug in.
2. **Run it locally** (run each command yourself, paste real output, fix only environment issues):
   - Backend: `cd backend && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt -r requirements-dev.txt && python -m pytest -q`
   - `cp .env.example .env` → set `ALLOW_PRIVATE_TARGETS=false`, keep `ALLOWED_ORIGINS=http://localhost:3000`; tell me exactly which keys I must fill (GROQ_API_KEY…).
   - Start backend: `./run.sh` (or `uvicorn main:app --host 0.0.0.0 --port 8000 --reload`), check `curl localhost:8000/health`.
   - Frontend: `cd frontend && cp .env.example .env.local && npm install && npm run dev` → http://localhost:3000.
3. Hide ExamGuard from the home page / header behind `NEXT_PUBLIC_ENABLE_EXAMGUARD=false` (do not delete its code) so the UI focuses on PS1.
4. Add `CREDITS.md` (original SentinelAI by Saee Nikam / Team Zen Hackers + link; "Our additions" section to be filled as we go). Leave LICENSE untouched.
5. `git checkout -b feat/auto-remediation` and commit.

## Acceptance
Existing tests pass, frontend runs, a normal scan of any public Python repo works end-to-end from the UI (paste the agent log feed).
