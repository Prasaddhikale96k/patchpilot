# Credits

## Original work — SentinelAI by Team Zen Hackers

This project is built on **SentinelAI** by **Saee Nikam / Team Zen Hackers**:

- Repository: https://github.com/Pushpenderrathore/sentinelai
- Team: Saee Nikam (Team Lead), Pushpender Singh (Backend · Agent Pipelines), Vaibhav Haval (Frontend · UI/UX), Shreya Magadum (ML · Integration), Sonika Kaswan (QA · Presentation)
- License: MIT (see `LICENSE` — left untouched)

The original provides the scan → analyze → exploit-reasoning → fix-suggestion → report pipeline (VulnSentinel), the ExamGuard module (kept in the repo but hidden from navigation for this work), and all base frontend/backend code.

## Our additions (PatchForge — PS1 auto-remediation)

_To be filled as we go (Prompts 02–08):_

- [x] Prompt 01 — Local setup, architecture notes (`docs/ARCHITECTURE_NOTES.md`), ExamGuard hidden behind `NEXT_PUBLIC_ENABLE_EXAMGUARD`, this file.
- [x] Prompt 00a — Multi-provider LLM router (Groq multi-key rotation + Gemini + OpenRouter + Ollama), `strip_reasoning`, per-provider semaphores + `llm_pool.map`, parallel Semgrep+Bandit, fix-queue ranking + retry escalation, `scripts/llm_check.py`, `/api/llm/status`. Remediation-loop wiring plugs in with prompts 03–06.
- [x] Prompt 01b — Windows support (`backend/run.ps1`, `dev.ps1`, `docs/WINDOWS.md`), Semgrep via Docker (`SEMGREP_MODE=auto|native|docker`, rules-cache volume), key tooling (`scripts/merge_env.py`, `scripts/check_keys.py`), first verified end-to-end scan (Vulnerable-Flask-App: Bandit 18 + Semgrep 26 → 35 vulns → 10 patches → CRITICAL 100/100).
- [x] Prompt 02 — `vulnbank` demo target (separate repo `Prasaddhikale96k/vulnbank`, tag `pristine`): Flask invoice portal, 5 planted vulns, 22 green tests, local-only `verify_vulns.py`; token-based `gh_run.py`/`git_push.py` helpers (no `gh` login needed).
- [ ] Prompt 03 — SecureCoder node (multi-line patch + exploit test).
- [ ] Prompt 04 — Docker sandbox + Tester node (red → green proof).
- [ ] Prompt 05 — Reviewer node (re-scan + LLM review gate).
- [ ] Prompt 06 — PRCreator node (branch → commit → push → PR).
- [ ] Prompt 07 — Frontend remediation UI (toggle, pipeline nodes, proof table, PR card).
- [ ] Prompt 08 — Demo hardening (replay, reset script, preflight).
