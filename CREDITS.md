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
- [ ] Prompt 02 — `vulnbank` demo target repo (separate repo).
- [ ] Prompt 03 — SecureCoder node (multi-line patch + exploit test).
- [ ] Prompt 04 — Docker sandbox + Tester node (red → green proof).
- [ ] Prompt 05 — Reviewer node (re-scan + LLM review gate).
- [ ] Prompt 06 — PRCreator node (branch → commit → push → PR).
- [ ] Prompt 07 — Frontend remediation UI (toggle, pipeline nodes, proof table, PR card).
- [ ] Prompt 08 — Demo hardening (replay, reset script, preflight).
