# TODO — PatchForge remediation loop (prompts 03–06)

- [x] Model escalation in SecureCoder (attempt 1 fast Groq `qwen/qwen3.8-27b`, attempt 2 strong Groq `openai/gpt-oss-120b`, attempt 3 Gemini `gemini-3-flash-preview`; router falls back). Done in prompt 03.
- [ ] Docker tester (prompt 04): build image once per scan, baseline once per scan, reuse for every vulnerability/attempt; baseline-failed repos skip Docker verification with a clear log.
- [ ] Reviewer gate (prompt 05): consume `tools/scan_cache.py` for changed-file re-scans.
- [ ] PR creator (prompt 06): commit from the kept `.git` work copy; emit per-vulnerability progress (`format_remediation_progress`) over the websocket.
- [ ] Multi-vulnerability queue: `build_fix_queue` + `PARALLEL_FIX_WORKERS` exist (prompt 00a); wire the per-vulnerability secure_coder → reviewer → tester loop when the nodes land.
