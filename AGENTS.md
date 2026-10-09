# AGENTS.md — Extending SentinelAI into a full PS1 pipeline (auto-PR + Docker-verified patches)

Read this whole file before every task.

## 0. Context
- This repository is a local clone of **SentinelAI** by **Saee Nikam / Team Zen Hackers** — https://github.com/Pushpenderrathore/sentinelai. We run it **locally only** (no deployment) and extend it for our hackathon PS1.
- Do NOT delete or edit the original `LICENSE` / copyright notice or the original team section in README. Keep a `CREDITS.md` that lists what is original vs. what we added.
- All NEW code goes in NEW files where possible (`backend/agents/remediation/…`, `backend/tools/sandbox.py`, `backend/tools/github_pr.py`, `backend/tools/patch_apply.py`) so our additions are clearly separable.
- Our add-on is called `PatchForge` internally (branch prefix `patchforge/…`, Docker image prefix `patchforge-…`).

## 1. Goal (Hackathon PS1)
Turn the existing "scan → analyze → exploit reasoning → suggest fixes → report" pipeline into:
**scan → analyze → exploit reasoning → suggest fixes → SECURE CODER (real multi-line patch + exploit test) → REVIEWER (re-scan + LLM review) → TESTER (Docker: baseline / exploit-before / after) → (retry loop ≤3) → PR CREATOR (branch + commit + push + GitHub PR with rationale) → report**

## 2. Existing codebase map (do not break it)
| Path | What it is |
|---|---|
| `backend/main.py` | FastAPI app. `POST /api/scan` → `_run_scan()` background task streams `_graph.astream()` updates into a per-scan `asyncio.Queue`; `WS /ws/{scan_id}` forwards `{"type":"update","node","logs","status","scan_id"}` then `{"type":"done","report"}`. `finally: cleanup_repo(scan_id)` deletes the clone. |
| `backend/agents/state.py` | `ScanState` TypedDict. `agent_logs` is `Annotated[List[str], operator.add]` → nodes must return a NEW list of log lines only. |
| `backend/agents/orchestrator.py` | LangGraph: `orchestrator → scanner → vuln_analyzer → exploit_reasoner → fix_suggester → report_generator → END`, compiled with `MemorySaver`. Helpers: `_parse_json`, `read_source_window`, `_log`, `invoke_llm` (from llm_router). |
| `backend/agents/llm_router.py` | `invoke_llm(messages)` — Groq first, Ollama fallback, raises `LLMUnavailableError`. **Reuse it. Do not add another LLM client.** |
| `backend/tools/git_cloner.py` | `clone_repo` (https only, depth 1, into `tempfile.gettempdir()/vulnsentinel_<scan_id>`), `cleanup_repo`, `_git_bin()`. |
| `backend/tools/semgrep_runner.py`, `bandit_runner.py` | `run_semgrep(repo_path)`, `run_bandit(repo_path)` → normalized dict findings. |
| `backend/exam_agents/`, `frontend/app/exam/*`, `components/examguard/*` | ExamGuard module — **not part of PS1**. Hide it from navigation behind a flag; do not delete (keeps original intact). |
| `frontend/components/vulnsentinel/ScanProgress.tsx` | Node list shown in the UI (`key/label/description`) — new nodes must be added here. |
| `frontend/` | Next.js 14 + Tailwind 3. |

## 3. New state fields (add to ScanState, all optional with safe defaults in `_initial_state`)
```python
create_pr: bool                 # from request; when False, new nodes are skipped (original behaviour)
target_vuln: dict | None        # the ONE vulnerability chosen for an auto-PR
work_dir: str                   # patched working copy for the current attempt
code_patch: dict | None         # {rationale, blocks:[{file,search,replace}], diff, files_changed, test_file, lines_added, lines_removed}
attempts: int
feedback: list[str]             # reviewer/tester feedback for the next coder attempt (replace, don't use operator.add)
review: dict | None             # {approved, checks:[{name,passed,detail}], llm:{...}, feedback_for_coder}
test_reports: dict              # {"baseline":{...}, "exploit_before":{...}, "after":{...}}
pr_url: str | None
remediation_status: str         # "skipped" | "running" | "pr_opened" | "verified_no_pr" | "failed"
```

## 4. New graph wiring
```
fix_suggester → (create_pr and repo scan and patchable target?) → secure_coder : report_generator
secure_coder → reviewer
reviewer → approved ? tester : (attempts < MAX_FIX_ATTEMPTS ? secure_coder : report_generator)
tester  → passed   ? pr_creator : (attempts < MAX_FIX_ATTEMPTS ? secure_coder : report_generator)
pr_creator → report_generator
```
Website scans (`tech_stack.type == "website"`) never enter the new nodes.

## 5. Rules
1. Small steps; only do what the current prompt asks. Run tests after each change: `cd backend && python -m pytest -q`. The existing 300+ tests must keep passing.
2. Never `shell=True`. Use `_git_bin()` and resolved binaries like the original code does.
3. Docker runs: `--network none --memory 1g --cpus 1 --pids-limit 256`, named containers, timeout + kill.
4. Never log or emit `GITHUB_TOKEN`. Mask it in exceptions.
5. Persist run artifacts (diff, PR body, test logs, LLM transcripts) to `backend/runs/<scan_id>/` (gitignored) — the clone dir is deleted at the end of a scan.
6. Every new node returns `agent_logs` lines prefixed with its name, e.g. `[SecureCoder] …`, `[Reviewer] ✅ …`, `[Tester] 🐳 …`, `[PRCreator] …` — the UI log feed depends on it.
7. Config via `.env` (add to `backend/.env.example`): `GITHUB_TOKEN`, `MAX_FIX_ATTEMPTS=3`, `SANDBOX=auto|docker|venv`, `SANDBOX_TIMEOUT_SECS=300`, `DRY_RUN_PR=false`, raise `SCAN_TIMEOUT_SECS` to 1500.
8. The skills in `.opencode/skills/` were written for a different layout (`backend/app/...`). **Apply their logic, but use THIS repo's layout** (section 2 and 4).
9. After each task print: files changed, commands run + real output, what to test manually, known gaps.
