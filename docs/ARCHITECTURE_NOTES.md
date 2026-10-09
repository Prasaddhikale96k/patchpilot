# ARCHITECTURE_NOTES (Prompt 01 — read-only exploration)

## Data flow
1. `POST /api/scan {repo_url}` → `start_scan` validates SSRF via `assert_safe_target`, creates `scan_id`, spawns `_run_scan` task.
2. `_run_scan` → `_initial_state(repo_url, scan_id)` → `_graph.astream()` (LangGraph + MemorySaver).
3. Graph: `orchestrator → scanner → vuln_analyzer → exploit_reasoner → fix_suggester → report_generator → END` (scanner/vuln_analyzer have conditional shortcuts to report_generator on no findings).
4. Scanner: GitHub URL? `clone_repo` + `detect_tech_stack` + `run_bandit` (python only) + `run_semgrep` : website HTTP checks + optional port scan.
5. `vuln_analyzer` merges scanner findings (authoritative) with LLM OWASP/CVE enrichment; `exploit_reasoner` (HIGH/CRITICAL only) → `fix_suggester` (1 LLM call/vuln, capped `MAX_PATCH_TARGETS=10`) → `report_generator` (deterministic `compute_risk`, LLM prose only).

## WebSocket message format (`WS /ws/{scan_id}`, `frontend/lib/ws.ts` ignores ping/pong)
- `{"type":"update","node":<node_name>,"logs":[agent_logs],"status":<status>,"scan_id":...}` per finished node.
- `{"type":"done","scan_id":...,"report":{summary,vulnerabilities,exploits,patches,total_findings,assessed}}`.
- `{"type":"error","scan_id":...,"kind":"llm_unavailable"|"internal","message":...}`; `{"type":"ping"}` keepalive every 30s.

## Where the cloned repo is deleted
- `backend/tools/git_cloner.py`: clone → `tempfile.gettempdir()/vulnsentinel_<scan_id>` (shallow `--depth 1`, https only).
- `backend/main.py::_run_scan finally: cleanup_repo(scan_id)` → `shutil.rmtree(dest)` + sends `None` sentinel to WS queue. Never raises.

## What fix_suggester outputs
- Repo: `[{vuln_id,file,original_code (exact flagged line via read_source_window),patched_code (gutter-stripped),explanation}]`; unreadable file → no diff, explanation only.
- Website: `[{vuln_id,file(URL),remediation,explanation,source}]` — never `original/patched_code` (no source to diff).
- Static-host header case: canned `platform-constraint` remediation. Sorted by severity, capped at 10.

## Where new nodes plug in (AGENTS.md §4, no logic changed yet)
- `fix_suggester → secure_coder` iff `create_pr && tech_stack.type != website && ≥1 non-website vuln`, else `→ report_generator`.
- `secure_coder → reviewer → (approved ? tester : retry secure_coder if attempts<3 else report_generator)`.
- `tester → (passed ? pr_creator : retry secure_coder if attempts<3 else report_generator) → report_generator`.
- New state fields (`create_pr,target_vuln,work_dir,code_patch,attempts,feedback,review,test_reports,pr_url,remediation_status`) + `backend/runs/<scan_id>/` artifacts (clone dir stays deleted as above).
