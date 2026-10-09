# PROMPT 04 — Docker sandbox + Tester node (the red → green proof)

Read AGENTS.md. Load skill: sandbox-test-runner.

## Task
1. **`backend/tools/sandbox.py`**
   - `docker_available()` (runs `docker info`, cached); resolve `SANDBOX=auto|docker|venv` (auto → docker if available, else venv; log which one was used).
   - `detect_project(code_dir)` → `"python"` (requirements.txt / pyproject.toml / setup.py) or `"node"` (package.json with `scripts.test`). Python is the must-have; Node is stretch.
   - `prepare_image(scan_id, code_dir) -> tag`: generate `Dockerfile.patchforge` in a temp build context containing ONLY dependency files (requirements*.txt, pyproject.toml, setup.py) and install deps + pytest. Build ONCE per scan WITH network (deps need it). Tag `patchforge-<scan_id>`. On failure return the last 40 lines of build output.
   - `run_tests(scan_id, phase, code_dir, selector=None) -> dict` (TestReport: `phase, total, passed, failed, errors, skipped, duration_s, passed_names, failed_tests:[{name,message}], output_tail, sandbox`). Docker command:
     ```
     docker run --rm --name pf-<scan_id>-<phase> --network none --memory 1g --cpus 1 --pids-limit 256
       -v <code_dir>:/app -v <out_dir>:/out -w /app patchforge-<scan_id>
       python -m pytest -q -p no:cacheprovider --junitxml=/out/junit.xml [selector]
     ```
     `subprocess.run(list, timeout=SANDBOX_TIMEOUT_SECS)`; on timeout `docker kill pf-…` and mark `timeout`. Parse junit with ElementTree; fall back to regex on pytest's summary line.
   - **Windows note:** if backend runs on Windows natively, convert paths for `-v` correctly (`Path.resolve()`, Docker Desktop accepts `C:\…`). Recommend WSL2 in the docs.
   - **venv fallback** with the identical return shape.
   - `remove_image(scan_id)` called from cleanup.
2. **`backend/agents/remediation/tester.py`** — `tester_node(state)`:
   - `baseline`: pristine clone, full suite. Cache it in state (`test_reports["baseline"]`) — run only once per scan even across retries.
   - `exploit_before`: a temp copy of the pristine clone + ONLY the new exploit test file → run only that file → MUST fail.
   - `after`: `work_dir` (patched + test) → full suite → exploit test must pass and no test that passed in baseline may fail (`regressions = baseline.passed_names - after.passed_names`).
   - Verdict + feedback: if exploit_before passed → feedback "Your exploit test does not reproduce the vulnerability on the original code — rewrite it so it fails on the vulnerable code." If after failed → failing test names + last 60 lines of output. Put feedback in `feedback` (replace list).
   - Logs: `[Tester] 🐳 Building sandbox image…`, `[Tester] Baseline: 15/15 passed`, `[Tester] Exploit test on ORIGINAL code: ❌ failed (vulnerability reproduced)`, `[Tester] After patch: 16/16 passed · 0 regressions ✅`.
   - Save junit + logs to artifacts.
3. **Wire:** `secure_coder → tester` for now (reviewer comes next): `tester → pr_creator placeholder → report_generator` if passed; `→ secure_coder` if failed and `attempts < MAX_FIX_ATTEMPTS`; else `→ report_generator`. Use a placeholder `pr_creator` node that just logs "[PRCreator] (not implemented yet)".
4. **Tests:** `test_sandbox_junit.py` (pass/fail/error/skip XML samples), `test_tester_verdict.py` (pure verdict logic with fake reports), a `@pytest.mark.docker` integration test that runs a tiny 2-test python project in Docker (skipped if Docker unavailable).

## Acceptance (paste real outputs)
- `docker images | grep patchforge` shows the image during a run; `docker ps` shows `pf-…` containers while tests run.
- Full curl scan of vulnbank with `create_pr=true` → Tester logs show the red → green proof. If the first attempt fails and the retry loop kicks in, show that too.
- All pytest green.
