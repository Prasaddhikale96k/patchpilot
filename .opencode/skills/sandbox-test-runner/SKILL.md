---
name: sandbox-test-runner
description: How the Tester agent builds and runs the target project's test suite inside a locked-down Docker container (with venv fallback), runs baseline/exploit/after phases, and parses JUnit XML into a TestReport. Use when working on backend/app/agents/tester.py, tools/sandbox.py, Dockerfiles, or when tests hang/fail in the sandbox.
---

# Skill: Tester agent + sandbox

## Three test phases (this is the "proof" judges love)
| Phase | Code state | Runs | Expected |
|---|---|---|---|
| `baseline` | original | full suite | record pre-existing failures (do NOT blame the patch for these) |
| `exploit_before` | original + new exploit test only | exploit test | **FAIL** (proves vuln is real) |
| `after` | patched + exploit test | full suite + exploit test | **PASS**, and no test that passed in baseline now fails |

Implement with `git stash` / copying worktrees: simplest reliable approach = keep `repo_path` pristine, create `work_before/` and `work_after/` copies with `shutil.copytree(ignore=shutil.ignore_patterns('.git','node_modules','.venv','__pycache__'))`.

## Project detection
- Python: `requirements.txt` | `pyproject.toml` | `setup.py` → test cmd `python -m pytest -q --junitxml=/out/junit.xml -p no:cacheprovider`
- Node: `package.json` with `scripts.test` → `npm ci && npm test` (jest: add `--ci --reporters=default --reporters=jest-junit`). Python first; Node is stretch.

## Docker strategy (deps need network, tests must not)
1. Generate `Dockerfile.patchpilot` in the work dir:
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements*.txt pyproject.toml* setup.py* ./
RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || pip install --no-cache-dir -e . ; pip install --no-cache-dir pytest
COPY . .
```
2. `docker build -t patchpilot-<run_id> -f Dockerfile.patchpilot .` (cache image per run; reuse for before/after by mounting code instead of rebuilding).
3. Run:
```
docker run --rm --network none --memory 1g --cpus 1 --pids-limit 256
  --read-only --tmpfs /tmp
  -v <work_dir>:/app:ro -v <out_dir>:/out
  patchpilot-<run_id> sh -c "cd /app && python -m pytest -q --junitxml=/out/junit.xml -p no:cacheprovider"
```
   (if `:ro` breaks a project that writes files, retry once without `--read-only`/`:ro` and log it.)
4. `subprocess.run(..., timeout=180, capture_output=True, text=True)`; on `TimeoutExpired` → `docker kill` container (use `--name pp-<run_id>-<phase>`), report `timeout`.

## Fallback (no Docker on a teammate's Windows laptop)
`python -m venv data/venvs/<run_id>` → pip install → run pytest with `cwd=work_dir`. Emit a `log` event "Docker unavailable → running in isolated venv (less isolation)". Config flag `SANDBOX=docker|venv|auto` (auto = docker if `docker info` succeeds).

## Parse results
Use `xml.etree.ElementTree` on junit.xml → `TestReport(phase, total, passed, failed, errors, skipped, duration_s, failed_tests:[{name, message}], output_tail)`. If junit.xml missing, parse pytest summary line with regex `(\d+) passed|(\d+) failed|(\d+) error`.

## Verdict logic
```
regressions = baseline.passed_names - after.passed_names
ok = exploit_before.failed > 0 and after.failed_exploit == 0 and not regressions
```
On failure, build feedback string: which phase failed, failing test names, last 60 lines of output → appended to `state.feedback`.

## Events
`log` per phase start ("🐳 Building sandbox image…", "Running baseline: 14 tests"), `result` with all three TestReports, so the UI can render the red→green table.
