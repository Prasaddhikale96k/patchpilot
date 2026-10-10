# PatchPilot

**Scanners find suspects. We prove the crime, fix it, prove the fix, and file the PR.**

PatchPilot is a multi-agent security tool. It scans a GitHub repository, writes a
fix and an exploit test, runs both in a locked-down Docker sandbox, and opens a pull
request that carries the evidence. A human always reviews and merges.

## How it works

```
Clone -> Bandit | Semgrep | Logic Auditor | Secrets (parallel)
      -> Specialist squad: Injection | AccessControl | Secrets&Config (parallel)
      -> Secure Coder -> Reviewer -> Tester (Docker) -> Pull request
```

| Stage | What it does |
|---|---|
| Scanner squad | Bandit, Semgrep and a secrets scan, plus an LLM Logic Auditor that finds IDOR and path traversal. |
| Specialist squad | Analyzer, exploit reasoner and fix suggester run per bug family at the same time. |
| Secure Coder | Writes a patch and an exploit test. Retries learn from the Reviewer and Tester. |
| Reviewer | Deterministic checks (applied, syntax, re-scan, scope, anti-cheat) plus an LLM review. |
| Tester | Baseline tests, the exploit on the original code (must fail), then the patched code (must pass), in Docker with no network. |
| PR Creator | Opens a pull request with the diff, CWE, test evidence and reviewer checklist. |

Proof, not promises: a fix is only called verified when the exploit test fails before
the patch and passes after it, with no regressions.

## Quick start (Windows)

Requirements: Python 3.11+, Node 22, Docker Desktop, and at least one LLM key
(Groq, Gemini or OpenRouter) or a local Ollama model.

```powershell
cd backend
copy .env.example .env        # add your keys; never commit .env
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
cd ..
.\dev.ps1                     # starts the backend (:8000) and the frontend (:3000)
```

Open http://localhost:3000. Use **Run a scan**, or **Watch demo** for an offline replay.

To open pull requests, set `PR_CREATION_ENABLED=true`, `GITHUB_TOKEN` and
`PR_ALLOWED_REPOS=<owner>/<repo>` in `backend/.env`. `DRY_RUN_PR=true` writes the PR
body without pushing anything.

## Speed

`PARALLEL_AGENTS=1` (default) runs the scanners and the specialist squad
concurrently; `0` restores the sequential path. Measured numbers and the honest
caveats are in [docs/PERF.md](docs/PERF.md). Benchmark with
`backend/scripts/bench_scan.py <repo_url>`.

## Deploy

See [DEPLOY.md](DEPLOY.md). The Docker test sandbox needs a host with Docker, so a
hosted copy can scan and replay demos but cannot verify fixes without a Docker host.

## Tests

```powershell
cd backend; .venv\Scripts\python -m pytest -q
cd ..\frontend; npx tsc --noEmit; npm run build
```

## Origins and license

PatchPilot is built on top of an open-source multi-agent scanning project
(the original scan, analysis and report pipeline, and the ExamGuard module,
which is hidden from navigation). That work belongs to its original authors.
See [CREDITS.md](CREDITS.md) for who they are and what was added here, and
[LICENSE](LICENSE), which stays in this repository. The original documentation is
kept under [docs/original/](docs/original/).

Everything described in "How it works" beyond the original scan, analysis and
report pipeline (the remediation loop, Docker verification, PR creation, the
parallel squad, and this UI) is new work in this repository.
