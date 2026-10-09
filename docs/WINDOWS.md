# Windows setup (native PowerShell, no WSL required)

## Prerequisites

- Python 3.11+ (`python --version`)
- Node.js 18+ (`node -v`)
- Docker Desktop running (`docker info` prints a server version)
- First run only: `docker pull semgrep/semgrep:latest` (the scanner pulls it
  automatically when missing, but pre-pulling avoids a long first scan)

## Start

```powershell
# From the repo root — backend + frontend in two windows:
.\dev.ps1

# Or individually:
cd backend; .\run.ps1        # → http://127.0.0.1:8000, docs at /docs
cd frontend; npm install; npm run dev   # → http://localhost:3000
```

`backend\run.ps1` reads `HOST`/`PORT` from `backend\.env` when present
(defaults `127.0.0.1:8000`).

## Semgrep on Windows

The `semgrep` pip package refuses to install on Windows, so repo scans use
the `semgrep/semgrep:latest` Docker image (`SEMGREP_MODE=auto` → native
binary when present, else Docker, else a clear error). The repo is
bind-mounted read-only; paths are reported with forward slashes (`-v`
needs the `C:/…` form — backslashes fail, verified). Force one engine with
`SEMGREP_MODE=native|docker` in `backend\.env`.

## Common errors

| Error | Fix |
|---|---|
| `Semgrep unavailable: install it in WSL or start Docker Desktop` | Start Docker Desktop and wait for `docker info` to answer |
| `docker: Error response from daemon …is not shared` / file-sharing error | Docker Desktop → Settings → Resources → File sharing: add `C:\` (or the drive holding `%TEMP%`), Apply & restart |
| Scan fails `llm_unavailable` | Set a real `GROQ_API_KEY` in `backend\.env` (or run Ollama); run `python scripts/check_keys.py` |
| Port 8000/3000 busy | An old server is still running: stop its window or `Stop-Process -Name python,node` selectively |
| `npm run dev` shows the onrender placeholder API | `frontend\.env.local` must point at `http://localhost:8000` (dev.ps1 setup does this) |
