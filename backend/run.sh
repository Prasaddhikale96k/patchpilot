#!/usr/bin/env bash
set -euo pipefail

# Load env vars (handles values containing spaces, unlike `export $(grep ...)`)
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"
WORKERS="${WORKERS:-1}"

# ENV=production → multi-worker, no auto-reload. Anything else → dev mode.
if [ "${ENV:-dev}" = "production" ]; then
  exec uvicorn main:app --host "$HOST" --port "$PORT" --workers "$WORKERS" --no-access-log
else
  exec uvicorn main:app --host "$HOST" --port "$PORT" --reload --reload-exclude "runs"
fi
