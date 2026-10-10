"""Make the backend package importable from the tests directory.

Tests are hermetic: backend/.env is never loaded (main.py honours
SENTINEL_DISABLE_DOTENV) and every provider / GitHub credential is removed
from the process environment before any test module imports the app. A
test that needs a key sets a fake one with monkeypatch. Without this, a
developer's real keys turned unit tests into paid, flaky network calls.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["SENTINEL_DISABLE_DOTENV"] = "1"
for _var in ("GROQ_API_KEY", "GROQ_API_KEYS", "GEMINI_API_KEY",
             "OPENROUTER_API_KEY", "GITHUB_TOKEN", "GH_TOKEN",
             "LLM_PROVIDER_ORDER", "API_AUTH_TOKEN"):
    os.environ.pop(_var, None)
# Ollama is never reachable in tests unless a test mocks it.
os.environ.setdefault("OLLAMA_BASE_URL", "http://127.0.0.1:9")

# Runtime stores go to a throwaway directory, never the developer's data.
_TEST_DATA = tempfile.mkdtemp(prefix="sentinel-tests-")
os.environ.setdefault("SENTINEL_DATA_DIR", _TEST_DATA)
os.environ.setdefault("SENTINEL_DB_PATH", os.path.join(_TEST_DATA, "scans.db"))
os.environ.setdefault("SENTINEL_LOG_DIR", os.path.join(_TEST_DATA, "logs"))
os.environ.setdefault("RUNS_DIR", os.path.join(_TEST_DATA, "runs"))
os.environ.setdefault("HISTORY_FILE", os.path.join(_TEST_DATA, "scan_history.json"))
os.environ.setdefault("RETENTION_ARCHIVE_DIR", os.path.join(_TEST_DATA, "archive"))
os.environ.setdefault("RETENTION_AUDIT_FILE", os.path.join(_TEST_DATA, "audit.jsonl"))


import pytest as _pytest  # noqa: E402


@_pytest.fixture(autouse=True)
def _reset_llm_provider_cooldowns():
    """A 429 cooldown set in one test must not make the next test skip a provider."""
    try:
        from agents import llm_router
        llm_router._provider_cooldowns.clear()
    except Exception:
        pass
    yield
    try:
        from agents import llm_router
        llm_router._provider_cooldowns.clear()
    except Exception:
        pass
