"""
LLM Router — multi-provider, Groq-first with Gemini / OpenRouter / Ollama fallback.

Routing priority (all cloud providers are tried in order; first healthy one wins)
--------------------------------------------------------------------------------
1. Groq (default models: qwen/qwen3.8-27b fast, openai/gpt-oss-120b strong,
   openai/gpt-oss-20b base) — fast cloud inference; requires internet +
   GROQ_API_KEY (or GROQ_API_KEYS for rotation). Override with GROQ_MODEL
   (single pin) or GROQ_MODELS (ordered list).
2. Gemini (OpenAI-compatible endpoint
   https://generativelanguage.googleapis.com/v1beta/openai/) — requires
   GEMINI_API_KEY. Override with GEMINI_MODELS.
3. OpenRouter (https://openrouter.ai/api/v1, free tier) — requires
   OPENROUTER_API_KEY. Override with OPENROUTER_MODELS. Free models are often
   "temporarily rate-limited upstream" (429): the router skips to the next
   model immediately instead of waiting. The daily free budget is tracked and
   OpenRouter is disabled for the day below 5 remaining requests.
4. Ollama (local) — offline fallback, model auto-selected by hardware tier
   unless OLLAMA_MODEL is set explicitly.

Prompt 00a additions (speed + hardening)
----------------------------------------
- strip_reasoning(text): removes <think>…</think> blocks and leading
  "thinking" preambles (some models leak reasoning into content). Applied to
  every cloud reply before it is returned.
- Per-provider semaphores bound concurrent calls (LLM_CONCURRENCY_GROQ=4,
  LLM_CONCURRENCY_GEMINI=2, LLM_CONCURRENCY_OPENROUTER=1,
  LLM_CONCURRENCY_OLLAMA=2) and llm_pool.map() spreads concurrent prompts
  across healthy providers, each call still falling back through the chain.
- Model escalation for retries: model_for_attempt(1) → fast Groq model,
  (2) → strong Groq model, (3+) → Gemini, so a retry gets a fresh
  perspective instead of repeating the same failure.
- Permanent vs transient errors: a retired/disabled model id is disabled for
  the process lifetime; overloads get a short cooldown; auth failures rotate
  to the next key (Groq) or the next provider. A wrong key with no other
  provider still surfaces as LLMUnavailableError, never as "internal error".
- No key material ever reaches logs, reasons or the /api/llm/status payload.

System-aware Ollama model selection
------------------------------------
On startup, system_detector.detect() classifies the host as:
  high  → llama3.1:8b   (RAM ≥ 16 GB  AND  cores ≥ 8)
  mid   → llama3.2      (RAM ≥ 8 GB   AND  cores ≥ 4,  or GPU present)
  low   → phi3:mini     (anything else — lightweight, ~2.3 GB)

Override any tier's model via env vars:
  OLLAMA_MODEL          — override for ALL tiers (backward-compatible)
  OLLAMA_MODEL_LOW      — override for low tier only
  OLLAMA_MODEL_MID      — override for mid tier only
  OLLAMA_MODEL_HIGH     — override for high tier only
  SYSTEM_SPEC_OVERRIDE  — force tier:  high | mid | low

Groq failover
-------------
Groq rate-limit / network errors switch ALL subsequent calls to the next
provider. After _GROQ_RETRY_SECS (30 min) the router probes Groq again
automatically. Auth errors rotate through GROQ_API_KEYS; when every key is
rejected and no other provider serves the call, the auth fault propagates as
LLMUnavailableError (it is a config problem, not an internal error).

Groq sits behind Cloudflare, which blocks the default Python urllib
User-Agent (error 1010). This module never calls Groq over bare urllib: the
Groq SDK (httpx-based) is used for chat, and requests calls carry a real
User-Agent header.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from agents.system_detector import detect as _detect_system

logger = logging.getLogger(__name__)

# ── Module-level state ────────────────────────────────────────────────────────
# Guarded by _state_lock so concurrent LangGraph nodes / pool threads don't race.

_state_lock      = threading.Lock()
_groq_llm        = None   # kept for backward compatibility (tests reset it)
_ollama_llm      = None
_active_backend:  str        = "groq"
_groq_failed_at:  float|None = None
_GROQ_RETRY_SECS: int        = 1800   # 30 minutes

# Groq retires models on a published schedule and a retired id starts returning
# 400 rather than serving traffic, so this default has a shelf life. The one it
# replaced, llama-3.1-8b-instant, was shut down on 2026-08-16 and took the
# hosted deployment down with it.
# https://console.groq.com/docs/deprecations
_DEFAULT_GROQ_MODEL = "openai/gpt-oss-20b"

# Verified working 2026-10-09 (override with GROQ_MODELS / GROQ_MODEL).
_DEFAULT_GROQ_MODELS = (
    "openai/gpt-oss-120b",
    "qwen/qwen3.8-27b",
    "openai/gpt-oss-20b",
)

# Verified working 2026-10-09 (override with GEMINI_MODELS). gemini-2.5-*
# returns 404 ("no longer available to new users") and *-pro returns 429 (no
# free quota): both are treated as permanently disabled, not retried.
_DEFAULT_GEMINI_MODELS = (
    "gemini-3.5-flash-lite",
    "gemini-3-flash-preview",
    "gemini-3.5-flash",
)
_GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"

# Verified working 2026-10-09 on the free tier (override with
# OPENROUTER_MODELS).
_DEFAULT_OPENROUTER_MODELS = (
    "nvidia/nemotron-3-super-120b-a12b:free",
    "cohere/north-mini-code:free",
)
_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
_OPENROUTER_KEY_URL = "https://openrouter.ai/api/v1/key"

# A browser-like User-Agent: Groq's Cloudflare front returns error 1010 for
# the default Python urllib agent, so every requests call from this module
# carries a real one.
_HTTP_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "PatchForge/1.0 (security-scan workload)")

# Transient Groq errors (e.g. 429 rate limit) are retried in-place with backoff
# before failing over — this matters on hosts with no Ollama (e.g. Render), where
# a single blip would otherwise lock every scan onto a dead backend.
_GROQ_MAX_ATTEMPTS:  int   = int(os.getenv("GROQ_MAX_ATTEMPTS", "3"))
_GROQ_RETRY_BACKOFF: float = float(os.getenv("GROQ_RETRY_BACKOFF", "2.0"))

# Per-call ceiling so one hung provider cannot wedge a pool worker forever.
_LLM_TIMEOUT_SECS: float = float(os.getenv("LLM_TIMEOUT_SECS", "120"))


def _concurrency(name: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(f"LLM_CONCURRENCY_{name}", str(default))))
    except ValueError:
        return default


# Per-provider semaphores bound concurrent calls (prompt 00a load balancing).
# Rebuildable in tests by replacing entries.
_SEMAPHORES: dict[str, threading.Semaphore] = {
    "groq":       threading.Semaphore(_concurrency("GROQ", 4)),
    "gemini":     threading.Semaphore(_concurrency("GEMINI", 2)),
    "openrouter": threading.Semaphore(_concurrency("OPENROUTER", 1)),
    "ollama":     threading.Semaphore(_concurrency("OLLAMA", 2)),
}

# Model escalation for retries (prompt 00a): attempt 1 fast, attempt 2 strong,
# attempt 3+ a different provider for a fresh perspective. Env-overridable
# (read at call time so tests and .env changes apply without reimport).
_ESCALATION_DEFAULTS = ("qwen/qwen3.8-27b", "openai/gpt-oss-120b",
                        "gemini-3-flash-preview")


def model_for_attempt(attempt: int) -> tuple[str, str]:
    """Return (provider, model) for a fix attempt number (1-based)."""
    fast = os.getenv("GROQ_FAST_MODEL", _ESCALATION_DEFAULTS[0]).strip() or _ESCALATION_DEFAULTS[0]
    strong = os.getenv("GROQ_STRONG_MODEL", _ESCALATION_DEFAULTS[1]).strip() or _ESCALATION_DEFAULTS[1]
    fresh = os.getenv("ESCALATION_MODEL_3", _ESCALATION_DEFAULTS[2]).strip() or _ESCALATION_DEFAULTS[2]
    if attempt <= 1:
        return ("groq", fast)
    if attempt == 2:
        return ("groq", strong)
    return ("gemini", fresh)


# ── Permanent / transient model state ─────────────────────────────────────────
# disabled: model id (or "provider" for whole-provider disable) → reason.
# cooldowns: model id → unix timestamp until which it is skipped.

_disabled: dict[str, str] = {}
_cooldowns: dict[str, float] = {}

_OR_BUDGET = {
    "remaining": None,       # free_model_daily_requests.remaining (None = unknown)
    "checked_at": 0.0,
    "calls_since_check": 0,
    "disabled_for_day": False,
    "disable_reason": "",
}

_GEMINI_COOLDOWN_SECS = 30.0      # 503 / high demand
_OPENROUTER_COOLDOWN_SECS = 60.0  # 429 rate-limited upstream


class _TryNext(Exception):
    """Internal: skip to the next model/provider immediately, without waiting."""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ollama_model() -> str:
    """
    Return the Ollama model name to use.

    Precedence (highest first):
      1. OLLAMA_MODEL env var  — explicit user override, always wins.
      2. System-detected tier  — auto-selected lightweight/mid/full model.
    """
    explicit = os.getenv("OLLAMA_MODEL", "").strip()
    if explicit:
        return explicit
    profile = _detect_system()
    logger.debug("llm_router: system tier=%s → ollama model=%s", profile.tier, profile.ollama_model)
    return profile.ollama_model


def _scrub(text: str) -> str:
    """Remove any configured key material from text before logging/raising."""
    if not text:
        return text
    for var in ("GROQ_API_KEY", "GROQ_API_KEYS", "GEMINI_API_KEY",
                "OPENROUTER_API_KEY"):
        for secret in os.getenv(var, "").split(","):
            secret = secret.strip()
            if secret and secret in text:
                text = text.replace(secret, "***")
    return text


_THINK_BLOCK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_THINK_PREAMBLE_RE = re.compile(
    r"^(?:thinking\b.*|let me think\b.*|hmm\b.*|"
    r"\*+thinking\*+.*|thinking:.*)$",
    re.IGNORECASE,
)


def strip_reasoning(text: str) -> str:
    """
    Remove leaked chain-of-thought before returning model content.

    Drops <think>…</think> blocks anywhere in the text, then drops leading
    "thinking" preamble lines (some Gemini builds leak a thinking paragraph
    before the answer). Never returns None; non-strings pass through.
    """
    if not isinstance(text, str):
        return text
    cleaned = _THINK_BLOCK_RE.sub("", text)
    lines = cleaned.splitlines()
    kept: list[str] = []
    preamble_done = False
    for line in lines:
        if not preamble_done:
            if not line.strip():
                continue  # skip leading blanks left by block removal
            if _THINK_PREAMBLE_RE.match(line.strip()):
                continue
            preamble_done = True
        kept.append(line)
    return "\n".join(kept).strip()


def _to_oai_messages(messages: list) -> list[dict]:
    """Convert LangChain-style messages (or dicts/strings) to OpenAI roles."""
    out: list[dict] = []
    for m in messages or []:
        if isinstance(m, dict) and "role" in m:
            out.append({"role": m["role"], "content": m.get("content", "")})
            continue
        if isinstance(m, str):
            out.append({"role": "user", "content": m})
            continue
        kind = getattr(m, "type", "") or type(m).__name__.lower()
        content = getattr(m, "content", str(m))
        if "system" in kind:
            role = "system"
        elif "human" in kind or "user" in kind:
            role = "user"
        elif "ai" in kind or "assistant" in kind:
            role = "assistant"
        else:
            role = "user"
        out.append({"role": role, "content": content})
    return out


class _Reply:
    """Minimal response wrapper with .content (plus provenance for logs)."""

    def __init__(self, content: str, provider: str = "", model: str = "") -> None:
        self.content = content
        self.provider = provider
        self.model = model


# ── Key / model configuration ─────────────────────────────────────────────────

def _groq_keys() -> list[str]:
    """All configured Groq keys: GROQ_API_KEYS (rotation) + GROQ_API_KEY."""
    keys: list[str] = []
    for part in os.getenv("GROQ_API_KEYS", "").split(","):
        if part.strip():
            keys.append(part.strip())
    single = os.getenv("GROQ_API_KEY", "").strip()
    if single and single not in keys:
        keys.append(single)
    return keys


def _list_env(name: str, default: tuple[str, ...]) -> list[str]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return list(default)
    return [p.strip() for p in raw.split(",") if p.strip()]


def _groq_models() -> list[str]:
    """
    Ordered Groq models. An explicit GROQ_MODEL pin wins (single model —
    a pinned retired id raises naming itself, per the retired-model tests).
    """
    pinned = os.getenv("GROQ_MODEL", "").strip()
    if pinned:
        return [pinned]
    return _list_env("GROQ_MODELS", _DEFAULT_GROQ_MODELS)


def _gemini_models() -> list[str]:
    return _list_env("GEMINI_MODELS", _DEFAULT_GEMINI_MODELS)


def _openrouter_models() -> list[str]:
    return _list_env("OPENROUTER_MODELS", _DEFAULT_OPENROUTER_MODELS)


def _groq_configured() -> bool:
    """True when a Groq API key is present in the environment."""
    return bool(_groq_keys())


def _gemini_configured() -> bool:
    return bool(os.getenv("GEMINI_API_KEY", "").strip())


def _openrouter_configured() -> bool:
    return bool(os.getenv("OPENROUTER_API_KEY", "").strip())


def _cloud_configured() -> bool:
    return (_groq_configured() or _gemini_configured()
            or _openrouter_configured())


# ── LLM constructors ──────────────────────────────────────────────────────────

# The model + key the zero-arg _build_groq() binds (set by the iteration loop).
_groq_model_override: str | None = None
_groq_key_index: int = 0


def _build_groq():
    """
    Groq chat client bound to the currently selected model/key.

    Zero-arg so existing call sites and tests keep working; the iteration loop
    selects the model via _groq_model_override and rotates keys via
    _groq_key_index. Uses the official Groq SDK (httpx-based), never bare
    urllib, so Cloudflare does not block it with error 1010.
    """
    from groq import Groq

    keys = _groq_keys()
    if not keys:
        raise RuntimeError("GROQ_API_KEY is not configured")
    model = _groq_model_override or _groq_model()
    key = keys[_groq_key_index % len(keys)]

    client = Groq(api_key=key, timeout=_LLM_TIMEOUT_SECS)

    class _GroqClient:
        def invoke(self, messages):
            resp = client.chat.completions.create(
                model=model,
                messages=_to_oai_messages(messages),
            )
            text = (resp.choices[0].message.content or "") if resp.choices else ""
            return _Reply(strip_reasoning(text), provider="groq", model=model)

    return _GroqClient()


def _oai_chat(provider: str, model: str, messages: list) -> _Reply:
    """
    One chat completion via an OpenAI-compatible endpoint (Gemini/OpenRouter).

    For Gemini, reasoning_effort="low" is requested; if the endpoint rejects
    the parameter the call is retried once without it (silent fallback).
    """
    from openai import OpenAI

    if provider == "gemini":
        base_url = os.getenv("GEMINI_BASE_URL", _GEMINI_BASE_URL).strip() or _GEMINI_BASE_URL
        api_key = os.getenv("GEMINI_API_KEY", "").strip()
    else:
        base_url = os.getenv("OPENROUTER_BASE_URL", _OPENROUTER_BASE_URL).strip() or _OPENROUTER_BASE_URL
        api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    client = OpenAI(api_key=api_key, base_url=base_url, timeout=_LLM_TIMEOUT_SECS)
    oai_messages = _to_oai_messages(messages)

    text: str | None = None
    if provider == "gemini":
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=oai_messages,
                extra_body={"reasoning_effort": "low"},
            )
            text = (resp.choices[0].message.content or "") if resp.choices else ""
        except Exception as exc:
            if _mentions_reasoning_param(exc):
                resp = client.chat.completions.create(model=model, messages=oai_messages)
                text = (resp.choices[0].message.content or "") if resp.choices else ""
            else:
                raise
    else:
        resp = client.chat.completions.create(model=model, messages=oai_messages)
        text = (resp.choices[0].message.content or "") if resp.choices else ""
    return _Reply(strip_reasoning(text or ""), provider=provider, model=model)


def _mentions_reasoning_param(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "reasoning_effort" in msg or "reasoning" in msg and "unsupported" in msg


def _build_ollama():
    global _ollama_llm
    with _state_lock:
        if _ollama_llm is None:
            from langchain_ollama import ChatOllama
            model    = _ollama_model()
            base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
            # Ollama defaults to a 2048-token context. The exploit reasoner
            # sends the whole OWASP Top 10 reference as grounding, which very
            # nearly fills that on its own, so the JSON answer was being cut
            # off mid-string: the array never closed, no parser could recover
            # it, and every offline scan silently fell back to unenriched
            # findings. Give the answer room.
            num_ctx     = int(os.getenv("OLLAMA_NUM_CTX", "8192"))
            num_predict = int(os.getenv("OLLAMA_NUM_PREDICT", "2048"))
            logger.info("llm_router: Ollama → %s @ %s (num_ctx=%d)", model, base_url, num_ctx)
            _ollama_llm = ChatOllama(
                model=model,
                base_url=base_url,
                temperature=0,
                num_ctx=num_ctx,
                num_predict=num_predict,
            )
        return _ollama_llm


def _groq_model() -> str:
    return os.getenv("GROQ_MODEL", _DEFAULT_GROQ_MODEL).strip() or _DEFAULT_GROQ_MODEL


class LLMUnavailableError(RuntimeError):
    """
    Raised when no language model can serve a request.

    This is an operational fault, not a bug in the pipeline, and the two are
    worth telling apart: a rejected API key or an exhausted quota is fixed in
    the deployment's configuration, while an internal error is fixed in the
    code. `reason` is the short form written for whoever is looking at the
    screen, and it deliberately carries no key material and no traceback. The
    full exception still reaches the logs.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(detail or reason)
        self.reason = reason


def _status_code(exc: Exception) -> int | None:
    code = getattr(exc, "status_code", None)
    if isinstance(code, int):
        return code
    return None


def _is_model_error(exc: Exception) -> bool:
    """
    True when the provider will not serve the model it was asked for.

    A retired model id is a configuration problem with a one-line fix, but it
    arrives as a plain 400 that matches neither an auth failure nor anything
    transient, so without this it fell through to the generic handler and was
    reported as an internal error.
    """
    msg = str(exc).lower()
    return any(k in msg for k in (
        "decommissioned", "model_decommissioned", "model_not_found",
        "no longer supported", "does not exist", "has been deprecated",
    ))


def _is_auth_error(exc: Exception) -> bool:
    """True when the provider rejected the credentials it was given."""
    exc_type = type(exc).__name__.lower()
    msg = str(exc).lower()
    return ("authentication" in exc_type
            or "invalid_api_key" in msg
            or "unauthorized" in msg
            or "401" in msg
            or "403" in msg and "api" in msg and "key" in msg)


def _is_groq_error(exc: Exception) -> bool:
    """Return True only for transient errors that justify falling back to Ollama."""
    exc_type = type(exc).__name__.lower()
    msg = str(exc).lower()
    # A WRONG key is a config problem and must surface. A MISSING key is not —
    # it just means the cloud backend was never set up, so Ollama should serve
    # the request instead of the whole pipeline dying.
    if "must be set" in msg or "api_key client option" in msg:
        return True
    if "authentication" in exc_type or "invalid_api_key" in msg or "401" in msg:
        return False
    return any(k in msg or k in exc_type for k in (
        "rate_limit", "ratelimit", "429", "token", "quota", "exceeded",
        "connectionerror", "connection_error", "connection refused",
        "network", "timeout", "unreachable", "503", "service_unavailable",
    ))


def _is_gemini_dead_model(exc: Exception) -> bool:
    """
    True when Gemini permanently refuses a model: 404 "no longer available to
    new users" (gemini-2.5-*) or 429 "exceeded your current quota" with zero
    quota (*-pro on the free tier). Neither will succeed on retry — disable.
    """
    msg = str(exc).lower()
    code = _status_code(exc)
    if code == 404 and ("no longer available" in msg or "not found" in msg
                        or "not_found" in msg):
        return True
    if code == 429 and "exceeded your current quota" in msg:
        return True
    return False


def _is_overload(exc: Exception) -> bool:
    """True for 503 / high-demand overloads: short cooldown, then retryable."""
    msg = str(exc).lower()
    return (_status_code(exc) == 503
            or "high demand" in msg or "overloaded" in msg
            or "temporarily unavailable" in msg)


def _is_openrouter_upstream_limit(exc: Exception) -> bool:
    """
    True when OpenRouter's free models are "temporarily rate-limited
    upstream" (429): skip to the next model immediately, do not wait.
    """
    msg = str(exc).lower()
    return (_status_code(exc) == 429
            and ("upstream" in msg or "rate-limited" in msg
                 or "rate limited" in msg))


def _disable_model(model: str, reason: str) -> None:
    with _state_lock:
        if model not in _disabled:
            logger.warning("llm_router: disabling model %s — %s", model, reason)
            _disabled[model] = reason


def _cooldown_model(model: str, seconds: float) -> None:
    with _state_lock:
        _cooldowns[model] = time.time() + seconds
    logger.info("llm_router: model %s cooling down for %.0fs", model, seconds)


def _model_usable(model: str) -> tuple[bool, str]:
    """Return (usable, state-label) for status reporting and chain skipping."""
    with _state_lock:
        if model in _disabled:
            return False, f"disabled: {_disabled[model]}"
        until = _cooldowns.get(model, 0)
        if until > time.time():
            return False, f"cooldown {int(until - time.time())}s"
        return True, "ok"


def _groq_cooldown_elapsed() -> bool:
    return _groq_failed_at is not None and (time.time() - _groq_failed_at) > _GROQ_RETRY_SECS


# ── OpenRouter daily budget ───────────────────────────────────────────────────

def refresh_openrouter_budget(force: bool = False) -> dict:
    """
    Read the free-tier budget (GET /api/v1/key → free_model_daily_requests).

    Refreshed at most once per call unless forced; failures keep the last
    known value (unknown budget never blocks a call). Below 5 remaining,
    OpenRouter is disabled for the day.
    """
    import requests

    with _state_lock:
        if _OR_BUDGET["disabled_for_day"]:
            return dict(_OR_BUDGET)
    if not _openrouter_configured():
        return dict(_OR_BUDGET)

    key = os.getenv("OPENROUTER_API_KEY", "").strip()
    try:
        resp = requests.get(
            _OPENROUTER_KEY_URL,
            headers={"Authorization": f"Bearer {key}",
                     "User-Agent": _HTTP_UA},
            timeout=15,
        )
        data = resp.json() if resp.ok else {}
    except Exception as exc:
        logger.warning("llm_router: budget check failed: %s", _scrub(str(exc)))
        return dict(_OR_BUDGET)

    remaining = _extract_budget_remaining(data)
    with _state_lock:
        _OR_BUDGET["checked_at"] = time.time()
        if remaining is not None:
            _OR_BUDGET["remaining"] = remaining
            if remaining < 5:
                _OR_BUDGET["disabled_for_day"] = True
                _OR_BUDGET["disable_reason"] = "daily free budget exhausted"
                logger.warning(
                    "llm_router: OpenRouter daily free budget exhausted "
                    "(%s left) — disabled for the day", remaining)
    return dict(_OR_BUDGET)


def _extract_budget_remaining(data: Any) -> int | float | None:
    """Parse free_model_daily_requests.remaining from the key payload."""
    def _walk(node: Any) -> Any:
        if isinstance(node, dict):
            if "free_model_daily_requests" in node:
                inner = node["free_model_daily_requests"]
                if isinstance(inner, dict) and "remaining" in inner:
                    return inner["remaining"]
            for value in node.values():
                found = _walk(value)
                if found is not None:
                    return found
        elif isinstance(node, list):
            for item in node:
                found = _walk(item)
                if found is not None:
                    return found
        return None

    remaining = _walk(data)
    if isinstance(remaining, (int, float)):
        return remaining
    # Fallback shape: {limit, usage} on the free tier.
    try:
        if isinstance(data, dict):
            payload = data.get("data", data)
            limit = payload.get("limit")
            usage = payload.get("usage", 0)
            if isinstance(limit, (int, float)) and limit > 0:
                return max(0, limit - usage)
    except Exception:
        pass
    return None


def _openrouter_usable() -> tuple[bool, str]:
    with _state_lock:
        if _OR_BUDGET["disabled_for_day"]:
            return False, f"disabled: {_OR_BUDGET['disable_reason']}"
    if not _openrouter_configured():
        return False, "not configured"
    return True, "ok"


def _note_openrouter_call() -> None:
    """Count calls; re-check the budget after every 10 (and on first use)."""
    with _state_lock:
        _OR_BUDGET["calls_since_check"] += 1
        due = _OR_BUDGET["calls_since_check"] == 1 or _OR_BUDGET["calls_since_check"] % 10 == 0
    if due:
        refresh_openrouter_budget()


# ── Provider dispatch ─────────────────────────────────────────────────────────

def _provider_order() -> list[str]:
    """Configured, non-disabled providers in chain order (env-overridable)."""
    raw = os.getenv("LLM_PROVIDER_ORDER", "").strip()
    order = [p.strip() for p in raw.split(",") if p.strip()] or \
        ["groq", "gemini", "openrouter", "ollama"]
    usable: list[str] = []
    for provider in order:
        if provider == "groq" and _groq_configured():
            usable.append(provider)
        elif provider == "gemini" and _gemini_configured():
            usable.append(provider)
        elif provider == "openrouter" and _openrouter_usable()[0]:
            usable.append(provider)
        elif provider == "ollama":
            usable.append(provider)
    return usable


def _provider_models(provider: str) -> list[str]:
    if provider == "groq":
        return _groq_models()
    if provider == "gemini":
        return _gemini_models()
    if provider == "openrouter":
        return _openrouter_models()
    return [_ollama_model()]


def _call_provider(provider: str, model: str, messages: list) -> Any:
    """
    One call on a specific provider/model, bounded by its semaphore.

    Raises _TryNext when the model should be skipped immediately (disabled,
    cooling down, upstream rate limit, budget exhausted). Anything else
    propagates for the chain to classify.
    """
    usable, _ = _model_usable(model)
    if not usable:
        raise _TryNext(f"{model} not usable")
    if provider == "openrouter":
        ok, _ = _openrouter_usable()
        if not ok:
            raise _TryNext("openrouter disabled for the day")

    sem = _SEMAPHORES.get(provider)
    if sem is None:
        sem = _SEMAPHORES.setdefault(provider, threading.Semaphore(1))
    with sem:
        if provider == "groq":
            global _groq_model_override
            with _state_lock:
                _groq_model_override = model
            try:
                return _build_groq().invoke(messages)
            finally:
                with _state_lock:
                    _groq_model_override = None
        if provider in ("gemini", "openrouter"):
            if provider == "openrouter":
                _note_openrouter_call()
            return _oai_chat(provider, model, messages)
        return _build_ollama().invoke(messages)


# ── Public API ────────────────────────────────────────────────────────────────

def get_active_backend() -> str:
    """Return 'groq' or 'ollama'."""
    # Report the backend that would actually serve the next call. Without a key
    # that is Ollama, even before the first request has flipped the state.
    if _active_backend == "groq" and not _groq_configured():
        return "ollama"
    return _active_backend


def active_model_label() -> str:
    """Human-readable label for the currently active LLM (used in /health)."""
    if get_active_backend() == "groq":
        return f"Groq / {_groq_model()}"
    model   = _ollama_model()
    profile = _detect_system()
    return f"Ollama / {model} (tier={profile.tier}, offline)"


def get_system_profile() -> dict:
    """Return the detected system profile as a plain dict (for /health endpoint)."""
    p = _detect_system()
    return {
        "tier":         p.tier,
        "ram_gb":       p.ram_gb,
        "cpu_cores":    p.cpu_cores,
        "has_gpu":      p.has_gpu,
        "ollama_model": p.ollama_model,
    }


def get_llm_status() -> dict:
    """Provider/model health + OpenRouter budget for /api/llm/status (no keys)."""
    providers: dict[str, dict] = {}
    for provider in ("groq", "gemini", "openrouter", "ollama"):
        if provider == "groq":
            configured = _groq_configured()
            concurrency = _concurrency("GROQ", 4)
        elif provider == "gemini":
            configured = _gemini_configured()
            concurrency = _concurrency("GEMINI", 2)
        elif provider == "openrouter":
            configured = _openrouter_configured()
            concurrency = _concurrency("OPENROUTER", 1)
        else:
            configured = True  # local; availability is probed per call
            concurrency = _concurrency("OLLAMA", 2)
        models = []
        for model in _provider_models(provider) if configured else []:
            usable, state = _model_usable(model)
            models.append({"id": model, "state": state, "usable": usable})
        if provider == "openrouter":
            ok, state = _openrouter_usable()
            providers[provider] = {
                "configured": configured, "concurrency": concurrency,
                "usable": ok, "state": state, "models": models,
                "budget": {k: _OR_BUDGET[k] for k in
                           ("remaining", "checked_at", "disabled_for_day",
                            "disable_reason")},
            }
        else:
            providers[provider] = {
                "configured": configured, "concurrency": concurrency,
                "models": models,
            }
    return {
        "active_backend": get_active_backend(),
        "provider_order": _provider_order(),
        "providers": providers,
    }


def _resolve_hint(hint: Any) -> list[str]:
    """Rotate the provider order so pool workers spread across providers."""
    order = _provider_order()
    if hint is None or hint not in order:
        return order
    idx = order.index(hint)
    return order[idx:] + order[:idx]


def invoke_llm(messages: list, model: str | None = None,
               hint: str | None = None) -> Any:
    """
    Invoke the active LLM with automatic fallback.

    Flow (no `model` pin):
      - Providers are tried in chain order (Groq → Gemini → OpenRouter →
        Ollama); transient errors move to the next provider.
      - A retired/disabled model id is disabled for the process and skipped;
        overloads get a short cooldown; OpenRouter upstream 429s skip
        immediately without waiting.
      - Groq auth failures rotate through GROQ_API_KEYS; if every key is
        rejected the fault is remembered and the chain continues, so a
        working Gemini still finishes the scan.
      - `model` pins one model ("provider:id" or a bare id): the pinned
        model is tried first, then the chain continues as usual.
      - `hint` rotates the starting provider (used by llm_pool to spread
        concurrent calls; ignored for pinned models).
      - If nothing serves the call, the most actionable recorded fault is
        raised (e.g. the rejected-key error, not a generic outage); with no
        provider at all the Ollama-missing explanation is raised.
    """
    global _active_backend, _groq_failed_at, _groq_llm

    # No cloud key configured at all — Groq was never an option. Go straight
    # to the local model instead of burning the retry/backoff budget.
    if not _cloud_configured() and model is None:
        with _state_lock:
            if _active_backend != "ollama":
                logger.info("llm_router: no cloud keys set — running offline on Ollama")
                _active_backend = "ollama"
        return _invoke_ollama(messages)

    # Auto-retry Groq after cooldown
    with _state_lock:
        if _active_backend == "ollama" and _groq_cooldown_elapsed():
            logger.info("llm_router: Groq cooldown elapsed — probing Groq again")
            _active_backend = "groq"
            _groq_failed_at = None
            _groq_llm       = None   # force fresh client

    pinned: tuple[str, str] | None = None
    if model:
        pinned = _parse_model_pin(model)

    order = _resolve_hint(hint) if pinned is None else _provider_order()
    if pinned is not None:
        # Pinned model first, then the rest of the chain as fallback.
        order = [pinned[0]] + [p for p in order if p != pinned[0]]

    hard_error: LLMUnavailableError | None = None
    tried_any = False

    for provider in order:
        models = _provider_models(provider)
        if pinned is not None and provider == pinned[0]:
            models = [pinned[1]]
        for item in models:
            is_pin = (pinned is not None and provider == pinned[0]
                      and item == pinned[1])
            if not is_pin:
                usable, _ = _model_usable(item)
                if not usable:
                    continue
            tried_any = True
            try:
                if provider == "groq":
                    return _invoke_groq_with_retry(item, messages)
                return _call_provider(provider, item, messages)
            except _TryNext as exc:
                logger.debug("llm_router: skipping %s: %s", item, exc)
                continue
            except LLMUnavailableError as exc:
                # A pinned/hard fault from deeper in the stack — remember it
                # and keep trying other providers before giving up.
                if hard_error is None:
                    hard_error = exc
                continue
            except Exception as exc:
                outcome = _classify_provider_error(provider, item, exc)
                if outcome in ("next", "retry"):
                    continue
                if outcome == "hard":
                    if hard_error is None:
                        hard_error = _hard_error_for(provider, item, exc)
                    continue
                raise  # bad prompt, programming error — don't swallow

    if hard_error is not None:
        raise hard_error
    if not tried_any:
        logger.warning("llm_router: no usable provider/model left in the chain")
    return _invoke_ollama(messages)


def _parse_model_pin(model: str) -> tuple[str, str]:
    """Split "provider:id" pins; bare ids are matched against known lists."""
    if ":" in model and "/" not in model.split(":")[0]:
        provider, mid = model.split(":", 1)
        if provider in ("groq", "gemini", "openrouter", "ollama"):
            return provider, mid.strip()
    bare = model.strip()
    for provider in ("groq", "gemini", "openrouter"):
        if bare in _provider_models(provider):
            return provider, bare
    # Unknown id: assume Groq (its error taxonomy names the model either way).
    return "groq", bare


def _invoke_groq_with_retry(model: str, messages: list) -> Any:
    """Groq call with in-place retry on transient errors (existing semantics)."""
    global _active_backend, _groq_failed_at

    last_exc: Exception | None = None
    for attempt in range(_GROQ_MAX_ATTEMPTS):
        try:
            return _call_provider("groq", model, messages)
        except _TryNext:
            raise
        except Exception as exc:
            if _is_model_error(exc):
                raise  # classified by the caller (disable vs pin-error)
            if _is_auth_error(exc):
                raise  # caller rotates keys / records the hard fault
            if not _is_groq_error(exc):
                raise
            last_exc = exc
            if attempt < _GROQ_MAX_ATTEMPTS - 1:
                delay = _GROQ_RETRY_BACKOFF * (2 ** attempt)
                logger.warning(
                    "llm_router: Groq transient error (%s) — retry %d/%d in %.1fs",
                    _scrub(str(exc)), attempt + 1, _GROQ_MAX_ATTEMPTS, delay,
                )
                time.sleep(delay)
    # Retries exhausted — cool Groq down and let the chain move on.
    logger.warning(
        "llm_router: Groq unavailable after %d attempts (%s) — trying next provider",
        _GROQ_MAX_ATTEMPTS, _scrub(str(last_exc)),
    )
    with _state_lock:
        _active_backend = "ollama"
        _groq_failed_at = time.time()
    raise _TryNext(f"groq exhausted: {last_exc}")


def _classify_provider_error(provider: str, model: str, exc: Exception) -> str:
    """
    Classify a provider failure: "next" (skip, chain continues), "retry"
    (same model with the next rotated key), "hard" (recorded, chain
    continues, raised if nothing else serves), or "raise" (programming error
    — propagates immediately).
    """
    global _groq_key_index

    if provider == "groq" and _is_model_error(exc):
        if os.getenv("GROQ_MODEL", "").strip():
            # Explicit pin: the user named this model; name it back at them.
            return "hard"
        _disable_model(model, f"provider will not serve it: {_scrub(str(exc))[:120]}")
        return "next"
    if provider == "groq" and _is_auth_error(exc):
        keys = _groq_keys()
        with _state_lock:
            if _groq_key_index + 1 < len(keys):
                _groq_key_index += 1
                logger.warning("llm_router: Groq rejected a key — rotating to key #%d",
                               _groq_key_index + 1)
                return "retry"  # same model, next key (index already advanced)
        return "hard"
    if provider == "gemini":
        if _is_gemini_dead_model(exc):
            _disable_model(model, f"permanently refused: {_scrub(str(exc))[:120]}")
            return "next"
        if _is_overload(exc):
            _cooldown_model(model, _GEMINI_COOLDOWN_SECS)
            return "next"
        if _is_auth_error(exc):
            return "hard"
        if _is_model_error(exc):
            _disable_model(model, f"provider will not serve it: {_scrub(str(exc))[:120]}")
            return "next"
    if provider == "openrouter":
        if _is_openrouter_upstream_limit(exc):
            _cooldown_model(model, _OPENROUTER_COOLDOWN_SECS)
            return "next"
        if _is_overload(exc):
            _cooldown_model(model, _OPENROUTER_COOLDOWN_SECS)
            return "next"
        if _is_auth_error(exc):
            return "hard"
        if _is_model_error(exc) or _status_code(exc) == 404:
            _disable_model(model, f"provider will not serve it: {_scrub(str(exc))[:120]}")
            return "next"
    if provider == "ollama":
        return "next"  # local miss just ends the chain; tail explains
    # Groq transients that escaped the retry loop, network errors elsewhere.
    if _is_groq_error(exc) or _is_overload(exc):
        return "next"
    return "raise"


def _hard_error_for(provider: str, model: str, exc: Exception) -> LLMUnavailableError:
    """Actionable fault for auth / pinned-model failures (no key material)."""
    scrubbed = _scrub(str(exc))
    logger.error("llm_router: %s hard fault on %s (%s)", provider, model, scrubbed)
    if _is_auth_error(exc):
        if provider == "groq":
            return LLMUnavailableError(
                "The AI provider rejected the configured API key.",
                f"Groq authentication failed: {scrubbed}",
            )
        return LLMUnavailableError(
            f"The {provider} API key was rejected. Check its value and quota.",
            f"{provider} authentication failed: {scrubbed}",
        )
    if _is_model_error(exc) or "decommissioned" in scrubbed.lower():
        env_hint = {"groq": "GROQ_MODEL", "gemini": "GEMINI_MODELS",
                    "openrouter": "OPENROUTER_MODELS"}.get(provider, "")
        return LLMUnavailableError(
            f"The AI provider no longer serves the configured model "
            f"({model}). Set {env_hint} to a current one." if env_hint else
            f"The AI provider no longer serves the configured model ({model}).",
            f"{provider} rejected model {model}: {scrubbed}",
        )
    return LLMUnavailableError(
        f"The {provider} backend failed ({model}).",
        f"{provider} error on {model}: {scrubbed}",
    )


def _invoke_ollama(messages: list) -> Any:
    """Run the request on the local Ollama model, or explain why it cannot."""
    global _active_backend, _groq_failed_at

    try:
        return _build_ollama().invoke(messages)
    except Exception as exc:
        # Ollama is unavailable too (common in cloud deploys). Don't stay pinned
        # to a dead backend for the whole cooldown — revert to Groq so the next
        # call retries the cloud instead of failing fast for 30 minutes. With no
        # key configured there is nothing to revert to, so stay on Ollama and
        # keep /health honest.
        if _groq_configured():
            with _state_lock:
                _active_backend = "groq"
                _groq_failed_at = None
        raise LLMUnavailableError(_ollama_unavailable_reason(exc),
            _scrub(f"Both Groq and Ollama are unavailable.\n"
            f"Ollama error: {exc}\n")) from exc


def _ollama_unavailable_reason(exc: Exception) -> str:
    """Short reason for the screen when no local model answers (no secrets)."""
    model   = _ollama_model()
    profile = _detect_system()
    groq_state = ("rate-limited / no internet" if _groq_configured()
                  else "no GROQ_API_KEY configured")
    if _groq_configured():
        reason = ("The AI provider is rate-limited or out of quota, and no local "
                  "model is available to fall back to.")
    else:
        reason = ("No AI provider is configured and no local model is running.")
    return (reason + f" Groq: {groq_state}. "
            f"Detected system: {profile} "
            f"(ollama pull {model} to enable offline mode)")


# ── Load-balanced pool ────────────────────────────────────────────────────────

class _LLMPool:
    """
    Spread concurrent prompts across healthy providers.

    map() preserves input order (like ThreadPoolExecutor.map). Each item still
    falls back through the full chain on failure. Rotation hints give each
    task a different starting provider; per-provider semaphores bound real
    concurrency, so a slow provider cannot starve the fast ones.
    """

    def map(self, prompts: list, max_workers: int | None = None,
            fn=None, model: str | None = None) -> list:
        import inspect

        jobs = list(prompts or [])
        if not jobs:
            return []
        if fn is None:
            def fn(messages, hint=None):  # noqa: ANN001,ANN202
                return invoke_llm(messages, model=model, hint=hint)
            accepts_hint = True
        else:
            try:
                params = inspect.signature(fn).parameters
                accepts_hint = ("hint" in params
                                or any(p.kind == inspect.Parameter.VAR_KEYWORD
                                       for p in params.values()))
            except (TypeError, ValueError):
                accepts_hint = False

        order = _provider_order() or ["ollama"]
        total_permits = sum(_SEMAPHORES.get(p, threading.Semaphore(1))._value
                            if hasattr(_SEMAPHORES.get(p), "_value") else 1
                            for p in order)
        workers = max_workers or min(len(jobs), max(1, total_permits))

        def _run(item):
            index, messages = item
            hint = order[index % len(order)]
            logger.info("llm_router: pool task %d starting on %s", index, hint)
            if accepts_hint:
                return fn(messages, hint=hint)
            return fn(messages)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            return list(executor.map(_run, enumerate(jobs)))


llm_pool = _LLMPool()
