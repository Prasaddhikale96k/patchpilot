#!/usr/bin/env python
"""Verify provider keys with one tiny live call each (prompt 01b, Task A).

Loads backend/.env and, for every provider that has a key (Groq, Gemini,
OpenRouter), lists its /models endpoint and sends one tiny chat completion
("Reply with OK") using the first model in *_MODELS (Groq falls back to
GROQ_MODEL). The openai SDK (httpx-based) is used with a real User-Agent
context, because Groq's Cloudflare front blocks default-Python urllib
agents (error 1010).

Prints provider / model / latency / error-kind only. Key values are never
printed, logged or included in errors (scrubbed defensively).

Usage:
    cd backend && python scripts/check_keys.py
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PROBE = "Reply with OK"

PROVIDERS = (
    {"env": "GROQ_API_KEY", "label": "groq",
     "base_url": "https://api.groq.com/openai/v1",
     "models_env": "GROQ_MODELS", "fallback_env": "GROQ_MODEL",
     "fallback_default": "openai/gpt-oss-20b"},
    {"env": "GEMINI_API_KEY", "label": "gemini",
     "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
     "models_env": "GEMINI_MODELS", "fallback_env": "",
     "fallback_default": "gemini-3.5-flash-lite"},
    {"env": "OPENROUTER_API_KEY", "label": "openrouter",
     "base_url": "https://openrouter.ai/api/v1",
     "models_env": "OPENROUTER_MODELS", "fallback_env": "",
     "fallback_default": "cohere/north-mini-code:free"},
)


def _load_env_file(path: str) -> None:
    """Minimal .env loader (KEY=VALUE, # comments, no value printing)."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        print(f"cannot read {path}: {exc}", file=sys.stderr)
        raise SystemExit(2)
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, _, raw = stripped.partition("=")
        name = name.strip()
        value = raw.strip()
        cut = value.find(" #")
        if cut != -1:
            value = value[:cut].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if name and name not in os.environ:
            os.environ[name] = value


def _first_model(spec: dict) -> str:
    raw = os.getenv(spec["models_env"], "").strip()
    if raw:
        return [p.strip() for p in raw.split(",") if p.strip()][0]
    if spec["fallback_env"]:
        pinned = os.getenv(spec["fallback_env"], "").strip()
        if pinned:
            return pinned
    return spec["fallback_default"]


def _scrub(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        if secret and secret in text:
            text = text.replace(secret, "***")
    return text


def _error_kind(exc: Exception) -> str:
    code = getattr(exc, "status_code", None)
    msg = str(exc).lower()
    if code == 401 or "invalid_api_key" in msg or "unauthorized" in msg:
        return "auth-rejected"
    if code == 404 or "not found" in msg or "no longer available" in msg:
        return "model-not-found"
    if code == 429 or "rate" in msg or "quota" in msg:
        return "rate-limited"
    if code == 503 or "overload" in msg or "high demand" in msg:
        return "overloaded"
    if "timeout" in msg or "timed out" in msg:
        return "timeout"
    if "connection" in msg or "network" in msg or "unreachable" in msg:
        return "network"
    return f"error({code or '?'})"


def check_provider(spec: dict, secrets: list[str]) -> tuple[str, str, float, str, str]:
    """Return (label, model, seconds, mark, detail) — never any key."""
    from openai import OpenAI

    label = spec["label"]
    model = _first_model(spec)
    client = OpenAI(api_key=os.environ[spec["env"]],
                    base_url=spec["base_url"], timeout=60.0)
    start = time.perf_counter()
    try:
        listed = [m.id for m in client.models.list().data[:5]]
        hint = f"models-ok({len(listed)})"
    except Exception as exc:  # noqa: BLE001 — reported as a category only
        elapsed = time.perf_counter() - start
        return (label, model, elapsed, "FAIL",
                f"models-list: {_scrub(_error_kind(exc), secrets)}")
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": PROBE}],
            max_tokens=256,
        )
        elapsed = time.perf_counter() - start
        msg = resp.choices[0].message if resp.choices else None
        text = ((msg.content or "") if msg else "")
        if not text.strip() and msg is not None:
            # Reasoning models can leave content empty while the answer sits
            # in reasoning_content (especially with a tiny token budget).
            text = getattr(msg, "reasoning_content", "") or ""
        if "ok" in text.lower():
            return (label, model, elapsed, "OK", hint)
        return (label, model, elapsed, "FAIL",
                f"{hint} but unexpected reply: {text[:40]!r}")
    except Exception as exc:  # noqa: BLE001 — reported as a category only
        elapsed = time.perf_counter() - start
        return (label, model, elapsed, "FAIL",
                f"{hint}; chat: {_scrub(_error_kind(exc), secrets)}")


def main() -> int:
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _load_env_file(os.path.join(backend_dir, ".env"))

    configured = [s for s in PROVIDERS if os.getenv(s["env"], "").strip()]
    secrets = [os.getenv(s["env"], "") for s in configured]
    if not configured:
        print("No provider keys in backend/.env — nothing to check.")
        return 1

    print(f"{'provider':<11} {'model':<42} {'result':<6} {'time':>7}  detail")
    print("-" * 100)
    ok = 0
    for spec in configured:
        label, model, elapsed, mark, detail = check_provider(spec, secrets)
        ok += mark == "OK"
        print(f"{label:<11} {model:<42} [{mark}] {elapsed:>6.1f}s  {detail}")
    print(f"\n{ok}/{len(configured)} providers answer.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
