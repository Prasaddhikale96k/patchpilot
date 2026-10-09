#!/usr/bin/env python
"""
LLM verification matrix (prompt 00a acceptance).

Probes every configured model with one tiny call and prints a ✅/❌ table.
Keys are never printed, logged or committed — only provider + model names,
latency and the error category appear. Exit 1 when no model answers (so a
demo setup can gate on it), 0 otherwise.

Usage:
    cd backend && python scripts/llm_check.py
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents import llm_router  # noqa: E402

PROBE = "Reply with exactly: ok"


def _check(provider: str, model: str) -> tuple[str, float, str]:
    """Return (ok|fail|skip, seconds, detail) for one model. Detail is scrubbed."""
    start = time.perf_counter()
    try:
        reply = llm_router.invoke_llm(
            [{"role": "user", "content": PROBE}],
            model=f"{provider}:{model}",
        )
        elapsed = time.perf_counter() - start
        # The pin falls back through the chain: an ok from a DIFFERENT model
        # must not be attributed to the pinned one.
        served = getattr(reply, "model", None)
        if served is None and provider == "ollama":
            served = model  # langchain reply carries no provenance; chain is ollama-only here
        if served is not None and served != model:
            return "fail", elapsed, f"answered by {served} instead"
        content = getattr(reply, "content", reply)
        text = llm_router.strip_reasoning(content if isinstance(content, str) else str(content))
        if "ok" in text.lower():
            return "ok", elapsed, text[:60]
        return "fail", elapsed, f"unexpected reply: {text[:60]!r}"
    except llm_router.LLMUnavailableError as exc:
        return "fail", time.perf_counter() - start, exc.reason
    except Exception as exc:  # programming/config fault — still scrubbed
        return "fail", time.perf_counter() - start, llm_router._scrub(str(exc))[:100]


def main() -> int:
    status = llm_router.get_llm_status()
    rows: list[tuple[str, str, str, float, str]] = []
    for provider, info in status["providers"].items():
        if provider == "ollama":
            continue  # local model probed separately below
        if not info.get("configured"):
            for model in info.get("models", []) or llm_router._provider_models(provider):
                mid = model["id"] if isinstance(model, dict) else model
                rows.append((provider, mid, "skip", 0.0, "not configured"))
            continue
        for model in info.get("models", []):
            if not model.get("usable", True):
                rows.append((provider, model["id"], "skip", 0.0, model.get("state", "")))
                continue
            state, elapsed, detail = _check(provider, model["id"])
            rows.append((provider, model["id"], state, elapsed, detail))

    # Ollama: probe only if no cloud model answered (it is the fallback).
    cloud_ok = any(r[2] == "ok" for r in rows)
    ollama_model = llm_router._ollama_model()
    if not cloud_ok:
        state, elapsed, detail = _check("ollama", ollama_model)
        rows.append(("ollama", ollama_model, state, elapsed, detail))
    else:
        rows.append(("ollama", ollama_model, "skip", 0.0, "cloud provider ok"))

    print(f"{'provider':<11} {'model':<42} {'result':<6} {'time':>7}  detail")
    print("-" * 100)
    for provider, model, state, elapsed, detail in rows:
        # ASCII marks: Windows consoles (cp1252) cannot encode emoji.
        mark = {"ok": "[OK]", "fail": "[FAIL]", "skip": "[SKIP]"}.get(state, "[?]")
        print(f"{provider:<11} {model:<42} {mark} {elapsed:>6.1f}s  {detail}")

    budget = status["providers"].get("openrouter", {}).get("budget", {})
    if budget and budget.get("remaining") is not None:
        print(f"\nOpenRouter free budget remaining: {budget['remaining']}")

    if cloud_ok or any(r[0] == "ollama" and r[2] == "ok" for r in rows):
        print("\nAt least one model answers — scans can run.")
        return 0
    print("\nNo model answers. Set GROQ_API_KEY (console.groq.com), "
          "GEMINI_API_KEY, OPENROUTER_API_KEY, or run Ollama (ollama pull "
          f"{ollama_model}).")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
