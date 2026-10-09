"""Tests for the load-balanced LLM pool (prompt 00a).

Uses fake providers (no network): verifies spread across providers,
semaphore bounds, failure re-routing and order preservation.
"""

from __future__ import annotations

import threading
import time

import pytest

from agents import llm_router


@pytest.fixture(autouse=True)
def reset_router_state(monkeypatch):
    monkeypatch.setattr(llm_router, "_disabled", {})
    monkeypatch.setattr(llm_router, "_cooldowns", {})
    monkeypatch.setattr(llm_router, "_groq_key_index", 0)
    monkeypatch.setattr(llm_router, "_groq_model_override", None)
    monkeypatch.setattr(llm_router, "_active_backend", "groq")
    monkeypatch.setattr(llm_router, "_groq_failed_at", None)
    monkeypatch.setenv("GROQ_API_KEY", "gsk_test")
    monkeypatch.setenv("GEMINI_API_KEY", "gem_test")
    yield


def _install_fakes(monkeypatch, fail_on=(), delay=0.05):
    """Two fake providers recording concurrency; fail_on names raise transiently."""
    state = {"current": {"groq": 0, "gemini": 0},
             "max": {"groq": 0, "gemini": 0},
             "served": [],
             "lock": threading.Lock()}

    monkeypatch.setattr(llm_router, "_provider_order",
                        lambda: ["groq", "gemini"])
    monkeypatch.setattr(llm_router, "_provider_models",
                        lambda p: [f"{p}-model"])
    monkeypatch.setattr(
        llm_router, "_SEMAPHORES",
        {"groq": threading.Semaphore(4), "gemini": threading.Semaphore(2)})

    def fake_call(provider, model, messages):
        sem = llm_router._SEMAPHORES[provider]
        with sem:
            with state["lock"]:
                state["current"][provider] += 1
                state["max"][provider] = max(state["max"][provider],
                                             state["current"][provider])
            try:
                if provider in fail_on:
                    raise Exception("service_unavailable: overloaded")
                time.sleep(delay)
                with state["lock"]:
                    state["served"].append(provider)
                return llm_router._Reply(f"reply-{messages}", provider=provider,
                                         model=model)
            finally:
                with state["lock"]:
                    state["current"][provider] -= 1

    monkeypatch.setattr(llm_router, "_call_provider", fake_call)
    return state


class TestPoolSpread:
    def test_ten_calls_split_across_providers_in_order(self, monkeypatch):
        state = _install_fakes(monkeypatch)
        prompts = [[{"role": "user", "content": f"q{i}"}] for i in range(10)]
        replies = llm_router.llm_pool.map(prompts, max_workers=6)
        assert [r.content for r in replies] == [f"reply-{p}" for p in prompts]
        assert len(state["served"]) == 10
        # Rotation hints alternate the starting provider, so both serve work.
        assert set(state["served"]) == {"groq", "gemini"}

    def test_empty_input_returns_empty(self, monkeypatch):
        _install_fakes(monkeypatch)
        assert llm_router.llm_pool.map([]) == []


class TestPoolSemaphores:
    def test_concurrency_never_exceeds_permits(self, monkeypatch):
        state = _install_fakes(monkeypatch, delay=0.08)
        monkeypatch.setattr(
            llm_router, "_SEMAPHORES",
            {"groq": threading.Semaphore(1), "gemini": threading.Semaphore(1)})
        prompts = [[{"role": "user", "content": f"q{i}"}] for i in range(6)]
        llm_router.llm_pool.map(prompts, max_workers=6)
        assert state["max"]["groq"] <= 1
        assert state["max"]["gemini"] <= 1


class TestPoolRerouting:
    def test_failing_provider_calls_get_rerouted(self, monkeypatch):
        state = _install_fakes(monkeypatch, fail_on=("groq",))
        prompts = [[{"role": "user", "content": f"q{i}"}] for i in range(4)]
        replies = llm_router.llm_pool.map(prompts, max_workers=4)
        assert len(replies) == 4
        assert set(state["served"]) == {"gemini"}
        assert all(r.provider == "gemini" for r in replies)


class TestPoolFallbackFn:
    def test_custom_fn_without_hint_param_still_works(self, monkeypatch):
        """Orchestrator fakes (lambda _m: ...) take no hint kwarg."""
        _install_fakes(monkeypatch)
        calls = []
        prompts = [["m1"], ["m2"], ["m3"]]

        def fake_fn(messages):
            calls.append(messages)
            return f"r:{messages[0]}"

        replies = llm_router.llm_pool.map(prompts, max_workers=2, fn=fake_fn)
        assert replies == ["r:m1", "r:m2", "r:m3"]
        assert sorted(calls) == [["m1"], ["m2"], ["m3"]]
