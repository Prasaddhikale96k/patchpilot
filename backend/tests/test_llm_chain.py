"""Tests for the multi-provider fallback chain (prompt 00a, Part A).

All providers are faked (no network). Keys are fake values; the suite also
asserts no key material ever leaks into status payloads or error reasons.
"""

from __future__ import annotations

import json

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
    monkeypatch.setattr(llm_router, "_OR_BUDGET", {
        "remaining": None, "checked_at": 0.0, "calls_since_check": 2,
        "disabled_for_day": False, "disable_reason": "",
    })
    monkeypatch.delenv("GROQ_API_KEYS", raising=False)
    monkeypatch.delenv("GROQ_MODELS", raising=False)
    monkeypatch.delenv("GROQ_MODEL", raising=False)
    monkeypatch.delenv("GEMINI_MODELS", raising=False)
    monkeypatch.delenv("OPENROUTER_MODELS", raising=False)
    yield


def _env(monkeypatch, **keys):
    for name in ("GROQ_API_KEY", "GEMINI_API_KEY", "OPENROUTER_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    for name, value in keys.items():
        monkeypatch.setenv(name, value)


class FakeOAI:
    """Fake _oai_chat: per-(provider, model) scripted outcomes."""

    def __init__(self, monkeypatch, script):
        self.calls: list[tuple[str, str]] = []
        self.script = script

        def fake(provider, model, messages):
            self.calls.append((provider, model))
            outcome = self.script.get((provider, model), "ok")
            if outcome == "ok":
                return llm_router._Reply("hello", provider=provider, model=model)
            raise outcome

        monkeypatch.setattr(llm_router, "_oai_chat", fake)


def _status_error(code, message):
    exc = Exception(message)
    exc.status_code = code  # noqa: B009 - mirrors openai.APIStatusError shape
    return exc


class TestGeminiMapping:
    def test_404_dead_model_disabled_and_skipped(self, monkeypatch):
        _env(monkeypatch, GEMINI_API_KEY="gem_test")
        monkeypatch.setenv("GEMINI_MODELS", "gemini-2.5-flash,gemini-3.5-flash-lite")
        script = {
            ("gemini", "gemini-2.5-flash"): _status_error(
                404, "404 models/gemini-2.5-flash is no longer available to new users"),
        }
        fake = FakeOAI(monkeypatch, script)
        reply = llm_router.invoke_llm([{"role": "user", "content": "hi"}])
        assert reply.model == "gemini-3.5-flash-lite"
        assert fake.calls[0] == ("gemini", "gemini-2.5-flash")
        assert "gemini-2.5-flash" in llm_router._disabled

    def test_503_overload_cools_down_then_skips(self, monkeypatch):
        _env(monkeypatch, GEMINI_API_KEY="gem_test")
        monkeypatch.setenv("GEMINI_MODELS", "gemini-3-flash-preview,gemini-3.5-flash-lite")
        script = {("gemini", "gemini-3-flash-preview"): _status_error(
            503, "503 high demand, try again later")}
        FakeOAI(monkeypatch, script)
        reply = llm_router.invoke_llm([{"role": "user", "content": "hi"}])
        assert reply.model == "gemini-3.5-flash-lite"
        assert "gemini-3-flash-preview" in llm_router._cooldowns


class TestOpenRouterMapping:
    def test_upstream_429_skips_immediately_with_60s_cooldown(self, monkeypatch):
        _env(monkeypatch, OPENROUTER_API_KEY="sk-or-test")
        before = __import__("time").time()
        script = {("openrouter", "nvidia/nemotron-3-super-120b-a12b:free"): _status_error(
            429, "429 temporarily rate-limited upstream")}
        FakeOAI(monkeypatch, script)
        reply = llm_router.invoke_llm([{"role": "user", "content": "hi"}])
        assert reply.provider == "openrouter"
        assert reply.model == "cohere/north-mini-code:free"
        cooldown_left = llm_router._cooldowns[
            "nvidia/nemotron-3-super-120b-a12b:free"] - before
        assert 45 < cooldown_left <= 62


class TestGroqRotationAndFallback:
    def test_auth_rotates_to_second_key(self, monkeypatch):
        _env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEYS", "gsk_bad,gsk_good")
        calls = {"n": 0}

        class AuthThenOk:
            def invoke(self, messages):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise Exception("Error code: 401 - invalid_api_key")
                return llm_router._Reply("ok-after-rotation",
                                         provider="groq", model="m")

        monkeypatch.setattr(llm_router, "_build_groq", lambda: AuthThenOk())
        reply = llm_router.invoke_llm([{"role": "user", "content": "hi"}])
        assert getattr(reply, "content", reply) == "ok-after-rotation"
        assert calls["n"] == 2
        assert llm_router._groq_key_index == 1

    def test_invalid_groq_key_falls_back_to_gemini(self, monkeypatch):
        """Acceptance scenario: GROQ_API_KEYS=invalid still finishes via Gemini."""
        _env(monkeypatch, GROQ_API_KEY="invalid", GEMINI_API_KEY="gem_test")

        class DeadGroq:
            def invoke(self, messages):
                raise Exception("Error code: 401 - invalid_api_key")

        monkeypatch.setattr(llm_router, "_build_groq", lambda: DeadGroq())
        FakeOAI(monkeypatch, {})
        reply = llm_router.invoke_llm([{"role": "user", "content": "hi"}])
        assert reply.provider == "gemini"

    def test_all_keys_rejected_and_nothing_else_serves_raises_auth(self, monkeypatch):
        _env(monkeypatch, GROQ_API_KEY="invalid")

        class DeadGroq:
            def invoke(self, messages):
                raise Exception("Error code: 401 - invalid_api_key gsk_secret_xyz")

        monkeypatch.setattr(llm_router, "_build_groq", lambda: DeadGroq())
        monkeypatch.setattr(llm_router, "_build_ollama",
                            lambda: (_ for _ in ()).throw(
                                ConnectionRefusedError("refused")))
        with pytest.raises(llm_router.LLMUnavailableError) as exc:
            llm_router.invoke_llm([{"role": "user", "content": "hi"}])
        assert "api key" in exc.value.reason.lower()
        assert "gsk_secret_xyz" not in exc.value.reason


class TestBudgetAndStatus:
    def test_budget_shape_parsed(self):
        payload = {"data": {"free_model_daily_requests": {"remaining": 3}}}
        assert llm_router._extract_budget_remaining(payload) == 3

    def test_budget_below_5_disables_openrouter(self, monkeypatch):
        _env(monkeypatch, OPENROUTER_API_KEY="sk-or-test")

        class FakeResp:
            ok = True

            def json(self):
                return {"data": {"free_model_daily_requests": {"remaining": 2}}}

        import requests
        monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
        budget = llm_router.refresh_openrouter_budget(force=True)
        assert budget["remaining"] == 2
        assert budget["disabled_for_day"] is True
        assert "openrouter" not in llm_router._provider_order()

    def test_status_contains_no_key_material(self, monkeypatch):
        _env(monkeypatch, GROQ_API_KEY="gsk_secret_xyz",
             GEMINI_API_KEY="gem_secret_xyz", OPENROUTER_API_KEY="sk-or-secret")
        dump = json.dumps(llm_router.get_llm_status())
        assert "gsk_secret_xyz" not in dump
        assert "gem_secret_xyz" not in dump
        assert "sk-or-secret" not in dump
        assert llm_router.get_llm_status()["providers"]["groq"]["configured"] is True
