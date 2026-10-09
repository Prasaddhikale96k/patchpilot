"""
Tests for LLM backend selection.

Covers a real failure: with no GROQ_API_KEY, ChatGroq raised at construction
time and the exception propagated instead of failing over, so every scan died
on a machine with no key. A missing key means the cloud backend was never set
up; a wrong key is a config error that must still surface.
"""

from __future__ import annotations

import pytest

from agents import llm_router


@pytest.fixture(autouse=True)
def reset_router_state(monkeypatch):
    """The router keeps module-level state; reset it around every test."""
    monkeypatch.setattr(llm_router, "_active_backend", "groq")
    monkeypatch.setattr(llm_router, "_groq_failed_at", None)
    monkeypatch.setattr(llm_router, "_groq_llm", None)
    yield


class TestGroqConfigured:
    def test_missing_key(self, monkeypatch):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        assert llm_router._groq_configured() is False

    def test_blank_key_counts_as_missing(self, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "   ")
        assert llm_router._groq_configured() is False

    def test_present_key(self, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "gsk_example")
        assert llm_router._groq_configured() is True


class TestActiveBackend:
    def test_reports_ollama_when_no_key(self, monkeypatch):
        """/health must not claim Groq when Groq cannot possibly serve a call."""
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        assert llm_router.get_active_backend() == "ollama"
        assert "Ollama" in llm_router.active_model_label()

    def test_reports_groq_when_key_present(self, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "gsk_example")
        assert llm_router.get_active_backend() == "groq"
        assert "Groq" in llm_router.active_model_label()


class TestErrorClassification:
    def test_missing_key_error_triggers_fallback(self):
        exc = Exception(
            "The api_key client option must be set either by passing api_key "
            "to the client or by setting the GROQ_API_KEY environment variable"
        )
        assert llm_router._is_groq_error(exc) is True

    def test_invalid_key_does_not_trigger_fallback(self):
        """A wrong key is a config problem and must surface, not be swallowed."""
        assert llm_router._is_groq_error(Exception("invalid_api_key")) is False

    def test_401_does_not_trigger_fallback(self):
        assert llm_router._is_groq_error(Exception("Error code: 401")) is False

    @pytest.mark.parametrize("msg", [
        "rate_limit_exceeded",
        "Error code: 429",
        "quota exceeded for this month",
        "service_unavailable",
    ])
    def test_transient_errors_trigger_fallback(self, msg):
        assert llm_router._is_groq_error(Exception(msg)) is True

    def test_connection_error_type_triggers_fallback(self):
        class APIConnectionError(Exception):
            pass

        assert llm_router._is_groq_error(APIConnectionError("Connection error.")) is True

    def test_unrelated_error_does_not_trigger_fallback(self):
        assert llm_router._is_groq_error(ValueError("bad prompt")) is False


class TestRoutingWithoutKey:
    def test_no_key_skips_groq_entirely(self, monkeypatch):
        """Without a key the router must not construct a Groq client at all."""
        monkeypatch.delenv("GROQ_API_KEY", raising=False)

        def _fail(*_args, **_kwargs):
            raise AssertionError("Groq client must not be built without a key")

        monkeypatch.setattr(llm_router, "_build_groq", _fail)
        monkeypatch.setattr(
            llm_router, "_build_ollama",
            lambda: type("M", (), {"invoke": lambda self, m: "ollama-reply"})(),
        )
        assert llm_router.invoke_llm(["hi"]) == "ollama-reply"
        assert llm_router.get_active_backend() == "ollama"


class TestUnavailableIsDistinctFromCrash:
    """
    A dead API key and a bug in the pipeline both used to reach the browser as
    "Scan failed due to an internal error", so the only way to tell an
    operational fault from a code fault was to read the server logs. These pin
    the distinction that makes the failure legible.
    """

    def test_auth_errors_are_recognised(self):
        class AuthenticationError(Exception):
            pass

        assert llm_router._is_auth_error(AuthenticationError("nope"))
        assert llm_router._is_auth_error(Exception("Error code: 401 - invalid_api_key"))
        assert llm_router._is_auth_error(Exception("Unauthorized"))

    def test_a_rate_limit_is_not_an_auth_error(self):
        assert not llm_router._is_auth_error(Exception("rate_limit_exceeded"))

    def test_rejected_key_raises_unavailable_not_a_bare_exception(self, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "gsk_revoked")

        class AuthenticationError(Exception):
            pass

        class DeadGroq:
            def invoke(self, _messages):
                raise AuthenticationError("Error code: 401 - invalid_api_key")

        monkeypatch.setattr(llm_router, "_build_groq", lambda: DeadGroq())

        with pytest.raises(llm_router.LLMUnavailableError) as exc:
            llm_router.invoke_llm([])

        assert "rejected" in exc.value.reason.lower()
        assert "api key" in exc.value.reason.lower()

    def test_the_reason_leaks_no_key_material_or_traceback(self, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "gsk_supersecret_value")

        class AuthenticationError(Exception):
            pass

        class DeadGroq:
            def invoke(self, _messages):
                raise AuthenticationError("401 invalid_api_key gsk_supersecret_value")

        monkeypatch.setattr(llm_router, "_build_groq", lambda: DeadGroq())

        with pytest.raises(llm_router.LLMUnavailableError) as exc:
            llm_router.invoke_llm([])

        assert "gsk_supersecret_value" not in exc.value.reason
        assert "Traceback" not in exc.value.reason

    def test_both_backends_down_raises_unavailable(self, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "gsk_example")
        monkeypatch.setattr(llm_router, "_GROQ_MAX_ATTEMPTS", 1)
        monkeypatch.setattr(llm_router, "_GROQ_RETRY_BACKOFF", 0)

        class RateLimited:
            def invoke(self, _messages):
                raise Exception("rate_limit_exceeded: tokens per day")

        def no_ollama():
            raise ConnectionRefusedError("connection refused")

        monkeypatch.setattr(llm_router, "_build_groq", lambda: RateLimited())
        monkeypatch.setattr(llm_router, "_build_ollama", no_ollama)

        with pytest.raises(llm_router.LLMUnavailableError) as exc:
            llm_router.invoke_llm([])

        assert "quota" in exc.value.reason.lower() or "rate-limited" in exc.value.reason.lower()

    def test_no_provider_at_all_says_so(self, monkeypatch):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)

        def no_ollama():
            raise ConnectionRefusedError("connection refused")

        monkeypatch.setattr(llm_router, "_build_ollama", no_ollama)

        with pytest.raises(llm_router.LLMUnavailableError) as exc:
            llm_router.invoke_llm([])

        assert "no ai provider is configured" in exc.value.reason.lower()

    def test_a_real_bug_still_surfaces_as_itself(self, monkeypatch):
        """A programming error must not be dressed up as an outage."""
        monkeypatch.setenv("GROQ_API_KEY", "gsk_example")

        class BrokenGroq:
            def invoke(self, _messages):
                raise TypeError("unhashable type: 'dict'")

        monkeypatch.setattr(llm_router, "_build_groq", lambda: BrokenGroq())

        with pytest.raises(TypeError):
            llm_router.invoke_llm([])


class TestRetiredModel:
    """
    Groq shut down llama-3.1-8b-instant on 2026-08-16, which was this project's
    default. The retirement arrives as a plain 400 matching neither an auth
    failure nor anything transient, so every hosted scan died reporting
    "internal error" while the deployment looked healthy.
    """

    def test_the_default_model_is_not_a_retired_one(self):
        assert llm_router._DEFAULT_GROQ_MODEL != "llama-3.1-8b-instant"
        assert llm_router._DEFAULT_GROQ_MODEL == "openai/gpt-oss-20b"

    def test_env_overrides_the_default(self, monkeypatch):
        monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")
        assert llm_router._groq_model() == "openai/gpt-oss-120b"

    def test_a_blank_override_falls_back_to_the_default(self, monkeypatch):
        monkeypatch.setenv("GROQ_MODEL", "   ")
        assert llm_router._groq_model() == llm_router._DEFAULT_GROQ_MODEL

    def test_decommissioned_is_recognised(self):
        assert llm_router._is_model_error(Exception(
            "Error code: 400 - The model `llama-3.1-8b-instant` has been "
            "decommissioned and is no longer supported."))
        assert llm_router._is_model_error(Exception("model_not_found"))

    def test_a_rate_limit_is_not_a_model_error(self):
        assert not llm_router._is_model_error(Exception("rate_limit_exceeded"))

    def test_a_retired_model_names_itself_instead_of_saying_internal_error(self, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "gsk_valid")
        monkeypatch.setenv("GROQ_MODEL", "llama-3.1-8b-instant")

        class Retired:
            def invoke(self, _messages):
                raise Exception("Error code: 400 - The model `llama-3.1-8b-instant` "
                                "has been decommissioned and is no longer supported.")

        monkeypatch.setattr(llm_router, "_build_groq", lambda: Retired())

        with pytest.raises(llm_router.LLMUnavailableError) as exc:
            llm_router.invoke_llm([])

        assert "llama-3.1-8b-instant" in exc.value.reason
        assert "GROQ_MODEL" in exc.value.reason

    def test_a_retired_model_does_not_burn_the_retry_budget(self, monkeypatch):
        """It will never succeed, so retrying it three times just wastes the scan."""
        monkeypatch.setenv("GROQ_API_KEY", "gsk_valid")
        calls = {"n": 0}

        class Retired:
            def invoke(self, _messages):
                calls["n"] += 1
                raise Exception("model_decommissioned")

        monkeypatch.setattr(llm_router, "_build_groq", lambda: Retired())

        with pytest.raises(llm_router.LLMUnavailableError):
            llm_router.invoke_llm([])

        # Multi-model chain (prompt 00a): each configured model is tried
        # exactly once and then disabled — never retried. With the default
        # three Groq models that is 3 calls total, 1 per model.
        assert calls["n"] == len(llm_router._groq_models()) == 3
        for model in llm_router._groq_models():
            assert model in llm_router._disabled
