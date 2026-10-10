"""SPEED-2: specialist grouping, deterministic merge, squad == sequential with a
mocked LLM, lane events, and the provider 429 cooldown + failover."""

from __future__ import annotations

import json
import threading
import time
from types import SimpleNamespace

import pytest

import agents.orchestrator as orch
import agents.squad as squad
from agents import llm_router

RAW = [
    {"source": "semgrep", "file": "app/routes.py", "line": 40, "severity": "ERROR",
     "description": "SQL injection via f-string in query", "rule_id": "sqli"},
    {"source": "semgrep", "file": "app/routes.py", "line": 70, "severity": "ERROR",
     "description": "Path traversal in /download", "rule_id": "path"},
    {"source": "bandit", "file": "app/config.py", "line": 9, "severity": "MEDIUM",
     "description": "Hardcoded secret key", "test_id": "B105"},
    {"source": "bandit", "file": "app/admin.py", "line": 31, "severity": "HIGH",
     "description": "subprocess call with shell=True command injection", "test_id": "B602"},
    {"source": "llm-audit", "file": "app/routes.py", "line": 52, "severity": "HIGH",
     "description": "CWE-639: IDOR in /invoices/<id>"},
    {"source": "semgrep", "file": "app/views.py", "line": 5, "severity": "WARNING",
     "description": "unrelated style finding"},
]


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setattr(orch, "_snapshot_after_fix", lambda *a, **k: None)
    monkeypatch.setenv("PARALLEL_AGENTS", "1")
    monkeypatch.delenv("FAST_SCAN", raising=False)


class TestGrouping:
    def test_families(self):
        groups = squad.group_findings(RAW)
        assert list(groups) == ["Injection", "AccessControl", "Secrets&Config", "Other"]
        assert [f["line"] for f in groups["Injection"]] == [40, 31]
        assert [f["line"] for f in groups["AccessControl"]] == [70, 52]
        assert [f["line"] for f in groups["Secrets&Config"]] == [9]
        assert [f["line"] for f in groups["Other"]] == [5]

    def test_empty_families_are_dropped_and_order_kept(self):
        groups = squad.group_findings([RAW[2], RAW[0]])
        assert list(groups) == ["Injection", "Secrets&Config"]

    def test_applicable_needs_two_families(self):
        assert squad.squad_applicable({"raw_findings": RAW, "tech_stack": {}})
        assert not squad.squad_applicable({"raw_findings": [RAW[0], RAW[3]], "tech_stack": {}})
        assert not squad.squad_applicable({"raw_findings": RAW,
                                           "tech_stack": {"type": "website"}})

    def test_flag_off_means_sequential(self, monkeypatch):
        monkeypatch.setenv("PARALLEL_AGENTS", "0")
        assert not squad.squad_applicable({"raw_findings": RAW, "tech_stack": {}})


class TestMergeOrder:
    def test_original_order_and_renumbered_ids(self):
        results = {
            "Injection": {"vulnerabilities": [
                {"id": "VULN-001", "file": "app/routes.py", "line": 40},
                {"id": "VULN-002", "file": "app/admin.py", "line": 31}],
                "exploits": [{"vuln_id": "VULN-002"}], "patches": [{"vuln_id": "VULN-001"}]},
            "AccessControl": {"vulnerabilities": [
                {"id": "VULN-001", "file": "app/routes.py", "line": 70},
                {"id": "VULN-002", "file": "app/routes.py", "line": 52}],
                "exploits": [{"vuln_id": "VULN-001"}], "patches": []},
        }
        vulns, exploits, patches = squad.merge_results(RAW, results)
        assert [(v["id"], v["line"]) for v in vulns] == [
            ("VULN-001", 40), ("VULN-002", 70), ("VULN-003", 31), ("VULN-004", 52)]
        # Exploits/patches follow their vulnerability to the new ids, in id order.
        assert [e["vuln_id"] for e in exploits] == ["VULN-002", "VULN-003"]
        assert [p["vuln_id"] for p in patches] == ["VULN-001"]


def _fake_llm(messages, **kw):
    text = str(getattr(messages[-1], "content", messages[-1]))
    if text.startswith("Fix this vulnerability"):
        vuln = json.loads(text.split("\n", 1)[1].split("\n\nThe real source")[0])
        return SimpleNamespace(content=json.dumps({
            "vuln_id": vuln["id"], "file": vuln["file"],
            "original_code": "x", "patched_code": "y", "explanation": "fixed"}))
    return SimpleNamespace(content="[]")  # analyzer/exploit: deterministic fallback


def _state():
    return {"repo_url": "https://github.com/a/b", "scan_id": "t", "repo_path": "",
            "tech_stack": {"languages": ["python"]}, "raw_findings": [dict(f) for f in RAW],
            "vulnerabilities": [], "exploits": [], "patches": []}


class TestSquadEqualsSequential:
    def test_same_output_with_a_mocked_llm(self, monkeypatch):
        monkeypatch.setattr(orch, "invoke_llm", _fake_llm)
        seq = _state()
        for node in (orch.vuln_analyzer_node, orch.exploit_reasoner_node,
                     orch.fix_suggester_node):
            seq.update({k: v for k, v in node(seq).items() if k != "agent_logs"})

        out = squad.run_squad(_state())

        key = lambda v: (v["id"], v["file"], v["line"], v["severity"])  # noqa: E731
        assert [key(v) for v in out["vulnerabilities"]] == [key(v) for v in seq["vulnerabilities"]]
        assert [e["vuln_id"] for e in out["exploits"]] == [e["vuln_id"] for e in seq["exploits"]]
        assert [p["vuln_id"] for p in out["patches"]] == [p["vuln_id"] for p in seq["patches"]]
        assert out["squad_done"] is True

    def test_logs_announce_the_squad(self, monkeypatch):
        monkeypatch.setattr(orch, "invoke_llm", _fake_llm)
        out = squad.run_squad(_state())
        assert out["agent_logs"][0] == (
            "[Squad] 4 specialists in parallel: Injection(2), AccessControl(2), "
            "Secrets&Config(1), Other(1)")

    def test_specialists_run_concurrently_with_their_own_prompt_note(self, monkeypatch):
        seen, lock = {}, threading.Lock()

        def slow_llm(messages, **kw):
            time.sleep(0.2)
            system = str(messages[0].content)
            with lock:
                seen[threading.current_thread().name] = system
            return _fake_llm(messages, **kw)

        monkeypatch.setattr(orch, "invoke_llm", slow_llm)
        start = time.perf_counter()
        squad.run_squad(_state())
        elapsed = time.perf_counter() - start
        # 4 lanes x (analyzer + exploit + fix) sequentially would be >2s.
        assert elapsed < 1.6
        assert any("INJECTION specialist" in s for s in seen.values())
        assert any("ACCESS-CONTROL specialist" in s for s in seen.values())

    def test_lane_events_stream_live(self, monkeypatch):
        monkeypatch.setattr(orch, "invoke_llm", _fake_llm)
        events = []
        squad.set_lane_sink("t", lambda lane, line: events.append((lane, line)))
        try:
            out = squad.run_squad(_state())
        finally:
            squad.set_lane_sink("t", None)
        assert {lane for lane, _ in events} >= {"Squad", "Injection", "AccessControl"}
        # Delivered live, so not repeated in the node's own log list.
        assert not any(l.startswith("[Injection]") for l in out["agent_logs"])

    def test_one_failing_specialist_does_not_sink_the_others(self, monkeypatch):
        def flaky(messages, **kw):
            if "ACCESS-CONTROL specialist" in str(messages[0].content):
                raise RuntimeError("provider down")
            return _fake_llm(messages, **kw)

        monkeypatch.setattr(orch, "invoke_llm", flaky)
        out = squad.run_squad(_state())
        assert len(out["vulnerabilities"]) == len(RAW)  # findings still all there
        assert any("AccessControl specialist failed" in l for l in out["agent_logs"])


class TestProviderCooldown:
    def test_429_cools_the_provider_and_the_next_one_serves(self, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "gsk_test")
        monkeypatch.setenv("GEMINI_API_KEY", "gem_test")
        monkeypatch.setattr(llm_router, "_provider_order", lambda: ["groq", "gemini"])
        monkeypatch.setattr(llm_router, "_provider_models", lambda p: [f"{p}-m"])
        monkeypatch.setattr(llm_router, "_disabled", {})
        monkeypatch.setattr(llm_router, "_cooldowns", {})
        calls = []

        class RateLimited(Exception):
            status_code = 429

        def fake_groq(model, messages):
            calls.append("groq")
            raise RateLimited("rate limit reached")

        def fake_call(provider, model, messages):
            calls.append(provider)
            return llm_router._Reply("ok", provider=provider, model=model)

        monkeypatch.setattr(llm_router, "_invoke_groq_with_retry", fake_groq)
        monkeypatch.setattr(llm_router, "_call_provider", fake_call)

        first = llm_router.invoke_llm([{"role": "user", "content": "a"}])
        assert first.content == "ok" and calls == ["groq", "gemini"]
        assert llm_router._provider_cooling("groq")

        calls.clear()
        llm_router.invoke_llm([{"role": "user", "content": "b"}])
        assert calls == ["gemini"]  # groq is skipped while cooling

    def test_cooldown_expires(self, monkeypatch):
        monkeypatch.setattr(llm_router, "_provider_cooldowns", {})
        llm_router._cool_provider("groq", 0.05)
        assert llm_router._provider_cooling("groq")
        time.sleep(0.08)
        assert not llm_router._provider_cooling("groq")

    def test_pool_limits_come_from_env(self, monkeypatch):
        monkeypatch.setenv("POOL_GROQ", "5")
        assert llm_router._concurrency("GROQ", 3) == 5
        monkeypatch.delenv("POOL_GROQ")
        monkeypatch.setenv("LLM_CONCURRENCY_GROQ", "2")
        assert llm_router._concurrency("GROQ", 3) == 2
