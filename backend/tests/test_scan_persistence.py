"""Durable scan lifecycle + report recovery (Priority 1).

Pins the contract that the in-memory registry broke: a known scan must
stay answerable after the process that ran it is gone (restart, --reload,
a second backend process), unfinished work must be distinguishable from
unknown ids, and a dead run must read `interrupted` — never `completed`,
never "running" forever.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from fastapi.testclient import TestClient

import main as app_main
from agents.llm_router import LLMUnavailableError
from tools import scan_store as ss


@pytest.fixture()
def store(tmp_path, monkeypatch):
    s = ss.ScanStore(tmp_path / "scans.db", runs_dir=tmp_path / "runs")
    monkeypatch.setattr(app_main, "_store", s)
    return s


@pytest.fixture()
def client(store):
    return TestClient(app_main.app)


def _report(sid: str, vulns=None) -> dict:
    return {"scan_id": sid, "repo_url": "https://github.com/x/y",
            "vulnerabilities": vulns or [], "summary": {"risk_score": 0,
                                                         "overall_risk": "LOW"},
            "assessed": True}


# ── store ──────────────────────────────────────────────────────────

class TestStoreLifecycle:
    def test_completed_report_survives_new_store_instance(self, tmp_path):
        first = ss.ScanStore(tmp_path / "s.db", runs_dir=tmp_path / "runs")
        first.create("aaaa1111", repo_url="https://github.com/x/y")
        first.mark_running("aaaa1111", "scanner")
        first.complete("aaaa1111", _report("aaaa1111", [{"id": "VULN-001"}]))
        # "restart": a brand-new store object on the same files
        second = ss.ScanStore(tmp_path / "s.db", runs_dir=tmp_path / "runs")
        rec = second.get("aaaa1111")
        assert rec["status"] == ss.COMPLETED
        assert second.load_report(rec)["vulnerabilities"] == [{"id": "VULN-001"}]

    def test_stale_running_run_becomes_interrupted_not_completed(
            self, tmp_path, monkeypatch):
        s = ss.ScanStore(tmp_path / "s.db", runs_dir=tmp_path / "runs")
        s.create("bbbb2222", repo_url="https://github.com/x/y")
        s.mark_running("bbbb2222", "tester")
        monkeypatch.setenv("SCAN_STALE_AFTER_SECS", "30")
        future = time.time() + 120
        monkeypatch.setattr(ss.time, "time", lambda: future)
        rec = s.get("bbbb2222")
        assert rec["status"] == ss.INTERRUPTED
        assert rec["error_kind"] == "interrupted"
        assert rec["report_path"] is None

    def test_fresh_heartbeat_is_not_interrupted(self, tmp_path):
        s = ss.ScanStore(tmp_path / "s.db", runs_dir=tmp_path / "runs")
        s.create("cccc3333", repo_url="https://github.com/x/y")
        s.mark_running("cccc3333")
        assert s.recover_stale() == []
        assert s.get("cccc3333")["status"] == ss.RUNNING

    def test_fail_never_overwrites_a_completed_run(self, tmp_path):
        s = ss.ScanStore(tmp_path / "s.db", runs_dir=tmp_path / "runs")
        s.create("dddd4444", repo_url="u")
        s.mark_running("dddd4444")
        s.complete("dddd4444", _report("dddd4444"))
        s.fail("dddd4444", "late failure")
        assert s.get("dddd4444")["status"] == ss.COMPLETED

    def test_events_round_trip(self, tmp_path):
        s = ss.ScanStore(tmp_path / "s.db", runs_dir=tmp_path / "runs")
        s.create("eeee5555", repo_url="u")
        s.append_event("eeee5555", {"type": "update", "node": "scanner",
                                    "logs": ["[Scanner] hi"]})
        assert s.events("eeee5555")[0]["node"] == "scanner"

    def test_path_like_ids_rejected(self, tmp_path):
        s = ss.ScanStore(tmp_path / "s.db", runs_dir=tmp_path / "runs")
        with pytest.raises(ValueError):
            s._run_dir("../evil")


# ── /api/report contract against the durable store ─────────────────

class TestReportEndpointFromStore:
    def test_unknown_id_404(self, client):
        resp = client.get("/api/report/nope0000")
        assert resp.status_code == 404
        assert resp.json() == {"detail": "Scan not found"}

    def test_running_is_202_with_retry_after_and_phase(self, client, store):
        store.create("run00001", repo_url="u")
        store.mark_running("run00001", "logic_auditor")
        resp = client.get("/api/report/run00001")
        assert resp.status_code == 202
        assert resp.headers["retry-after"] == str(app_main.REPORT_RETRY_AFTER_SECS)
        body = resp.json()
        assert body["status"] == "running"
        assert body["phase"] == "logic_auditor"
        assert "in progress" in body["detail"]

    def test_queued_is_202(self, client, store):
        store.create("que00001", repo_url="u")
        assert client.get("/api/report/que00001").status_code == 202

    def test_completed_after_restart_returns_report(self, client, store):
        """No in-memory session at all — exactly the post-restart case."""
        store.create("done0001", repo_url="u")
        store.complete("done0001", _report("done0001", [{"id": "VULN-001"}]))
        assert "done0001" not in app_main._scans
        resp = client.get("/api/report/done0001")
        assert resp.status_code == 200
        assert resp.json()["vulnerabilities"] == [{"id": "VULN-001"}]

    def test_zero_findings_is_a_completed_report_not_pending(self, client, store):
        store.create("zero0001", repo_url="u")
        store.complete("zero0001", _report("zero0001", []))
        resp = client.get("/api/report/zero0001")
        assert resp.status_code == 200
        assert resp.json()["vulnerabilities"] == []

    def test_failed_returns_error_json(self, client, store):
        store.create("fail0001", repo_url="u")
        store.mark_running("fail0001")
        store.fail("fail0001", "Scan timed out after 600s", "timeout")
        resp = client.get("/api/report/fail0001")
        assert resp.status_code == 200
        assert resp.json() == {"status": "error",
                               "detail": "Scan timed out after 600s"}

    def test_interrupted_is_explicit(self, client, store, monkeypatch):
        store.create("intr0001", repo_url="u")
        store.mark_running("intr0001")
        future = time.time() + 10_000
        monkeypatch.setattr(ss.time, "time", lambda: future)
        resp = client.get("/api/report/intr0001")
        assert resp.status_code == 200
        assert resp.json()["status"] == "interrupted"

    def test_purged_report_is_410_not_404(self, client, store):
        store.create("purg0001", repo_url="u")
        store.complete("purg0001", _report("purg0001"))
        store.forget_report("purg0001")
        assert client.get("/api/report/purg0001").status_code == 410

    def test_status_endpoint(self, client, store):
        store.create("stat0001", repo_url="https://github.com/x/y")
        store.mark_running("stat0001", "tester")
        body = client.get("/api/scans/stat0001/status").json()
        assert body["status"] == "running" and body["phase"] == "tester"
        assert "report_path" not in body  # no server paths leak
        assert client.get("/api/scans/zzzz9999/status").status_code == 404

    def test_list_scans_reads_durable_store(self, client, store):
        store.create("list0001", repo_url="https://github.com/x/y")
        ids = [r["scan_id"] for r in client.get("/api/scans").json()]
        assert "list0001" in ids


class TestWebSocketReplay:
    def test_finished_scan_not_in_memory_is_replayed(self, client, store):
        store.create("wsrp0001", repo_url="u")
        store.append_event("wsrp0001", {"type": "update", "node": "scanner",
                                        "logs": ["[Scanner] x"]})
        store.complete("wsrp0001", _report("wsrp0001"))
        with client.websocket_connect("/ws/wsrp0001") as ws:
            first = ws.receive_json()
            second = ws.receive_json()
        assert first["type"] == "update"
        assert second["type"] == "done"
        assert second["report"]["scan_id"] == "wsrp0001"

    def test_failed_scan_not_in_memory_sends_error(self, client, store):
        store.create("wsfl0001", repo_url="u")
        store.mark_running("wsfl0001")
        store.fail("wsfl0001", "boom message", "internal")
        with client.websocket_connect("/ws/wsfl0001") as ws:
            msg = ws.receive_json()
        assert msg == {"type": "error", "scan_id": "wsfl0001",
                       "kind": "internal", "message": "boom message"}


# ── _run_scan writes the durable record on every outcome ───────────

class _FakeGraph:
    def __init__(self, events=None, exc=None):
        self.events, self.exc = events or [], exc

    async def astream(self, state, config=None):
        for event in self.events:
            yield event
        if self.exc:
            raise self.exc


def _run(store, monkeypatch, graph, sid):
    monkeypatch.setattr(app_main, "_graph", graph)
    monkeypatch.setattr(app_main, "cleanup_repo", lambda _sid: None)

    async def no_history(*_a, **_k):
        return None
    monkeypatch.setattr(app_main, "_append_scan_history", no_history)
    store.create(sid, repo_url="https://github.com/x/y")
    app_main._scans[sid] = app_main._new_session("https://github.com/x/y")
    try:
        asyncio.run(app_main._run_scan("https://github.com/x/y", sid))
    finally:
        app_main._scans.pop(sid, None)
    return store.get(sid)


class TestRunScanPersistence:
    def test_success_persists_completed_report_and_events(self, store, monkeypatch):
        graph = _FakeGraph(events=[
            {"scanner": {"agent_logs": ["[Scanner] ok"], "status": "analyzing"}},
            {"report_generator": {"agent_logs": [], "status": "done",
                                  "report": _report("okok0001")}},
        ])
        rec = _run(store, monkeypatch, graph, "okok0001")
        assert rec["status"] == ss.COMPLETED
        assert store.load_report(rec)["scan_id"] == "okok0001"
        assert [e["node"] for e in store.events("okok0001")] == [
            "scanner", "report_generator"]

    def test_crash_persists_failed_with_safe_message(self, store, monkeypatch):
        graph = _FakeGraph(exc=RuntimeError("secret internal detail"))
        rec = _run(store, monkeypatch, graph, "crsh0001")
        assert rec["status"] == ss.FAILED
        assert rec["error_kind"] == "internal"
        assert "secret internal detail" not in rec["error"]

    def test_llm_outage_kind(self, store, monkeypatch):
        graph = _FakeGraph(exc=LLMUnavailableError("No model reachable."))
        rec = _run(store, monkeypatch, graph, "llmd0001")
        assert rec["status"] == ss.FAILED
        assert rec["error_kind"] == "llm_unavailable"

    def test_graph_without_report_is_a_failure_not_a_clean_scan(
            self, store, monkeypatch):
        graph = _FakeGraph(events=[{"scanner": {"agent_logs": []}}])
        rec = _run(store, monkeypatch, graph, "nore0001")
        assert rec["status"] == ss.FAILED


# ── duplicate-scan protection ──────────────────────────────────────

class TestDuplicateScanProtection:
    @pytest.fixture(autouse=True)
    def _no_real_scan(self, monkeypatch):
        monkeypatch.setattr(app_main, "assert_safe_target", lambda url: None)
        started: list[str] = []

        async def fake_run(repo_url, scan_id, create_pr=False, target_hint=None):
            started.append(scan_id)
            app_main._store.mark_running(scan_id)
        monkeypatch.setattr(app_main, "_run_scan", fake_run)
        self.started = started
        yield
        for sid in started:
            app_main._scans.pop(sid, None)

    def test_same_idempotency_key_returns_same_scan(self, client):
        body = {"repo_url": "https://github.com/x/idem"}
        first = client.post("/api/scan", json=body,
                            headers={"Idempotency-Key": "k-123"})
        second = client.post("/api/scan", json=body,
                             headers={"Idempotency-Key": "k-123"})
        assert first.status_code == 201
        assert second.status_code == 200
        assert second.json()["scan_id"] == first.json()["scan_id"]
        assert second.json()["deduplicated"] is True

    def test_identical_active_scan_is_reused(self, client):
        body = {"repo_url": "https://github.com/x/dupe"}
        first = client.post("/api/scan", json=body).json()
        second = client.post("/api/scan", json=body).json()
        assert second["scan_id"] == first["scan_id"]
        assert second["deduplicated"] is True

    def test_different_options_start_a_new_scan(self, client):
        a = client.post("/api/scan", json={"repo_url": "https://github.com/x/o"}).json()
        b = client.post("/api/scan", json={"repo_url": "https://github.com/x/o",
                                           "create_pr": True}).json()
        assert a["scan_id"] != b["scan_id"]


class TestArtifactEndpoint:
    def test_serves_file_and_refuses_traversal(self, client, store, monkeypatch, tmp_path):
        import tools.run_artifacts as ra
        monkeypatch.setattr(ra, "_BASE", tmp_path / "runs")
        (tmp_path / "runs" / "art00001").mkdir(parents=True)
        (tmp_path / "runs" / "art00001" / "patch.diff").write_text("+fix\n")
        ok = client.get("/api/scans/art00001/artifacts/patch.diff")
        assert ok.status_code == 200 and ok.text == "+fix\n"
        for bad in ("..%2F..%2Fmain.py", "report.exe", ".env"):
            assert client.get(f"/api/scans/art00001/artifacts/{bad}").status_code == 404
        assert client.get("/api/scans/..%2Fx/artifacts/patch.diff").status_code == 404


class TestStartupRecovery:
    def test_startup_marks_stale_runs_and_cleans_their_clones(
            self, store, monkeypatch):
        store.create("crsh0002", repo_url="u")
        store.mark_running("crsh0002", "scanner")
        monkeypatch.setenv("SCAN_STALE_AFTER_SECS", "30")
        future = time.time() + 600
        monkeypatch.setattr(ss.time, "time", lambda: future)
        cleaned: list[str] = []
        monkeypatch.setattr(app_main, "cleanup_repo", cleaned.append)
        with TestClient(app_main.app):  # runs the lifespan startup
            pass
        assert store.get("crsh0002")["status"] == ss.INTERRUPTED
        assert cleaned == ["crsh0002"]
