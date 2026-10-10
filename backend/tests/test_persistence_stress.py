"""Persistence / recovery edge cases (phase 3). Temporary stores only."""

from __future__ import annotations

import asyncio
import threading
import time

import pytest
from fastapi.testclient import TestClient

import main as app_main
from tools import scan_store as ss


@pytest.fixture()
def store(tmp_path, monkeypatch):
    s = ss.ScanStore(tmp_path / "scans.db", runs_dir=tmp_path / "runs")
    monkeypatch.setattr(app_main, "_store", s)
    return s


@pytest.fixture()
def client(store):
    return TestClient(app_main.app)


def _report(sid, vulns=None):
    return {"scan_id": sid, "repo_url": "https://github.com/x/y",
            "vulnerabilities": vulns or [], "summary": {"risk_score": 10,
                                                         "overall_risk": "LOW"},
            "assessed": True, "patches": []}


class TestConcurrency:
    def test_two_store_instances_writing_concurrently_do_not_corrupt(self, tmp_path):
        """Two backend processes share one DB file (WAL + busy timeout)."""
        a = ss.ScanStore(tmp_path / "s.db", runs_dir=tmp_path / "runs")
        b = ss.ScanStore(tmp_path / "s.db", runs_dir=tmp_path / "runs")
        errors: list[Exception] = []

        def worker(store, prefix):
            try:
                for i in range(25):
                    sid = f"{prefix}{i:04d}"
                    store.create(sid, repo_url="u")
                    store.mark_running(sid, "scanner")
                    store.heartbeat(sid)
                    store.update_phase(sid, "tester")
                    store.complete(sid, _report(sid))
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(s, p))
                   for s, p in ((a, "aa"), (b, "bb"), (a, "cc"), (b, "dd"))]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        assert errors == []
        rows = a.list(limit=500)
        assert len(rows) == 100
        assert {r["status"] for r in rows} == {ss.COMPLETED}
        assert all(a.load_report(r)["scan_id"] == r["scan_id"] for r in rows)

    def test_concurrent_identical_start_requests_create_one_run(self, client, monkeypatch):
        monkeypatch.setattr(app_main, "assert_safe_target", lambda url: None)
        started: list[str] = []

        async def fake_run(repo_url, scan_id, create_pr=False, target_hint=None):
            started.append(scan_id)
            app_main._store.mark_running(scan_id)
        monkeypatch.setattr(app_main, "_run_scan", fake_run)
        body = {"repo_url": "https://github.com/x/concurrent"}
        results: list[dict] = []
        threads = [threading.Thread(target=lambda: results.append(
            client.post("/api/scan", json=body).json())) for _ in range(6)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        try:
            assert len({r["scan_id"] for r in results}) == 1
            assert len(started) == 1
            assert sum(1 for r in results if r["deduplicated"]) == 5
        finally:
            for sid in started:
                app_main._scans.pop(sid, None)


class _SlowFailingGraph:
    """Two nodes succeed, the third raises (a crash inside an agent node)."""

    async def astream(self, state, config=None):
        yield {"orchestrator": {"agent_logs": ["[Orchestrator] start"], "status": "scanning"}}
        yield {"scanner": {"agent_logs": ["[Scanner] 3 findings"], "status": "analyzing"}}
        raise ValueError("node exploded: internal detail")


class _SlowGraph:
    async def astream(self, state, config=None):
        for node in ("orchestrator", "scanner"):
            await asyncio.sleep(0.05)
            yield {node: {"agent_logs": [f"[{node}] ok"], "status": ""}}
        await asyncio.sleep(0.2)
        yield {"report_generator": {"agent_logs": [], "status": "done",
                                    "report": _report(state["scan_id"])}}


def _prime(store, monkeypatch, sid, graph):
    monkeypatch.setattr(app_main, "_graph", graph)
    monkeypatch.setattr(app_main, "cleanup_repo", lambda _sid: None)

    async def no_history(*_a, **_k):
        return None
    monkeypatch.setattr(app_main, "_append_scan_history", no_history)
    store.create(sid, repo_url="https://github.com/x/y")
    app_main._scans[sid] = app_main._new_session("https://github.com/x/y")


class TestFailureEvidence:
    def test_node_crash_keeps_event_trail_and_logs(self, store, monkeypatch, caplog):
        sid = "crsh1234"
        _prime(store, monkeypatch, sid, _SlowFailingGraph())
        try:
            with caplog.at_level("INFO"):
                asyncio.run(app_main._run_scan("https://github.com/x/y", sid))
        finally:
            app_main._scans.pop(sid, None)
        rec = store.get(sid)
        assert rec["status"] == ss.FAILED and rec["error_kind"] == "internal"
        assert rec["phase"] == "scanner"  # last node that completed
        assert [e["node"] for e in store.events(sid)] == ["orchestrator", "scanner"]
        assert "crashed after node scanner" in caplog.text
        assert "node exploded" in caplog.text           # detail in server log
        assert "node exploded" not in (rec["error"] or "")  # not shown to clients


class TestWebSocketLoss:
    def test_disconnecting_client_does_not_stop_the_scan(self, store, monkeypatch):
        sid = "wslo1234"
        _prime(store, monkeypatch, sid, _SlowGraph())

        async def scenario():
            task = asyncio.create_task(app_main._run_scan("https://github.com/x/y", sid))
            # a subscriber joins, reads one message, then vanishes
            q: asyncio.Queue = asyncio.Queue()
            app_main._scans[sid]["subscribers"].add(q)
            await asyncio.wait_for(q.get(), 2)
            app_main._scans[sid]["subscribers"].discard(q)
            await asyncio.wait_for(task, 5)

        try:
            asyncio.run(scenario())
        finally:
            app_main._scans.pop(sid, None)
        rec = store.get(sid)
        assert rec["status"] == ss.COMPLETED
        assert store.load_report(rec)["scan_id"] == sid


class TestRetentionEndToEnd:
    def test_purge_through_api_turns_report_into_410(self, client, store):
        sid = "purg1234"
        store.create(sid, repo_url="https://github.com/x/y")
        store.complete(sid, _report(sid, [{"id": "VULN-001", "severity": "HIGH"}]))
        # other artifacts that also hold findings / source, plus a re-run
        (store.runs_dir / sid / "state_after_fix.json").write_text('{"v": "VULN-001"}')
        (store.runs_dir / sid / "secure_coder_prompt.md").write_text("source code")
        store.create(f"{sid}-r1", repo_url="https://github.com/x/y", kind="remediation")
        store.complete(f"{sid}-r1", _report(f"{sid}-r1", [{"id": "VULN-001"}]))
        unrelated = store.runs_dir / "purg12345"  # prefix-alike, must survive
        unrelated.mkdir()
        (unrelated / "keep.txt").write_text("x")
        asyncio.run(app_main._append_scan_history(
            sid, "https://github.com/x/y", _report(sid, [{"id": "VULN-001"}]), time.time()))
        assert client.get(f"/api/report/{sid}").status_code == 200
        receipt = client.post(f"/api/retention/scans/{sid}/purge?mode=full").json()
        assert receipt["outcome"] in ("complete", "partial")
        assert any(c["component"] == "run_report" and c["outcome"] == "complete"
                   for c in receipt["components"])
        resp = client.get(f"/api/report/{sid}")
        assert resp.status_code == 410
        assert "VULN-001" not in resp.text
        assert store.events(sid) == []
        assert not (store.runs_dir / sid).exists()
        assert not (store.runs_dir / f"{sid}-r1").exists()
        assert client.get(f"/api/report/{sid}-r1").status_code == 410
        assert (unrelated / "keep.txt").exists()

    def test_unknown_stays_unknown_after_restart(self, tmp_path):
        a = ss.ScanStore(tmp_path / "s.db", runs_dir=tmp_path / "runs")
        a.create("known001", repo_url="u")
        b = ss.ScanStore(tmp_path / "s.db", runs_dir=tmp_path / "runs")
        assert b.get("never000") is None and b.get("known001") is not None


class TestPhase4Fixes:
    def test_stale_running_row_does_not_block_a_new_scan(self, tmp_path, monkeypatch):
        s = ss.ScanStore(tmp_path / "s.db", runs_dir=tmp_path / "runs")
        s.create_unless_duplicate("dead0001", repo_url="https://github.com/x/y")
        s.mark_running("dead0001")
        future = time.time() + 10_000
        monkeypatch.setattr(ss.time, "time", lambda: future)
        rec, created = s.create_unless_duplicate("new00001", repo_url="https://github.com/x/y")
        assert created and rec["scan_id"] == "new00001"

    def test_idempotency_key_returns_completed_run_too(self, tmp_path):
        s = ss.ScanStore(tmp_path / "s.db", runs_dir=tmp_path / "runs")
        s.create_unless_duplicate("idem0001", repo_url="u", idempotency_key="k1")
        s.complete("idem0001", _report("idem0001"))
        rec, created = s.create_unless_duplicate("idem0002", repo_url="u", idempotency_key="k1")
        assert not created and rec["scan_id"] == "idem0001"

    def test_remediation_respects_the_shared_capacity(self, client, monkeypatch, tmp_path):
        import tools.run_artifacts as ra
        monkeypatch.setattr(ra, "_BASE", tmp_path / "runs")
        ra.save_state("cap00001", {"repo_url": "https://github.com/x/y", "vulnerabilities": []})
        monkeypatch.setattr(app_main, "MAX_CONCURRENT_SCANS", 1)
        app_main._scans["busy0001"] = app_main._new_session("u")
        app_main._scans["busy0001"]["status"] = "running"
        try:
            resp = client.post("/api/remediate", json={"scan_id": "cap00001"})
            assert resp.status_code == 429
        finally:
            app_main._scans.pop("busy0001", None)

    def test_exploit_test_path_outside_repo_is_refused(self, tmp_path):
        from agents.remediation import tester
        from tools.patch_apply import PatchApplyError
        (tmp_path / "repo").mkdir()
        with pytest.raises(PatchApplyError):
            tester._write_test_file(str(tmp_path / "repo"), "../../escape.py", "x")
        assert not (tmp_path / "escape.py").exists()
