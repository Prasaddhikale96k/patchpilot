"""Tests for fail-fast errors + the remediate-only loop (prompt 05a)."""

from __future__ import annotations

import asyncio
import time

import pytest


class TestStateSnapshotRoundTrip:
    def test_save_and_load(self, tmp_path, monkeypatch):
        import tools.run_artifacts as ra
        monkeypatch.setattr(ra, "_BASE", tmp_path / "runs")
        state = {"scan_id": "abc", "repo_url": "https://github.com/x/y",
                 "vulnerabilities": [{"id": "VULN-001"}],
                 "agent_logs": ["[Scanner] hi"], "attempts": 0}
        ra.save_state("abc", state)
        assert ra.load_state_snapshot("abc") == state

    def test_load_missing_raises(self, tmp_path, monkeypatch):
        import tools.run_artifacts as ra
        monkeypatch.setattr(ra, "_BASE", tmp_path / "runs")
        with pytest.raises(FileNotFoundError):
            ra.load_state_snapshot("nope")


class TestFailFastReport:
    def test_error_status_returns_detail_json(self):
        import main as app_main
        app_main._scans["err-test"] = {
            "queue": None, "report": None, "status": "error",
            "error": "tester node blew up: boom",
            "repo_url": "https://github.com/x/y", "started_at": time.time(),
        }
        try:
            result = asyncio.run(app_main.get_report("err-test"))
        finally:
            app_main._scans.pop("err-test", None)
        assert result == {"status": "error", "detail": "tester node blew up: boom"}


class TestRemediateEndpoint:
    def test_remediate_runs_mocked_graph(self, monkeypatch):
        import main as app_main
        import agents.remediation.loop as loop

        snapshot = {"scan_id": "base1",
                    "repo_url": "https://github.com/x/y",
                    "vulnerabilities": [], "target_hint": None}
        monkeypatch.setattr(
            "tools.run_artifacts.load_state_snapshot", lambda sid: snapshot)

        async def fake_stream(state, run_id, entry_point="secure_coder"):
            yield ("secure_coder", {"agent_logs": ["[SecureCoder] hi"],
                                    "attempts": 1,
                                    "test_verdict": "verified"})

        monkeypatch.setattr(loop, "stream_remediation", fake_stream)

        from fastapi.testclient import TestClient
        client = TestClient(app_main.app)
        try:
            resp = client.post("/api/remediate",
                               json={"scan_id": "base1",
                                     "target_hint": "CWE-89"})
            assert resp.status_code == 201, resp.text
            new_id = resp.json()["scan_id"]
            assert new_id.startswith("base1-r")
            assert resp.json()["ws_url"] == f"/ws/{new_id}"
            report = None
            for _ in range(50):
                report = client.get(f"/api/report/{new_id}").json()
                if "vulnerabilities" in report or report.get("status") == "error":
                    break
                time.sleep(0.2)
            assert report.get("remediation", {}).get("test_verdict") == "verified"
        finally:
            app_main._scans.pop("base1-r1", None)

    def test_remediate_missing_snapshot_is_404(self):
        import main as app_main
        from fastapi.testclient import TestClient
        client = TestClient(app_main.app)
        resp = client.post("/api/remediate", json={"scan_id": "ghost-id"})
        assert resp.status_code == 404


class TestCloneHygiene:
    def test_force_rmtree_removes_read_only_git_packs(self, tmp_path):
        """Windows left .git/objects/pack/*.pack (read-only) behind."""
        import os
        import stat
        from tools.git_cloner import force_rmtree
        pack = tmp_path / "clone" / ".git" / "objects" / "pack"
        pack.mkdir(parents=True)
        packfile = pack / "pack-1.pack"
        packfile.write_bytes(b"x")
        os.chmod(packfile, stat.S_IREAD)
        os.chmod(pack, stat.S_IREAD | stat.S_IEXEC)
        assert force_rmtree(str(tmp_path / "clone")) is True
        assert not (tmp_path / "clone").exists()

    def test_git_husk_is_not_a_usable_clone(self, tmp_path):
        from tools.git_cloner import is_usable_clone
        (tmp_path / "husk" / ".git").mkdir(parents=True)
        assert is_usable_clone(str(tmp_path / "husk")) is False
        (tmp_path / "husk" / "app.py").write_text("x = 1\n")
        assert is_usable_clone(str(tmp_path / "husk")) is True

    def test_ensure_repo_reclones_over_a_husk(self, tmp_path, monkeypatch):
        import agents.remediation.loop as loop
        import tools.git_cloner as gc
        (tmp_path / "husk" / ".git").mkdir(parents=True)
        cloned = []
        monkeypatch.setattr(gc, "clone_repo",
                            lambda url, rid: cloned.append(rid) or str(tmp_path / "fresh"))
        state = loop._ensure_repo({"repo_path": str(tmp_path / "husk"),
                                   "repo_url": "https://github.com/x/y"}, "s-r1")
        assert cloned == ["s-r1"]
        assert state["repo_path"] == str(tmp_path / "fresh")
