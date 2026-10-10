"""Cross-site write protection (CSRF) for the unauthenticated local API."""

from __future__ import annotations

import asyncio
import time

import pytest
from fastapi.testclient import TestClient

import main as app_main
from tools import scan_store as ss


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(app_main, "_store",
                        ss.ScanStore(tmp_path / "s.db", runs_dir=tmp_path / "runs"))
    return TestClient(app_main.app)


def _seed_history(sid: str) -> None:
    asyncio.run(app_main._append_scan_history(
        sid, "https://x.io", {"vulnerabilities": [], "summary": {}}, time.time()))


def test_cross_site_purge_is_refused_and_erases_nothing(client):
    _seed_history("csrf0001")
    resp = client.post("/api/retention/scans/csrf0001/purge?mode=full",
                       headers={"Origin": "https://evil.example"})
    assert resp.status_code == 403
    assert any(r.get("scan_id") == "csrf0001" for r in app_main._load_history())


def test_allowed_origin_can_still_write(client):
    _seed_history("csrf0002")
    resp = client.post("/api/retention/scans/csrf0002/purge?mode=full",
                       headers={"Origin": app_main._ALLOWED_ORIGINS[0]})
    assert resp.status_code == 200


def test_requests_without_origin_are_unaffected(client):
    """curl / scripts send no Origin header."""
    _seed_history("csrf0003")
    assert client.post("/api/retention/scans/csrf0003/purge?mode=full").status_code == 200


@pytest.mark.parametrize("path", ["/api/scan", "/api/remediate"])
def test_cross_site_json_writes_refused(client, path):
    resp = client.post(path, json={"repo_url": "https://github.com/x/y", "scan_id": "a"},
                       headers={"Origin": "https://evil.example"})
    assert resp.status_code == 403


def test_cross_site_reads_still_reach_cors(client):
    resp = client.get("/health", headers={"Origin": "https://evil.example"})
    assert resp.status_code == 200
    assert "access-control-allow-origin" not in resp.headers
