"""Report endpoint states (prompt 05a follow-up).

The client must be able to tell apart: an unknown scan id (real 404),
an unfinished scan (202), a failed scan (200 error JSON via fail-fast),
and a completed scan with zero vulnerabilities (200, empty list — a clean
scan is not a 404). A previous incident showed an ad-hoc poller treating
404s as "still waiting" after uvicorn --reload wiped in-memory state.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

import main as app_main


@pytest.fixture()
def client():
    return TestClient(app_main.app)


def _entry(**overrides: object) -> dict:
    entry = {
        "queue": None,
        "report": None,
        "status": "starting",
        "error": None,
        "repo_url": "https://github.com/Prasaddhikale96k/vulnbank",
        "started_at": time.time(),
    }
    entry.update(overrides)
    return entry


class TestReportStates:
    def test_unknown_id_is_real_404(self, client):
        resp = client.get("/api/report/does-not-exist")
        assert resp.status_code == 404
        assert "status" not in resp.json()

    def test_unfinished_scan_is_202(self, client):
        app_main._scans["st-test"] = _entry(status="scanning")
        try:
            resp = client.get("/api/report/st-test")
            assert resp.status_code == 202
            assert "in progress" in resp.json()["detail"]
        finally:
            app_main._scans.pop("st-test", None)

    def test_failed_scan_returns_error_json_not_500(self, client):
        app_main._scans["st-test"] = _entry(
            status="error", error="tester node blew up: boom")
        try:
            resp = client.get("/api/report/st-test")
            assert resp.status_code == 200
            assert resp.json() == {"status": "error",
                                   "detail": "tester node blew up: boom"}
        finally:
            app_main._scans.pop("st-test", None)

    def test_clean_scan_is_200_with_empty_list(self, client):
        report = {"scan_id": "st-test", "vulnerabilities": [],
                  "summary": {"risk_score": 0}}
        app_main._scans["st-test"] = _entry(status="done", report=report)
        try:
            resp = client.get("/api/report/st-test")
            assert resp.status_code == 200
            assert resp.json()["vulnerabilities"] == []
        finally:
            app_main._scans.pop("st-test", None)

    def test_done_report_passes_through(self, client):
        report = {"scan_id": "st-test",
                  "vulnerabilities": [{"id": "VULN-001"}]}
        app_main._scans["st-test"] = _entry(status="done", report=report)
        try:
            resp = client.get("/api/report/st-test")
            assert resp.status_code == 200
            assert resp.json() == report
        finally:
            app_main._scans.pop("st-test", None)
