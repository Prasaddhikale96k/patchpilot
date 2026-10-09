"""Tests for LogicAuditor (Addition A) with a mocked LLM batch."""

from __future__ import annotations

import pytest

from agents.remediation import logic_auditor
from agents.remediation.logic_auditor import find_handlers, logic_auditor_node

ROUTES_PY = '''from flask import Blueprint, jsonify, request
from .auth import login_required

bp = Blueprint("routes", __name__)


@bp.route("/invoices/<int:invoice_id>")
@login_required
def invoice_detail(invoice_id):
    invoice = Invoice.query.get(invoice_id)
    return jsonify({"amount": invoice.amount})


@bp.route("/download")
@login_required
def download():
    name = request.args.get("file", "")
    path = os.path.join(UPLOAD_DIR, name)
    return send_file(path)
'''


@pytest.fixture()
def repo(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    (app / "routes.py").write_text(ROUTES_PY)
    return tmp_path


def _state(repo, **overrides):
    base = {"scan_id": "audit01", "repo_url": "https://github.com/x/y",
            "repo_path": str(repo), "tech_stack": {"languages": ["python"]},
            "raw_findings": [{"source": "bandit", "file": "app/x.py"}]}
    base.update(overrides)
    return base


class TestFindHandlers:
    def test_detects_flask_handlers_with_auth(self, repo):
        handlers = find_handlers(str(repo))
        assert len(handlers) == 2
        by_route = {h["route"]: h for h in handlers}
        assert by_route["/invoices/<int:invoice_id>"]["auth"] == ["@login_required"]
        assert "Invoice.query.get" in by_route["/invoices/<int:invoice_id>"]["code"]

    def test_skips_test_dirs(self, tmp_path):
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "test_x.py").write_text(
            '@app.route("/x")\ndef x():\n    return 1\n')
        assert find_handlers(str(tmp_path)) == []


class TestLogicAuditorNode:
    def test_valid_finding_kept_hallucinations_dropped(self, repo, monkeypatch):
        handlers = find_handlers(str(repo))
        target_line = next(
            h["line"] for h in handlers if "invoices" in h["route"])
        canned = [
            {"file": "app/routes.py", "line": target_line,
             "category": "broken_access_control", "cwe": "CWE-639",
             "severity": "HIGH",
             "evidence": "invoice fetched by id with no owner check: "
                         "Invoice.query.get(invoice_id)",
             "exploit_scenario": "GET /invoices/2 as alice"},
            {"file": "app/ghost.py", "line": 3,
             "category": "broken_access_control", "cwe": "CWE-639",
             "severity": "HIGH", "evidence": "made up",
             "exploit_scenario": "none"},
            {"file": "app/routes.py", "line": 9999,
             "category": "path_traversal", "cwe": "CWE-22",
             "severity": "HIGH", "evidence": "outside handler",
             "exploit_scenario": "none"},
        ]
        monkeypatch.setattr(logic_auditor, "_audit_batch",
                            lambda batch: canned)
        result = logic_auditor_node(_state(repo))
        assert len(result["raw_findings"]) == 2  # 1 old + 1 valid
        kept = result["raw_findings"][1]
        assert kept["source"] == "llm-audit"
        assert kept["category"] == "A01:2021-Broken Access Control"
        assert kept["line"] == target_line
        assert any("Audited 2 routes" in line and "1 issues" in line
                   for line in result["agent_logs"])

    def test_website_scan_skipped(self, monkeypatch):
        monkeypatch.setattr(
            logic_auditor, "_audit_batch",
            lambda batch: (_ for _ in ()).throw(
                AssertionError("LLM must not be called")))
        result = logic_auditor_node(_state(
            None, repo_path="", tech_stack={"type": "website"}))
        assert "raw_findings" not in result
        assert any("Skipped (website scan" in line
                   for line in result["agent_logs"])
