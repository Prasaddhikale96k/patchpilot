"""PR Creator hardening: inconclusive evidence, races, partial failures,
rate limits and the real GitHub client against a scripted session.

No network: the node uses the FakeGitHub from test_pr_creator, and the
GitHub client tests drive a scripted requests-like session.
"""

from __future__ import annotations

import base64
import logging
import threading
import time

import pytest
import requests

from agents.remediation import pr_creator as prc
from tools import github_pr as gh

from test_pr_creator import TOKEN, _enable, _runs, _state, fake  # noqa: F401  (fixtures)


class TestEvidenceGate:
    @pytest.mark.parametrize("verdict", ["error", None, "failed", "VERIFIED"])
    def test_non_verified_verdicts_never_open_a_pr(self, tmp_path, monkeypatch, fake, verdict):
        _enable(monkeypatch)
        api = fake()
        out = prc.pr_creator_node(_state(tmp_path, test_verdict=verdict))
        assert out["pr"]["status"] == gh.BLOCKED
        assert api.pushes == [] and api.created == []

    @pytest.mark.parametrize("reports, why", [
        ({"exploit_before": {"failed": 0, "errors": 1}, "after": {"passed": 3}}, "reproduce"),
        ({"exploit_before": {"failed": 1}, "after": {"passed": 2, "failed": 1}}, "failures"),
        ({"exploit_before": {"failed": 1}, "after": {"infra_error": "exit 125"}}, "did not run"),
        ({"exploit_before": {"failed": 1}}, "missing"),
    ])
    def test_verdict_contradicted_by_raw_evidence_is_blocked(
            self, tmp_path, monkeypatch, fake, reports, why):
        """A 'verified' label with contradicting phase data must not pass."""
        _enable(monkeypatch)
        api = fake()
        out = prc.pr_creator_node(_state(tmp_path, test_reports=reports))
        assert out["pr"]["status"] == gh.BLOCKED
        assert why in out["pr"]["reason"]
        assert api.pushes == []

    def test_missing_base_branch_blocks(self, tmp_path, monkeypatch, fake):
        _enable(monkeypatch)
        monkeypatch.setenv("PR_BASE_BRANCH", "release-9")
        api = fake()
        out = prc.pr_creator_node(_state(tmp_path))
        assert out["pr"]["status"] == gh.BLOCKED
        assert "release-9" in out["pr"]["reason"] and api.pushes == []

    def test_empty_allowlist_skips(self, tmp_path, monkeypatch):
        _enable(monkeypatch, allow="")
        out = prc.pr_creator_node(_state(tmp_path))
        assert out["pr"]["status"] == gh.SKIPPED


class TestRacesAndPartialFailures:
    def test_existing_branch_with_other_content_is_refused(self, tmp_path, monkeypatch, fake):
        _enable(monkeypatch)
        api = fake(branch_exists=True, branch_files={
            "app/routes.py": b"evil = True\n",
            "tests/test_patchforge_cwe89.py": b"def test_x():\n    pass\n"})
        out = prc.pr_creator_node(_state(tmp_path))
        assert out["pr"]["status"] == gh.BLOCKED
        assert "differs from the verified patch" in out["pr"]["reason"]
        assert api.created == []

    def test_push_lost_race_reuses_identical_branch(self, tmp_path, monkeypatch, fake):
        _enable(monkeypatch)
        api = fake()
        calls = {"n": 0}

        def racing_push(**_k):
            api.branch_exists = True  # another run pushed the same patch first
            calls["n"] += 1
            raise RuntimeError("git push failed: non-fast-forward")
        monkeypatch.setattr(gh, "commit_and_push", racing_push)
        out = prc.pr_creator_node(_state(tmp_path))
        assert calls["n"] == 1
        assert out["pr"]["status"] == gh.CREATED

    def test_push_failure_without_branch_is_failed_and_masked(self, tmp_path, monkeypatch, fake):
        _enable(monkeypatch)
        fake()

        def broken_push(**_k):
            raise RuntimeError(f"git push failed: 403 for {TOKEN}")
        monkeypatch.setattr(gh, "commit_and_push", broken_push)
        out = prc.pr_creator_node(_state(tmp_path))
        assert out["pr"]["status"] == gh.FAILED
        assert TOKEN not in out["pr"]["reason"]
        assert out["pr_url"] is None

    def test_create_failure_but_pr_exists_is_reported_as_exists(self, tmp_path, monkeypatch, fake):
        """422 'already exists' or a lost response: never a second PR."""
        _enable(monkeypatch)
        api = fake(create_error="422 A pull request already exists",
                   existing_after_create_error={
                       "html_url": "https://github.com/owner/demo/pull/9", "number": 9})
        out = prc.pr_creator_node(_state(tmp_path))
        assert out["pr"]["status"] == gh.EXISTS
        assert out["pr_url"].endswith("/pull/9")
        assert len(api.pushes) == 1

    def test_rate_limit_is_failed_retryable_with_reason(self, tmp_path, monkeypatch, fake):
        _enable(monkeypatch)
        fake(create_error=gh.GitHubRateLimited("GitHub rate limit reached until 12:00:00 UTC."))
        out = prc.pr_creator_node(_state(tmp_path))
        assert out["pr"]["status"] == gh.FAILED
        assert out["pr"]["retryable"] is True
        assert "rate limit" in out["pr"]["reason"]

    def test_concurrent_identical_requests_open_one_pr(self, tmp_path, monkeypatch, fake):
        _enable(monkeypatch)
        api = fake()

        def slow_push(**k):
            time.sleep(0.2)
            api.branch_exists = True
            api.pushes.append(k)
            return "c0ffee"
        monkeypatch.setattr(gh, "commit_and_push", slow_push)
        original_create = api.create_pr

        def create_and_publish(slug, **kw):
            pr = original_create(slug, **kw)
            api.existing = pr
            return pr
        api.create_pr = create_and_publish
        results: list[dict] = []
        threads = [threading.Thread(target=lambda: results.append(
            prc.pr_creator_node(_state(tmp_path)))) for _ in range(2)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        assert sorted(r["pr"]["status"] for r in results) == [gh.CREATED, gh.EXISTS]
        assert len(api.pushes) == 1 and len(api.created) == 1

    def test_logs_and_result_file_never_contain_token(self, tmp_path, monkeypatch, fake, caplog):
        _enable(monkeypatch)
        fake(create_error=f"boom {TOKEN}")
        with caplog.at_level(logging.INFO):
            prc.pr_creator_node(_state(tmp_path))
        assert TOKEN not in caplog.text
        result = (tmp_path / "runs" / "abcd1234" / "pr_result.json").read_text()
        assert TOKEN not in result


class _Resp:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self._body = status, body or {}
        self.headers, self.text = headers or {}, str(body)

    def json(self):
        return self._body


class _ScriptedSession:
    """Plays back responses/exceptions in order; records each request."""

    def __init__(self, script):
        self.script, self.calls, self.headers = list(script), [], {}

    def request(self, method, url, **kw):
        self.calls.append((method, url))
        step = self.script.pop(0)
        if isinstance(step, Exception):
            raise step
        return step


class TestGitHubClient:
    @pytest.fixture(autouse=True)
    def _no_sleep(self, monkeypatch):
        monkeypatch.setattr(gh, "_sleep", lambda s: None)

    def test_transient_get_failures_are_retried(self):
        sess = _ScriptedSession([requests.ConnectionError("reset"), _Resp(502),
                                 _Resp(200, {"commit": {"sha": "abc"}})])
        assert gh.GitHub(TOKEN, session=sess).branch_sha("o/r", "main") == "abc"
        assert len(sess.calls) == 3

    def test_get_gives_up_after_bounded_attempts(self):
        sess = _ScriptedSession([requests.ConnectionError(f"x {TOKEN}")] * 3)
        with pytest.raises(RuntimeError) as exc:
            gh.GitHub(TOKEN, session=sess).repo("o/r")
        assert len(sess.calls) == 3 and TOKEN not in str(exc.value)

    def test_writes_are_never_auto_retried(self):
        sess = _ScriptedSession([_Resp(502, {"message": "bad gateway"})])
        with pytest.raises(RuntimeError):
            gh.GitHub(TOKEN, session=sess).create_pr("o/r", title="t", head="h",
                                                      base="main", body="b")
        assert sess.calls == [("POST", "https://api.github.com/repos/o/r/pulls")]

    @pytest.mark.parametrize("resp", [
        _Resp(403, {"message": "API rate limit exceeded"},
              {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1700000000"}),
        _Resp(429, {"message": "secondary"}, {"Retry-After": "60"}),
        _Resp(403, {"message": "You have exceeded a secondary rate limit"}),
    ])
    def test_rate_limits_are_identified(self, resp):
        sess = _ScriptedSession([resp])
        with pytest.raises(gh.GitHubRateLimited) as exc:
            gh.GitHub(TOKEN, session=sess).repo("o/r")
        assert "rate limit" in str(exc.value)

    def test_plain_403_is_permission_denied_not_rate_limit(self):
        sess = _ScriptedSession([_Resp(403, {"message": "Resource not accessible"},
                                       {"X-RateLimit-Remaining": "4999"})])
        with pytest.raises(gh.PRBlocked):
            gh.GitHub(TOKEN, session=sess).repo("o/r")

    def test_file_at_decodes_and_handles_missing(self):
        sess = _ScriptedSession([
            _Resp(200, {"encoding": "base64",
                        "content": base64.b64encode(b"x=1\n").decode()}),
            _Resp(404)])
        api = gh.GitHub(TOKEN, session=sess)
        assert api.file_at("o/r", "a.py", "br") == b"x=1\n"
        assert api.file_at("o/r", "missing.py", "br") is None
