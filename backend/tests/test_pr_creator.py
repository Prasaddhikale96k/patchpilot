"""PR Creator (prompt 06): explicit-consent gates, idempotency, redaction.

No test here talks to GitHub: the REST client is replaced by a fake, and
the one real git test pushes to a local bare repository.
"""

from __future__ import annotations

import subprocess

import pytest

from agents.remediation import pr_creator as prc
from tools import github_pr as gh

TOKEN = "ghp_FAKEtokenFAKEtokenFAKEtoken1234"


@pytest.fixture(autouse=True)
def _runs(tmp_path, monkeypatch):
    import tools.run_artifacts as ra
    monkeypatch.setattr(ra, "_BASE", tmp_path / "runs")
    for var in ("PR_CREATION_ENABLED", "DRY_RUN_PR", "PR_ALLOWED_REPOS",
                "PR_BASE_BRANCH", "GITHUB_TOKEN"):
        monkeypatch.delenv(var, raising=False)

    def no_network(*_a, **_k):
        raise AssertionError("unexpected network call")
    monkeypatch.setattr("requests.Session.request", no_network)


def _enable(monkeypatch, allow="owner/demo"):
    monkeypatch.setenv("PR_CREATION_ENABLED", "true")
    monkeypatch.setenv("GITHUB_TOKEN", TOKEN)
    monkeypatch.setenv("PR_ALLOWED_REPOS", allow)


def _state(tmp_path, **over) -> dict:
    work = tmp_path / "work"
    (work / "app").mkdir(parents=True, exist_ok=True)
    (work / "tests").mkdir(parents=True, exist_ok=True)
    (work / "app" / "routes.py").write_text("safe = True\n")
    (work / "tests" / "test_patchforge_cwe89.py").write_text("def test_x():\n    pass\n")
    state = {
        "scan_id": "abcd1234", "repo_url": "https://github.com/owner/demo",
        "repo_path": str(tmp_path / "clone"), "work_dir": str(work),
        "create_pr": True, "open_pr": True, "attempts": 1,
        "test_verdict": "verified",
        "review": {"approved": True, "checks": [
            {"name": "syntax", "passed": True, "detail": "ok"}], "llm": {}},
        "target_vuln": {"id": "VULN-001", "severity": "HIGH",
                        "category": "A03:2021-Injection CWE-89",
                        "description": "SQL injection in search",
                        "file": "app/routes.py", "line": 40},
        "code_patch": {"diff": "--- a/app/routes.py\n+++ b/app/routes.py\n-x\n+y",
                       "files_changed": ["app/routes.py"],
                       "test_file": "tests/test_patchforge_cwe89.py",
                       "rationale": "parameterise"},
        "test_reports": {"baseline": {"passed": 22, "total": 22},
                         "exploit_before": {"failed": 1, "errors": 0},
                         "after": {"passed": 23, "total": 23}},
    }
    state.update(over)
    return state


class FakeGitHub:
    def __init__(self, *, push=True, base_sha="sha-base", existing=None,
                 branch_exists=False, create_error=None, branch_files=None,
                 existing_after_create_error=None):
        self.push, self.base_sha = push, base_sha
        self.existing, self.branch_exists = existing, branch_exists
        self.create_error = create_error
        self.created: list[dict] = []
        # content of files on an already-existing remote branch; default =
        # identical to the verified work copy written by _state()
        self.branch_files = branch_files if branch_files is not None else {
            "app/routes.py": b"safe = True\n",
            "tests/test_patchforge_cwe89.py": b"def test_x():\n    pass\n"}
        self.existing_after_create_error = existing_after_create_error

    def file_at(self, slug, path, ref):
        return self.branch_files.get(path)

    def __call__(self, token):  # stands in for the GitHub class
        self._token = token
        return self

    def mask(self, text):
        return text.replace(self._token, "***")

    def repo(self, slug):
        return {"full_name": slug, "default_branch": "main",
                "permissions": {"push": self.push}}

    def branch_sha(self, slug, branch):
        if branch == "main":
            return self.base_sha
        return "sha-branch" if self.branch_exists else None

    def open_pr_for(self, slug, owner, branch):
        return self.existing

    def create_pr(self, slug, **kw):
        if self.create_error:
            if self.existing_after_create_error:
                self.existing = self.existing_after_create_error
            if isinstance(self.create_error, Exception):
                raise self.create_error
            raise RuntimeError(self.create_error)
        self.created.append(kw)
        return {"html_url": "https://github.com/owner/demo/pull/7", "number": 7}


@pytest.fixture()
def fake(monkeypatch):
    def install(**kw):
        fake_gh = FakeGitHub(**kw)
        monkeypatch.setattr(gh, "GitHub", fake_gh)
        monkeypatch.setattr(gh, "local_head", lambda path: "sha-base")
        pushes: list[dict] = []
        monkeypatch.setattr(gh, "commit_and_push",
                            lambda **k: pushes.append(k) or "c0ffee1234567")
        fake_gh.pushes = pushes
        return fake_gh
    return install


class TestGates:
    def test_not_requested_is_skipped(self, tmp_path, monkeypatch):
        _enable(monkeypatch)
        out = prc.pr_creator_node(_state(tmp_path, open_pr=False))
        assert out["pr"]["status"] == gh.SKIPPED
        assert out["pr"]["requested"] is False
        assert out["remediation_status"] == "verified_no_pr"

    def test_unverified_patch_is_blocked(self, tmp_path, monkeypatch):
        _enable(monkeypatch)
        out = prc.pr_creator_node(_state(tmp_path, test_verdict="failed"))
        assert out["pr"]["status"] == gh.BLOCKED

    def test_unapproved_patch_is_blocked(self, tmp_path, monkeypatch):
        _enable(monkeypatch)
        out = prc.pr_creator_node(_state(tmp_path, review={"approved": False}))
        assert out["pr"]["status"] == gh.BLOCKED

    def test_disabled_server_skips_with_reason(self, tmp_path):
        out = prc.pr_creator_node(_state(tmp_path))
        assert out["pr"]["status"] == gh.SKIPPED
        assert "PR_CREATION_ENABLED" in out["pr"]["reason"]

    def test_missing_token_skips(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PR_CREATION_ENABLED", "true")
        monkeypatch.setenv("PR_ALLOWED_REPOS", "owner/demo")
        out = prc.pr_creator_node(_state(tmp_path))
        assert out["pr"]["status"] == gh.SKIPPED
        assert "GITHUB_TOKEN" in out["pr"]["reason"]

    def test_repo_not_allowlisted_skips(self, tmp_path, monkeypatch):
        _enable(monkeypatch, allow="someone/else")
        out = prc.pr_creator_node(_state(tmp_path))
        assert out["pr"]["status"] == gh.SKIPPED
        assert "PR_ALLOWED_REPOS" in out["pr"]["reason"]

    def test_non_github_repo_blocked(self, tmp_path, monkeypatch):
        _enable(monkeypatch)
        out = prc.pr_creator_node(_state(
            tmp_path, repo_url="https://gitlab.com/owner/demo"))
        assert out["pr"]["status"] == gh.BLOCKED

    def test_dry_run_writes_body_and_never_calls_github(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PR_CREATION_ENABLED", "true")
        monkeypatch.setenv("DRY_RUN_PR", "true")
        out = prc.pr_creator_node(_state(tmp_path))
        assert out["pr"]["status"] == gh.DRY_RUN
        body = (tmp_path / "runs" / "abcd1234" / "pr_body.md").read_text()
        assert "SQL injection" in body and "22/22" in body


class TestRemoteFlow:
    def test_created_records_api_url(self, tmp_path, monkeypatch, fake):
        _enable(monkeypatch)
        api = fake()
        out = prc.pr_creator_node(_state(tmp_path))
        assert out["pr"]["status"] == gh.CREATED
        assert out["pr_url"] == "https://github.com/owner/demo/pull/7"
        assert out["pr"]["number"] == 7
        assert out["remediation_status"] == "pr_opened"
        assert len(api.pushes) == 1
        assert api.pushes[0]["files"] == ["app/routes.py",
                                          "tests/test_patchforge_cwe89.py"]
        assert api.created[0]["base"] == "main"

    def test_existing_pr_is_not_duplicated(self, tmp_path, monkeypatch, fake):
        _enable(monkeypatch)
        api = fake(existing={"html_url": "https://github.com/owner/demo/pull/3",
                             "number": 3})
        out = prc.pr_creator_node(_state(tmp_path))
        assert out["pr"]["status"] == gh.EXISTS
        assert out["pr_url"].endswith("/pull/3")
        assert api.pushes == [] and api.created == []

    def test_retry_after_push_reuses_branch(self, tmp_path, monkeypatch, fake):
        _enable(monkeypatch)
        api = fake(branch_exists=True)
        out = prc.pr_creator_node(_state(tmp_path))
        assert out["pr"]["status"] == gh.CREATED
        assert api.pushes == []

    def test_moved_base_blocks_push(self, tmp_path, monkeypatch, fake):
        _enable(monkeypatch)
        api = fake(base_sha="sha-someone-else-pushed")
        out = prc.pr_creator_node(_state(tmp_path))
        assert out["pr"]["status"] == gh.BLOCKED
        assert "moved" in out["pr"]["reason"]
        assert api.pushes == []

    def test_no_push_permission_blocks(self, tmp_path, monkeypatch, fake):
        _enable(monkeypatch)
        out = prc.pr_creator_node(_state(tmp_path))  # noqa: F841 (warm-up)
        api = fake(push=False)
        out = prc.pr_creator_node(_state(tmp_path))
        assert out["pr"]["status"] == gh.BLOCKED
        assert api.pushes == []

    def test_api_failure_is_recorded_with_token_masked(self, tmp_path, monkeypatch, fake):
        _enable(monkeypatch)
        fake(create_error=f"422 Validation failed for {TOKEN}")
        out = prc.pr_creator_node(_state(tmp_path))
        assert out["pr"]["status"] == gh.FAILED
        assert TOKEN not in out["pr"]["reason"]
        assert out["pr_url"] is None

    def test_same_patch_same_branch(self):
        fp = gh.patch_fingerprint("diff", "test")
        a = gh.branch_name("patchforge/", "abcd1234", "cwe-89", fp)
        b = gh.branch_name("patchforge/", "abcd1234-r2", "cwe-89", fp)
        assert a == b
        assert a != gh.branch_name("patchforge/", "abcd1234", "cwe-89",
                                   gh.patch_fingerprint("other", "test"))


class TestGitTransport:
    def test_token_never_in_argv_or_url(self):
        env = gh._git_env(TOKEN)
        assert TOKEN not in " ".join(k for k in env if k.startswith("GIT_"))
        assert TOKEN not in env["GIT_CONFIG_VALUE_0"]  # base64-wrapped header
        assert env["GIT_TERMINAL_PROMPT"] == "0"

    def test_commit_and_push_to_local_bare_remote(self, tmp_path):
        def git(*args, cwd):
            subprocess.run(["git", *args], cwd=cwd, check=True,
                           capture_output=True)
        remote = tmp_path / "remote.git"
        git("init", "--bare", "-b", "main", str(remote), cwd=tmp_path)
        seed = tmp_path / "seed"
        git("clone", str(remote), str(seed), cwd=tmp_path)
        (seed / "app.py").write_text("vulnerable = True\n")
        git("add", ".", cwd=seed)
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m",
            "init", cwd=seed)
        git("push", "origin", "HEAD:main", cwd=seed)
        clone = tmp_path / "clone"
        git("clone", str(remote), str(clone), cwd=tmp_path)
        work = tmp_path / "work"
        work.mkdir()
        (work / "app.py").write_text("vulnerable = False\n")
        (work / "tests").mkdir()
        (work / "tests" / "test_fix.py").write_text("def test_fix(): pass\n")

        cfg = gh.pr_config()
        cfg.token = TOKEN
        sha = gh.commit_and_push(repo_path=str(clone), work_dir=str(work),
                                 files=["app.py", "tests/test_fix.py"],
                                 branch="patchforge/t-cwe-89-abc",
                                 message="fix", cfg=cfg)
        shown = subprocess.run(
            ["git", "--git-dir", str(remote), "show",
             "patchforge/t-cwe-89-abc:app.py"],
            capture_output=True, text=True, check=True).stdout
        assert shown == "vulnerable = False\n"
        assert len(sha) == 40
        # the scanned clone itself was not modified
        assert (clone / "app.py").read_text() == "vulnerable = True\n"
        assert not (clone / "tests").exists()

    def test_path_escape_refused(self, tmp_path):
        (tmp_path / "clone").mkdir()
        subprocess.run(["git", "init", str(tmp_path / "clone")], check=True,
                       capture_output=True)
        cfg = gh.pr_config()
        with pytest.raises(gh.PRBlocked):
            gh.commit_and_push(repo_path=str(tmp_path / "clone"),
                               work_dir=str(tmp_path), files=["../outside.py"],
                               branch="patchforge/x", message="m", cfg=cfg)
