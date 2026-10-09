"""Tests for Semgrep native/Docker engine selection (prompt 01b, Task B).

subprocess.run is mocked: no Docker or Semgrep binary is needed.
"""

from __future__ import annotations

import json

import pytest

import tools.semgrep_runner as semgrep_runner


def _finding(path):
    return {"path": path, "start": {"line": 7},
            "extra": {"severity": "ERROR", "message": "SQL injection",
                      "lines": "q = 'select ' + u"},
            "check_id": "python.lang.security.audit.sqli"}


def _json_payload(paths):
    return json.dumps({"results": [_finding(p) for p in paths], "errors": []})


@pytest.fixture(autouse=True)
def reset_runner_state(monkeypatch):
    monkeypatch.setattr(semgrep_runner, "last_mode", "native")
    monkeypatch.setattr(semgrep_runner, "last_pull", False)
    monkeypatch.setattr(semgrep_runner, "_docker_ok", None)
    monkeypatch.delenv("SEMGREP_MODE", raising=False)
    monkeypatch.delenv("SEMGREP_RULES_PATH", raising=False)
    yield


class _FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _dispatcher(monkeypatch, calls, native_json=None, docker_json=None,
                image_present=True):
    """Route mocked subprocess.run by command shape; record every command."""
    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        if cmd[:2] == ["docker", "info"]:
            return _FakeCompleted(0, "", "")
        if cmd[:2] == ["docker", "images"]:
            return _FakeCompleted(0, "sha256:abc\n" if image_present else "", "")
        if cmd[:2] == ["docker", "pull"]:
            return _FakeCompleted(0, "Pulled", "")
        if cmd and cmd[0] == "docker":
            assert "--name" in cmd and "-v" in cmd and "-w" in cmd
            assert cmd[-5:] == ["--json", "--quiet", "--timeout", "30", "."]
            return _FakeCompleted(1 if docker_json else 0, docker_json or "", "")
        return _FakeCompleted(0, native_json or "", "")
    monkeypatch.setattr(semgrep_runner.subprocess, "run", fake_run)


class TestAutoSelection:
    def test_auto_picks_native_when_binary_exists(self, monkeypatch, tmp_path):
        calls: list = []
        _dispatcher(monkeypatch, calls,
                    native_json=_json_payload(["app/x.py"]))
        monkeypatch.setattr(semgrep_runner, "_semgrep_bin",
                            lambda: "C:/venv/Scripts/semgrep.exe")
        findings = semgrep_runner.run_semgrep(str(tmp_path))
        assert semgrep_runner.last_mode == "native"
        assert findings[0]["file"] == "app/x.py"
        assert not any(c[0] == "docker" for c in calls)

    def test_auto_picks_docker_when_native_missing(self, monkeypatch, tmp_path):
        calls: list = []
        _dispatcher(monkeypatch, calls,
                    docker_json=_json_payload(["/src/app/x.py"]))
        monkeypatch.setattr(semgrep_runner, "_semgrep_bin",
                            lambda: (_ for _ in ()).throw(
                                RuntimeError("semgrep is not installed")))
        findings = semgrep_runner.run_semgrep(str(tmp_path))
        assert semgrep_runner.last_mode == "docker"
        assert findings[0]["file"] == "app/x.py"
        docker_runs = [c for c in calls if c[:2] == ["docker", "run"]]
        assert len(docker_runs) == 1
        assert "--rm" in docker_runs[0] and "--name" in docker_runs[0]
        assert "semgrep/semgrep:latest" in docker_runs[0]

    def test_docker_unavailable_raises_clear_error(self, monkeypatch, tmp_path):
        monkeypatch.setattr(semgrep_runner, "_semgrep_bin",
                            lambda: (_ for _ in ()).throw(RuntimeError("nope")))
        monkeypatch.setattr(semgrep_runner, "_docker_available", lambda: False)
        with pytest.raises(RuntimeError, match="install it in WSL|start Docker"):
            semgrep_runner.run_semgrep(str(tmp_path))


class TestDockerOutput:
    def _docker_findings(self, monkeypatch, tmp_path, payload):
        calls: list = []
        _dispatcher(monkeypatch, calls, docker_json=payload)
        monkeypatch.setenv("SEMGREP_MODE", "docker")
        monkeypatch.setattr(semgrep_runner, "_docker_available", lambda: True)
        return semgrep_runner.run_semgrep(str(tmp_path)), calls

    def test_src_prefixed_paths_normalized(self, monkeypatch, tmp_path):
        findings, _ = self._docker_findings(
            monkeypatch, tmp_path, _json_payload(["/src/app/x.py", "lib/y.py"]))
        assert [f["file"] for f in findings] == ["app/x.py", "lib/y.py"]

    def test_exit_code_1_with_json_still_parses(self, monkeypatch, tmp_path):
        findings, _ = self._docker_findings(
            monkeypatch, tmp_path, _json_payload(["/src/a.py"]))
        assert len(findings) == 1
        assert findings[0]["rule_id"].endswith("sqli")

    def test_repo_path_is_resolved_posix_for_volume(self, monkeypatch, tmp_path):
        _, calls = self._docker_findings(
            monkeypatch, tmp_path, _json_payload([]))
        volumes = [c[i + 1] for c in calls for i, a in enumerate(c)
                   if a == "-v"]
        assert any(":/src:ro" in v and "\\" not in v for v in volumes)
        assert any(v == "semgrep-cache:/root/.semgrep" for v in volumes)

    def test_real_docker_error_raises_with_stderr_tail(self, monkeypatch, tmp_path):
        def failing_run(cmd, **kwargs):
            if cmd[:2] == ["docker", "images"]:
                return _FakeCompleted(0, "sha256:abc\n", "")
            if cmd and cmd[0] == "docker":
                return _FakeCompleted(125, "", "docker: bad flag\nline2")
            return _FakeCompleted(0, "", "")

        monkeypatch.setattr(semgrep_runner.subprocess, "run", failing_run)
        monkeypatch.setenv("SEMGREP_MODE", "docker")
        monkeypatch.setattr(semgrep_runner, "_docker_available", lambda: True)
        with pytest.raises(RuntimeError, match="exit 125"):
            semgrep_runner.run_semgrep(str(tmp_path))
