"""Runs Semgrep with the auto ruleset and returns normalized findings.

Two engines (prompt 01b, Task B):
- native: the semgrep binary (venv copy or PATH). Unavailable on Windows —
  the package refuses to install there.
- docker: semgrep/semgrep:latest with the repo bind-mounted read-only.

SEMGREP_MODE=auto (default) uses native when present, else Docker when
`docker info` succeeds, else raises a clear RuntimeError. Force one engine
with SEMGREP_MODE=native|docker. The findings format is identical either way.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess  # nosec B404 - argument list only, never shell=True
import sys
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)

SEMGREP_IMAGE = "semgrep/semgrep:latest"

# Last engine used by run_semgrep ("native" | "docker"); the scanner node
# reads it for the agent-feed line. True when the image was just pulled, so
# the node can log the first-run pull.
last_mode: str = "native"
last_pull: bool = False

_docker_ok: bool | None = None


def _semgrep_bin() -> str:
    """
    Absolute path to semgrep: the venv copy if there is one, else whatever is on
    PATH. Resolved rather than invoked by bare name, so an executable planted
    earlier on PATH cannot take its place.
    """
    venv_bin = os.path.join(os.path.dirname(sys.executable), "semgrep")
    if os.path.isfile(venv_bin):
        return venv_bin
    if os.name == "nt":
        venv_exe = venv_bin + ".exe"
        if os.path.isfile(venv_exe):
            return venv_exe
    resolved = shutil.which("semgrep")
    if not resolved:
        raise RuntimeError("semgrep is not installed or not on PATH")
    return resolved


def _semgrep_mode() -> str:
    mode = os.getenv("SEMGREP_MODE", "auto").strip().lower()
    return mode if mode in ("auto", "native", "docker") else "auto"


def _docker_available() -> bool:
    """True when the Docker daemon answers (result cached per process)."""
    global _docker_ok
    if _docker_ok is None:
        try:
            # nosec B603 - resolved daemon probe, fixed argument list, no shell.
            subprocess.run(  # nosec B603
                ["docker", "info"],
                capture_output=True,
                timeout=15,
            )
            _docker_ok = True
        except Exception:
            _docker_ok = False
    return _docker_ok


def _relative(path: str, repo_path: str) -> str:
    """Report paths relative to the repo root. Repos are cloned into a temp
    directory, so the absolute path leaks a meaningless location into reports."""
    if not path:
        return path
    cleaned = path.replace("\\", "/")
    for prefix in ("/src/", "src/"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix):]
            break
    from tools.repo_paths import normalize_repo_path
    if cleaned.startswith("./"):
        cleaned = cleaned[2:]
    if os.path.isabs(path) and not path.replace("\\", "/").startswith("/src/"):
        return normalize_repo_path(path, repo_path)
    return normalize_repo_path(cleaned, repo_path)


_BUNDLED_RULES = Path(__file__).resolve().parent.parent / "rules"


def _fast_mode() -> bool:
    """PARALLEL_AGENTS=0 restores the old path (registry rules, no speed flags)."""
    return os.getenv("PARALLEL_AGENTS", "1").strip().lower() not in ("0", "false", "no", "off")


def _bundled_rules_dir() -> str | None:
    """backend/rules/*.yml (python, flask, secrets), downloaded once, so a
    scan never re-fetches rulesets from the registry. None if missing."""
    if not _fast_mode():
        return None
    if _BUNDLED_RULES.is_dir() and any(_BUNDLED_RULES.glob("*.yml")):
        return str(_BUNDLED_RULES)
    return None


def _rules_dir() -> str | None:
    """Local rules directory: SEMGREP_RULES_PATH, else the bundled rules."""
    local = os.getenv("SEMGREP_RULES_PATH", "").strip()
    if local and os.path.isdir(os.path.expanduser(local)):
        return os.path.expanduser(local)
    return _bundled_rules_dir()


def _speed_flags() -> list[str]:
    """Fast, offline-friendly flags; test and vendor dirs are skipped."""
    if not _fast_mode():
        return []
    flags = ["--metrics=off", "--jobs", "4", "--timeout", "20"]
    skip = ["node_modules", ".venv", "venv"]
    from tools.scan_exclusions import include_tests
    if not include_tests():
        skip = ["tests"] + skip
    for name in skip:
        flags += ["--exclude", name]
    return flags


def _semgrep_config() -> str:
    """
    Ruleset to scan with.

    "auto" resolves rules from the Semgrep registry over the network, so with no
    internet it silently produces zero findings. Point SEMGREP_RULES_PATH at a
    local checkout of semgrep-rules (or any directory of rule YAML) to scan
    fully offline:

        git clone --depth 1 https://github.com/semgrep/semgrep-rules ~/.semgrep-rules
        SEMGREP_RULES_PATH=~/.semgrep-rules
    """
    return _rules_dir() or "auto"


def _parse_results(stdout: str, repo_path: str) -> list[dict]:
    import json as _json

    try:
        data = _json.loads(stdout)
    except _json.JSONDecodeError:
        return []

    normalized = []
    for finding in data.get("results", []):
        extra = finding.get("extra", {})
        normalized.append({
            "source": "semgrep",
            "file": _relative(finding.get("path", ""), repo_path),
            "line": finding.get("start", {}).get("line", 0),
            "severity": extra.get("severity", "WARNING").upper(),
            "description": extra.get("message", ""),
            "code": extra.get("lines", ""),
            "rule_id": finding.get("check_id", ""),
        })

    return normalized


def _ensure_docker_image() -> bool:
    """
    Pull semgrep/semgrep:latest when it is not present. Returns True when a
    pull happened (the scanner node logs it as a first-run notice).
    """
    global last_pull
    # nosec B603 - fixed argument list, no shell.
    probe = subprocess.run(  # nosec B603
        ["docker", "images", "-q", SEMGREP_IMAGE],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if probe.stdout.strip():
        last_pull = False
        return False
    logger.info("Pulling Semgrep Docker image (first run only)…")
    # nosec B603 - fixed argument list, no shell.
    pulled = subprocess.run(  # nosec B603
        ["docker", "pull", SEMGREP_IMAGE],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if pulled.returncode != 0:
        raise RuntimeError(
            "Could not pull semgrep/semgrep:latest: "
            + "\n".join(pulled.stderr.splitlines()[-10:]))
    last_pull = True
    return True


def _run_docker(repo_path: str, files: list[str] | None = None) -> list[dict]:
    global last_mode
    # Docker Desktop accepts C:/… paths; backslashes confuse the daemon
    # (verified: -v "C:\\…:/t:ro" fails, -v "C:/…:/t:ro" mounts fine).
    src = Path(repo_path).resolve().as_posix()
    name = f"semgrep-{uuid.uuid4().hex[:8]}"
    cmd = ["docker", "run", "--rm", "--name", name,
           "-v", f"{src}:/src:ro", "-w", "/src",
           # Persist the registry-rules cache across scans: without it every
           # Docker run re-downloads the ruleset (~1 min of the scan time).
           "-v", "semgrep-cache:/root/.semgrep"]
    rules = _rules_dir()
    if rules:
        cmd += ["-v", f"{Path(rules).resolve().as_posix()}:/rules:ro"]
        config = "/rules"
    else:
        config = "auto"
    cmd += [SEMGREP_IMAGE, "semgrep", "scan", "--config", config,
            "--json", "--quiet", *_speed_flags(),
            *([f"/src/{f}" for f in files] if files else ["."])]
    try:
        # nosec B603 - fixed argument list, no shell.
        result = subprocess.run(  # nosec B603
            cmd,
            capture_output=True,
            text=True,
            timeout=240,
        )
    except subprocess.TimeoutExpired:
        try:
            subprocess.run(["docker", "kill", name],
                           capture_output=True, timeout=15)
        except Exception:
            logger.debug("docker kill %s failed", name, exc_info=True)
        raise RuntimeError("Semgrep Docker run timed out after 240s")
    # Exit code 1 just means findings exist — parse stdout anyway.
    if result.returncode not in (0, 1) or not result.stdout.strip():
        tail = "\n".join(result.stderr.splitlines()[-20:])
        raise RuntimeError(f"Semgrep Docker run failed (exit {result.returncode}): {tail}")
    last_mode = "docker"
    return _parse_results(result.stdout, repo_path)


def _run_native(repo_path: str, files: list[str] | None = None) -> list[dict]:
    global last_mode
    cmd = [_semgrep_bin(), "--config", _semgrep_config()]
    kwargs: dict = {}
    if files:
        # Relative targets with cwd=repo keep output paths repo-relative,
        # comparable with full-scan findings.
        cmd += [f.replace("\\", "/") for f in files]
        kwargs["cwd"] = repo_path
    else:
        cmd += [repo_path]
    cmd += ["--json", "--quiet", *_speed_flags()]
    # nosec B603 - resolved executable, fixed argument list, no shell.
    result = subprocess.run(  # nosec B603
        cmd,
        capture_output=True,
        text=True,
        timeout=180,
        **kwargs,
    )
    last_mode = "native"
    return _parse_results(result.stdout, repo_path)


def run_semgrep(repo_path: str, files: list[str] | None = None) -> list[dict]:
    """Scan the repo (or only `files`, repo-relative) with Semgrep."""
    mode = _semgrep_mode()
    if mode == "native":
        return _run_native(repo_path, files)
    if mode == "docker":
        if not _docker_available():
            raise RuntimeError("Semgrep unavailable: start Docker Desktop "
                               "or set SEMGREP_MODE=native")
        _ensure_docker_image()
        return _run_docker(repo_path, files)
    # auto: native binary first, Docker second, clear error otherwise.
    try:
        return _run_native(repo_path, files)
    except Exception as native_exc:
        logger.debug("native semgrep unavailable (%s), trying Docker", native_exc)
        if not _docker_available():
            raise RuntimeError("Semgrep unavailable: install it in WSL "
                               "or start Docker Desktop") from native_exc
        _ensure_docker_image()
        return _run_docker(repo_path, files)
