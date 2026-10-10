"""Speculative baseline: warm the Docker image and run the baseline tests in
the background while the scan is still analysing, so the Tester node finds
the result waiting instead of running it itself.

Results are cached by (repo_url, commit sha): the same commit never has its
baseline run twice. Only clean runs are cached (an infrastructure error or a
timeout is never reused).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess  # nosec B404 - fixed argument list, no shell
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_inflight: dict[str, Future] = {}
_memory: dict[str, dict] = {}
_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="baseline")


def _cache_dir() -> Path:
    base = os.getenv("BASELINE_CACHE_DIR", "").strip()
    path = Path(base) if base else Path(__file__).resolve().parents[2] / "runs" / "_baseline_cache"
    path.mkdir(parents=True, exist_ok=True)
    return path


def commit_sha(repo_path: str) -> str:
    """HEAD sha of a clone, or "" when it cannot be determined."""
    try:
        out = subprocess.run(  # nosec B603 B607
            ["git", "-C", repo_path, "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=15)
        return out.stdout.strip() if out.returncode == 0 else ""
    except Exception:
        return ""


def cache_key(repo_url: str, sha: str) -> str:
    return hashlib.sha256(f"{repo_url}@{sha}".encode()).hexdigest()[:32]


def _usable(report: dict | None) -> bool:
    return bool(report) and not report.get("infra_error") and not report.get("timed_out")


def _load(key: str) -> dict | None:
    with _lock:
        if key in _memory:
            return _memory[key]
    path = _cache_dir() / f"{key}.json"
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if _usable(report):
        with _lock:
            _memory[key] = report
        return report
    return None


def _store(key: str, report: dict) -> None:
    if not _usable(report):
        return
    with _lock:
        _memory[key] = report
    try:
        (_cache_dir() / f"{key}.json").write_text(json.dumps(report), encoding="utf-8")
    except OSError:
        logger.debug("baseline cache write failed", exc_info=True)


def _run_baseline(repo_path: str, scan_id: str) -> dict | None:
    """Prepare the image and run the baseline phase on a throwaway copy."""
    from agents.remediation.tester import _fresh_copy
    from tools.sandbox import SandboxUnavailable, prepare_image, resolve_sandbox, run_tests

    try:
        engine = resolve_sandbox()
    except SandboxUnavailable:
        return None
    tag = prepare_image(repo_path) if engine == "docker" else None
    code_dir = _fresh_copy(repo_path, "baseline")
    try:
        return run_tests(code_dir, "baseline", tag, scan_id=scan_id)
    finally:
        shutil.rmtree(os.path.dirname(code_dir), ignore_errors=True)


def start(repo_url: str, repo_path: str, scan_id: str) -> str | None:
    """Kick the baseline off in the background. Returns the cache key."""
    sha = commit_sha(repo_path)
    if not sha:
        return None
    key = cache_key(repo_url, sha)
    with _lock:
        if key in _memory or key in _inflight:
            return key
    if _load(key):
        return key

    def _job() -> dict | None:
        try:
            report = _run_baseline(repo_path, scan_id)
            if report:
                _store(key, report)
            return report
        except Exception:
            logger.warning("speculative baseline failed", exc_info=True)
            return None
        finally:
            with _lock:
                _inflight.pop(key, None)

    with _lock:
        _inflight[key] = _executor.submit(_job)
    return key


def get(repo_url: str, repo_path: str, wait_s: float = 600.0) -> dict | None:
    """The cached baseline for this commit, waiting for an in-flight run."""
    sha = commit_sha(repo_path)
    if not sha:
        return None
    key = cache_key(repo_url, sha)
    with _lock:
        future = _inflight.get(key)
    if future is not None:
        try:
            future.result(timeout=wait_s)
        except Exception:
            return None
    return _load(key)
