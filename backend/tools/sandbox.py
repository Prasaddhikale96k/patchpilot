"""Docker sandbox test runner (prompt 04a).

Runs a target repo's pytest suite either in a locked-down Docker container
(preferred) or a local venv fallback, with an identical TestReport dict
either way. The tester node (prompt 04b) consumes prepare_image/run_tests;
scripts/local_verify.py already imports the shared venv helpers from here.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import subprocess  # nosec B404 - argument list only, never shell=True
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

logger = logging.getLogger(__name__)

_DOCKER_OK: bool | None = None

_DEP_FILES = ("requirements.txt", "pyproject.toml", "setup.py")


def _timeout_secs() -> int:
    try:
        return max(30, int(os.getenv("SANDBOX_TIMEOUT_SECS", "180")))
    except ValueError:
        return 180


# ── Engine resolution ─────────────────────────────────────────────────────

def docker_available() -> bool:
    """True when the Docker daemon answers (result cached per process)."""
    global _DOCKER_OK
    if _DOCKER_OK is None:
        try:
            # nosec B603 - daemon probe, fixed argument list, no shell.
            subprocess.run(["docker", "info"],  # nosec B603
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=15)
            _DOCKER_OK = True
        except Exception:
            _DOCKER_OK = False
    return _DOCKER_OK


def resolve_sandbox() -> str:
    """'docker' or 'venv' per SANDBOX=auto|docker|venv (auto prefers docker)."""
    mode = os.getenv("SANDBOX", "auto").strip().lower()
    if mode == "docker":
        engine = "docker" if docker_available() else "venv"
        if engine == "venv":
            logger.warning("sandbox: SANDBOX=docker but Docker is down — venv")
    elif mode == "venv":
        engine = "venv"
    else:
        engine = "docker" if docker_available() else "venv"
    logger.info("sandbox: engine=%s (SANDBOX=%s)", engine, mode)
    return engine


def detect_project(code_dir: str) -> str | None:
    """'python' when dependency files exist, else None."""
    root = Path(code_dir)
    if any((root / name).is_file() for name in _DEP_FILES):
        return "python"
    for pattern in ("requirements*.txt",):
        if next(root.glob(pattern), None) is not None:
            return "python"
    return None


def host_path_for_docker(path: str) -> str:
    """C:\\… → C:/… forward-slash form Docker Desktop accepts for -v."""
    return Path(path).resolve().as_posix()


# ── Image build (content-addressed, reused) ───────────────────────────────

def _dep_digest(code_dir: str) -> tuple[str, dict[str, bytes]]:
    """sha256 over the sorted dependency-file contents present in code_dir."""
    root = Path(code_dir)
    blobs: dict[str, bytes] = {}
    for name in sorted(os.listdir(code_dir)):
        full = root / name
        if not full.is_file():
            continue
        if (name in _DEP_FILES or
                (name.startswith("requirements") and name.endswith(".txt"))):
            blobs[name] = full.read_bytes()
    digest = hashlib.sha256()
    for name in sorted(blobs):
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(blobs[name])
    return digest.hexdigest()[:12], blobs


def _dockerfile_text(blobs: dict[str, bytes]) -> str:
    copies = " ".join(sorted(blobs)) or "requirements.txt"
    if "requirements.txt" in blobs:
        install = ("RUN pip install --no-cache-dir -r requirements.txt; "
                   "pip install --no-cache-dir pytest")
    else:
        install = ("RUN pip install --no-cache-dir -e .; "
                   "pip install --no-cache-dir pytest")
    return (f"FROM python:3.12-slim\nWORKDIR /app\n"
            f"COPY {copies} ./\n{install}\n")


def _image_exists(tag: str) -> bool:
    proc = subprocess.run(["docker", "image", "inspect", tag],  # nosec B603
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=30)
    return proc.returncode == 0


def prepare_image(code_dir: str) -> str:
    """Build (or reuse) the dependency image for code_dir. Returns the tag.

    Tag = pp-deps-<12 hex chars of the dependency files' sha256>, so
    identical dependency sets share one image across scans. On build
    failure raises RuntimeError carrying the last 40 lines of output.
    """
    if not docker_available():
        raise RuntimeError("Docker is unavailable (docker info failed)")
    digest, blobs = _dep_digest(code_dir)
    tag = f"pp-deps-{digest}"
    if _image_exists(tag):
        print(f"reusing image {tag}")
        logger.info("sandbox: reusing image %s", tag)
        return tag
    if detect_project(code_dir) is None:
        raise RuntimeError(f"No dependency files in {code_dir}")
    build_dir = tempfile.mkdtemp(prefix="pp-build-")
    try:
        for name, content in blobs.items():
            (Path(build_dir) / name).write_bytes(content)
        if "requirements.txt" not in blobs:
            (Path(build_dir) / "requirements.txt").write_text("")
        (Path(build_dir) / "Dockerfile").write_text(
            _dockerfile_text(blobs))
        logger.info("sandbox: building image %s (uses network)…", tag)
        # nosec B603 - fixed argument list, no shell. Build needs network.
        proc = subprocess.run(  # nosec B603
            ["docker", "build", "-t", tag, build_dir],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=600)
        if proc.returncode != 0:
            tail = "\n".join((proc.stdout + "\n" + proc.stderr)
                             .splitlines()[-40:])
            raise RuntimeError(f"docker build failed for {tag}:\n{tail}")
    finally:
        shutil.rmtree(build_dir, ignore_errors=True)
    logger.info("sandbox: built image %s", tag)
    return tag


# ── JUnit parsing ─────────────────────────────────────────────────────────

_SUMMARY_RES = {
    "passed": re.compile(r"(\d+) passed"),
    "failed": re.compile(r"(\d+) failed"),
    "errors": re.compile(r"(\d+) error"),
    "skipped": re.compile(r"(\d+) skipped"),
}


def parse_junit(xml_path: str, phase: str, output_text: str,
                duration_s: float, sandbox: str) -> dict:
    """Build the TestReport dict from junit.xml, or the summary line."""
    passed_names: list[str] = []
    failed_tests: list[dict] = []
    total = passed = failed = errors = skipped = 0
    parsed = False
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        suites = root.findall("testsuite") or [root]
        for suite in suites:
            total += int(suite.get("tests", 0))
            failed += int(suite.get("failures", 0))
            errors += int(suite.get("errors", 0))
            skipped += int(suite.get("skipped", 0))
            duration_s = float(suite.get("time", duration_s))
            for case in suite.findall("testcase"):
                name = f"{case.get('classname', '')}::{case.get('name', '')}"
                trouble = case.find("failure")
                if trouble is None:
                    trouble = case.find("error")
                if trouble is None:
                    passed_names.append(name)
                else:
                    message = (trouble.get("message", "") or "")
                    text = (trouble.text or "")[:500]
                    failed_tests.append(
                        {"name": name, "message": f"{message} {text}".strip()})
        passed = total - failed - errors - skipped
        parsed = True
    except (ET.ParseError, OSError, ValueError):
        parsed = False
    if not parsed or total == 0 and not output_text.strip():
        counts = {k: (int(m.group(1)) if (m := rx.search(output_text)) else 0)
                  for k, rx in _SUMMARY_RES.items()}
        passed, failed, errors, skipped = (
            counts["passed"], counts["failed"], counts["errors"],
            counts["skipped"])
        total = passed + failed + errors + skipped
    return {
        "phase": phase,
        "total": total,
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "skipped": skipped,
        "duration_s": round(duration_s, 2),
        "passed_names": passed_names,
        "failed_tests": failed_tests,
        "output_tail": "\n".join(output_text.splitlines()[-60:]),
        "sandbox": sandbox,
        "timed_out": False,
    }


def run_cmd(cmd: list[str], cwd: str, timeout: int):
    """Shared subprocess helper (list form, no shell; UTF-8 output)."""
    return subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout,
                          cwd=cwd)


# ── Docker run ────────────────────────────────────────────────────────────

def _run_tests_docker(code_dir: str, phase: str, tag: str,
                      selector: str | None, scan_id: str,
                      timeout: int) -> dict:
    out_dir = tempfile.mkdtemp(prefix=f"pp-out-{scan_id}-{phase}-")
    name = f"pp-{scan_id}-{phase}"
    cmd = ["docker", "run", "--rm", "--name", name,
           "--network", "none", "--memory", "1g", "--cpus", "1",
           "--pids-limit", "256",
           "-e", "PYTHONDONTWRITEBYTECODE=1",
           "-v", f"{host_path_for_docker(code_dir)}:/app",
           "-v", f"{host_path_for_docker(out_dir)}:/out",
           "-w", "/app", tag,
           "python", "-m", "pytest", "-q", "-p", "no:cacheprovider",
           "--junitxml=/out/junit.xml"]
    if selector:
        cmd.append(selector)
    start = time.perf_counter()
    timed_out = False
    returncode = 0
    try:
        # nosec B603 - fixed argument list, no shell.
        proc = subprocess.run(cmd, capture_output=True,  # nosec B603
                              text=True, encoding="utf-8", errors="replace",
                              timeout=timeout)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        returncode = proc.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = 124
        output = ((exc.stdout or b"").decode(errors="replace")
                  if isinstance(exc.stdout, bytes) else (exc.stdout or ""))
        try:
            subprocess.run(["docker", "kill", name],  # nosec B603
                           capture_output=True, timeout=15)
        except Exception:
            logger.debug("sandbox: docker kill %s failed", name,
                         exc_info=True)
    duration = time.perf_counter() - start
    report = parse_junit(os.path.join(out_dir, "junit.xml"), phase, output,
                         duration, "docker")
    report["timed_out"] = timed_out
    report["returncode"] = returncode
    shutil.rmtree(out_dir, ignore_errors=True)
    return report


# ── venv fallback (shared with scripts/local_verify.py) ───────────────────

def create_venv(work_dir: str) -> str:
    """Create a venv under work_dir; return the python binary path."""
    venv = os.path.join(work_dir, "venv")
    proc = run_cmd([sys.executable, "-m", "venv", venv], work_dir, 300)
    if proc.returncode != 0:
        raise RuntimeError(f"venv creation failed: {proc.stderr[-1000:]}")
    scripts = "Scripts" if os.name == "nt" else "bin"
    return os.path.join(venv, scripts, "python")


def install_requirements(python_bin: str, code_dir: str,
                         timeout: int = 600) -> None:
    """pip install the project's requirements (if any) + pytest."""
    pip = os.path.join(os.path.dirname(python_bin), "pip")
    req = os.path.join(code_dir, "requirements.txt")
    if os.path.isfile(req):
        proc = run_cmd([pip, "install", "-r", req], code_dir, timeout)
        if proc.returncode != 0:
            raise RuntimeError(
                f"requirements install failed:\n{proc.stderr[-2000:]}")
    proc = run_cmd([pip, "install", "pytest"], code_dir, timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"pytest install failed:\n{proc.stderr[-2000:]}")


def run_tests_venv(code_dir: str, phase: str, python_bin: str,
                   selector: str | None = None,
                   timeout: int | None = None) -> dict:
    """Run pytest with a venv python; same TestReport shape as Docker."""
    timeout = timeout or _timeout_secs()
    cmd = [python_bin, "-m", "pytest", "-q", "-p", "no:cacheprovider"]
    if selector:
        cmd.append(selector)
    start = time.perf_counter()
    timed_out = False
    try:
        proc = run_cmd(cmd, code_dir, timeout)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        returncode = proc.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        output = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        returncode = 124
    duration = time.perf_counter() - start
    report = parse_junit("", phase, output, duration, "venv")
    report["timed_out"] = timed_out
    report["returncode"] = returncode
    return report


# ── Entry point ───────────────────────────────────────────────────────────

def run_tests(code_dir: str, phase: str, tag: str | None,
              selector: str | None = None, scan_id: str = "x") -> dict:
    """Run one test phase via the resolved engine (docker or venv)."""
    engine = resolve_sandbox()
    timeout = _timeout_secs()
    if engine == "docker":
        if not tag:
            raise RuntimeError("docker engine needs a prepared image tag")
        return _run_tests_docker(code_dir, phase, tag, selector, scan_id,
                                 timeout)
    work = tempfile.mkdtemp(prefix=f"pp-venv-{scan_id}-{phase}-")
    try:
        python_bin = create_venv(work)
        install_requirements(python_bin, code_dir, timeout)
        return run_tests_venv(code_dir, phase, python_bin, selector, timeout)
    finally:
        shutil.rmtree(work, ignore_errors=True)
