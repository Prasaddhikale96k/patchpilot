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

class SandboxUnavailable(RuntimeError):
    """No isolated engine is available; untrusted tests must not run."""


_DOCKER_PROBED_AT = 0.0
_DOCKER_REPROBE_SECS = 30.0


def docker_available() -> bool:
    """True when the Docker daemon actually answers.

    `docker info` exits non-zero when the CLI exists but the daemon is
    down; the old probe only caught a missing binary, so a stopped Docker
    Desktop read as available. A positive result is cached; a negative
    one is re-probed after 30s so starting Docker needs no backend restart.
    """
    global _DOCKER_OK, _DOCKER_PROBED_AT
    if _DOCKER_OK or (_DOCKER_OK is False
                      and time.monotonic() - _DOCKER_PROBED_AT < _DOCKER_REPROBE_SECS):
        return bool(_DOCKER_OK)
    try:
        # nosec B603 - daemon probe, fixed argument list, no shell.
        proc = subprocess.run(["docker", "info", "--format",  # nosec B603
                               "{{.ServerVersion}}"],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=15)
        _DOCKER_OK = proc.returncode == 0 and bool(proc.stdout.strip())
    except Exception:
        _DOCKER_OK = False
    _DOCKER_PROBED_AT = time.monotonic()
    if not _DOCKER_OK:
        logger.warning("sandbox: Docker daemon is not reachable")
    return _DOCKER_OK


def resolve_sandbox() -> str:
    """'docker', or 'venv' ONLY when explicitly requested with SANDBOX=venv.

    SANDBOX=auto|docker never falls back to the host: generated exploit
    tests are untrusted code, and silently running them outside a
    container (as the old auto/docker fallback did) is exactly what the
    sandbox exists to prevent. SANDBOX=venv is a deliberate developer
    opt-in and is logged loudly.
    """
    mode = os.getenv("SANDBOX", "auto").strip().lower()
    if mode == "venv":
        logger.warning("sandbox: SANDBOX=venv — tests run UNISOLATED on the "
                       "host. Use only with trusted fixtures.")
        return "venv"
    if docker_available():
        logger.info("sandbox: engine=docker (SANDBOX=%s)", mode)
        return "docker"
    raise SandboxUnavailable(
        "Docker is not available, so generated tests cannot be run in "
        "isolation. Start Docker (or Docker Desktop) and retry. Tests are "
        "never run on the host unless SANDBOX=venv is set explicitly.")


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
    if not blobs:
        # Stdlib-only project: no manifests to stage, so there is nothing
        # to COPY and nothing to pip-install besides the test runner.
        # (The old text unconditionally COPYed requirements.txt and ran
        # `pip install -e .`, which fails without manifests in context.)
        return ("FROM python:3.12-slim\nWORKDIR /app\n"
                "RUN pip install --no-cache-dir pytest\n")
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
    if not blobs:
        # Stdlib-only project (e.g. DSVPWA: app + tests import nothing
        # beyond the standard library, so the clone legitimately has no
        # requirements.txt / pyproject.toml / setup.py). The old code
        # raised "No dependency files" here, which made every such repo
        # permanently unverifiable — reviewer-approved patches could never
        # reach Docker verification or a PR. A pytest-only image is the
        # correct environment; missing third-party imports, if any, still
        # surface honestly as test failures/errors, never as passes.
        logger.info("sandbox: no supported manifests in %s — building "
                    "stdlib-only (pytest) image %s", code_dir, tag)
    build_dir = tempfile.mkdtemp(prefix="pp-build-")
    try:
        for name, content in blobs.items():
            (Path(build_dir) / name).write_bytes(content)
        if blobs and "requirements.txt" not in blobs:
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

_MAX_JUNIT_BYTES = 5 * 1024 * 1024

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
        # junit.xml is written by code running inside the sandbox, i.e. by
        # an untrusted test. Cap its size and refuse any DTD/ENTITY before
        # the host parses it (entity-expansion "billion laughs" defence).
        if os.path.getsize(xml_path) > _MAX_JUNIT_BYTES:
            raise ValueError("junit.xml too large")
        with open(xml_path, "rb") as fh:
            raw = fh.read()
        if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
            raise ValueError("junit.xml contains a DTD; refusing to parse")
        root = ET.fromstring(raw)  # nosec B314 - size-capped, DTD-free, see above
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

# docker's own exit codes: the container never ran the tests.
_DOCKER_INFRA_RCS = {125: "docker could not create/start the container",
                     126: "the test command could not be invoked",
                     127: "the test command was not found in the image"}


def docker_run_args(code_dir: str, out_dir: str, tag: str, name: str) -> list[str]:
    """Locked-down `docker run` prefix shared by every test phase.

    No network, bounded memory/CPU/pids, all capabilities dropped,
    no privilege escalation, non-root user, read-only root filesystem.
    Writable: /tmp (tmpfs), /out (results) and /app — which is always a
    DISPOSABLE copy made for this phase, never the scanned clone or any
    user checkout. (A read-only /app broke ordinary apps that create
    their instance/ dir on startup: VulnBank's 22 tests all errored.)
    No Docker socket or host credential is mounted.
    """
    return ["docker", "run", "--rm", "--name", name,
            "--network", "none", "--memory", "1g", "--memory-swap", "1g",
            "--cpus", "1", "--pids-limit", "256",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", _container_user(), "--read-only",
            # container-side tmpfs, not a host path
            "--tmpfs", "/tmp:rw,exec,size=256m",  # nosec B108
            "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "HOME=/tmp",
            "-v", f"{host_path_for_docker(code_dir)}:/app",
            "-v", f"{host_path_for_docker(out_dir)}:/out",
            "-w", "/app", tag]


def _container_user() -> str:
    """Non-root uid that can write the disposable bind mount.

    Linux: the host user's own uid (the copy is owned by it). Docker
    Desktop (Windows/macOS) maps bind-mount ownership, so the unprivileged
    `nobody` uid works there. Never root.
    """
    getuid = getattr(os, "getuid", None)
    if getuid is not None and getuid() != 0:
        return f"{getuid()}:{os.getgid()}"
    return "65534:65534"

def _run_tests_docker(code_dir: str, phase: str, tag: str,
                      selector: str | None, scan_id: str,
                      timeout: int) -> dict:
    out_dir = tempfile.mkdtemp(prefix=f"pp-out-{scan_id}-{phase}-")
    # The container runs as an unprivileged uid; let it write junit.xml.
    os.chmod(out_dir, 0o777)  # nosec B103 - private temp dir, results only
    name = f"pp-{scan_id}-{phase}-{os.getpid()}-{int(time.time())}"
    cmd = docker_run_args(code_dir, out_dir, tag, name) + [
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
        logger.warning("sandbox: docker run timed out: scan=%s phase=%s "
                       "container=%s after %ss; killed", scan_id, phase,
                       name, timeout)
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
    # pytest exit codes: 0 ok, 1 failures, 2 interrupted, 3 internal error,
    # 4 usage error, 5 no tests collected. Docker's 125-127 mean the tests
    # never ran. Either way "0 failures" must not read as a pass.
    if returncode in _DOCKER_INFRA_RCS:
        report["infra_error"] = (f"{_DOCKER_INFRA_RCS[returncode]} "
                                 f"(exit {returncode}): {output.strip()[-300:]}")
    elif returncode in (2, 3, 4):
        report["infra_error"] = f"pytest could not run (exit {returncode})"
    logger.info("sandbox: docker run done: scan=%s phase=%s rc=%s "
                "passed=%s failed=%s errors=%s (%.1fs)", scan_id, phase,
                returncode, report["passed"], report["failed"],
                report["errors"], duration)
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
