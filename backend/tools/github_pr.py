"""GitHub branch + commit + push + pull request for a verified patch.

Remote writes happen only when EVERY gate in `pr_config()` passes; the
caller (pr_creator node) additionally requires an explicit request and a
reviewer-approved, Docker-verified patch. Nothing here decides that a PR
is wanted.

Safety properties:
- Repository identity is checked against the API (full_name, push
  permission) and an explicit allowlist (PR_ALLOWED_REPOS).
- The scanned revision must still be the base branch head; if the base
  moved, the patch was verified against different code and we stop.
- Branch name = prefix + scan + content fingerprint, so a retry of the
  same patch finds the existing branch/PR instead of opening a duplicate.
- The token never appears in argv, URLs, logs or errors: git receives it
  through GIT_CONFIG_* environment variables as an http.extraheader.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
import shutil
import subprocess  # nosec B404 - argument lists only, never shell=True
import tempfile
from dataclasses import dataclass, field

import requests

from tools.log_safety import redact

logger = logging.getLogger(__name__)

API = "https://api.github.com"
_REPO_URL_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$")
_TIMEOUT = 20

# outcome statuses recorded in the report
CREATED = "created"
EXISTS = "exists"
DRY_RUN = "dry_run"
SKIPPED = "skipped"      # not configured / disabled (safe no-op)
BLOCKED = "blocked"      # configured, but a safety check refused
FAILED = "failed"        # attempted and the remote operation failed


class PRBlocked(RuntimeError):
    """A safety check refused the remote write (message is user-safe)."""


@dataclass
class PRConfig:
    enabled: bool
    dry_run: bool
    token: str = field(repr=False)
    allowed: frozenset[str]
    base_branch: str
    branch_prefix: str
    author_name: str
    author_email: str

    def missing(self, slug: str) -> str | None:
        """Why PR creation cannot run for `slug`, or None when it can."""
        if not self.enabled:
            return ("PR creation is disabled on this server "
                    "(set PR_CREATION_ENABLED=true to allow it).")
        if self.dry_run:
            return None  # dry runs need no token/allowlist: no remote writes
        if not self.token:
            return "GITHUB_TOKEN is not configured on the backend."
        if slug.lower() not in self.allowed:
            return (f"{slug} is not in PR_ALLOWED_REPOS; remote writes are "
                    "only made to explicitly allowlisted repositories.")
        return None


def _truthy(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


def pr_config() -> PRConfig:
    allowed = frozenset(s.strip().lower() for s in
                        os.getenv("PR_ALLOWED_REPOS", "").split(",") if s.strip())
    return PRConfig(
        enabled=_truthy("PR_CREATION_ENABLED"),
        dry_run=_truthy("DRY_RUN_PR"),
        token=os.getenv("GITHUB_TOKEN", "").strip(),
        allowed=allowed,
        base_branch=os.getenv("PR_BASE_BRANCH", "").strip(),
        branch_prefix=os.getenv("PR_BRANCH_PREFIX", "patchforge/").strip() or "patchforge/",
        author_name=os.getenv("PR_AUTHOR_NAME", "PatchForge Bot"),
        author_email=os.getenv("PR_AUTHOR_EMAIL",
                               "patchforge-bot@users.noreply.github.com"),
    )


def parse_repo_slug(repo_url: str) -> str:
    match = _REPO_URL_RE.match((repo_url or "").strip())
    if not match:
        raise PRBlocked("Only https://github.com/<owner>/<repo> repositories "
                        "are supported for PR creation.")
    return f"{match.group('owner')}/{match.group('repo')}"


def _slug_part(text: str, limit: int = 24) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")[:limit] or "fix"


def branch_name(prefix: str, scan_id: str, cwe_hint: str, fingerprint: str) -> str:
    """Deterministic per (scan, patch content): retries reuse it."""
    root = scan_id.split("-r")[0]
    name = f"{prefix}{_slug_part(root, 12)}-{_slug_part(cwe_hint)}-{fingerprint[:10]}"
    if not re.fullmatch(r"[A-Za-z0-9._/\-]+", name) or ".." in name:
        raise PRBlocked("Refusing an unsafe branch name.")
    return name


def patch_fingerprint(diff: str, test_content: str) -> str:
    digest = hashlib.sha256()
    digest.update((diff or "").encode())
    digest.update(b"\0")
    digest.update((test_content or "").encode())
    return digest.hexdigest()


# ── GitHub REST ───────────────────────────────────────────────────────────

class GitHub:
    def __init__(self, token: str, session: requests.Session | None = None):
        self._token = token
        self._s = session or requests.Session()
        self._s.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "PatchPilot",
        })

    def _call(self, method: str, path: str, **kw) -> requests.Response:
        """One API call. Idempotent GETs retry transient failures (network
        error, 5xx) with backoff; writes never auto-retry — the caller
        re-checks remote state instead, so a lost response cannot open a
        second PR. Rate limiting is raised as GitHubRateLimited."""
        attempts = _GET_ATTEMPTS if method == "GET" else 1
        for attempt in range(1, attempts + 1):
            try:
                resp = self._s.request(method, f"{API}{path}", timeout=_TIMEOUT, **kw)
            except requests.RequestException as exc:
                if attempt == attempts:
                    raise RuntimeError(self.mask(f"GitHub API unreachable: {exc}")) from None
                _sleep(_BACKOFF_SECS * attempt)
                continue
            if _is_rate_limited(resp):
                raise GitHubRateLimited(_rate_limit_message(resp))
            if resp.status_code >= 500 and attempt < attempts:
                _sleep(_BACKOFF_SECS * attempt)
                continue
            return resp
        raise RuntimeError("unreachable")  # pragma: no cover

    def mask(self, text: str) -> str:
        text = text.replace(self._token, "***") if self._token else text
        return redact(text)

    def _error(self, resp: requests.Response, what: str) -> RuntimeError:
        try:
            message = resp.json().get("message", "")
        except ValueError:
            message = resp.text[:200]
        return RuntimeError(self.mask(f"{what} failed: HTTP {resp.status_code} {message}"))

    def repo(self, slug: str) -> dict:
        resp = self._call("GET", f"/repos/{slug}")
        if resp.status_code == 404:
            raise PRBlocked(f"Repository {slug} is not visible to this token.")
        if resp.status_code in (401, 403):
            raise PRBlocked("GitHub rejected the token (authentication or "
                            "permission failure).")
        if resp.status_code != 200:
            raise self._error(resp, "Reading the repository")
        return resp.json()

    def branch_sha(self, slug: str, branch: str) -> str | None:
        resp = self._call("GET", f"/repos/{slug}/branches/{branch}")
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise self._error(resp, f"Reading branch {branch}")
        return resp.json()["commit"]["sha"]

    def open_pr_for(self, slug: str, owner: str, branch: str) -> dict | None:
        resp = self._call("GET", f"/repos/{slug}/pulls",
                          params={"head": f"{owner}:{branch}", "state": "open"})
        if resp.status_code != 200:
            raise self._error(resp, "Listing pull requests")
        pulls = resp.json()
        return pulls[0] if pulls else None

    def create_pr(self, slug: str, *, title: str, head: str, base: str,
                  body: str) -> dict:
        resp = self._call("POST", f"/repos/{slug}/pulls", json={
            "title": title, "head": head, "base": base, "body": body,
            "maintainer_can_modify": True})
        if resp.status_code != 201:
            raise self._error(resp, "Creating the pull request")
        data = resp.json()
        if not data.get("html_url") or not data.get("number"):
            raise RuntimeError("GitHub returned no pull request URL/number.")
        return data

    def file_at(self, slug: str, path: str, ref: str) -> bytes | None:
        """Raw file content at `ref`, or None when the file is absent."""
        resp = self._call("GET", f"/repos/{slug}/contents/{path}",
                          params={"ref": ref})
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise self._error(resp, f"Reading {path} at {ref}")
        data = resp.json()
        if not isinstance(data, dict) or data.get("encoding") != "base64":
            return None
        return base64.b64decode(data.get("content", ""))


class GitHubRateLimited(RuntimeError):
    """GitHub refused the call for rate limiting (message is user-safe)."""


_GET_ATTEMPTS = 3
_BACKOFF_SECS = 1.0


def _sleep(seconds: float) -> None:
    import time
    time.sleep(seconds)


def _is_rate_limited(resp: requests.Response) -> bool:
    if resp.status_code == 429:
        return True
    if resp.status_code != 403:
        return False
    if resp.headers.get("X-RateLimit-Remaining") == "0":
        return True
    try:
        return "rate limit" in (resp.json().get("message", "") or "").lower()
    except ValueError:
        return False


def _rate_limit_message(resp: requests.Response) -> str:
    import time
    reset = resp.headers.get("X-RateLimit-Reset", "")
    retry_after = resp.headers.get("Retry-After", "")
    when = ""
    if reset.isdigit():
        when = f" until {time.strftime('%H:%M:%S UTC', time.gmtime(int(reset)))}"
    elif retry_after.isdigit():
        when = f" for {retry_after}s"
    return (f"GitHub rate limit reached{when}. Nothing was pushed or opened "
            "after this point; retry later.")


# ── git (local commit + push) ─────────────────────────────────────────────

def _git_env(token: str) -> dict:
    """Credentials via env-provided config, never argv/URL."""
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    return {**os.environ, "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
            "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}"}


def _git(args: list[str], cwd: str, env: dict | None = None,
         timeout: int = 120) -> str:
    from tools.git_cloner import _git_bin
    proc = subprocess.run([_git_bin(), *args], cwd=cwd, capture_output=True,  # nosec B603
                          text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, env=env or {**os.environ,
                                                       "GIT_TERMINAL_PROMPT": "0"})
    if proc.returncode != 0:
        raise RuntimeError(redact(f"git {args[0]} failed: "
                                  f"{(proc.stderr or proc.stdout).strip()[-400:]}"))
    return proc.stdout.strip()


def local_head(repo_path: str) -> str:
    return _git(["rev-parse", "HEAD"], repo_path)


def commit_and_push(*, repo_path: str, work_dir: str, files: list[str],
                    branch: str, message: str, cfg: PRConfig) -> str:
    """Copy the verified files from work_dir onto a fresh copy of the
    scanned clone, commit on `branch`, push it. Returns the commit sha.
    The scanned clone itself is never modified."""
    from tools.patch_apply import PatchApplyError, _resolve
    stage = tempfile.mkdtemp(prefix="pp-pr-")
    dest = os.path.join(stage, "repo")
    try:
        shutil.copytree(repo_path, dest, symlinks=False)
        for rel in files:
            try:
                src = _resolve(work_dir, rel)
                target = _resolve(dest, rel)
            except PatchApplyError as exc:
                raise PRBlocked(str(exc)) from None
            if os.path.isdir(target) or (os.sep + ".git" + os.sep) in target + os.sep:
                raise PRBlocked(f"Refusing to commit {rel}.")
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copyfile(src, target)
        _git(["checkout", "-b", branch], dest)
        _git(["add", "--", *files], dest)
        _git(["-c", f"user.name={cfg.author_name}",
              "-c", f"user.email={cfg.author_email}",
              "commit", "--no-verify", "-m", message], dest)
        sha = _git(["rev-parse", "HEAD"], dest)
        _git(["push", "origin", f"HEAD:refs/heads/{branch}"], dest,
             env=_git_env(cfg.token), timeout=300)
        return sha
    finally:
        from tools.git_cloner import force_rmtree
        force_rmtree(stage)
