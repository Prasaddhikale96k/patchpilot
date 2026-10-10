"""LogicAuditor node (Addition A): LLM audit for logic flaws static tools miss.

Runs between scanner and vuln_analyzer on GitHub repo scans only. Finds web
route handlers with regex, sends each handler body (+ the auth decorators it
uses) to the LLM in batches of at most 6, and appends validated results to
raw_findings with source "llm-audit" so they flow through the normal
vulnerability pipeline untouched.
"""

from __future__ import annotations

import logging
import os
import re

logger = logging.getLogger(__name__)

_BATCH_SIZE = 6
_MAX_FILES = 80
_MAX_FILE_BYTES = 200_000
_MAX_HANDLER_LINES = 120
_MAX_IN_FLIGHT = 3   # concurrent LLM batches

_SKIP_DIRS = {"tests", "test", ".venv", "venv", "node_modules", ".git",
              "__pycache__", "instance", ".pytest_cache"}
_CODE_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx"}

_ROUTE_RES = [
    re.compile(r"@(?P<obj>\w+)\.route\(\s*[\"'](?P<route>[^\"']+)[\"']"),
    re.compile(r"@(?P<obj>\w+)\.(?:get|post|put|delete|patch)"
               r"\(\s*[\"'](?P<route>[^\"']+)[\"']"),
    re.compile(r"(?P<obj>app|router)\.(?:get|post|put|delete|patch|use)"
               r"\(\s*[\"'](?P<route>[^\"']+)[\"']"),
]

_VALID_CATEGORIES = {"broken_access_control", "path_traversal", "missing_auth"}
_VALID_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_CATEGORY_OWASP = {
    "broken_access_control": "A01:2021-Broken Access Control",
    "path_traversal": "A01:2021-Broken Access Control",
    "missing_auth": "A07:2021-Identification and Authentication Failures",
}
_CATEGORY_SHORT = {
    "broken_access_control": "IDOR",
    "path_traversal": "path traversal",
    "missing_auth": "missing auth",
}
_CATEGORY_CWE = {
    "broken_access_control": "CWE-639",
    "path_traversal": "CWE-22",
    "missing_auth": "CWE-306",
}


def find_handlers(repo_path: str) -> list[dict]:
    """Collect web route handlers: {file, line, route, code, auth}."""
    handlers: list[dict] = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in sorted(files):
            if os.path.splitext(name)[1] not in _CODE_EXTS:
                continue
            full = os.path.join(root, name)
            try:
                if os.path.getsize(full) > _MAX_FILE_BYTES:
                    continue
                with open(full, "r", encoding="utf-8",
                          errors="replace") as handle:
                    lines = handle.read().splitlines()
            except OSError:
                continue
            rel = os.path.relpath(full, repo_path).replace("\\", "/")
            handlers.extend(_handlers_in_file(rel, lines))
            if len(handlers) >= _MAX_FILES * 4:
                return handlers
    return handlers


def _handlers_in_file(rel: str, lines: list[str]) -> list[dict]:
    found: list[dict] = []
    for i, line in enumerate(lines):
        route = None
        for pattern in _ROUTE_RES:
            match = pattern.search(line)
            if match:
                route = match.group("route")
                break
        if route is None:
            continue
        # Decorators between the route line and the def (auth evidence).
        auth: list[str] = []
        j = i + 1
        while j < len(lines) and lines[j].strip().startswith("@"):
            auth.append(lines[j].strip())
            j += 1
        body, end = _handler_body(lines, j)
        if body is None:
            continue
        found.append({"file": rel, "line": j + 1, "end": end, "route": route,
                      "code": body, "auth": auth})
    return found


def _handler_body(lines: list[str], j: int) -> tuple[str | None, int]:
    """Capture a handler body: indented Python def or brace-balanced JS."""
    if j >= len(lines):
        return None, j
    stripped = lines[j].strip()
    if stripped.startswith("def ") or stripped.startswith("async def "):
        base_indent = len(lines[j]) - len(lines[j].lstrip())
        chunk = [lines[j]]
        k = j + 1
        while k < len(lines) and len(chunk) < _MAX_HANDLER_LINES:
            text = lines[k]
            if text.strip() and len(text) - len(text.lstrip()) <= base_indent:
                break
            chunk.append(text)
            k += 1
        return "\n".join(chunk), k
    # JS/TS: balance braces from the first opening brace.
    depth = 0
    started = False
    chunk = []
    k = j
    while k < len(lines) and len(chunk) < _MAX_HANDLER_LINES:
        text = lines[k]
        chunk.append(text)
        depth += text.count("{") - text.count("}")
        if "{" in text:
            started = True
        k += 1
        if started and depth <= 0:
            break
    if not started:
        return None, j
    return "\n".join(chunk), k


def _audit_batch(batch: list[dict]) -> list[dict]:
    """One LLM call per batch of ≤6 handlers; returns raw finding dicts."""
    from ..llm_router import invoke_llm
    from ..orchestrator import _parse_json

    presented = []
    for handler in batch:
        presented.append(
            f"--- {handler['file']}:{handler['line']} {handler['route']}\n"
            f"auth decorators: {handler['auth'] or '(none)'}\n"
            f"{handler['code'][:3000]}")
    system = (
        "You are a strict application-security auditor. Report ONLY issues "
        "with concrete code evidence below — no guesses, no generic advice. "
        "Look for: (a) a handler taking an object id from the URL or request "
        "(e.g. /invoices/<id>) that fetches the object and returns it "
        "without ever comparing the object's owner to the logged-in user — "
        "@login_required alone is NOT an ownership check "
        "(broken_access_control, CWE-639); (b) a filesystem open/join "
        "on request input without confinement (path_traversal, CWE-22); "
        "(c) a sensitive handler with no auth decorator or check "
        "(missing_auth, CWE-306). A handler WITH an ownership check, path "
        "confinement, or an auth decorator doing the job is NOT a finding.\n"
        "Return a strict JSON array. Each object must have exactly:\n"
        '{"file": "relative path as shown", "line": <line number inside the '
        'handler>, "category": "broken_access_control|path_traversal|'
        'missing_auth", "cwe": "CWE-639|CWE-22|CWE-306", "severity": '
        '"CRITICAL|HIGH|MEDIUM|LOW", "evidence": "why, citing the exact code", '
        '"exploit_scenario": "one concrete request"}\n'
        "No markdown, no prose.")
    reply = invoke_llm([{"role": "system", "content": system},
                        {"role": "user",
                         "content": "Audit these handlers:\n\n"
                                    + "\n\n".join(presented)}])
    content = getattr(reply, "content", reply)
    parsed = _parse_json(content if isinstance(content, str) else str(content),
                         [])
    return parsed if isinstance(parsed, list) else []


def _validate(repo_path: str, handlers: list[dict],
              findings: list[dict]) -> list[dict]:
    """Keep only findings inside a real handler; coerce bad enums."""
    spans = {(h["file"], h["line"]): h.get("end", h["line"]) for h in handlers}
    files = {h["file"] for h in handlers}
    valid: list[dict] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        path, line = finding.get("file", ""), finding.get("line", 0)
        if path not in files:
            continue
        full = os.path.realpath(os.path.join(repo_path, path))
        if full != os.path.realpath(repo_path) and not full.startswith(
                os.path.realpath(repo_path) + os.sep):
            continue
        if not isinstance(line, int):
            continue
        if not any(start <= line <= spans[(f, start)]
                   for (f, start) in spans if f == path):
            continue
        category = finding.get("category", "")
        if category not in _VALID_CATEGORIES:
            continue
        severity = (finding.get("severity") or "").upper()
        if severity not in _VALID_SEVERITIES:
            severity = "MEDIUM"
        evidence = str(finding.get("evidence", "")).strip()
        if not evidence:
            continue
        scenario = str(finding.get("exploit_scenario", "")).strip()
        cwe = _CATEGORY_CWE[category]
        valid.append({
            "source": "llm-audit",
            "file": path,
            "line": line,
            "severity": severity,
            "category": _CATEGORY_OWASP[category],
            "description": f"{cwe}: {evidence}",
            "code": evidence[:500],
            "exploit_scenario": scenario,
        })
    return valid


def audit_repo(repo_path: str) -> dict:
    """Run the LLM audit on a cloned repo: {"findings": [...], "logs": [...]}.

    Needs only the clone (not scanner output), so the scanner can run it
    concurrently with Bandit and Semgrep. Batches go through the LLM pool.
    """
    from ..llm_router import LLMUnavailableError, llm_pool

    handlers = find_handlers(repo_path)
    if not handlers:
        return {"findings": [],
                "logs": ["[LogicAuditor] Audited 0 routes → 0 issues."]}

    batches = [handlers[i:i + _BATCH_SIZE]
               for i in range(0, len(handlers), _BATCH_SIZE)]
    try:
        batch_results = llm_pool.map(batches, fn=_audit_batch,
                                     max_workers=_MAX_IN_FLIGHT)
    except LLMUnavailableError as exc:
        return {"findings": [],
                "logs": [f"[LogicAuditor] LLM unavailable: {exc.reason}"]}
    except Exception as exc:
        logger.exception("LogicAuditor failed")
        return {"findings": [], "logs": [f"[LogicAuditor] ERROR: {exc}"]}

    raw: list[dict] = []
    for batch in batch_results:
        raw.extend(batch or [])
    valid = _validate(repo_path, handlers, raw)

    _cwe_short = {"CWE-639": "IDOR", "CWE-22": "path traversal",
                  "CWE-306": "missing auth"}
    shorts = ", ".join(
        f"{_cwe_short.get(v['description'].split(':')[0], 'issue')} "
        f"in {v['file']}:{v['line']}"
        for v in valid)
    logs = [f"[LogicAuditor] Audited {len(handlers)} routes → "
            f"{len(valid)} issues"
            + (f" ({shorts})" if shorts else "")
            + (f" ({len(raw) - len(valid)} dropped in validation)"
               if len(raw) > len(valid) else "")]
    return {"findings": valid, "logs": logs}


def logic_auditor_node(state: dict) -> dict:
    """Audit route handlers for logic flaws; append valid findings.

    With PARALLEL_AGENTS the scanner already ran the audit concurrently and
    left it in state["logic_audit"]; this node then only merges it.
    """
    repo_path = state.get("repo_path", "")
    tech_type = (state.get("tech_stack", {}) or {}).get("type")
    if tech_type == "website" or not repo_path or not os.path.isdir(repo_path):
        return {"agent_logs": [
            "[LogicAuditor] Skipped (website scan — no source to audit)."]}

    result = state.get("logic_audit") or audit_repo(repo_path)
    findings = result.get("findings", [])
    out: dict = {"agent_logs": list(result.get("logs", []))}
    if findings:
        out["raw_findings"] = list(state.get("raw_findings", [])) + findings
    return out
