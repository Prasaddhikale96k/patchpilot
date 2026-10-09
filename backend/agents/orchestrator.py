"""
VulnSentinel — LangGraph Orchestrator
Coordinates all security scanning agents in a directed acyclic pipeline.

Graph shape:
  orchestrator → scanner → vuln_analyzer → exploit_reasoner → fix_suggester → report_generator → END
                         ↘                ↘
                       (no findings)   (no vulns)
                               ↘         ↘
                              report_generator → END
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from typing import AsyncGenerator, Literal, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph

from .llm_router import active_model_label, invoke_llm, llm_pool
from .state import ScanState

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)

_MISSING = object()  # sentinel: "no value yet", since None is a valid parse result


def _balanced_slice(text: str, open_ch: str, close_ch: str) -> str | None:
    """Return the first balanced open_ch..close_ch span, ignoring brackets that
    appear inside JSON string literals."""
    start = text.find(open_ch)
    if start == -1:
        return None
    depth = 0
    in_str = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def _parse_json(text: str, fallback: object) -> object:
    """
    Parse JSON out of an LLM response.

    Smaller local models routinely wrap the answer in prose ("Here are the
    findings:") and/or markdown fences. Treating that as a parse failure
    discarded the whole result, which in the vulnerability analyzer meant a repo
    full of real findings was reported as clean. Try, in order: the raw text,
    any fenced block, then the first balanced JSON array or object anywhere in
    the response.

    Each candidate is also retried with strict=False, which tolerates literal
    newlines inside string values. Models produce those whenever the schema
    asks for prose — a "step-by-step attack walkthrough" comes back with real
    line breaks in it — and the strict parser rejects the whole document for
    it, discarding an otherwise perfectly good answer.
    """
    cleaned = text.strip()
    candidates = [cleaned]
    candidates += [m.group(1).strip() for m in _FENCE_RE.finditer(cleaned)]
    for open_ch, close_ch in (("[", "]"), ("{", "}")):
        span = _balanced_slice(cleaned, open_ch, close_ch)
        if span:
            candidates.append(span)

    # The fallback declares the shape the caller wants. Without that, a reply
    # like {"executive_summary": ..., "key_recommendations": [...]} was parsed
    # into just the inner recommendations array, because the first balanced
    # "[" span is found before the enclosing "{" span — a perfectly good
    # summary object came back as a list and was discarded.
    expected = type(fallback) if isinstance(fallback, (list, dict)) else None
    wrong_shape = _MISSING

    for candidate in candidates:
        if not candidate:
            continue
        for strict in (True, False):
            try:
                value = json.loads(candidate, strict=strict)
            except json.JSONDecodeError:
                continue
            if expected is None or isinstance(value, expected):
                return value
            if wrong_shape is _MISSING:
                wrong_shape = value
            break

    if wrong_shape is not _MISSING:
        # Parsed, but not the shape asked for. Still better than the fallback:
        # the caller normalises it.
        return wrong_shape

    logger.warning("JSON parse failed, using fallback. Raw: %s", text[:200])
    return fallback


def _log(msg: str) -> list[str]:
    logger.info(msg)
    return [msg]


# Semgrep reports ERROR/WARNING/INFO; the rest of the pipeline speaks
# CRITICAL/HIGH/MEDIUM/LOW.
_SEMGREP_SEVERITY = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
_VALID_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Patch generation is one LLM call per vulnerability, so it is capped.
_MAX_PATCH_TARGETS = int(os.getenv("MAX_PATCH_TARGETS", "10"))

# How many findings fit in one enrichment prompt. The rest are still reported,
# with the scanner's own severity and description.
_MAX_ENRICHED_FINDINGS = int(os.getenv("MAX_ENRICHED_FINDINGS", "25"))

# ── Risk scoring ──────────────────────────────────────────────
# The risk score used to be whatever number the model wrote, and it did not
# survive comparison between scans: 12 findings (1 HIGH, 5 MEDIUM, 6 LOW)
# scored 20/100 LOW while 6 findings (1 HIGH, 2 MEDIUM, 3 LOW) scored 40/100
# MEDIUM — half the findings, less severe, double the score. The score is the
# largest number in the UI and it is plotted as a trend across rescans, so it
# has to be reproducible and it has to fall when a vulnerability is fixed.
# It is now derived from the severity counts; the model only writes prose.
_SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 2}
# Each severity contributes at most this much, so a long tail of LOW findings
# cannot add up to a crisis (50 informational findings is not a breach).
_SEVERITY_BAND_CAP = {"CRITICAL": 100, "HIGH": 60, "MEDIUM": 30, "LOW": 10}
# ...and the worst finding sets a floor, so one RCE in an otherwise clean repo
# cannot be diluted into a low score.
_SEVERITY_FLOOR = {"CRITICAL": 80, "HIGH": 40, "MEDIUM": 15, "LOW": 5}
_RISK_BANDS = ((80, "CRITICAL"), (60, "HIGH"), (30, "MEDIUM"), (0, "LOW"))


def compute_risk(vulnerabilities: list[dict]) -> dict:
    """
    Score 0-100 from the severity mix, plus the arithmetic behind it.

    Deterministic and monotonic: the same findings always give the same score,
    and removing a finding never raises it.
    """
    counts = {sev: 0 for sev in _VALID_SEVERITIES}
    for v in vulnerabilities:
        sev = (v.get("severity") or "").upper()
        counts[sev if sev in counts else "MEDIUM"] += 1

    contributions = {
        sev: min(_SEVERITY_BAND_CAP[sev], _SEVERITY_WEIGHT[sev] * n)
        for sev, n in counts.items()
    }
    score = sum(contributions.values())

    worst = next((sev for sev in _VALID_SEVERITIES if counts[sev]), None)
    if worst:
        score = max(score, _SEVERITY_FLOOR[worst])
    score = min(100, score)

    level = next(name for threshold, name in _RISK_BANDS if score >= threshold)
    return {
        "risk_score": score,
        "overall_risk": level,
        "counts": counts,
        "contributions": contributions,
        "floor_applied": _SEVERITY_FLOOR[worst] if worst else 0,
    }


def _normalize_severity(finding: dict) -> str:
    sev = (finding.get("severity") or "").upper()
    if finding.get("source") == "semgrep":
        sev = _SEMGREP_SEVERITY.get(sev, sev)
    return sev if sev in _VALID_SEVERITIES else "MEDIUM"


def _vulns_from_raw_findings(findings: list[dict]) -> list[dict]:
    """
    Map scanner output to structured vulnerabilities without the LLM.

    Used when the model returns nothing usable. Semgrep and Bandit already
    supply a file, line, severity and description, so a failed LLM call must
    never turn real findings into a clean bill of health — it should only cost
    the enrichment (CVE lookup, prose, patches), not the findings themselves.
    """
    from tools.owasp_data import OWASP_TOP_10, match_owasp_category

    vulns = []
    for i, f in enumerate(findings, start=1):
        description = f.get("description", "") or ""
        category = f.get("category")
        if not category:
            key = match_owasp_category(
                f"{description} {f.get('rule_id', '')} {f.get('test_id', '')}"
            )
            category = (f"{key}-{OWASP_TOP_10[key]['name']}" if key
                        else "A05:2021-Security Misconfiguration")
        vulns.append({
            "id": f"VULN-{i:03d}",
            "file": f.get("file", ""),
            "line": f.get("line", 0),
            "severity": _normalize_severity(f),
            "category": category,
            "description": description,
            "cve": None,
            "source": f.get("source", "static-analysis"),
            "rule": f.get("test_id") or f.get("rule_id") or "",
        })
    return vulns


# Sources whose severity is a fact from a tool, not an opinion to revisit.
#
# Website findings come from deterministic header checks in our own code: the
# header is present or it is not. Semgrep and Bandit severities are the rule
# author's considered rating, and anyone can run either tool and compare.
#
# The model was allowed to re-rate static analysis on the theory that judging
# exploitability is real work. Measured on a self-scan, it was not judging: it
# promoted every Semgrep WARNING to HIGH, turning 1 HIGH / 12 MEDIUM / 24 LOW
# into 15 HIGH / 0 MEDIUM / 23 LOW and the score from 60 to 70. Reproducibility
# is worth more than that. The model still supplies category, CVE and prose.
_AUTHORITATIVE_SEVERITY = {"website", "semgrep", "bandit"}

# Wording is a separate question. The website descriptions are deliberately
# phrased and a rewrite loses the meaning (the meta-CSP note was inverted into
# "Implement Content-Security-Policy" once already). Semgrep and Bandit messages
# are terse and factual, so the model's prose is an improvement there.
_AUTHORITATIVE_WORDING = {"website"}

# A CVE identifies a vulnerability in a specific piece of software. A missing
# Referrer-Policy header is not one: it is a configuration weakness, which is
# what the CWE and OWASP labels are for, and this scanner deliberately reports
# no software version to match against anyway. Asked for a CVE on every finding,
# the model supplied plausible-looking identifiers for findings that cannot have
# one, and a bare "starts with CVE-" check waved them through.
#
# So the model is not trusted to name a CVE for these sources. The port scanner
# keeps its own, which are hand-written and checked, not generated.
_NO_CVE_SOURCES = {"website"}

# CVE-YYYY-NNNN, four digits or more in the sequence.
_CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$", re.IGNORECASE)


def _valid_cve(value: object, *, this_year: int | None = None) -> str | None:
    """
    Return a well-formed CVE id, or None.

    Shape is all that can be checked without a network lookup, so this is a
    filter and not proof the identifier exists. It rejects the malformed
    (CVE-XXXX-XXXX, a bare year, prose wrapped around an id) and the impossible
    (a year before the scheme began in 1999, or one in the future).
    """
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    match = _CVE_RE.match(candidate)
    if not match:
        return None
    year = int(match.group(1))
    ceiling = this_year if this_year is not None else datetime.now(timezone.utc).year
    if year < 1999 or year > ceiling:
        return None
    return candidate.upper()


def _norm(text: str) -> str:
    return " ".join((text or "").lower().split())


def _id_key(value: object) -> str:
    """VULN-1, VULN-001 and "1" are the same finding as far as matching goes."""
    digits = re.sub(r"\D", "", str(value or ""))
    return digits.lstrip("0")


# An OWASP label, which is what the category field is for. A model that answers
# "Security" or "Misconfiguration" is less specific than the deterministic
# match_owasp_category() lookup the baseline already did, so it is not an upgrade.
_OWASP_LABEL_RE = re.compile(r"^A\d{2}:\d{4}")


def _match_llm_entry(vuln: dict, by_id: dict, by_desc: dict, by_loc: dict) -> dict | None:
    """Find the model's version of a finding we already know about."""
    entry = by_id.get(_id_key(vuln["id"]))
    if entry is not None:
        return entry

    desc = _norm(vuln.get("description", ""))
    if desc in by_desc:
        return by_desc[desc]
    for candidate_desc, candidate in by_desc.items():
        if desc and (desc.startswith(candidate_desc[:60]) or candidate_desc.startswith(desc[:60])):
            return candidate

    # Only useful for source findings: every website finding shares one URL and
    # line 0, so location would match all of them to the first entry.
    if vuln.get("line"):
        return by_loc.get((vuln.get("file", ""), vuln.get("line")))
    return None


def _merge_llm_enrichment(baseline: list[dict], llm_vulns: list[dict],
                          enrichable: int | None = None) -> tuple[list[dict], dict]:
    """
    Enrich the scanner's findings with the model's analysis, without letting it
    change what was found.

    The findings list drove the risk score, so anything the model did to it
    moved the number: on a live scan it silently dropped one finding and
    promoted another from LOW to MEDIUM, and the report disagreed with the
    scanner log directly above it. The scanner's list is the finding set; the
    model contributes category, CVE, and (for static analysis) severity and
    prose.
    """
    by_id: dict[str, dict] = {}
    by_desc: dict[str, dict] = {}
    by_loc: dict[tuple, dict] = {}
    for entry in llm_vulns:
        if not isinstance(entry, dict):
            continue
        if _id_key(entry.get("id")):
            by_id.setdefault(_id_key(entry["id"]), entry)
        by_desc.setdefault(_norm(entry.get("description", "")), entry)
        by_loc.setdefault((str(entry.get("file", "")), entry.get("line", 0)), entry)

    # Findings past this index were never sent to the model, so their absence
    # from its reply says nothing about it.
    limit = len(baseline) if enrichable is None else enrichable

    stats = {"enriched": 0, "dropped_by_llm": 0, "severity_kept": 0,
             "cve_rejected": 0, "cve_refused": 0,
             "not_sent": max(0, len(baseline) - limit)}
    merged = []

    for index, vuln in enumerate(baseline):
        entry = _match_llm_entry(vuln, by_id, by_desc, by_loc)
        result = dict(vuln)

        if entry is None:
            if index < limit:
                stats["dropped_by_llm"] += 1
            merged.append(result)
            continue

        stats["enriched"] += 1
        category = entry.get("category")
        if isinstance(category, str) and _OWASP_LABEL_RE.match(category.strip()):
            # "A05:2021 - Security Misconfiguration" and "A05:2021-Security
            # Misconfiguration" are the same category; left as written they show
            # up as two entries in the report's category list.
            result["category"] = re.sub(r"^(A\d{2}:\d{4})\s*[-–—]\s*", r"\1-",
                                        category.strip())
        source = vuln.get("source")
        if source not in _NO_CVE_SOURCES:
            cve = _valid_cve(entry.get("cve"))
            if cve:
                result["cve"] = cve
            elif entry.get("cve"):
                stats["cve_rejected"] += 1
        elif entry.get("cve"):
            stats["cve_refused"] += 1

        if source in _AUTHORITATIVE_SEVERITY:
            stats["severity_kept"] += 1
        else:
            severity = (entry.get("severity") or "").upper()
            if severity in _VALID_SEVERITIES:
                result["severity"] = severity

        if source not in _AUTHORITATIVE_WORDING:
            description = entry.get("description")
            if isinstance(description, str) and description.strip():
                result["description"] = description.strip()

        merged.append(result)

    return merged, stats


def _recommendations_from_vulns(vulnerabilities: list[dict], limit: int = 3) -> list[str]:
    """
    Derive action items from the findings themselves.

    The report model sometimes returns an executive summary and simply omits
    key_recommendations, which rendered as an empty "Key Recommendations"
    section on a report that had six findings. The most severe findings are
    the recommendations, so they never need to be invented.
    """
    ranked = sorted(
        vulnerabilities,
        key=lambda v: _SEVERITY_RANK.get((v.get("severity") or "").upper(), 99),
    )
    recs, seen = [], set()
    for v in ranked:
        # Falls back to the OWASP category so a finding with a blank
        # description still produces an action item rather than vanishing.
        description = (v.get("description") or "").strip() or v.get("category", "")
        if not description or description in seen:
            continue
        seen.add(description)
        location = v.get("file") or ""
        suffix = f" ({location})" if location and not location.startswith("http") else ""
        recs.append(f"[{v.get('severity', 'MEDIUM')}] Remediate: {description}{suffix}")
        if len(recs) == limit:
            break
    return recs


_SOURCE_WINDOW = 4          # lines of context either side of the finding
_MAX_SOURCE_BYTES = 2_000_000

# "   12 >| some code" — the gutter the excerpt is rendered with. Models copy it
# straight into their answer, which puts a line number and a marker into the
# patched code shown in the report.
_GUTTER_RE = re.compile(r"^\s*\d+\s*>?\s*\|\s?|^>\s?")


def _strip_gutter(text: str) -> str:
    """Remove excerpt line numbering the model echoed back into its patch."""
    if not isinstance(text, str):
        return text
    return "\n".join(_GUTTER_RE.sub("", line) for line in text.splitlines())


def read_source_window(repo_path: str, rel_file: str, line: int,
                       radius: int = _SOURCE_WINDOW) -> tuple[str, str] | None:
    """
    Return (numbered context, the exact flagged line) from the cloned repo.

    The fix suggester used to receive only a finding's metadata, so it invented
    the code it claimed to be patching: for frontend/lib/ws.ts:14 it produced a
    plausible WebSocket constructor call against an example.com URL, a line
    that does not appear anywhere in that file. The repository is already on
    disk, so the real line can just be read.

    Returns None when there is nothing trustworthy to show, in which case the
    caller must not claim to know the original code.
    """
    if not repo_path or not rel_file or not line or line < 1:
        return None

    root = os.path.realpath(repo_path)
    target = os.path.realpath(os.path.join(root, rel_file))
    # A finding's path comes from a scanner, but it still ends up in an
    # open() call, so keep it inside the clone.
    if target != root and not target.startswith(root + os.sep):
        logger.warning("fix_suggester: refusing to read outside the repo: %s", rel_file)
        return None

    try:
        if os.path.getsize(target) > _MAX_SOURCE_BYTES:
            return None
        with open(target, "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except (OSError, ValueError):
        return None

    if line > len(lines):
        return None

    start = max(0, line - 1 - radius)
    end = min(len(lines), line + radius)
    numbered = "\n".join(
        f"{n + 1:>5}{' >' if n + 1 == line else '  '}| {lines[n]}"
        for n in range(start, end)
    )
    return numbered, lines[line - 1]


# Headers a browser only honours from a real response header, so a meta tag is
# not a workaround for them. (CSP and Referrer-Policy are excluded: those can be
# applied from the document, so the host is not what blocks them.)
_HEADER_ONLY_POLICIES = (
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Permissions-Policy",
    "Strict-Transport-Security",
)


def _header_remediation_for_static_host(vuln: dict, static_host: str | None) -> dict | None:
    """
    The fixed, correct answer for a header that the host cannot set.

    Returns None when this is not that case, so the caller falls through to the
    model. Deterministic because the remediation depends only on the platform:
    asking an LLM produced confident instructions for a settings page that does
    not exist.
    """
    if not static_host:
        return None

    description = vuln.get("description", "")
    if "security header" not in description.lower():
        return None
    header = next((h for h in _HEADER_ONLY_POLICIES if h.lower() in description.lower()), None)
    if not header:
        return None

    return {
        "vuln_id": vuln.get("id", ""),
        "file": vuln.get("file", ""),
        "remediation": (
            f"Not fixable on {static_host}. Serve the site through a proxy that "
            f"can add headers (Cloudflare: Rules > Transform Rules > Modify "
            f"Response Header), or move to a host with header rules "
            f"(Netlify _headers, Vercel vercel.json, Cloudflare Pages _headers), "
            f"then set: {header}"
        ),
        "explanation": (
            f"{static_host} serves static files and exposes no way to set a "
            f"response header, so there is no change to this repository that "
            f"adds {header}. A meta tag is not a substitute: browsers ignore "
            f"{header} in markup. Until the site sits behind something that can "
            f"set headers, this finding stands as an accepted risk."
        ),
        "source": "platform-constraint",
    }


def _exploit_from_vuln(vuln: dict) -> dict:
    """
    Describe a vulnerability's attack surface without the LLM.

    Counterpart to _vulns_from_raw_findings: when the model returns nothing
    usable for a finding, the OWASP category still supplies a real attack
    vector and impact. Degraded enrichment, not a missing finding.
    """
    from tools.owasp_data import get_category_detail

    detail = get_category_detail(vuln.get("category", "")) or {}
    location = vuln.get("file") or "the affected component"
    if vuln.get("line"):
        location = f"{location}:{vuln['line']}"
    examples = detail.get("examples") or []

    return {
        "vuln_id": vuln["id"],
        # Unscored rather than guessed — claiming EASY without analysis would
        # be the same invention this fallback exists to avoid.
        "exploitability": "UNKNOWN",
        "attack_vector": (
            f"{detail.get('name', 'Security weakness')} reachable at {location}. "
            f"Typical vector: {examples[0]}" if examples
            else f"{detail.get('name', 'Security weakness')} reachable at {location}."
        ),
        "impact": detail.get("description", vuln.get("description", "")),
        "poc_description": (
            "Automated exploit reasoning was unavailable for this finding. "
            f"Reproduce manually at {location}: {vuln.get('description', '')}"
        ),
        "cwes": detail.get("cwes", []),
        "source": "owasp-reference",
    }


# ══════════════════════════════════════════════════════════════
#  Node: Orchestrator
# ══════════════════════════════════════════════════════════════

def orchestrator_node(state: ScanState) -> dict:
    """Uses LLM to plan the scan strategy before handing off to the scanner."""
    from tools.website_scanner import is_github_url
    scan_type = "github" if is_github_url(state["repo_url"]) else "website"

    response = invoke_llm([
        SystemMessage(content="""You are a security orchestrator agent.
Given a target URL (GitHub repo or live website), output a JSON scan plan:
{
  "strategy": "brief description of approach",
  "priority_areas": ["list", "of", "focus", "areas"],
  "risk_level": "HIGH|MEDIUM|LOW"
}
Output only valid JSON. No markdown."""),
        HumanMessage(content=f"Plan a security audit for: {state['repo_url']}"),
    ])

    plan = _parse_json(response.content, {
        "strategy": "standard security scan",
        "priority_areas": ["authentication", "input validation", "dependencies"],
        "risk_level": "MEDIUM",
    })

    scan_label = "GitHub repository" if scan_type == "github" else "live website"
    return {
        "status": "scanning",
        "agent_logs": [
            f"[Orchestrator] Scan {state['scan_id']} started — target: {state['repo_url']}",
            f"[Orchestrator] Scan type: {scan_label}",
            f"[Orchestrator] LLM: {active_model_label()}",
            f"[Orchestrator] Strategy: {plan['strategy']}",
            f"[Orchestrator] Priority areas: {', '.join(plan['priority_areas'])}",
            f"[Orchestrator] Estimated risk level: {plan['risk_level']}",
        ],
    }


# ══════════════════════════════════════════════════════════════
#  Node: Scanner
# ══════════════════════════════════════════════════════════════

def scanner_node(state: ScanState) -> dict:
    """Routes to repo scanner (Semgrep + Bandit) or website scanner based on URL."""
    from tools.website_scanner import is_github_url, scan_website

    if is_github_url(state["repo_url"]):
        return _scan_github(state)
    return _scan_website(state)


def _scan_github(state: ScanState) -> dict:
    """Clone repo and run Semgrep + Bandit static analysis."""
    from tools.bandit_runner import run_bandit
    from tools.git_cloner import clone_repo, detect_tech_stack
    import tools.semgrep_runner as semgrep_runner

    try:
        repo_path = clone_repo(state["repo_url"], state["scan_id"])
        tech_stack = detect_tech_stack(repo_path)
        logs = [
            f"[Scanner] Mode: GitHub repository",
            f"[Scanner] Cloned to {repo_path}",
            f"[Scanner] Languages: {', '.join(tech_stack.get('languages', ['unknown']))}",
            f"[Scanner] Dependencies: {len(tech_stack.get('dependencies', []))} found",
        ]

        raw_findings: list[dict] = []

        # Prompt 00a: Semgrep and Bandit run concurrently (ThreadPoolExecutor;
        # both are blocking subprocess calls, so threads are the right tool).
        # Findings format and order are unchanged: Bandit first, then Semgrep.
        import time as _time
        from concurrent.futures import ThreadPoolExecutor as _Pool

        is_python = "python" in [l.lower() for l in tech_stack.get("languages", [])]

        def _timed_bandit() -> tuple[list, float, str | None]:
            start = _time.perf_counter()
            try:
                result = run_bandit(repo_path) if is_python else []
            except Exception as exc:
                return [], _time.perf_counter() - start, str(exc)
            return result, _time.perf_counter() - start, None

        def _timed_semgrep() -> tuple[list, float, str | None]:
            start = _time.perf_counter()
            try:
                result = semgrep_runner.run_semgrep(repo_path)
            except Exception as exc:
                return [], _time.perf_counter() - start, str(exc)
            return result, _time.perf_counter() - start, None

        with _Pool(max_workers=2) as _ex:
            _futures = [_ex.submit(_timed_bandit), _ex.submit(_timed_semgrep)]
            (bandit_results, bandit_secs, bandit_err), \
                (semgrep_results, semgrep_secs, semgrep_err) = \
                [f.result() for f in _futures]

        # One failed scanner must not sink the other: continue with whatever
        # succeeded and say so. Only both failing is a scan error.
        if bandit_err and semgrep_err:
            raise RuntimeError(
                f"Bandit failed: {bandit_err}; Semgrep failed: {semgrep_err}")

        if is_python and not bandit_err:
            raw_findings.extend(bandit_results)
            logs.append(f"[Scanner] Bandit: {len(bandit_results)} issues ({bandit_secs:.1f}s)")
        elif bandit_err:
            logs.append(f"[Scanner] Bandit failed: {bandit_err} — continuing with Semgrep results")
        else:
            logs.append("[Scanner] Bandit: skipped (no Python detected)")

        if not semgrep_err:
            if semgrep_runner.last_pull:
                logs.append("[Scanner] Pulling Semgrep Docker image (first run only)…")
            raw_findings.extend(semgrep_results)
            logs.append(f"[Scanner] Semgrep ({semgrep_runner.last_mode}): "
                        f"{len(semgrep_results)} issues ({semgrep_secs:.1f}s)")
        else:
            logs.append(f"[Scanner] Semgrep failed: {semgrep_err} — continuing with Bandit results")

        # Test code does unsafe things deliberately, so findings against it are
        # mostly noise: a self-scan produced 231 findings, 218 of them in tests,
        # and one patch proposed "fixing" the 0.0.0.0 fixture that proves the
        # URL guard blocks 0.0.0.0. Counted and logged rather than hidden,
        # because a credential committed in a test file is still a leak.
        from tools.scan_exclusions import include_tests, partition_findings

        raw_findings, test_findings, vendor_findings = partition_findings(raw_findings)
        if vendor_findings:
            # Always excluded: the owner cannot patch a dependency's source,
            # and vulnerable dependency *versions* are audited separately.
            logs.append(
                f"[Scanner] Excluded {len(vendor_findings)} findings in vendored "
                f"dependencies and build output"
            )
        if include_tests():
            raw_findings.extend(test_findings)
            logs.append("[Scanner] Scanning test code as well (SCAN_INCLUDE_TESTS)")
        elif test_findings:
            logs.append(
                f"[Scanner] Excluded {len(test_findings)} findings in test "
                f"files — test code is unsafe by design "
                f"(set SCAN_INCLUDE_TESTS=true to include them)"
            )

        logs.append(f"[Scanner] Total raw findings: {len(raw_findings)}")

        return {
            "repo_path": repo_path,
            "tech_stack": tech_stack,
            "raw_findings": raw_findings,
            "status": "analyzing",
            "agent_logs": logs,
        }

    except Exception as exc:
        logger.exception("GitHub scanner failed")
        return {
            "errors": [f"Scanner error: {exc}"],
            "status": "error",
            "agent_logs": [f"[Scanner] ERROR: {exc}"],
        }


def _scan_website(state: ScanState) -> dict:
    """Run HTTP-based security checks + port scan against a live website."""
    from urllib.parse import urlparse

    from tools.port_scanner import scan_ports
    from tools.website_scanner import scan_website

    try:
        logs = [
            f"[Scanner] Mode: Live website",
            f"[Scanner] Checking security headers, SSL, exposed files, CORS, cookies…",
        ]
        meta: dict = {}
        raw_findings = scan_website(state["repo_url"], meta=meta)

        # The target served a bot challenge instead of the application. Its
        # headers and cookies are the challenge page's, so grading them would
        # produce confident findings about a page real users never see. Stop
        # here, and do not port scan a host that has just told us to go away.
        if meta.get("blocked"):
            logs.append(f"[Scanner] Target blocked automated scanning: {meta['blocked']}")
            logs.append("[Scanner] No assessment performed - results would not "
                        "reflect the real security posture")
            return {
                "repo_path": "",
                "tech_stack": {"type": "website", "url": state["repo_url"],
                               "cdn": meta.get("cdn"), "blocked": meta["blocked"]},
                "raw_findings": [],
                "errors": [f"Target blocked automated scanning: {meta['blocked']}. "
                           f"Scan a target you control, or one that permits scanning."],
                "not_assessed": f"the target blocked automated scanning ({meta['blocked']})",
                "status": "analyzing",
                "agent_logs": logs,
            }

        # The server answered with an error page. Grading it would describe the
        # error page, not the site.
        if meta.get("server_error"):
            logs.append(f"[Scanner] Target returned HTTP {meta['server_error']} - "
                        f"that is a server error page, not the application")
            logs.append("[Scanner] No assessment performed")
            return {
                "repo_path": "",
                "tech_stack": {"type": "website", "url": state["repo_url"]},
                "raw_findings": [],
                "errors": [f"{state['repo_url']} returned HTTP {meta['server_error']}. "
                           f"The site is down or erroring, so there is nothing to assess."],
                "not_assessed": f"the site returned HTTP {meta['server_error']}, "
                                f"so only its error page was reachable",
                "status": "analyzing",
                "agent_logs": logs,
            }

        # No response at all: there is nothing to grade, and a host that does
        # not answer must not be scored as though it had failed a check.
        if meta.get("unreachable"):
            logs.append(f"[Scanner] Target unreachable: {meta['unreachable']}")
            logs.append("[Scanner] No assessment performed")
            return {
                "repo_path": "",
                "tech_stack": {"type": "website", "url": state["repo_url"]},
                "raw_findings": [],
                "errors": [f"Could not reach {state['repo_url']}: {meta['unreachable']}"],
                "not_assessed": f"the target could not be reached ({meta['unreachable']})",
                "status": "analyzing",
                "agent_logs": logs,
            }

        # Findings describe the response that came back, which after a redirect
        # is a different URL. Say so, rather than labelling them with the URL
        # that was typed in.
        if meta.get("redirected"):
            logs.append(
                f"[Scanner] Redirected to {meta['final_url']}"
                + (" - a different host, so the findings describe that host"
                   if meta.get("host_changed") else "")
            )

        if meta.get("cdn"):
            logs.append(f"[Scanner] Fronted by {meta['cdn']} - findings describe the "
                        f"edge, not necessarily the origin")

        by_sev: dict[str, int] = {}
        for f in raw_findings:
            s = f.get("severity", "?")
            by_sev[s] = by_sev.get(s, 0) + 1

        logs.append(f"[Scanner] HTTP checks complete — {len(raw_findings)} raw findings")
        logs.append(f"[Scanner] Severity breakdown: {by_sev}")

        # Port scan, against authorised hosts only. Reading a site's headers is
        # what any browser does; connecting to 25 of its ports is unauthorised
        # testing when the host is not yours, and a scan box that accepts any
        # URL should not leave that decision to whoever is typing.
        from tools.scan_authorisation import is_authorised, refusal_reason

        # The host actually served, so a redirect cannot move the scan onto a
        # third party that was never authorised.
        scanned_url = meta.get("final_url") or state["repo_url"]
        host = urlparse(scanned_url).hostname or scanned_url
        port_findings: list[dict] = []

        if not is_authorised(host):
            logs.append(f"[Scanner] Port scan skipped — {refusal_reason(host)}")
        else:
            from tools.port_scanner import COMMON_PORTS as _CP
            logs.append(f"[Scanner] {host} is an authorised target — port scanning "
                        f"({len(_CP)} common ports)…")
            # On an HTTPS site, 443 is the site itself and 80 exists to redirect to
            # it. Both are the website working as intended, not exposures.
            from tools.port_scanner import WEB_SERVICE_PORTS
            skip = WEB_SERVICE_PORTS if urlparse(scanned_url).scheme == "https" else frozenset()
            port_findings = scan_ports(host, skip_ports=skip, cdn=meta.get("cdn"))

        open_ports = [p for p in port_findings if "port" in p]
        critical_ports = [p for p in open_ports if p["severity"] in ("CRITICAL", "HIGH")]

        if open_ports:
            port_list = ", ".join(f"{p['port']}/{p['service']}" for p in open_ports)
            logs.append(f"[Scanner] Open ports ({len(open_ports)}): {port_list}")
        elif port_findings or is_authorised(host):
            logs.append(f"[Scanner] No common high-risk ports found open")

        if critical_ports:
            for p in critical_ports:
                logs.append(f"[Scanner] {p['severity']} RISK — {p['port']}/{p['service']}: {p['description']}")

        raw_findings = raw_findings + port_findings

        if meta.get("static_host"):
            logs.append(f"[Scanner] Host is {meta['static_host']} — response headers "
                        f"cannot be set here, remediation must go through a proxy or a "
                        f"host that supports header rules")

        return {
            "repo_path": "",
            "tech_stack": {"type": "website", "url": state["repo_url"],
                           "cdn": meta.get("cdn"),
                           "static_host": meta.get("static_host")},
            "raw_findings": raw_findings,
            "status": "analyzing",
            "agent_logs": logs,
        }

    except Exception as exc:
        logger.exception("Website scanner failed")
        return {
            "errors": [f"Scanner error: {exc}"],
            "status": "error",
            "agent_logs": [f"[Scanner] ERROR: {exc}"],
        }


# ══════════════════════════════════════════════════════════════
#  Node: Vulnerability Analyzer
# ══════════════════════════════════════════════════════════════

def vuln_analyzer_node(state: ScanState) -> dict:
    """Maps raw static-analysis findings to structured Vulnerability objects."""
    from tools.owasp_data import get_owasp_context

    # Port scan findings already have CVE/CWE data — promote them directly
    port_vulns = []
    for i, f in enumerate(state["raw_findings"]):
        if f.get("type") == "port_exposure" and "port" in f:
            port_vulns.append({
                "id": f"PORT-{f['port']}",
                "file": f.get("file", f"{f['service']}:{f['port']}"),
                "line": 0,
                "severity": f["severity"],
                "category": f.get("owasp_category", "A05:2021-Security Misconfiguration"),
                "description": f["description"],
                "cve": f["cves"][0] if f.get("cves") else None,
                "cwes": f.get("cwes", []),
                "all_cves": f.get("cves", []),
                "port": f["port"],
                "service": f["service"],
                "banner": f.get("banner", "—"),
                "recommendation": f.get("recommendation", ""),
                # Carried through so a report can be pivoted into OSINT without
                # re-resolving the host — and so the UI knows not to offer that
                # for a loopback address, which no external dataset describes.
                "ip": f.get("ip"),
                "loopback": f.get("loopback", False),
            })

    # Static analysis / HTTP findings go through the LLM. Only the first slice
    # fits the token budget — a scan of this repo produces 231 findings — but
    # the ones beyond it are still reported, just without enrichment. They were
    # never shown to the model, so they must not be counted as findings it
    # dropped.
    other_findings = [f for f in state["raw_findings"] if f.get("type") != "port_exposure"]
    sent_to_llm = other_findings[:_MAX_ENRICHED_FINDINGS]
    findings_json = json.dumps(sent_to_llm, indent=2)
    owasp_ref = get_owasp_context()

    response = invoke_llm([
        SystemMessage(content=f"""You are a vulnerability analysis agent.
Map raw static analysis findings to structured vulnerability objects.
Use the OWASP reference below to assign the correct category and severity.

{owasp_ref}

Return a JSON array. Each object must have:
{{
  "id": "VULN-001",
  "file": "relative/path/to/file.py",
  "line": 42,
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "category": "OWASP label e.g. A03:2021-Injection",
  "description": "clear one-sentence description",
  "cve": "a real CVE id you are certain applies, otherwise null"
}}
Use null for "cve" unless the finding is a known vulnerability in a specific,
named software version. Configuration and hardening findings, such as a missing
or misconfigured HTTP header, do not have CVEs: use null for those. A wrong CVE
is far worse than no CVE, and any id that cannot be verified is discarded.
Severity guide: CRITICAL = direct RCE/SQLi/auth bypass, HIGH = exploitable with low effort,
MEDIUM = exploitable with moderate effort or requires chaining, LOW = hardening/best-practice.
Output only a valid JSON array. No markdown."""),
        HumanMessage(content=f"Analyze these raw findings:\n{findings_json}"),
    ])

    llm_vulns = _parse_json(response.content, [])
    if isinstance(llm_vulns, dict):
        # Either the array wrapped in an object, e.g. {"vulnerabilities": [...]},
        # or a single finding returned bare instead of in an array — which is
        # what a repo scan actually produced, and it cost the whole enrichment.
        nested = next((v for v in llm_vulns.values() if isinstance(v, list)), None)
        if nested is not None:
            llm_vulns = nested
        elif any(k in llm_vulns for k in ("id", "description", "severity")):
            llm_vulns = [llm_vulns]
        else:
            llm_vulns = []
    if not isinstance(llm_vulns, list):
        llm_vulns = []

    # The scanner's output is the finding set. The model enriches it; it does
    # not get to decide what was found. Previously its array *was* the result,
    # so a finding it forgot to copy simply vanished from the report.
    baseline = _vulns_from_raw_findings(other_findings)
    analyzed, merge_stats = _merge_llm_enrichment(
        baseline, llm_vulns, enrichable=len(sent_to_llm)
    )

    degraded = bool(sent_to_llm) and merge_stats["enriched"] == 0
    if degraded:
        logger.warning(
            "vuln_analyzer: LLM returned no usable vulnerabilities for %d raw "
            "findings — falling back to deterministic mapping",
            len(other_findings),
        )

    vulns = port_vulns + analyzed

    severity_counts: dict[str, int] = {}
    for v in vulns:
        sev = v.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    owasp_cats = list({v.get("category", "").split("-")[0].strip()
                       for v in vulns if v.get("category")})

    logs = [
        f"[VulnAnalyzer] Mapped {len(vulns)} structured vulnerabilities",
        f"[VulnAnalyzer] Severity breakdown: {severity_counts}",
        f"[VulnAnalyzer] OWASP categories identified: {', '.join(sorted(owasp_cats)) or 'none'}",
    ]
    if port_vulns:
        logs.append(f"[VulnAnalyzer] Port exposures: {len(port_vulns)} open ports mapped to CVEs/CWEs")
    if merge_stats["severity_kept"]:
        logs.append(
            f"[VulnAnalyzer] {merge_stats['severity_kept']} findings kept the "
            f"scanner's severity (deterministic checks, not model judgement)"
        )
    if merge_stats["cve_refused"]:
        logs.append(
            f"[VulnAnalyzer] {merge_stats['cve_refused']} model-supplied CVE ids discarded: "
            f"a configuration finding has no CVE, and this scanner reads no software "
            f"version to match one against"
        )
    if merge_stats["cve_rejected"]:
        logs.append(
            f"[VulnAnalyzer] {merge_stats['cve_rejected']} model-supplied CVE ids discarded "
            f"as malformed or impossible"
        )
    if merge_stats["dropped_by_llm"] and not degraded:
        # When nothing was enriched the "LLM enrichment unavailable" line below
        # says it better; both together read as two separate failures.
        logs.append(
            f"[VulnAnalyzer] {merge_stats['dropped_by_llm']} findings were "
            f"missing from the model's output and were kept anyway"
        )
    if merge_stats["not_sent"]:
        logs.append(
            f"[VulnAnalyzer] {merge_stats['not_sent']} findings beyond the "
            f"{_MAX_ENRICHED_FINDINGS}-finding enrichment budget are reported "
            f"with the scanner's own severity (raise MAX_ENRICHED_FINDINGS to change)"
        )
    if degraded:
        logs.append(
            f"[VulnAnalyzer] LLM enrichment unavailable — reported "
            f"{len(analyzed)} findings directly from Semgrep/Bandit"
        )

    return {
        "vulnerabilities": vulns,
        "status": "exploiting",
        "agent_logs": logs,
    }


# ══════════════════════════════════════════════════════════════
#  Node: Exploit Reasoner
# ══════════════════════════════════════════════════════════════

def exploit_reasoner_node(state: ScanState) -> dict:
    """Reasons about real-world exploitability for HIGH/CRITICAL vulnerabilities."""
    targets = [v for v in state["vulnerabilities"] if v["severity"] in ("CRITICAL", "HIGH")]

    if not targets:
        return {
            "exploits": [],
            "status": "patching",
            "agent_logs": ["[ExploitReasoner] No HIGH/CRITICAL findings — skipping."],
        }

    from tools.owasp_data import get_owasp_context
    owasp_ref = get_owasp_context()

    response = invoke_llm([
        SystemMessage(content=f"""You are an exploit reasoning agent.
For each vulnerability explain how a real-world attacker would exploit it.
Use the OWASP reference to inform the attack vector and realistic impact.

{owasp_ref}

Return a JSON array. Each object must have:
{{
  "vuln_id": "VULN-001",
  "exploitability": "EASY|MODERATE|HARD",
  "attack_vector": "e.g. unauthenticated POST /api/login with payload",
  "impact": "e.g. full database dump, RCE, account takeover",
  "poc_description": "step-by-step attack walkthrough"
}}
Output only a valid JSON array. Be specific and technical. No markdown."""),
        HumanMessage(content=f"Reason about exploitability:\n{json.dumps(targets, indent=2)}"),
    ])

    parsed = _parse_json(response.content, [])
    if isinstance(parsed, dict):
        parsed = [parsed]
    if not isinstance(parsed, list):
        parsed = []

    # Keep only entries that describe a vulnerability this scan actually found.
    # A model that hallucinates VULN-042 would otherwise put an exploit in the
    # report with nothing to click through to.
    target_ids = {v["id"] for v in targets}
    exploits = [
        e for e in parsed
        if isinstance(e, dict) and e.get("vuln_id") in target_ids
    ]

    # The log used to count the parsed reply, so a failed parse announced
    # "Analyzed 0 critical/high vulnerabilities" on a report that displayed a
    # HIGH finding and a patch for it — the pipeline looked like it disagreed
    # with itself. Every target is now accounted for: enriched by the model
    # where that worked, described from the OWASP category where it did not.
    covered = {e["vuln_id"] for e in exploits}
    unenriched = [v for v in targets if v["id"] not in covered]
    exploits.extend(_exploit_from_vuln(v) for v in unenriched)
    exploits.sort(key=lambda e: _SEVERITY_RANK.get(
        next((v["severity"] for v in targets if v["id"] == e["vuln_id"]), ""), 99))

    easy = sum(1 for e in exploits if e.get("exploitability") == "EASY")
    logs = [
        f"[ExploitReasoner] Analyzed {len(exploits)}/{len(targets)} critical/high vulnerabilities",
        f"[ExploitReasoner] {easy} are trivially exploitable (EASY)",
    ]
    if unenriched:
        logs.append(
            f"[ExploitReasoner] LLM enrichment unavailable for {len(unenriched)} "
            f"finding(s) — attack context taken from the OWASP category"
        )

    return {
        "exploits": exploits,
        "status": "patching",
        "agent_logs": logs,
    }


# ══════════════════════════════════════════════════════════════
#  Node: Fix Suggester
# ══════════════════════════════════════════════════════════════

def fix_suggester_node(state: ScanState) -> dict:
    """Generates code patches for the most severe vulnerabilities."""
    targets = [v for v in state["vulnerabilities"] if v["severity"] in ("CRITICAL", "HIGH", "MEDIUM")]

    if not targets:
        return {
            "patches": [],
            "status": "reporting",
            "agent_logs": ["[FixSuggester] Nothing to patch."],
        }

    # This loop costs one LLM call per vulnerability. A repo with 40+ findings
    # would otherwise mean 40 sequential calls: minutes of wall time on a local
    # model, and enough requests to trip a free-tier cloud rate limit. Patch the
    # most severe findings first and cap the rest.
    total_targets = len(targets)
    targets = sorted(
        targets, key=lambda v: _SEVERITY_RANK.get(v.get("severity"), 99)
    )[:_MAX_PATCH_TARGETS]

    patches = []
    logs = []
    if total_targets > len(targets):
        logs.append(
            f"[FixSuggester] {total_targets} patchable findings — generating "
            f"patches for the {len(targets)} most severe "
            f"(raise MAX_PATCH_TARGETS to change)"
        )

    # A website scan never sees source code. Asking for a code patch anyway makes
    # the model invent a codebase: scanning a site fronted by a CDN produced a
    # Flask snippet "fixing" cookies for a company that does not run Flask. With
    # no source to diff, the honest deliverable is configuration guidance.
    is_website = state.get("tech_stack", {}).get("type") == "website"

    if is_website:
        system_prompt = """You are a web security remediation agent.
You are advising on a LIVE WEBSITE. You have NOT seen its source code and you
do not know its language, framework or server software.

Never invent source code, file paths, or a framework. Give the concrete
configuration directive that fixes the issue, for the common web servers.

Return a single JSON object:
{
  "vuln_id": "VULN-001",
  "file": "the affected URL",
  "remediation": "the exact header or config directive to set",
  "explanation": "what this fixes and where to apply it (web server, CDN or app config)"
}
Output only valid JSON. No markdown."""
    else:
        system_prompt = """You are a secure code fix agent.
Generate a targeted code patch for the vulnerability provided.

You are shown the real source around the finding, with the flagged line marked
">". Patch THAT line. Never invent code that is not in the excerpt: copy the
flagged line verbatim into original_code.

If the flagged line is a comment, a string, or otherwise not the vulnerability
the description claims, say so in the explanation and return the line unchanged
in patched_code rather than inventing a fix.

Return a single JSON object:
{
  "vuln_id": "VULN-001",
  "file": "path/to/file.py",
  "original_code": "the vulnerable snippet, copied from the excerpt",
  "patched_code": "the fixed snippet",
  "explanation": "what changed and why it fixes the vulnerability"
}
Output only valid JSON. No markdown."""

    static_host = state.get("tech_stack", {}).get("static_host")

    # Prompt 00a: one LLM call per vulnerability, fanned out over the
    # load-balanced pool (llm_pool.map preserves order, so patches[] and the
    # log lines come out exactly as the sequential loop produced them).
    jobs: list[tuple[dict, object, str, bool]] = []  # (vuln, source, prompt, unreadable)
    for vuln in targets:
        # When the host cannot set response headers, the remediation is a known
        # fact about the platform, not something to ask a model about. Left to
        # the LLM it answered "add the following header in the GitHub Pages
        # settings", which is a setting that does not exist.
        canned = _header_remediation_for_static_host(vuln, static_host)
        if canned:
            patches.append(canned)
            logs.append(f"[FixSuggester] {vuln['id']} cannot be fixed on "
                        f"{static_host} — gave the platform-level remediation")
            continue

        source = None
        if not is_website:
            source = read_source_window(
                state.get("repo_path", ""), vuln.get("file", ""), vuln.get("line", 0)
            )

        prompt = f"Fix this vulnerability:\n{json.dumps(vuln, indent=2)}"
        if source:
            context, _ = source
            prompt += (
                f"\n\nThe real source at {vuln['file']} "
                f"(the flagged line is marked with '>'):\n{context}"
            )
            unreadable = False
        else:
            unreadable = not is_website

        jobs.append((vuln, source, prompt, unreadable))

    message_lists = [
        [SystemMessage(content=system_prompt), HumanMessage(content=prompt)]
        for (_, _, prompt, _) in jobs
    ]
    # fn is resolved from this module's globals at call time, so tests that
    # monkeypatch orchestrator.invoke_llm keep working.
    replies = llm_pool.map(message_lists, fn=invoke_llm) if jobs else []

    for (vuln, source, _, unreadable), response in zip(jobs, replies):
        patch = _parse_json(response.content, None)
        if isinstance(patch, list):
            # Asked for one object, answered with an array. Left alone, a list
            # was appended to patches[] and every consumer that expects a patch
            # object breaks on it.
            patch = next((p for p in patch if isinstance(p, dict)), None)

        if isinstance(patch, dict) and source:
            # The file is on disk, so the original line is a fact. Whatever the
            # model echoed back, the report shows what is actually there.
            _, exact = source
            patch["original_code"] = exact
            if "patched_code" in patch:
                patch["patched_code"] = _strip_gutter(patch["patched_code"])
        elif isinstance(patch, dict) and unreadable:
            # No source to check the model against, so it must not present a
            # diff as if there were one.
            patch.pop("original_code", None)
            patch.pop("patched_code", None)
            patch["explanation"] = (
                f"Could not read {vuln.get('file', 'the file')} to produce a "
                f"verified diff. "
            ) + str(patch.get("explanation", ""))

        if isinstance(patch, dict) and is_website:
            # Guarantee no fabricated diff reaches the report, whatever the
            # model returned. The UI hides empty diff blocks.
            patch.pop("original_code", None)
            patch.pop("patched_code", None)
            patch.setdefault("vuln_id", vuln.get("id", ""))
            patch.setdefault("file", vuln.get("file", ""))
        if patch:
            patches.append(patch)
            logs.append(f"[FixSuggester] Patch ready for {vuln['id']} — {vuln['severity']}")
        else:
            logs.append(f"[FixSuggester] Could not generate patch for {vuln['id']}")

    logs.append(f"[FixSuggester] {len(patches)}/{len(targets)} patches generated")

    return {
        "patches": patches,
        "status": "reporting",
        "agent_logs": logs,
    }


# ══════════════════════════════════════════════════════════════
#  Node: Report Generator
# ══════════════════════════════════════════════════════════════

def _unassessed_report(state: ScanState) -> dict:
    """
    The report for a scan that could not examine its target.

    No model is asked for a summary here. Given "0 vulnerabilities" it writes a
    reassuring one, and there is nothing to be reassured about: the question of
    whether this site is secure is simply unanswered. The score is None rather
    than 0, so it cannot be plotted as a clean data point in the risk trend.
    """
    reason = state.get("not_assessed", "the target could not be assessed")
    summary = {
        "executive_summary": (
            f"No assessment was performed, because {reason}. This is not a clean "
            f"result: nothing about {state['repo_url']} was examined, so its "
            f"security posture is unknown. Re-run the scan once the target "
            f"responds."
        ),
        "key_recommendations": [
            "Confirm the target is reachable and serving the real application, "
            "then scan it again.",
        ],
        "risk_score": None,
        "overall_risk": "UNKNOWN",
        "assessed": False,
        "not_assessed_reason": reason,
    }
    report = {
        "scan_id": state["scan_id"],
        "repo_url": state["repo_url"],
        "tech_stack": state.get("tech_stack", {}),
        "summary": summary,
        "vulnerabilities": [],
        "exploits": [],
        "patches": [],
        "total_findings": 0,
        "assessed": False,
        "not_assessed_reason": reason,
        "errors": state.get("errors", []),
    }
    return {
        "report": report,
        "status": "done",
        "agent_logs": [
            f"[ReportGenerator] No assessment performed: {reason}",
            "[ReportGenerator] No risk score: zero findings here means nothing was "
            "examined, not that nothing is wrong",
            f"[ReportGenerator] Scan {state['scan_id']} ended without an assessment.",
        ],
    }


def report_generator_node(state: ScanState) -> dict:
    """Compiles all agent outputs into the final structured report."""
    vulns = state.get("vulnerabilities", [])
    critical = [v for v in vulns if v["severity"] == "CRITICAL"]
    high = [v for v in vulns if v["severity"] == "HIGH"]

    # An unreachable host, a bot challenge and an error page all end here with
    # an empty findings list, which scores 0/100 LOW and reads as an all-clear.
    # A site that never answered was being reported as "no vulnerabilities
    # found, the site appears secure" — the worst thing a security tool can
    # say, because it is indistinguishable from a real clean result. There is
    # no score to give when nothing was examined.
    if state.get("not_assessed"):
        return _unassessed_report(state)

    # Scored here, before the model is asked for anything, so the number is a
    # fact about the findings rather than an opinion about them.
    risk = compute_risk(vulns)

    response = invoke_llm([
        SystemMessage(content="""You are a security report writer.
Produce an executive summary for a security audit.

The risk score has already been calculated from the severity counts. Do not
restate it, dispute it, or invent one of your own — describe what was found.

Return a JSON object:
{
  "executive_summary": "2-3 sentences for a non-technical stakeholder",
  "key_recommendations": ["top 3 action items, ordered by priority"]
}
Output only valid JSON. No markdown."""),
        HumanMessage(content=f"""Repository: {state['repo_url']}
Tech stack: {state.get('tech_stack', {})}
Total vulnerabilities: {len(vulns)}
Critical: {len(critical)}, High: {len(high)}
Assessed risk: {risk['overall_risk']} ({risk['risk_score']}/100)
Top findings: {json.dumps(vulns[:5], indent=2)}"""),
    ])

    summary = _parse_json(response.content, {
        "executive_summary": "Security scan completed. Review findings for details.",
        "key_recommendations": ["Review and patch all CRITICAL and HIGH findings immediately."],
    })
    if not isinstance(summary, dict):
        summary = {"executive_summary": "Security scan completed. Review findings for details."}

    # Authoritative, whatever the model returned.
    summary["risk_score"] = risk["risk_score"]
    summary["overall_risk"] = risk["overall_risk"]
    summary["risk_breakdown"] = {
        "counts": risk["counts"],
        "contributions": risk["contributions"],
        "weights": _SEVERITY_WEIGHT,
        "band_caps": _SEVERITY_BAND_CAP,
        "floor_applied": risk["floor_applied"],
        "method": (
            "score = sum over severities of min(count * weight, band cap), "
            "raised to the floor for the most severe finding, capped at 100"
        ),
    }

    # Normalise key_recommendations — local models sometimes return objects
    # ...as {"priority": 1, "action_item": "..."} among others.
    recs = summary.get("key_recommendations", [])
    summary["key_recommendations"] = [
        r if isinstance(r, str)
        else (r.get("action_item") or r.get("recommendation")
              or r.get("action") or r.get("text") or str(r))
        for r in (recs if isinstance(recs, list) else [])
        if r
    ]
    # ...and sometimes omit the key entirely. An empty recommendations section
    # under a list of findings reads as "nothing to do here".
    if not summary["key_recommendations"] and vulns:
        summary["key_recommendations"] = _recommendations_from_vulns(vulns)

    report = {
        "scan_id": state["scan_id"],
        "repo_url": state["repo_url"],
        "tech_stack": state.get("tech_stack", {}),
        "summary": summary,
        "vulnerabilities": state.get("vulnerabilities", []),
        "exploits": state.get("exploits", []),
        "patches": state.get("patches", []),
        "total_findings": len(state.get("vulnerabilities", [])),
        "assessed": True,
        "errors": state.get("errors", []),
    }

    return {
        "report": report,
        "status": "done",
        "agent_logs": [
            "[ReportGenerator] Severity counts: "
            + ", ".join(f"{sev} {risk['counts'][sev]}" for sev in _VALID_SEVERITIES),
            "[ReportGenerator] Score contributions: "
            + ", ".join(f"{sev} +{risk['contributions'][sev]}" for sev in _VALID_SEVERITIES)
            + (f", floor {risk['floor_applied']}" if risk["floor_applied"] else ""),
            f"[ReportGenerator] Risk score: {summary['risk_score']}/100 (calculated, not model-generated)",
            f"[ReportGenerator] Overall risk: {summary['overall_risk']}",
            f"[ReportGenerator] Scan {state['scan_id']} complete.",
        ],
    }


# ══════════════════════════════════════════════════════════════
#  Conditional routing
# ══════════════════════════════════════════════════════════════

def _route_after_scanner(state: ScanState) -> Literal["vuln_analyzer", "report_generator"]:
    if state.get("errors") or not state.get("raw_findings"):
        return "report_generator"
    return "vuln_analyzer"


def _route_after_vuln_analyzer(state: ScanState) -> Literal["exploit_reasoner", "report_generator"]:
    if not state.get("vulnerabilities"):
        return "report_generator"
    return "exploit_reasoner"


# ══════════════════════════════════════════════════════════════
#  Graph assembly
# ══════════════════════════════════════════════════════════════

def build_graph() -> StateGraph:
    graph = StateGraph(ScanState)

    graph.add_node("orchestrator", orchestrator_node)
    graph.add_node("scanner", scanner_node)
    graph.add_node("vuln_analyzer", vuln_analyzer_node)
    graph.add_node("exploit_reasoner", exploit_reasoner_node)
    graph.add_node("fix_suggester", fix_suggester_node)
    graph.add_node("report_generator", report_generator_node)

    graph.set_entry_point("orchestrator")

    graph.add_edge("orchestrator", "scanner")
    graph.add_conditional_edges("scanner", _route_after_scanner, {
        "vuln_analyzer": "vuln_analyzer",
        "report_generator": "report_generator",
    })
    graph.add_conditional_edges("vuln_analyzer", _route_after_vuln_analyzer, {
        "exploit_reasoner": "exploit_reasoner",
        "report_generator": "report_generator",
    })
    graph.add_edge("exploit_reasoner", "fix_suggester")
    graph.add_edge("fix_suggester", "report_generator")
    graph.add_edge("report_generator", END)

    return graph.compile(checkpointer=MemorySaver())


_graph = build_graph()


# ══════════════════════════════════════════════════════════════
#  Public API
# ══════════════════════════════════════════════════════════════

def _initial_state(repo_url: str, scan_id: Optional[str] = None) -> ScanState:
    sid = scan_id or str(uuid.uuid4())[:8]
    return ScanState(
        repo_url=repo_url,
        scan_id=sid,
        repo_path="",
        tech_stack={},
        raw_findings=[],
        vulnerabilities=[],
        exploits=[],
        patches=[],
        report={},
        status="starting",
        errors=[],
        not_assessed="",
        agent_logs=[f"[Orchestrator] Initializing scan {sid} for {repo_url}"],
    )


async def run_scan(repo_url: str, scan_id: Optional[str] = None) -> ScanState:
    """Run a full scan and return the completed state."""
    state = _initial_state(repo_url, scan_id)
    config = {"configurable": {"thread_id": state["scan_id"]}}
    return await _graph.ainvoke(state, config=config)


async def stream_scan(repo_url: str, scan_id: Optional[str] = None) -> AsyncGenerator[dict, None]:
    """Yield node-by-node updates for WebSocket streaming to the frontend."""
    state = _initial_state(repo_url, scan_id)
    config = {"configurable": {"thread_id": state["scan_id"]}}

    async for event in _graph.astream(state, config=config):
        node_name, node_output = next(iter(event.items()))
        yield {
            "node": node_name,
            "logs": node_output.get("agent_logs", []),
            "status": node_output.get("status", ""),
            "scan_id": state["scan_id"],
        }
