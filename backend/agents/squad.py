"""Specialist squad: analyse findings in parallel, one expert per bug family.

The sequential pipeline runs vuln_analyzer -> exploit_reasoner -> fix_suggester
over ALL findings, each with one big LLM call. The squad splits the raw
findings into families (Injection, AccessControl, Secrets&Config, Other) and
runs those three stages for every family concurrently, reusing the existing
node logic on a sub-state. Each specialist gets a short CWE-focused addition
to its system prompts. Results are merged back in the original finding order
and renumbered, so the output has the same shape as the sequential path.

A family that fails does not sink the others: it falls back to the
deterministic mapping (findings kept, no enrichment).
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

logger = logging.getLogger(__name__)

FAMILIES = ("Injection", "AccessControl", "Secrets&Config", "Other")

_NOTES = {
    "Injection": (
        "\n\nYou are the INJECTION specialist (CWE-89 SQL injection, CWE-78 "
        "command injection, CWE-94 code/template injection, XSS). Focus on "
        "attacker-controlled input reaching a query, shell, template or "
        "eval. Fixes: parameterized queries, argument lists with shell=False "
        "plus input validation, output escaping."),
    "AccessControl": (
        "\n\nYou are the ACCESS-CONTROL specialist (CWE-639 IDOR, CWE-22 path "
        "traversal, CWE-306 missing authentication, CWE-601 open redirect). "
        "Focus on who may reach which object or file. Fixes: ownership "
        "checks, path confinement with realpath, authentication decorators."),
    "Secrets&Config": (
        "\n\nYou are the SECRETS-AND-CONFIG specialist (CWE-798 hard-coded "
        "secrets, weak cryptography, debug mode, insecure configuration). "
        "Fixes: read secrets from the environment, modern hashing, disable "
        "debug in production."),
    "Other": "",
}

_KEYWORDS = {
    "Injection": ("sql", "injection", "command", "subprocess", "shell", "eval",
                  "exec(", "xss", "cross-site", "template", "ssti", "cwe-89",
                  "cwe-78", "cwe-94", "cwe-79", "deserial", "a03:2021"),
    "AccessControl": ("idor", "access control", "traversal", "path", "authoriz",
                      "missing auth", "unauthenticated", "cwe-639", "cwe-22",
                      "cwe-306", "cwe-601", "redirect", "a01:2021", "a07:2021"),
    "Secrets&Config": ("secret", "password", "hardcoded", "hard-coded",
                       "credential", "token", "api key", "cwe-798", "md5",
                       "sha1", "weak", "crypto", "debug", "cwe-327", "cwe-489",
                       "misconfig", "a02:2021", "a05:2021"),
}


def classify_family(finding: dict) -> str:
    """Family of a raw scanner finding, from its text (first match wins)."""
    text = " ".join(str(finding.get(k, "")) for k in
                    ("description", "rule_id", "test_id", "category", "code")).lower()
    for family in ("Injection", "AccessControl", "Secrets&Config"):
        if any(k in text for k in _KEYWORDS[family]):
            return family
    return "Other"


def group_findings(raw_findings: list[dict]) -> dict[str, list[dict]]:
    """Non-empty families in FAMILIES order; relative finding order preserved."""
    groups: dict[str, list[dict]] = {f: [] for f in FAMILIES}
    for finding in raw_findings:
        groups[classify_family(finding)].append(finding)
    return {f: g for f, g in groups.items() if g}


# ── Specialist prompt note (read by the three nodes at call time) ─────────────

_local = threading.local()


def specialist_note() -> str:
    return getattr(_local, "note", "") or ""


# ── Live lane events (set by the API layer so the UI can draw lanes) ──────────

_lane_sinks: dict[str, Callable[[str, str], None]] = {}


def set_lane_sink(scan_id: str, sink: Callable[[str, str], None] | None) -> None:
    if sink is None:
        _lane_sinks.pop(scan_id, None)
    else:
        _lane_sinks[scan_id] = sink


def _emit(scan_id: str, lane: str, line: str) -> bool:
    sink = _lane_sinks.get(scan_id)
    if sink is None:
        return False
    try:
        sink(lane, line)
        return True
    except Exception:
        logger.debug("lane sink failed", exc_info=True)
        return False


# ── Running the squad ────────────────────────────────────────────────────────

def squad_applicable(state: dict) -> bool:
    import os
    from agents.orchestrator import parallel_agents_enabled

    if not parallel_agents_enabled():
        return False
    if (state.get("tech_stack") or {}).get("type") == "website":
        return False
    if state.get("target_hint") and os.getenv("FAST_SCAN", "1").strip() == "1":
        return False  # fast single-target runs keep the shortlist logic
    return len(group_findings(state.get("raw_findings") or [])) >= 2


def _run_family(family: str, findings: list[dict], state: dict, lane_logs: list[str],
                emit: Callable[[str], None]) -> dict:
    """analyzer -> exploit_reasoner -> fix_suggester on a sub-state."""
    import agents.orchestrator as orch

    _local.note = _NOTES[family]
    sub = {**state, "raw_findings": findings, "vulnerabilities": [], "exploits": [],
           "patches": [], "_squad_sub": True}

    def stage(fn) -> None:
        out = fn(sub)
        for line in out.get("agent_logs", []):
            lane_logs.append(line)
            emit(line)
        for key in ("vulnerabilities", "exploits", "patches"):
            if key in out:
                sub[key] = out[key]

    try:
        stage(orch.vuln_analyzer_node)
        stage(orch.exploit_reasoner_node)
        stage(orch.fix_suggester_node)
        error = None
    except Exception as exc:  # isolated: keep this family's findings, unenriched
        logger.exception("squad lane %s failed", family)
        error = str(exc)
        line = f"[Squad] {family} specialist failed ({error}); kept findings unenriched"
        lane_logs.append(line)
        emit(line)
        sub["vulnerabilities"] = orch._vulns_from_raw_findings(findings)
        sub["exploits"], sub["patches"] = [], []
    finally:
        _local.note = ""
    return {"vulnerabilities": sub["vulnerabilities"], "exploits": sub["exploits"],
            "patches": sub["patches"], "error": error}


def merge_results(raw_findings: list[dict],
                  results: dict[str, dict]) -> tuple[list, list, list]:
    """Deterministic merge: original finding order, ids renumbered VULN-001..."""
    position: dict[tuple, int] = {}
    for i, f in enumerate(raw_findings):
        position.setdefault((f.get("file", ""), f.get("line", 0)), i)

    entries = []  # (sort key, family, vuln)
    for family_index, family in enumerate(FAMILIES):
        for n, vuln in enumerate((results.get(family) or {}).get("vulnerabilities", [])):
            key = (position.get((vuln.get("file", ""), vuln.get("line", 0)), 10 ** 9),
                   family_index, n)
            entries.append((key, family, vuln))
    entries.sort(key=lambda e: e[0])

    idmap: dict[tuple[str, str], str] = {}
    merged, counter = [], 1
    for _, family, vuln in entries:
        old = str(vuln.get("id", ""))
        if old.startswith("VULN-"):
            new = f"VULN-{counter:03d}"
            counter += 1
        else:
            new = old  # PORT-xxx and similar are already unique
        idmap[(family, old)] = new
        merged.append({**vuln, "id": new})

    def remap(items: list, family: str) -> list:
        return [{**item, "vuln_id": idmap.get((family, str(item.get("vuln_id", ""))),
                                              item.get("vuln_id"))}
                for item in items if isinstance(item, dict)]

    exploits, patches = [], []
    for family in FAMILIES:
        res = results.get(family) or {}
        exploits.extend(remap(res.get("exploits", []), family))
        patches.extend(remap(res.get("patches", []), family))
    # Same ordering as the sequential nodes: most severe first, ties in id order.
    import agents.orchestrator as orch
    order = {v["id"]: i for i, v in enumerate(merged)}
    sev = {v["id"]: orch._SEVERITY_RANK.get(v.get("severity"), 99) for v in merged}

    def rank(item: dict) -> tuple:
        vid = item.get("vuln_id")
        return (sev.get(vid, 99), order.get(vid, 10 ** 9))

    exploits.sort(key=rank)
    patches.sort(key=rank)
    # Each lane capped its own patch targets; keep the global cap too.
    del patches[orch._MAX_PATCH_TARGETS:]
    return merged, exploits, patches


def run_squad(state: dict) -> dict:
    """Run the specialists concurrently; returns the combined node output."""
    import agents.orchestrator as orch

    raw = state.get("raw_findings") or []
    groups = group_findings(raw)
    scan_id = state.get("scan_id", "")
    summary = ", ".join(f"{f}({len(g)})" for f, g in groups.items())
    head = f"[Squad] {len(groups)} specialists in parallel: {summary}"
    logs = [] if _emit(scan_id, "Squad", head) else [head]

    lane_logs: dict[str, list[str]] = {f: [] for f in groups}
    undelivered: list[str] = []

    def make_emit(family: str) -> Callable[[str], None]:
        def emit(line: str) -> None:
            if not _emit(scan_id, family, line):
                undelivered.append(f"[{family}] {line}")
        return emit

    results: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=len(groups), thread_name_prefix="squad") as ex:
        futures = {f: ex.submit(_run_family, f, g, state, lane_logs[f], make_emit(f))
                   for f, g in groups.items()}
        for family, fut in futures.items():
            results[family] = fut.result()

    if all(r["error"] for r in results.values()):
        raise RuntimeError("every specialist failed: "
                           + "; ".join(r["error"] for r in results.values()))

    vulns, exploits, patches = merge_results(raw, results)
    logs.extend(undelivered)
    logs.append(f"[Squad] merged {len(vulns)} vulnerabilities, "
                f"{len(exploits)} exploit analyses, {len(patches)} patches")

    final_state = {**state, "vulnerabilities": vulns, "exploits": exploits,
                   "patches": patches}
    orch._snapshot_after_fix(final_state, patches)
    return {"vulnerabilities": vulns, "exploits": exploits, "patches": patches,
            "status": "reporting", "squad_done": True, "agent_logs": logs}
