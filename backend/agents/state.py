"""
Shared state schema for the VulnSentinel agent graph.
All nodes read from and write to ScanState.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, Dict, List, Optional, TypedDict


class Vulnerability(TypedDict):
    id: str
    file: str
    line: int
    severity: str       # CRITICAL | HIGH | MEDIUM | LOW
    category: str       # OWASP Top 10 label e.g. "A03:2021-Injection"
    description: str
    cve: Optional[str]


class ExploitAnalysis(TypedDict):
    vuln_id: str
    exploitability: str     # EASY | MODERATE | HARD | UNKNOWN (not model-assessed)
    attack_vector: str
    impact: str
    poc_description: str


class Patch(TypedDict):
    vuln_id: str
    file: str
    original_code: str
    patched_code: str
    explanation: str


class ScanState(TypedDict):
    # ── Input ──────────────────────────────────────────────
    repo_url: str
    scan_id: str
    create_pr: bool                # from request; False → original behaviour
    target_hint: Optional[str]     # demo control: CWE id or VULN id to fix

    # ── Scanner output ─────────────────────────────────────
    repo_path: str
    tech_stack: Dict[str, Any]
    raw_findings: List[Dict[str, Any]]

    # ── Per-agent outputs ──────────────────────────────────
    vulnerabilities: List[Vulnerability]
    exploits: List[ExploitAnalysis]
    patches: List[Patch]

    # ── Final report ───────────────────────────────────────
    report: Dict[str, Any]

    # ── Control flow ───────────────────────────────────────
    status: str         # starting | scanning | analyzing | exploiting | patching | reporting | done | error
    errors: List[str]

    # Why no assessment was performed: the target was unreachable, blocked
    # automated scanning, or served an error page. Empty when the scan ran.
    # Zero findings mean "nothing found" only when this is empty; otherwise
    # they mean "nothing was looked at", which is not the same result and must
    # never be reported as one.
    not_assessed: str

    # ── PatchForge remediation (prompts 03–06; skipped when create_pr False)
    target_vuln: Optional[Dict[str, Any]]  # the ONE vulnerability for auto-PR
    work_dir: str                   # patched working copy, current attempt
    code_patch: Optional[Dict[str, Any]]   # rationale/blocks/diff/test_file/…
    attempts: int
    # reviewer/tester feedback for the next coder attempt (replaced, not added)
    feedback: List[str]
    review: Optional[Dict[str, Any]]
    test_reports: Dict[str, Any]    # {"baseline":…, "exploit_before":…, "after":…}
    pr_url: Optional[str]
    remediation_status: str         # skipped|running|pr_opened|verified_no_pr|failed

    # Accumulates across nodes; streamed live to frontend via WebSocket
    agent_logs: Annotated[List[str], operator.add]
