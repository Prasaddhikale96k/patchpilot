"""
SentinelAI — FastAPI backend

── VulnSentinel (code security) ──────────────────────────────
POST /api/scan              Start a scan; returns scan_id + ws_url
WS   /ws/{scan_id}          Stream real-time agent logs
GET  /api/report/{scan_id}  Fetch completed report JSON
GET  /api/scans             List all scans

── Retention (data lifecycle) ────────────────────────────────
Every destructive operation returns a receipt: one result per store plus a
single outcome of complete | partial | blocked | unresolved.

GET    /api/retention/policy               Schedule, state counts, ledger health
GET    /api/retention/scans                Inventory with state, hold and next due action
POST   /api/retention/scans/{id}/archive   Offload findings to the cold archive
POST   /api/retention/scans/{id}/restore   Undo a trash, rehydrate an archive
POST   /api/retention/scans/{id}/trash     Reversible delete
POST   /api/retention/scans/{id}/purge     Irreversible erasure (?mode=full|payload)
POST   /api/retention/scans/{id}/hold      Legal hold; blocks every destructive step
DELETE /api/retention/scans/{id}/hold      Release the hold
GET    /api/retention/scans/{id}/verify    Re-check every store for residue
POST   /api/retention/sweep                Apply the policy (?dry_run, ?as_of)
GET    /api/retention/audit                Hash-chained ledger of every operation

── OSIRIS (OSINT enrichment) ─────────────────────────────────
On-demand only: nothing reaches osirisai.live until a report is clicked.

GET  /api/osiris/ip/{ip}        Geolocation, ASN, reputation, exposed services
GET  /api/osiris/cve/{cve_id}   Upstream record for a single CVE id

── ExamGuard (exam integrity) ────────────────────────────────
POST /api/exam/session          Create exam session; returns exam_id + ws_url
WS   /ws/exam/{exam_id}         Bidirectional: browser sends events → server sends immediate alerts
POST /api/exam/{exam_id}/analyze  Trigger LangGraph post-session analysis
WS   /ws/exam/{exam_id}/analysis  Stream analysis progress (mirrors VulnSentinel WS pattern)
GET  /api/exam/report/{exam_id}   Fetch completed integrity report
GET  /api/exam/sessions           List all exam sessions

── Shared ────────────────────────────────────────────────────
GET  /health

WebSocket message envelopes
───────────────────────────
VulnSentinel:
  server→client  { type: "update"|"done"|"error"|"ping", ... }

ExamGuard event socket (/ws/exam/{id}):
  client→server  { type: "tab_event"|"face_event"|"keystroke_stats"|"copy_paste"|"end_exam"|"ping" }
  server→client  { type: "immediate_alert"|"exam_ended"|"pong"|"error" }

ExamGuard analysis socket (/ws/exam/{id}/analysis):
  server→client  { type: "analysis_update"|"done"|"error"|"ping" }
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, List, Optional

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from agents.orchestrator import _graph, _initial_state
from agents.llm_router import LLMUnavailableError
from tools.url_guard import assert_safe_target, UnsafeTargetError
from tools.git_cloner import cleanup_repo, _repo_dest
from tools import retention as rt
from tools import osiris
from exam_agents.exam_pipeline import _exam_graph, stream_exam_analysis
from exam_agents.exam_state import ExamSession
from exam_agents.event_rules import (
    check_copy_paste,
    check_face_event,
    check_tab_event,
    check_absence_duration,
    check_phone_detected,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(name)s  %(message)s")
logger = logging.getLogger("sentinelai")

# ── Scan history persistence ──────────────────────────────────
_HISTORY_FILE = Path(os.getenv("HISTORY_FILE", "scan_history.json"))
_history_lock = asyncio.Lock()


def _load_history() -> list[dict]:
    if not _HISTORY_FILE.exists():
        return []
    try:
        return json.loads(_HISTORY_FILE.read_text())
    except Exception:
        return []


def _write_history(records: list[dict]) -> None:
    _HISTORY_FILE.write_text(json.dumps(records, indent=2))


async def _save_history(records: list[dict]) -> None:
    async with _history_lock:
        _write_history(records)


def _visible_history() -> list[dict]:
    """
    History as the product shows it: trashed scans are gone from listings,
    trends and comparisons until they are restored.
    """
    return [r for r in _load_history()
            if rt.lifecycle_of(r).get("state") != rt.STATE_TRASHED]


async def _append_scan_history(scan_id: str, repo_url: str, report: dict, started_at: float) -> None:
    """
    Persist a completed scan to scan_history.json. Called only on success.

    A scan that never reached its target is not a result. Recorded, it would
    enter the history listing and the risk trend as a clean 0/100 point, which
    is exactly the reading it must not be given, so it is left out.
    """
    from urllib.parse import urlparse

    if report.get("assessed") is False:
        logger.info("Scan %s (%s) not saved to history: %s", scan_id, repo_url,
                    report.get("not_assessed_reason", "no assessment performed"))
        return
    vulns: list[dict] = report.get("vulnerabilities", [])
    sev: dict[str, int] = {}
    for v in vulns:
        s = v.get("severity", "UNKNOWN")
        sev[s] = sev.get(s, 0) + 1

    try:
        parsed = urlparse(repo_url if "://" in repo_url else f"https://{repo_url}")
        domain = parsed.netloc or parsed.path.split("/")[0]
    except Exception:
        domain = repo_url

    record = {
        "scan_id":         scan_id,
        "lifecycle":       rt.default_lifecycle(started_at),
        "domain":          domain,
        "repo_url":        repo_url,
        "scan_date":       time.strftime("%Y-%m-%d", time.gmtime(started_at)),
        "timestamp":       started_at,
        "total_vulns":     len(vulns),
        "severity":        {"critical": sev.get("CRITICAL", 0), "high": sev.get("HIGH", 0),
                            "medium": sev.get("MEDIUM", 0), "low": sev.get("LOW", 0)},
        "risk_score":      report.get("summary", {}).get("risk_score", 0),
        "overall_risk":    report.get("summary", {}).get("overall_risk", "UNKNOWN"),
        "vulnerabilities": vulns,
        "patches":         report.get("patches", []),
        "summary":         report.get("summary", {}),
    }

    async with _history_lock:
        records = _load_history()
        # Never overwrite — each scan is a new entry; only deduplicate same scan_id
        records = [r for r in records if r.get("scan_id") != scan_id]
        records.insert(0, record)
        _HISTORY_FILE.write_text(json.dumps(records, indent=2))
    logger.info("Scan %s (%s) saved to history (%d total)", scan_id, domain, len(records) + 1)

# ── Operational limits (overridable via environment) ──────────
MAX_CONCURRENT_SCANS   = int(os.getenv("MAX_CONCURRENT_SCANS", "3"))
SCAN_TIMEOUT_SECS      = float(os.getenv("SCAN_TIMEOUT_SECS", "600"))
ANALYSIS_TIMEOUT_SECS  = float(os.getenv("ANALYSIS_TIMEOUT_SECS", "300"))
SESSION_TTL_SECS       = float(os.getenv("SESSION_TTL_SECS", str(24 * 3600)))
JANITOR_INTERVAL_SECS  = float(os.getenv("JANITOR_INTERVAL_SECS", "600"))
MAX_EVENTS_PER_LIST    = int(os.getenv("MAX_EVENTS_PER_LIST", "5000"))

# Phone detection runs client-side (coco-ssd in the browser); the browser
# sends a `phone_detected` event, handled below. No server-side ML needed.

# ── In-process registries ─────────────────────────────────────
_scans: Dict[str, dict] = {}           # VulnSentinel scan sessions
_exam_sessions: Dict[str, dict] = {}   # ExamGuard sessions

# Global multi-student monitor: fan-out queues for the class-wide host
# dashboard, plus the latest trust snapshot per exam (so a dashboard that
# connects mid-exam immediately sees every active student).
_global_monitor_queues: List[asyncio.Queue] = []
_latest_trust: Dict[str, dict] = {}    # exam_id → last trust_update payload

# ── Retention / data lifecycle ────────────────────────────────
_ARCHIVE_DIR = Path(os.getenv("RETENTION_ARCHIVE_DIR", "retention_archive"))
_AUDIT_FILE = Path(os.getenv("RETENTION_AUDIT_FILE", "retention_audit.jsonl"))

_retention = rt.RetentionStore(
    load_records=_load_history,
    save_records=_write_history,
    archive_dir=_ARCHIVE_DIR,
    ledger=rt.AuditLedger(_AUDIT_FILE),
    live_sessions=_scans,
    workspace_for=_repo_dest,
)


async def _broadcast_global(msg: dict) -> None:
    """Push a message to every connected class-wide dashboard."""
    for q in list(_global_monitor_queues):
        await q.put(msg)


async def _close_quietly(websocket: WebSocket, context: str) -> None:
    """
    Close a WebSocket that is probably already gone.

    Every WS endpoint ends with this in a finally block. Failing to close a
    socket the client has already dropped is expected and not worth an error,
    but swallowing it silently means a genuine transport fault leaves no trace
    at all, so it is recorded at debug level.
    """
    try:
        await websocket.close()
    except Exception:
        logger.debug("WS close failed for %s (already closed?)", context, exc_info=True)


# ══════════════════════════════════════════════════════════════
#  App lifecycle
# ══════════════════════════════════════════════════════════════

async def _janitor() -> None:
    """Periodically purge finished scans/sessions older than SESSION_TTL_SECS."""
    while True:
        await asyncio.sleep(JANITOR_INTERVAL_SECS)
        cutoff = time.time() - SESSION_TTL_SECS
        for sid in [s for s, d in _scans.items()
                    if d["status"] in ("done", "error") and d["started_at"] < cutoff]:
            _scans.pop(sid, None)
            logger.info("Janitor: purged expired scan %s", sid)
        for eid in [e for e, d in _exam_sessions.items()
                    if d["session"]["status"] in ("done", "error") and d["started_at"] < cutoff]:
            _exam_sessions.pop(eid, None)
            logger.info("Janitor: purged expired exam session %s", eid)


@asynccontextmanager
async def lifespan(app: FastAPI):
    janitor = asyncio.create_task(_janitor())
    from agents.orchestrator import _graph
    try:
        nodes = sorted(getattr(_graph, "nodes", {}).keys())
    except Exception:
        nodes = []
    logger.info("Serving graph nodes: %s", nodes)
    yield
    janitor.cancel()
    _scans.clear()
    _exam_sessions.clear()


app = FastAPI(title="SentinelAI", version="1.0.0", lifespan=lifespan)

_default_origins = "http://localhost:3000,http://127.0.0.1:3000"
# ALLOWED_ORIGIN_REGEX is handy for Vercel preview URLs, e.g.
#   https://.*\.vercel\.app
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.getenv("ALLOWED_ORIGINS", _default_origins).split(",") if o.strip()],
    allow_origin_regex=os.getenv("ALLOWED_ORIGIN_REGEX") or None,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ══════════════════════════════════════════════════════════════
#  Pydantic models
# ══════════════════════════════════════════════════════════════

class ScanRequest(BaseModel):
    repo_url: str = Field(min_length=4, max_length=2048)
    create_pr: bool = False
    target_hint: Optional[str] = Field(default=None, max_length=32)

    @field_validator("repo_url")
    @classmethod
    def must_be_https_url(cls, v: str) -> str:
        v = v.strip()
        if v.startswith(("http://", "https://")):
            return v
        # Bare domain like "example.com" — scheme is added downstream
        if "://" not in v and " " not in v and "." in v:
            return v
        raise ValueError("repo_url must be an http(s) URL or a bare domain")


class ScanResponse(BaseModel):
    scan_id: str
    ws_url: str
    status: str


class ScanSummary(BaseModel):
    scan_id: str
    repo_url: str
    status: str
    started_at: float


# ══════════════════════════════════════════════════════════════
#  Background task
# ══════════════════════════════════════════════════════════════

async def _run_scan(repo_url: str, scan_id: str, create_pr: bool = False,
                  target_hint: Optional[str] = None) -> None:
    queue: asyncio.Queue = _scans[scan_id]["queue"]
    accumulated: dict = {}

    try:
        state = _initial_state(repo_url, scan_id, create_pr=create_pr,
                               target_hint=target_hint)
        config = {"configurable": {"thread_id": scan_id}}

        async with asyncio.timeout(SCAN_TIMEOUT_SECS):
            async for event in _graph.astream(state, config=config):
                node_name, node_output = next(iter(event.items()))

                # Merge into accumulated so we can retrieve the report at the end.
                # agent_logs uses operator.add so we handle it manually.
                for k, v in node_output.items():
                    if k == "agent_logs":
                        accumulated.setdefault("agent_logs", [])
                        accumulated["agent_logs"].extend(v)
                    else:
                        accumulated[k] = v

                await queue.put({
                    "type": "update",
                    "node": node_name,
                    "logs": node_output.get("agent_logs", []),
                    "status": node_output.get("status", ""),
                    "scan_id": scan_id,
                })

        report = accumulated.get("report", {})
        _scans[scan_id]["report"] = report
        _scans[scan_id]["status"] = "done"

        await queue.put({"type": "done", "scan_id": scan_id, "report": report})

        # Persist to history only on successful completion
        await _append_scan_history(scan_id, repo_url, report, _scans[scan_id]["started_at"])

    except TimeoutError:
        logger.error("Scan %s exceeded %ss timeout", scan_id, SCAN_TIMEOUT_SECS)
        _scans[scan_id]["status"] = "error"
        await queue.put({"type": "error", "scan_id": scan_id,
                         "message": f"Scan timed out after {int(SCAN_TIMEOUT_SECS)}s"})

    except LLMUnavailableError as exc:
        # An operational fault, not a bug. Collapsing it into "internal error"
        # meant a dead API key and a crash in the pipeline looked identical from
        # the browser, and only the server logs could tell them apart.
        logger.error("Scan %s could not reach a language model: %s", scan_id, exc)
        _scans[scan_id]["status"] = "error"
        await queue.put({"type": "error", "scan_id": scan_id,
                         "kind": "llm_unavailable",
                         "message": f"{exc.reason} The scan could not run. "
                                    "Nothing was written to scan history."})

    except Exception:
        logger.exception("Scan %s crashed", scan_id)
        _scans[scan_id]["status"] = "error"
        await queue.put({"type": "error", "scan_id": scan_id,
                         "kind": "internal",
                         "message": "Scan failed due to an internal error. See server logs."})

    finally:
        cleanup_repo(scan_id)  # remove cloned repo, if any
        await queue.put(None)  # sentinel — unblocks the WebSocket reader


# ══════════════════════════════════════════════════════════════
#  REST endpoints
# ══════════════════════════════════════════════════════════════

@app.post("/api/scan", response_model=ScanResponse, status_code=201)
async def start_scan(req: ScanRequest) -> ScanResponse:
    active = sum(1 for s in _scans.values() if s["status"] not in ("done", "error"))
    if active >= MAX_CONCURRENT_SCANS:
        raise HTTPException(status_code=429,
                            detail=f"Too many scans in progress ({active}/{MAX_CONCURRENT_SCANS}) — try again shortly")

    try:
        # Resolve in a thread — getaddrinfo blocks
        await asyncio.get_running_loop().run_in_executor(None, assert_safe_target, req.repo_url)
    except UnsafeTargetError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    scan_id = str(uuid.uuid4())[:8]
    _scans[scan_id] = {
        "queue": asyncio.Queue(),
        "report": None,
        "status": "starting",
        "repo_url": req.repo_url,
        "started_at": time.time(),
    }
    asyncio.create_task(_run_scan(req.repo_url, scan_id,
                                  create_pr=req.create_pr,
                                  target_hint=req.target_hint))
    logger.info("Scan %s started for %s", scan_id, req.repo_url)
    return ScanResponse(scan_id=scan_id, ws_url=f"/ws/{scan_id}", status="starting")


@app.get("/api/report/{scan_id}")
async def get_report(scan_id: str) -> dict:
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["status"] in ("starting", "scanning", "analyzing", "exploiting", "patching", "reporting"):
        raise HTTPException(status_code=202, detail=f"Scan in progress: {scan['status']}")
    if scan["status"] == "error":
        raise HTTPException(status_code=500, detail="Scan failed — check WebSocket logs")
    return scan["report"]


@app.get("/api/scans", response_model=list[ScanSummary])
async def list_scans() -> list[ScanSummary]:
    return [
        ScanSummary(
            scan_id=sid,
            repo_url=data["repo_url"],
            status=data["status"],
            started_at=data["started_at"],
        )
        for sid, data in sorted(_scans.items(), key=lambda x: x[1]["started_at"], reverse=True)
    ]


@app.get("/api/scans/history")
async def list_scan_history() -> list[dict]:
    """Return all completed scans from history, newest first. Trashed scans are excluded."""
    return _visible_history()


@app.get("/api/scans/history/domains")
async def list_history_domains() -> list[dict]:
    """Return one summary entry per unique domain, newest scan first."""
    records = _visible_history()
    seen: dict[str, dict] = {}
    for r in records:                          # records are newest-first
        d = r.get("domain", r.get("repo_url", ""))
        if d not in seen:
            seen[d] = {
                "domain":       d,
                "latest_scan":  r,
                "scan_count":   0,
                "scans":        [],
            }
        seen[d]["scan_count"] += 1
        seen[d]["scans"].append({
            "scan_id":    r["scan_id"],
            "timestamp":  r["timestamp"],
            "scan_date":  r["scan_date"],
            "risk_score": r["risk_score"],
            "overall_risk": r["overall_risk"],
            "total_vulns":  r["total_vulns"],
            "severity":     r["severity"],
        })
    return list(seen.values())


@app.get("/api/scans/history/domain/{domain:path}")
async def get_domain_history(domain: str) -> list[dict]:
    """Return all scans for one domain, newest first (full records)."""
    records = _visible_history()
    result = [r for r in records if r.get("domain", "") == domain]
    if not result:
        raise HTTPException(status_code=404, detail="No scans found for this domain")
    return result


@app.get("/api/scans/history/compare/{scan_a}/{scan_b}")
async def compare_scans(scan_a: str, scan_b: str) -> dict:
    """Compare two scans (scan_a = older, scan_b = newer)."""
    records = _visible_history()
    by_id = {r["scan_id"]: r for r in records}
    a = by_id.get(scan_a)
    b = by_id.get(scan_b)
    if not a or not b:
        raise HTTPException(status_code=404, detail="One or both scans not found")

    ids_a = {v["id"] for v in a.get("vulnerabilities", []) if "id" in v}
    ids_b = {v["id"] for v in b.get("vulnerabilities", []) if "id" in v}

    # Fallback: match by (file, line, category) if IDs differ across scans
    def _key(v: dict) -> str:
        return f"{v.get('file','')}:{v.get('line','')}:{v.get('category','')}"
    keys_a = {_key(v) for v in a.get("vulnerabilities", [])}
    keys_b = {_key(v) for v in b.get("vulnerabilities", [])}

    fixed_ids   = ids_a - ids_b
    new_ids     = ids_b - ids_a
    fixed_keys  = keys_a - keys_b
    new_keys    = keys_b - keys_a

    score_delta = b["risk_score"] - a["risk_score"]
    vuln_delta  = b["total_vulns"] - a["total_vulns"]

    return {
        "scan_a":        {"scan_id": scan_a, "timestamp": a["timestamp"], "scan_date": a["scan_date"],
                          "risk_score": a["risk_score"], "overall_risk": a["overall_risk"],
                          "total_vulns": a["total_vulns"], "severity": a["severity"]},
        "scan_b":        {"scan_id": scan_b, "timestamp": b["timestamp"], "scan_date": b["scan_date"],
                          "risk_score": b["risk_score"], "overall_risk": b["overall_risk"],
                          "total_vulns": b["total_vulns"], "severity": b["severity"]},
        "score_delta":   score_delta,          # negative = improvement
        "vuln_delta":    vuln_delta,
        "fixed_count":   len(fixed_keys),
        "new_count":     len(new_keys),
        "fixed_vulns":   [v for v in a.get("vulnerabilities", []) if _key(v) in fixed_keys],
        "new_vulns":     [v for v in b.get("vulnerabilities", []) if _key(v) in new_keys],
    }


@app.get("/api/scans/history/{scan_id}")
async def get_scan_history(scan_id: str) -> dict:
    """Return full details of one historical scan."""
    for record in _visible_history():
        if record.get("scan_id") == scan_id:
            return record
    raise HTTPException(status_code=404, detail="Scan not found in history")


@app.delete("/api/scans/history/{scan_id}")
async def delete_scan_history(scan_id: str) -> dict:
    """
    Reversible delete. The scan leaves every listing immediately but its data
    is retained until the trash window expires, so this reports `partial`
    rather than `complete`. Purge is what erases it.
    """
    return await _lifecycle_op(_retention.trash, scan_id)


# ══════════════════════════════════════════════════════════════
#  Retention / data lifecycle
# ══════════════════════════════════════════════════════════════

class HoldRequest(BaseModel):
    reason: str = Field(default="", max_length=500)


async def _lifecycle_op(fn, *args, **kwargs) -> dict:
    """Run one lifecycle operation under the history lock and return its receipt."""
    async with _history_lock:
        try:
            receipt = fn(*args, **kwargs)
        except rt.RetentionError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
    return receipt.as_dict()


@app.get("/api/retention/policy")
async def retention_policy() -> dict:
    """The active retention schedule and how many scans sit in each state."""
    inv = _retention.inventory()
    return {
        "policy": inv["policy"],
        "counts": inv["counts"],
        "held": inv["held"],
        "with_residue": inv["with_residue"],
        "total": inv["total"],
        "archive_files": inv["archive_files"],
        "archive_bytes": inv["archive_bytes"],
        "audit": _retention.ledger.verify(),
    }


@app.get("/api/retention/scans")
async def retention_inventory(state: str | None = None) -> dict:
    """Every scan with its lifecycle state, hold, residue and next due action."""
    states = tuple(s.strip() for s in state.split(",")) if state else rt.ALL_STATES
    return _retention.inventory(include_states=states)


@app.post("/api/retention/scans/{scan_id}/archive")
async def retention_archive(scan_id: str) -> dict:
    return await _lifecycle_op(_retention.archive, scan_id)


@app.post("/api/retention/scans/{scan_id}/restore")
async def retention_restore(scan_id: str) -> dict:
    return await _lifecycle_op(_retention.restore, scan_id)


@app.post("/api/retention/scans/{scan_id}/trash")
async def retention_trash(scan_id: str) -> dict:
    return await _lifecycle_op(_retention.trash, scan_id)


@app.post("/api/retention/scans/{scan_id}/purge")
async def retention_purge(scan_id: str, mode: str | None = None) -> dict:
    """
    Irreversible erasure. mode=full removes everything; mode=payload erases the
    findings but keeps the score row so the site's risk trend stays continuous.
    """
    if mode is not None and mode not in (rt.PURGE_FULL, rt.PURGE_PAYLOAD):
        raise HTTPException(status_code=422,
                            detail=f"mode must be {rt.PURGE_FULL} or {rt.PURGE_PAYLOAD}")
    return await _lifecycle_op(_retention.purge, scan_id, mode)


@app.post("/api/retention/scans/{scan_id}/hold")
async def retention_place_hold(scan_id: str, req: HoldRequest) -> dict:
    """Put the scan beyond reach of every destructive operation."""
    return await _lifecycle_op(_retention.place_hold, scan_id, req.reason)


@app.delete("/api/retention/scans/{scan_id}/hold")
async def retention_release_hold(scan_id: str) -> dict:
    return await _lifecycle_op(_retention.release_hold, scan_id)


@app.get("/api/retention/scans/{scan_id}/verify")
async def retention_verify(scan_id: str) -> dict:
    """
    Re-check every store for this scan and report what is actually there.
    This answers the ledger with evidence rather than trusting it.
    """
    return _retention.verify(scan_id)


@app.post("/api/retention/sweep")
async def retention_sweep(dry_run: bool = True, as_of: float | None = None) -> dict:
    """
    Apply the retention policy. Defaults to a dry run; `as_of` evaluates the
    schedule at a future timestamp so the whole plan can be seen at once.
    """
    if dry_run:
        return _retention.sweep(as_of=as_of, dry_run=True)
    async with _history_lock:
        return _retention.sweep(as_of=as_of, dry_run=False)


@app.get("/api/retention/audit")
async def retention_audit(limit: int = 100, scan_id: str | None = None) -> dict:
    """The hash-chained ledger of every lifecycle operation, newest first."""
    return {
        "verification": _retention.ledger.verify(),
        "entries": _retention.ledger.read(limit=limit, scan_id=scan_id),
    }


# ══════════════════════════════════════════════════════════════
#  OSIRIS OSINT enrichment
# ══════════════════════════════════════════════════════════════
#
# The browser cannot call OSIRIS directly — it sends no CORS headers — and
# routing the lookup through here keeps scan targets off the client. Nothing is
# sent to OSIRIS until an analyst asks for a specific finding: these routes are
# only reached by a click on a report.


@app.get("/api/osiris/ip/{ip}")
async def osiris_ip(ip: str) -> dict:
    """Passive OSINT for one address: geolocation, ASN, reputation, exposure."""
    try:
        return await asyncio.to_thread(osiris.ip_intel, ip)
    except osiris.OsirisDisabledError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/osiris/cve/{cve_id}")
async def osiris_cve(cve_id: str) -> dict:
    """The upstream record for one CVE id, or found=false if nothing carries it."""
    try:
        return await asyncio.to_thread(osiris.cve_record, cve_id)
    except osiris.OsirisDisabledError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/llm/status")
async def llm_status() -> dict:
    """
    Multi-provider LLM health (prompt 00a): per-provider configuration,
    per-model state (ok / cooldown / disabled + reason) and the remaining
    OpenRouter free budget. Never contains key material.
    """
    from agents.llm_router import get_llm_status
    return get_llm_status()


@app.get("/health")
async def health() -> dict:
    from agents.llm_router import get_active_backend, get_system_profile
    return {
        "status": "ok",
        "version": app.version,
        "llm_backend": get_active_backend(),
        "osiris_enabled": osiris.is_enabled(),
        "system_profile": get_system_profile(),
        "active_scans": sum(1 for s in _scans.values() if s["status"] not in ("done", "error")),
        "active_exam_sessions": sum(
            1 for e in _exam_sessions.values() if e["session"]["status"] == "active"
        ),
    }


# ══════════════════════════════════════════════════════════════
#  WebSocket endpoint
# ══════════════════════════════════════════════════════════════

PING_INTERVAL = 30.0   # seconds between keepalive pings
WS_TIMEOUT    = 600.0  # max seconds to wait for a queue message before giving up

@app.websocket("/ws/{scan_id}")
async def ws_scan_feed(websocket: WebSocket, scan_id: str) -> None:
    if scan_id not in _scans:
        await websocket.close(code=4004, reason="Scan not found")
        return

    await websocket.accept()
    logger.info("WS client connected for scan %s", scan_id)

    queue: asyncio.Queue = _scans[scan_id]["queue"]
    deadline = time.monotonic() + WS_TIMEOUT

    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                logger.warning("Scan %s timed out", scan_id)
                await websocket.send_json({"type": "error", "message": "Scan timed out", "scan_id": scan_id})
                break

            try:
                msg = await asyncio.wait_for(queue.get(), timeout=min(PING_INTERVAL, remaining))
            except asyncio.TimeoutError:
                # Send a keepalive so the browser doesn't drop the connection
                await websocket.send_json({"type": "ping"})
                continue

            if msg is None:
                # Sentinel from the background task — scan finished or errored
                break

            await websocket.send_json(msg)

            if msg.get("type") in ("done", "error"):
                break

    except WebSocketDisconnect:
        logger.info("WS client disconnected from scan %s", scan_id)
    except Exception as exc:
        logger.error("WS error for scan %s: %s", scan_id, exc)
    finally:
        await _close_quietly(websocket, f"scan {scan_id}")
        logger.info("WS connection closed for scan %s", scan_id)


# ══════════════════════════════════════════════════════════════
#  ExamGuard — Pydantic models
# ══════════════════════════════════════════════════════════════

class ExamSessionRequest(BaseModel):
    student_id:       str = Field(min_length=1, max_length=100)
    student_name:     str = Field(min_length=1, max_length=200)
    exam_name:        str = Field(min_length=1, max_length=200)
    duration_minutes: int = Field(default=60, ge=1, le=600)


class ExamSessionResponse(BaseModel):
    exam_id:    str
    ws_url:     str
    status:     str


class ExamSessionSummary(BaseModel):
    exam_id:      str
    student_name: str
    exam_name:    str
    status:       str
    started_at:   float


# ══════════════════════════════════════════════════════════════
#  ExamGuard — REST endpoints
# ══════════════════════════════════════════════════════════════

@app.post("/api/exam/session", response_model=ExamSessionResponse, status_code=201)
async def create_exam_session(req: ExamSessionRequest) -> ExamSessionResponse:
    exam_id = str(uuid.uuid4())[:8]
    now     = time.time()

    session: ExamSession = ExamSession(
        exam_id=exam_id,
        student_id=req.student_id,
        student_name=req.student_name,
        exam_name=req.exam_name,
        duration_minutes=req.duration_minutes,
        started_at=now,
        ended_at=None,
        tab_events=[],
        face_events=[],
        keystroke_stats=None,
        copy_paste_events=[],
        immediate_alerts=[],
        behavior_flags=[],
        anomaly_scores=[],
        alerts=[],
        integrity_score=100.0,
        verdict="CLEAN",
        report={},
        status="active",
        errors=[],
        agent_logs=[f"[SessionMonitor] Session {exam_id} created for {req.student_name}"],
    )

    _exam_sessions[exam_id] = {
        "session":        session,
        "analysis_queue": asyncio.Queue(),
        "monitor_queues": [],     # fan-out queues for invigilator monitor connections
        "absent_since":   None,   # tracks continuous face-absent window
        "started_at":     now,
    }

    logger.info("Exam session %s created for student %s", exam_id, req.student_id)
    return ExamSessionResponse(exam_id=exam_id, ws_url=f"/ws/exam/{exam_id}", status="active")


@app.get("/api/exam/session/{exam_id}")
async def get_exam_session(exam_id: str) -> dict:
    entry = _exam_sessions.get(exam_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Exam session not found")
    s = entry["session"]
    return {
        "exam_id":          exam_id,
        "student_name":     s["student_name"],
        "exam_name":        s["exam_name"],
        "duration_minutes": s["duration_minutes"],
        "status":           s["status"],
    }


@app.post("/api/exam/{exam_id}/analyze", status_code=202)
async def trigger_analysis(exam_id: str) -> dict:
    entry = _exam_sessions.get(exam_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Exam session not found")

    session = entry["session"]
    if session["status"] == "analyzing":
        # Analysis already running — don't spawn a duplicate pipeline
        return {"exam_id": exam_id, "status": "analyzing", "ws_url": f"/ws/exam/{exam_id}/analysis"}

    if session["status"] == "active":
        session["status"]   = "ended"
        session["ended_at"] = time.time()

    session["status"] = "analyzing"
    asyncio.create_task(_run_exam_analysis(exam_id))
    return {"exam_id": exam_id, "status": "analyzing", "ws_url": f"/ws/exam/{exam_id}/analysis"}


@app.get("/api/exam/report/{exam_id}")
async def get_exam_report(exam_id: str) -> dict:
    entry = _exam_sessions.get(exam_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Exam session not found")
    session = entry["session"]
    if session["status"] in ("active", "ended", "analyzing"):
        raise HTTPException(status_code=202, detail=f"Analysis in progress: {session['status']}")
    if session["status"] == "error":
        raise HTTPException(status_code=500, detail="Analysis failed")
    return session["report"]


@app.get("/api/exam/sessions", response_model=list[ExamSessionSummary])
async def list_exam_sessions() -> list[ExamSessionSummary]:
    return [
        ExamSessionSummary(
            exam_id=eid,
            student_name=e["session"]["student_name"],
            exam_name=e["session"]["exam_name"],
            status=e["session"]["status"],
            started_at=e["started_at"],
        )
        for eid, e in sorted(
            _exam_sessions.items(), key=lambda x: x[1]["started_at"], reverse=True
        )
    ]


# ══════════════════════════════════════════════════════════════
#  ExamGuard — background analysis task
# ══════════════════════════════════════════════════════════════

async def _run_exam_analysis(exam_id: str) -> None:
    entry   = _exam_sessions[exam_id]
    session = entry["session"]
    queue   = entry["analysis_queue"]

    try:
        config      = {"configurable": {"thread_id": exam_id}}
        accumulated: dict = {}

        async with asyncio.timeout(ANALYSIS_TIMEOUT_SECS):
            async for event in _exam_graph.astream(session, config=config):
                node_name, node_output = next(iter(event.items()))

                # Accumulate full node output so report/score/verdict are captured
                for k, v in node_output.items():
                    if k == "agent_logs":
                        accumulated.setdefault("agent_logs", [])
                        accumulated["agent_logs"].extend(v if isinstance(v, list) else [v])
                    else:
                        accumulated[k] = v

                await queue.put({
                    "type":    "analysis_update",
                    "node":    node_name,
                    "logs":    node_output.get("agent_logs", []),
                    "status":  node_output.get("status", ""),
                    "exam_id": exam_id,
                })

        # Persist final state back into the live session object
        for field in ("report", "verdict", "integrity_score", "behavior_flags",
                      "anomaly_scores", "alerts"):
            if field in accumulated:
                session[field] = accumulated[field]

        session["status"] = "done"
        await queue.put({
            "type":    "done",
            "exam_id": exam_id,
            "report":  session["report"],
        })

    except TimeoutError:
        logger.error("Exam analysis %s exceeded %ss timeout", exam_id, ANALYSIS_TIMEOUT_SECS)
        session["status"] = "error"
        await queue.put({"type": "error", "exam_id": exam_id,
                         "message": f"Analysis timed out after {int(ANALYSIS_TIMEOUT_SECS)}s"})

    except Exception:
        logger.exception("Exam analysis %s crashed", exam_id)
        session["status"] = "error"
        await queue.put({"type": "error", "exam_id": exam_id,
                         "message": "Analysis failed due to an internal error — see server logs"})

    finally:
        await queue.put(None)


async def _fan_out(entry: dict, msg: dict) -> None:
    """Push a message to all connected invigilator monitor queues."""
    for q in list(entry["monitor_queues"]):
        await q.put(msg)


# ══════════════════════════════════════════════════════════════
#  ExamGuard — bidirectional event WebSocket
#  Browser sends events; server applies rule checks and sends
#  immediate alerts back in real-time.
# ══════════════════════════════════════════════════════════════

def _append_capped(lst: list, item: dict) -> None:
    """Append an event, dropping the oldest beyond MAX_EVENTS_PER_LIST."""
    lst.append(item)
    if len(lst) > MAX_EVENTS_PER_LIST:
        del lst[: len(lst) - MAX_EVENTS_PER_LIST]


@app.websocket("/ws/exam/{exam_id}")
async def ws_exam_events(websocket: WebSocket, exam_id: str) -> None:
    entry = _exam_sessions.get(exam_id)
    if not entry:
        await websocket.close(code=4004, reason="Exam session not found")
        return
    if entry["session"]["status"] != "active":
        await websocket.close(code=4003, reason="Exam session is no longer active")
        return

    await websocket.accept()
    session: ExamSession = entry["session"]
    logger.info("Exam event WS connected for session %s", exam_id)

    try:
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_json(), timeout=PING_INTERVAL)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
                # Check for prolonged face absence even with no new events
                if entry["absent_since"] is not None:
                    alert = check_absence_duration(entry["absent_since"])
                    if alert:
                        await websocket.send_json(alert)
                        session["immediate_alerts"].append(alert)
                continue

            event_type = data.get("type")

            # ── Tab events ───────────────────────────────────
            if event_type == "tab_event":
                _append_capped(session["tab_events"], data)
                blur_count = sum(
                    1 for e in session["tab_events"]
                    if e.get("event_type") in ("blur", "hidden")
                )
                alert = check_tab_event(blur_count, data.get("timestamp", time.time()))
                if alert:
                    await websocket.send_json(alert)
                    session["immediate_alerts"].append(alert)
                    await _fan_out(entry, alert)

            # ── Face events ──────────────────────────────────
            elif event_type == "face_event":
                _append_capped(session["face_events"], data)
                face_count = data.get("face_count", 1)
                confidence = data.get("confidence", 1.0)
                ts         = data.get("timestamp", time.time())

                if face_count == 0:
                    if entry["absent_since"] is None:
                        entry["absent_since"] = ts
                    else:
                        alert = check_absence_duration(entry["absent_since"], ts)
                        if alert:
                            await websocket.send_json(alert)
                            session["immediate_alerts"].append(alert)
                            await _fan_out(entry, alert)
                else:
                    entry["absent_since"] = None   # face back in frame

                alert = check_face_event(face_count, confidence, ts)
                if alert:
                    await websocket.send_json(alert)
                    session["immediate_alerts"].append(alert)
                    await _fan_out(entry, alert)

            # ── Keystroke stats ──────────────────────────────
            elif event_type == "keystroke_stats":
                session["keystroke_stats"] = data

            # ── Copy-paste ───────────────────────────────────
            elif event_type == "copy_paste":
                _append_capped(session["copy_paste_events"], data)
                count = len(session["copy_paste_events"])
                alert = check_copy_paste(count, data.get("timestamp", time.time()))
                if alert:
                    await websocket.send_json(alert)
                    session["immediate_alerts"].append(alert)
                    await _fan_out(entry, alert)

            # ── Phone detection (client-side coco-ssd) ───────
            elif event_type == "phone_detected":
                _append_capped(session.setdefault("phone_events", []), data)
                phone_count = len(session["phone_events"])
                confidence  = data.get("confidence", 0.0)
                alert = check_phone_detected(phone_count, confidence, data.get("timestamp", time.time()))
                if alert:
                    await websocket.send_json(alert)
                    session["immediate_alerts"].append(alert)
                    await _fan_out(entry, alert)

            # ── Trust score update (client-computed, browser-side) ──
            elif event_type == "trust_update":
                # Persist the latest snapshot and fan out to both the
                # per-exam monitor and the class-wide dashboard.
                payload = {
                    "type":         "trust_update",
                    "exam_id":      exam_id,
                    "student_id":   data.get("student_id", exam_id),
                    "student_name": data.get("student_name") or session["student_name"],
                    "exam_name":    data.get("exam_name") or session["exam_name"],
                    "score":        data.get("score", 100),
                    "status":       data.get("status", "clean"),
                    "counts":       data.get("counts", {}),
                    "flagged":      data.get("flagged", False),
                    "terminated":   data.get("terminated", False),
                    "recent":       data.get("recent", []),
                    "timestamp":    data.get("timestamp", time.time()),
                }
                session["integrity_score"] = payload["score"]
                _latest_trust[exam_id] = payload
                await _fan_out(entry, payload)
                await _broadcast_global(payload)

            # ── End exam ─────────────────────────────────────
            elif event_type == "end_exam":
                session["status"]   = "ended"
                session["ended_at"] = time.time()
                ended_msg = {
                    "type":    "exam_ended",
                    "exam_id": exam_id,
                    "message": "Exam ended. Run POST /api/exam/{exam_id}/analyze to generate the integrity report.",
                }
                await websocket.send_json(ended_msg)
                await _fan_out(entry, ended_msg)
                await _broadcast_global({**ended_msg, "student_id": exam_id})
                break

            # ── Keepalive ────────────────────────────────────
            elif event_type == "ping":
                await websocket.send_json({"type": "pong"})

    except WebSocketDisconnect:
        logger.info("Exam event WS disconnected for %s", exam_id)
    except Exception:
        logger.exception("Exam event WS error for %s", exam_id)
        try:
            await websocket.send_json({"type": "error", "message": "Internal error processing exam events"})
        except Exception:
            logger.debug("Could not deliver the error frame for exam %s", exam_id, exc_info=True)
    finally:
        await _close_quietly(websocket, f"exam events {exam_id}")


# ══════════════════════════════════════════════════════════════
#  ExamGuard — invigilator monitor WebSocket
#  One-directional: server fans out immediate alerts and
#  exam_ended events to the invigilator dashboard in real-time.
# ══════════════════════════════════════════════════════════════

@app.websocket("/ws/exam/{exam_id}/monitor")
async def ws_exam_monitor(websocket: WebSocket, exam_id: str) -> None:
    entry = _exam_sessions.get(exam_id)
    if not entry:
        await websocket.close(code=4004, reason="Exam session not found")
        return

    await websocket.accept()
    q: asyncio.Queue = asyncio.Queue()
    entry["monitor_queues"].append(q)
    logger.info("Monitor WS connected for exam %s", exam_id)

    try:
        while True:
            try:
                msg = await asyncio.wait_for(q.get(), timeout=PING_INTERVAL)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
                continue

            if msg is None:
                break

            await websocket.send_json(msg)

    except WebSocketDisconnect:
        logger.info("Monitor WS disconnected for exam %s", exam_id)
    except Exception as exc:
        logger.error("Monitor WS error for exam %s: %s", exam_id, exc)
    finally:
        if q in entry["monitor_queues"]:
            entry["monitor_queues"].remove(q)
        await _close_quietly(websocket, f"exam monitor {exam_id}")


# ══════════════════════════════════════════════════════════════
#  ExamGuard — class-wide monitor WebSocket
#  One-directional: streams trust_update + exam_ended for EVERY
#  active session to the host's multi-student dashboard.
# ══════════════════════════════════════════════════════════════

@app.websocket("/ws/exam/monitor/all")
async def ws_exam_monitor_all(websocket: WebSocket) -> None:
    await websocket.accept()
    q: asyncio.Queue = asyncio.Queue()
    _global_monitor_queues.append(q)
    logger.info("Class-wide monitor WS connected (%d total)", len(_global_monitor_queues))

    # Replay the latest snapshot for every student so a dashboard that joins
    # mid-exam is immediately populated.
    try:
        for snapshot in list(_latest_trust.values()):
            await websocket.send_json(snapshot)
    except Exception:
        # The dashboard stays blank until the next live event, which looks like
        # "no students connected". Worth a warning rather than nothing.
        logger.warning("Could not replay trust snapshots to a new dashboard", exc_info=True)

    try:
        while True:
            try:
                msg = await asyncio.wait_for(q.get(), timeout=PING_INTERVAL)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
                continue
            if msg is None:
                break
            await websocket.send_json(msg)

    except WebSocketDisconnect:
        logger.info("Class-wide monitor WS disconnected")
    except Exception as exc:
        logger.error("Class-wide monitor WS error: %s", exc)
    finally:
        if q in _global_monitor_queues:
            _global_monitor_queues.remove(q)
        await _close_quietly(websocket, "class-wide monitor")


# ══════════════════════════════════════════════════════════════
#  ExamGuard — analysis progress WebSocket
#  One-directional: server streams LangGraph node progress
#  to the invigilator dashboard after analysis is triggered.
# ══════════════════════════════════════════════════════════════

@app.websocket("/ws/exam/{exam_id}/analysis")
async def ws_exam_analysis(websocket: WebSocket, exam_id: str) -> None:
    entry = _exam_sessions.get(exam_id)
    if not entry:
        await websocket.close(code=4004, reason="Exam session not found")
        return

    await websocket.accept()
    queue: asyncio.Queue = entry["analysis_queue"]
    deadline = time.monotonic() + WS_TIMEOUT

    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                await websocket.send_json({"type": "error", "message": "Analysis timed out"})
                break

            try:
                msg = await asyncio.wait_for(queue.get(), timeout=min(PING_INTERVAL, remaining))
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
                continue

            if msg is None:
                break

            await websocket.send_json(msg)

            if msg.get("type") in ("done", "error"):
                break

    except WebSocketDisconnect:
        logger.info("Analysis WS disconnected for exam %s", exam_id)
    finally:
        await _close_quietly(websocket, f"exam analysis {exam_id}")
