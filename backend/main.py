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
import re
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, List, Optional

from dotenv import load_dotenv
# Tests set SENTINEL_DISABLE_DOTENV so a developer's real keys never turn
# unit tests into live (paid) provider calls.
if not os.getenv("SENTINEL_DISABLE_DOTENV"):
    load_dotenv()

from fastapi import (FastAPI, Header, HTTPException, Response, WebSocket,
                     WebSocketDisconnect)
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from agents.orchestrator import _graph, _initial_state
from agents.llm_router import LLMUnavailableError
from tools.url_guard import assert_safe_target, UnsafeTargetError
from tools.git_cloner import cleanup_repo, _repo_dest
from tools import retention as rt
from tools import osiris
from tools import scan_store as ss
from tools.scan_store import ScanStore
from exam_agents.exam_pipeline import _exam_graph, stream_exam_analysis
from exam_agents.exam_state import ExamSession
from exam_agents.event_rules import (
    check_copy_paste,
    check_face_event,
    check_tab_event,
    check_absence_duration,
    check_phone_detected,
)

def configure_logging(log_dir: str | Path | None = None) -> Path:
    """Console + persistent file logging with timestamps and PID.

    The file log (gitignored backend/logs/) survives console loss and
    worker restarts, so a vanished in-memory scan can still be diagnosed.
    Never log secrets here: callers must pass ids/counts only.
    """
    from logging.handlers import RotatingFileHandler
    from tools.log_safety import RedactingFilter, RedactingFormatter

    if log_dir:
        log_path = Path(log_dir)
    elif os.getenv("SENTINEL_LOG_DIR"):
        log_path = Path(os.environ["SENTINEL_LOG_DIR"])
    else:
        log_path = Path(__file__).resolve().parent / "logs"
    log_path.mkdir(parents=True, exist_ok=True)
    fmt = RedactingFormatter(
        "%(asctime)s pid=%(process)d %(levelname)s %(name)s %(message)s")
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    if not any(getattr(h, "_sentinel_console", False) for h in root.handlers):
        console = logging.StreamHandler()
        console.setFormatter(fmt)
        console.addFilter(RedactingFilter())
        console._sentinel_console = True  # type: ignore[attr-defined]
        root.addHandler(console)
    marker = str(log_path / "sentinelai.log")
    if not any(getattr(h, "_sentinel_file", None) == marker
               for h in root.handlers):
        # Rotation bounds disk use (default 5 x 5 MB).
        fh = RotatingFileHandler(
            marker, encoding="utf-8",
            maxBytes=int(os.getenv("LOG_MAX_BYTES", str(5 * 1024 * 1024))),
            backupCount=int(os.getenv("LOG_BACKUP_COUNT", "5")))
        fh.setFormatter(fmt)
        fh.addFilter(RedactingFilter())
        fh._sentinel_file = marker  # type: ignore[attr-defined]
        root.addHandler(fh)
    return Path(marker)


configure_logging()
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
# Upper bound on graph steps (each retry adds coder→reviewer→tester), so a
# routing bug fails the scan instead of spinning.
GRAPH_RECURSION_LIMIT  = int(os.getenv("GRAPH_RECURSION_LIMIT", "60"))
# Seconds a client should wait before re-polling an unfinished report.
REPORT_RETRY_AFTER_SECS = int(os.getenv("REPORT_RETRY_AFTER_SECS", "3"))

# Phone detection runs client-side (coco-ssd in the browser); the browser
# sends a `phone_detected` event, handled below. No server-side ML needed.

# ── In-process registries ─────────────────────────────────────
# _scans holds only what cannot be persisted: live WebSocket subscribers and
# the in-process event buffer. The durable lifecycle (status, phase, error,
# report) lives in _store, so a restart or a second backend process can
# still answer for a scan instead of 404ing it (scan ebd4ddea).
_scans: Dict[str, dict] = {}           # VulnSentinel scan sessions
_exam_sessions: Dict[str, dict] = {}   # ExamGuard sessions
_store = ScanStore()
_background_tasks: set[asyncio.Task] = set()  # strong refs: no GC'd scans
HEARTBEAT_SECS = float(os.getenv("SCAN_HEARTBEAT_SECS", "15"))
_MAX_BUFFERED_EVENTS = 2000


def _new_session(repo_url: str) -> dict:
    return {
        "queue": None,          # legacy key; subscribers replace it
        "subscribers": set(),   # one asyncio.Queue per connected WS client
        "events": [],           # replay buffer for late/reconnecting clients
        "report": None,
        "status": "starting",
        "error": None,
        "repo_url": repo_url,
        "started_at": time.time(),
    }


async def _publish(scan_id: str, msg: dict | None) -> None:
    """Fan a message out to every WS subscriber; buffer + persist it.

    None is the end-of-stream sentinel. Previously one shared queue meant
    two tabs split the messages between them and a refreshed tab lost
    every earlier log line.
    """
    session = _scans.get(scan_id)
    if session is None:
        return
    if msg is not None:
        events = session.setdefault("events", [])
        events.append(msg)
        if len(events) > _MAX_BUFFERED_EVENTS:
            del events[: len(events) - _MAX_BUFFERED_EVENTS]
        if msg.get("type") == "update":
            _store.append_event(scan_id, msg)
    else:
        session["closed"] = True
    for q in list(session.get("subscribers", ())):
        await q.put(msg)


def _spawn(coro) -> asyncio.Task:
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task


async def _heartbeat(scan_id: str) -> None:
    """Keep the durable row fresh so other processes know we're alive."""
    while True:
        await asyncio.sleep(HEARTBEAT_SECS)
        try:
            _store.heartbeat(scan_id)
        except Exception:
            logger.warning("Heartbeat failed for %s", scan_id, exc_info=True)


def _report_summary(report: dict) -> dict:
    """Small summary kept on the run row (listing without loading reports)."""
    summary = report.get("summary") or {}
    remediation = report.get("remediation") or {}
    return {
        "total_findings": len(report.get("vulnerabilities") or []),
        "risk_score": summary.get("risk_score"),
        "overall_risk": summary.get("overall_risk"),
        "assessed": report.get("assessed", True),
        "remediation_status": remediation.get("status"),
        "test_verdict": remediation.get("test_verdict"),
        "pr_url": (remediation.get("pr") or {}).get("url")
                  or remediation.get("pr_url"),
    }

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
    logger.info("Serving graph nodes: %s (db=%s)", nodes, _store.db_path)
    # Runs whose process died (crash, --reload, kill) are marked interrupted
    # here — never left "running" forever, never reported as completed.
    recovered = _store.recover_stale()
    if recovered:
        logger.warning("Startup recovery: %d stale run(s) marked "
                       "interrupted: %s", len(recovered), recovered)
        # A crashed run never reached its `finally`; its clone and work
        # copies would otherwise stay in the temp dir indefinitely.
        for sid in recovered:
            cleanup_repo(sid)
    yield
    janitor.cancel()
    # Graceful shutdown: running scans are cancelled; their handlers record
    # the interruption durably before the process exits.
    for task in list(_background_tasks):
        task.cancel()
    if _background_tasks:
        await asyncio.gather(*_background_tasks, return_exceptions=True)
    _scans.clear()
    _exam_sessions.clear()


app = FastAPI(title="SentinelAI", version="1.0.0", lifespan=lifespan)

_default_origins = "http://localhost:3000,http://127.0.0.1:3000"
# ALLOWED_ORIGIN_REGEX is handy for Vercel preview URLs, e.g.
#   https://.*\.vercel\.app
_ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", _default_origins).split(",") if o.strip()]
_ALLOWED_ORIGIN_RE = re.compile(os.getenv("ALLOWED_ORIGIN_REGEX")) if os.getenv("ALLOWED_ORIGIN_REGEX") else None
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@app.middleware("http")
async def _reject_cross_site_writes(request, call_next):
    """CSRF guard. CORS only hides responses; a browser still SENDS a
    cross-site "simple" POST (form, no-cors fetch). Body-less endpoints
    such as retention purge executed that way. Browsers always attach
    Origin to cross-site writes, so a write from a non-allowed Origin is
    refused; requests without Origin (curl, server-side) are unaffected."""
    origin = request.headers.get("origin")
    if (request.method not in _SAFE_METHODS and origin
            and origin not in _ALLOWED_ORIGINS
            and not (_ALLOWED_ORIGIN_RE and _ALLOWED_ORIGIN_RE.fullmatch(origin))):
        logger.warning("Refused cross-site %s %s from origin %s",
                       request.method, request.url.path, origin)
        return JSONResponse(status_code=403,
                            content={"detail": "Cross-site request refused (origin not allowed)."})
    return await call_next(request)


app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
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
    # True when an identical request (same Idempotency-Key, or the same
    # repo/options already running) was answered with the existing run
    # instead of starting a second, separately billed one.
    deduplicated: bool = False


class ScanSummary(BaseModel):
    scan_id: str
    repo_url: str
    status: str
    started_at: float
    kind: str = "scan"
    phase: str = ""
    finished_at: Optional[float] = None
    error: Optional[str] = None


class RemediateRequest(BaseModel):
    scan_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_\-]+$")
    target_hint: Optional[str] = Field(default=None, max_length=32)
    # Explicit, separate consent for the remote write. False = generate,
    # review and Docker-verify the patch, but never push or open a PR.
    open_pr: bool = False


# ══════════════════════════════════════════════════════════════
#  Background task
# ══════════════════════════════════════════════════════════════

async def _run_scan(repo_url: str, scan_id: str, create_pr: bool = False,
                  target_hint: Optional[str] = None) -> None:
    accumulated: dict = {}
    _store.mark_running(scan_id, "orchestrator")
    _scans[scan_id]["status"] = "running"
    beat = asyncio.create_task(_heartbeat(scan_id))
    started = time.monotonic()
    node_name = "orchestrator"

    try:
        state = _initial_state(repo_url, scan_id, create_pr=create_pr,
                               target_hint=target_hint)
        config = {"configurable": {"thread_id": scan_id},
                  "recursion_limit": GRAPH_RECURSION_LIMIT}

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

                _store.update_phase(scan_id, node_name)
                await _publish(scan_id, {
                    "type": "update",
                    "node": node_name,
                    "logs": node_output.get("agent_logs", []),
                    "status": node_output.get("status", ""),
                    "scan_id": scan_id,
                })
                logger.info("Scan %s node %s status=%s (%d log lines, %.1fs)",
                            scan_id, node_name,
                            node_output.get("status", ""),
                            len(node_output.get("agent_logs", [])),
                            time.monotonic() - started)

        report = accumulated.get("report") or {}
        if not report:
            raise RuntimeError("graph finished without producing a report")
        # Durable first: a client that sees "done" can always fetch it.
        _store.complete(scan_id, report, _report_summary(report))
        _scans[scan_id]["report"] = report
        _scans[scan_id]["status"] = "done"
        await _publish(scan_id, {"type": "done", "scan_id": scan_id,
                                 "report": report})
        logger.info("Scan %s completed (%d findings, %.1fs)", scan_id,
                    len(report.get("vulnerabilities") or []),
                    time.monotonic() - started)

        # Persist to history only on successful completion
        await _append_scan_history(scan_id, repo_url, report, _scans[scan_id]["started_at"])

    except TimeoutError:
        logger.error("Scan %s exceeded %ss timeout in node %s", scan_id,
                     SCAN_TIMEOUT_SECS, node_name)
        await _fail_run(scan_id, f"Scan timed out after "
                                 f"{int(SCAN_TIMEOUT_SECS)}s", "timeout")

    except LLMUnavailableError as exc:
        # An operational fault, not a bug. Collapsing it into "internal error"
        # meant a dead API key and a crash in the pipeline looked identical from
        # the browser, and only the server logs could tell them apart.
        logger.error("Scan %s could not reach a language model: %s", scan_id, exc)
        await _fail_run(scan_id, f"{exc.reason} The scan could not run. "
                                 "Nothing was written to scan history.",
                        "llm_unavailable")

    except asyncio.CancelledError:
        logger.warning("Scan %s cancelled (backend shutting down) in node %s",
                       scan_id, node_name)
        await _fail_run(scan_id, "The backend shut down while this scan was "
                                 "running. It did not complete; start a new "
                                 "scan.", "interrupted",
                        status=ss.INTERRUPTED)
        raise

    except Exception:
        logger.exception("Scan %s crashed after node %s", scan_id, node_name)
        await _fail_run(scan_id, "Scan failed due to an internal error. "
                                 "See server logs.", "internal")

    finally:
        beat.cancel()
        cleanup_repo(scan_id)  # remove cloned repo, if any
        await _publish(scan_id, None)  # sentinel — unblocks WebSocket readers


async def _fail_run(scan_id: str, message: str, kind: str,
                    status: str = ss.FAILED) -> None:
    """Record a terminal failure durably, then tell live clients."""
    try:
        _store.fail(scan_id, message, kind, status=status)
    except Exception:
        logger.exception("Could not persist failure of %s", scan_id)
    session = _scans.get(scan_id)
    if session is not None:
        session["status"] = "error"
        session["error"] = message
    await _publish(scan_id, {"type": "error", "scan_id": scan_id,
                             "kind": kind, "message": message})


# ══════════════════════════════════════════════════════════════
#  REST endpoints
# ══════════════════════════════════════════════════════════════

def _enforce_capacity() -> None:
    """Scans and remediation runs share one cap: each holds LLM + Docker."""
    active = sum(1 for s in _scans.values() if s["status"] not in ("done", "error"))
    if active >= MAX_CONCURRENT_SCANS:
        raise HTTPException(
            status_code=429,
            detail=f"Too many runs in progress ({active}/{MAX_CONCURRENT_SCANS}) — try again shortly")


def _existing_run_response(rec: dict, response: Response) -> ScanResponse:
    response.status_code = 200
    return ScanResponse(scan_id=rec["scan_id"], ws_url=f"/ws/{rec['scan_id']}",
                        status=rec["status"], deduplicated=True)


@app.post("/api/scan", response_model=ScanResponse, status_code=201)
async def start_scan(
    req: ScanRequest,
    response: Response,
    idempotency_key: Optional[str] = Header(default=None, max_length=128),
) -> ScanResponse:
    _enforce_capacity()

    try:
        # Resolve in a thread — getaddrinfo blocks
        await asyncio.get_running_loop().run_in_executor(None, assert_safe_target, req.repo_url)
    except UnsafeTargetError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    # A double-click or a client retry must not start (and bill) a second
    # scan: the same Idempotency-Key, or an identical run still in flight,
    # returns the existing scan id with 200 instead of 201. The check and
    # the insert are one DB transaction, so it also holds across workers.
    scan_id = _new_run_id()
    # Re-checked after the DNS await above, with no await before the insert,
    # so concurrent distinct requests cannot all slip past the cap.
    _enforce_capacity()
    rec, created = _store.create_unless_duplicate(
        scan_id, repo_url=req.repo_url, create_pr=req.create_pr,
        target_hint=req.target_hint, idempotency_key=idempotency_key)
    if not created:
        logger.info("Scan request deduplicated -> existing run %s",
                    rec["scan_id"])
        return _existing_run_response(rec, response)
    _scans[scan_id] = _new_session(req.repo_url)
    _spawn(_run_scan(req.repo_url, scan_id,
                     create_pr=req.create_pr,
                     target_hint=req.target_hint))
    logger.info("Scan %s started for %s (create_pr=%s)", scan_id,
                req.repo_url, req.create_pr)
    return ScanResponse(scan_id=scan_id, ws_url=f"/ws/{scan_id}", status="starting")


def _new_run_id() -> str:
    """8 hex chars, re-drawn on the (rare) collision with a stored run."""
    for _ in range(10):
        candidate = uuid.uuid4().hex[:8]
        if candidate not in _scans and _store.get(candidate) is None:
            return candidate
    return uuid.uuid4().hex


async def _run_remediation_task(run_id: str, state: dict,
                                  entry_point: str = "secure_coder") -> None:
    """Stream the small remediation graph over the same WS format as scans."""
    from agents.remediation.loop import stream_remediation

    from agents.remediation.report import build_remediation_section

    if entry_point not in ("secure_coder", "reviewer", "tester", "pr_creator"):
        entry_point = "secure_coder"
    accumulated: dict = dict(state)
    _store.mark_running(run_id, entry_point)
    _scans[run_id]["status"] = "running"
    beat = asyncio.create_task(_heartbeat(run_id))
    node_name = entry_point
    try:
        resume_reason = state.get("_resume_reason")
        resume_source = state.get("_resume_source")
        if resume_reason and entry_point != "secure_coder":
            _store.update_phase(run_id, entry_point)
            await _publish(run_id, {
                "type": "update",
                "node": entry_point,
                "logs": [f"[Resume] {resume_reason}"],
                "status": "",
                "scan_id": run_id,
            })
            accumulated.setdefault("agent_logs", []).append(
                f"[Resume] {resume_reason}")
            logger.info("Remediation %s resuming at %s from %s", run_id,
                        entry_point, resume_source)
        async with asyncio.timeout(SCAN_TIMEOUT_SECS):
            async for node_name, node_output in stream_remediation(
                    state, run_id, entry_point):
                for key, value in node_output.items():
                    if key == "agent_logs":
                        accumulated.setdefault("agent_logs", [])
                        accumulated["agent_logs"].extend(value)
                    else:
                        accumulated[key] = value
                _store.update_phase(run_id, node_name)
                await _publish(run_id, {
                    "type": "update",
                    "node": node_name,
                    "logs": node_output.get("agent_logs", []),
                    "status": node_output.get("status", ""),
                    "scan_id": run_id,
                })
                logger.info("Remediation %s node %s (%d log lines)", run_id,
                            node_name, len(node_output.get("agent_logs", [])))

        remediation = build_remediation_section(accumulated)
        report = {
            "scan_id": run_id,
            "kind": "remediation",
            "parent_scan_id": state.get("parent_scan_id"),
            "repo_url": accumulated.get("repo_url", ""),
            "vulnerabilities": accumulated.get("vulnerabilities", []),
            "remediation": remediation,
        }
        _store.complete(run_id, report, _report_summary(report))
        _scans[run_id]["report"] = report
        _scans[run_id]["status"] = "done"
        await _publish(run_id, {"type": "done", "scan_id": run_id,
                                "report": report})
        logger.info("Remediation %s completed: outcome=%s verdict=%s",
                    run_id, remediation["outcome"],
                    remediation["test_verdict"])
    except TimeoutError:
        logger.error("Remediation %s exceeded %ss in node %s", run_id,
                     SCAN_TIMEOUT_SECS, node_name)
        await _fail_run(run_id, f"Remediation timed out after "
                                f"{int(SCAN_TIMEOUT_SECS)}s", "timeout")
    except LLMUnavailableError as exc:
        logger.error("Remediation %s: no language model: %s", run_id, exc)
        await _fail_run(run_id, f"{exc.reason} Remediation could not run.",
                        "llm_unavailable")
    except asyncio.CancelledError:
        await _fail_run(run_id, "The backend shut down while this "
                                "remediation was running. It did not "
                                "complete.", "interrupted",
                        status=ss.INTERRUPTED)
        raise
    except Exception:
        # Internal exception text stays in the server log, not the client.
        logger.exception("Remediation %s crashed after node %s", run_id,
                         node_name)
        await _fail_run(run_id, "Remediation failed due to an internal "
                                "error. See server logs.", "internal")
    finally:
        beat.cancel()
        cleanup_repo(run_id)
        await _publish(run_id, None)


@app.post("/api/remediate", response_model=ScanResponse, status_code=201)
async def start_remediation(req: RemediateRequest,
                            response: Response) -> ScanResponse:
    """Resume the remediation workflow from validated saved progress.

    Accepts either the original scan id (``d97e9820``) or an interrupted
    remediation attempt (``d97e9820-r1``): the snapshot always comes from
    the parent scan, while the resume entry (secure_coder / reviewer /
    tester / pr_creator) is decided from the newest validated prior
    attempt. Never restarts the full scan pipeline (no re-clone for
    analysis, no Semgrep/Bandit re-scan, no Orchestrator).
    """
    from agents.remediation.loop import fresh_remediation_state
    from agents.remediation.resume import (decide_resume, is_remediation_id,
                                           load_prior_progress, parent_id_for)
    from tools.run_artifacts import load_state_snapshot

    parent_id = parent_id_for(req.scan_id)
    try:
        snapshot = load_state_snapshot(parent_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404,
                            detail=f"No saved state for scan {req.scan_id}")
    if not snapshot.get("repo_url"):
        raise HTTPException(status_code=422,
                            detail="Snapshot has no repo_url")
    # One remediation of a given scan at a time: a second click returns the
    # run already in flight instead of paying for a duplicate LLM/Docker run.
    # The check is on the parent id so retrying from ``<id>-r1`` does not
    # start a duplicate ``<id>-r1-r1`` chain.
    for sid, session in _scans.items():
        if (sid.startswith(f"{parent_id}-r")
                and session["status"] not in ("done", "error")):
            response.status_code = 200
            return ScanResponse(scan_id=sid, ws_url=f"/ws/{sid}",
                                status="running", deduplicated=True)
    _enforce_capacity()
    n = 1
    while f"{parent_id}-r{n}" in _scans or _store.get(f"{parent_id}-r{n}"):
        n += 1
    run_id = f"{parent_id}-r{n}"
    state = fresh_remediation_state(snapshot, run_id,
                                    target_hint=req.target_hint)
    state["parent_scan_id"] = parent_id
    # create_pr comes from this explicit request only — never implied by the
    # original scan. Default False: verify the patch, open no PR.
    state["create_pr"] = True
    state["open_pr"] = bool(req.open_pr)
    # Resume from validated saved progress: the persisted phase may lag
    # behind the artifacts (e.g. phase secure_coder with review.json already
    # on disk), so the entry point comes from the artifacts, not the row.
    hint_run = req.scan_id if is_remediation_id(req.scan_id) else None
    prior = load_prior_progress(parent_id, hint_run_id=hint_run)
    decision = decide_resume(snapshot, prior, req.target_hint)
    entry_point = decision.get("resume_from") or "secure_coder"
    restored = decision.get("restored") or {}
    for key, value in restored.items():
        state[key] = value
    if entry_point != "secure_coder":
        state["_resume_reason"] = decision.get("reason", "")
        state["_resume_source"] = decision.get("source_run")
    _store.create(run_id, repo_url=snapshot.get("repo_url", ""),
                  kind="remediation", create_pr=bool(req.open_pr),
                  target_hint=req.target_hint, parent_scan_id=parent_id)
    # The durable phase shows the resumed entry immediately, so a client
    # that polls before the first node update sees Reviewer/Tester — never
    # a misleading Orchestrator/Scanner restart.
    _store.mark_running(run_id, entry_point)
    _scans[run_id] = _new_session(snapshot.get("repo_url", ""))
    _spawn(_run_remediation_task(run_id, state, entry_point))
    logger.info("Remediation %s started from scan %s (hint=%s, open_pr=%s, "
                "resume=%s from %s)",
                run_id, parent_id, req.target_hint, req.open_pr,
                entry_point, decision.get("source_run"))
    return ScanResponse(scan_id=run_id, ws_url=f"/ws/{run_id}", status="starting")


def _legacy_record(scan_id: str) -> dict | None:
    """Map an in-memory-only session (no durable row) onto the store shape."""
    scan = _scans.get(scan_id)
    if not scan:
        return None
    status = {"done": ss.COMPLETED, "error": ss.FAILED}.get(
        scan["status"], ss.RUNNING)
    return {"scan_id": scan_id, "status": status, "phase": scan["status"],
            "error": scan.get("error"), "error_kind": None,
            "_report": scan.get("report")}


@app.get("/api/report/{scan_id}")
async def get_report(scan_id: str):
    """Report contract (see README "Report states"):

    404 unknown id | 202 queued/running (+Retry-After) | 200 report when
    completed (zero findings is still a report) | 200 {"status":"error"}
    when failed | 200 {"status":"interrupted"} when the run's process died
    | 410 when a completed report was purged by retention.
    """
    rec = _store.get(scan_id) or _legacy_record(scan_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    status = rec["status"]
    if status in ss.ACTIVE:
        return JSONResponse(
            status_code=202,
            headers={"Retry-After": str(REPORT_RETRY_AFTER_SECS)},
            content={"status": "running", "phase": rec.get("phase", ""),
                     "detail": f"Scan in progress: {rec.get('phase') or status}"})
    if status == ss.FAILED:
        # Fail fast: a crashed node is visible here immediately with the
        # message, instead of hanging the caller on 202s.
        return {"status": "error",
                "detail": rec.get("error") or "Scan failed — check server logs"}
    if status in (ss.INTERRUPTED, ss.CANCELLED):
        return {"status": status,
                "detail": rec.get("error") or "The scan did not complete."}
    report = rec.get("_report") if "_report" in rec else _store.load_report(rec)
    if report is None:
        raise HTTPException(status_code=410,
                            detail="This scan completed, but its report is "
                                   "no longer stored (erased by retention).")
    return report


@app.get("/api/scans/{scan_id}/status")
async def get_scan_status(scan_id: str) -> dict:
    """Durable lifecycle record for one run (works after restarts)."""
    rec = _store.get(scan_id)
    if rec is None:
        legacy = _legacy_record(scan_id)
        if legacy is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        return {"scan_id": scan_id, "status": legacy["status"],
                "phase": legacy["phase"], "error": legacy["error"],
                "has_report": legacy["_report"] is not None}
    view = ss.public_view(rec)
    view["live"] = scan_id in _scans and not _scans[scan_id].get("closed")
    return view


@app.get("/api/scans/{scan_id}/events")
async def get_scan_events(scan_id: str) -> dict:
    """The agent log feed so far — lets a refreshed page rebuild its log."""
    if _store.get(scan_id) is None and scan_id not in _scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    session = _scans.get(scan_id)
    events = (list(session.get("events", [])) if session
              else _store.events(scan_id))
    return {"scan_id": scan_id,
            "events": [e for e in events if e.get("type") == "update"]}


@app.get("/api/scans/{scan_id}/artifacts/{name}")
async def get_scan_artifact(scan_id: str, name: str):
    """One persisted run artifact (patch.diff, review.json, test_*.json …)
    as plain text. Restricted to files directly inside runs/<scan_id>/."""
    from fastapi.responses import PlainTextResponse
    from agents.remediation.report import artifact_path
    if not _ARTIFACT_NAME_RE.fullmatch(name or ""):
        raise HTTPException(status_code=404, detail="Artifact not found")
    path = artifact_path(scan_id, name)
    if path is None:
        raise HTTPException(status_code=404, detail="Artifact not found")
    if os.path.getsize(path) > 2 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Artifact too large")
    with open(path, encoding="utf-8", errors="replace") as fh:
        return PlainTextResponse(fh.read(),
                                 headers={"X-Content-Type-Options": "nosniff"})


_ARTIFACT_NAME_RE = re.compile(
    r"[A-Za-z0-9_\-]+\.(diff|json|md|txt|py|jsonl)")


@app.get("/api/scans", response_model=list[ScanSummary])
async def list_scans(limit: int = 50, offset: int = 0) -> list[ScanSummary]:
    """Recent runs from the durable store (survives restarts), newest first."""
    limit = max(1, min(limit, 200))
    return [
        ScanSummary(scan_id=r["scan_id"], repo_url=r["repo_url"],
                    status=r["status"], started_at=r["created_at"],
                    kind=r["kind"], phase=r["phase"],
                    finished_at=r.get("finished_at"),
                    error=r.get("error"))
        for r in _store.list(limit=limit, offset=max(0, offset))
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
    receipt = await _lifecycle_op(_retention.purge, scan_id, mode)
    # The durable report copy (runs/<id>/report.json + event feed) holds the
    # same findings; leaving it would make /api/report a purge bypass.
    if receipt.get("outcome") in ("complete", "partial"):
        try:
            erased = _store.forget_report(scan_id)
        except OSError as exc:
            logger.error("Purge %s: durable report not erased: %s", scan_id, exc)
            receipt.setdefault("components", []).append({
                "component": "run_report", "outcome": rt.C_UNRESOLVED,
                "detail": "Stored run report could not be deleted."})
            receipt["outcome"] = "unresolved"
        else:
            receipt.setdefault("components", []).append({
                "component": "run_report",
                "outcome": rt.C_DONE if erased else rt.C_ABSENT,
                "detail": ("All stored run data erased (report, events, patch, review, test results, prompts, and remediation re-runs)."
                           if erased else "No stored run report existed.")})
    return receipt


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
# Max lifetime of one scan-feed socket: outlives the scan's own deadline.
WS_TIMEOUT    = SCAN_TIMEOUT_SECS + 120.0

@app.websocket("/ws/{scan_id}")
async def ws_scan_feed(websocket: WebSocket, scan_id: str) -> None:
    session = _scans.get(scan_id)
    if session is None:
        # Not running in this process. A finished run (even from before a
        # restart) is answered from the durable store so a refreshed page
        # still gets its result; anything else is closed with 4004 and the
        # client falls back to REST polling of /api/report.
        rec = _store.get(scan_id)
        if rec is None or rec["status"] in ss.ACTIVE:
            await websocket.close(code=4004, reason="Scan not live here")
            return
        await websocket.accept()
        try:
            for event in _store.events(scan_id):
                await websocket.send_json(event)
            if rec["status"] == ss.COMPLETED:
                report = _store.load_report(rec)
                if report is not None:
                    await websocket.send_json({"type": "done",
                                               "scan_id": scan_id,
                                               "report": report})
                else:
                    await websocket.send_json({
                        "type": "error", "scan_id": scan_id,
                        "kind": "report_unavailable",
                        "message": "The report is no longer stored."})
            else:
                await websocket.send_json({
                    "type": "error", "scan_id": scan_id,
                    "kind": rec.get("error_kind") or rec["status"],
                    "message": rec.get("error") or "The scan did not complete."})
        except WebSocketDisconnect:
            pass
        finally:
            await _close_quietly(websocket, f"scan {scan_id} (replay)")
        return

    await websocket.accept()
    logger.info("WS client connected for scan %s", scan_id)

    queue: asyncio.Queue = asyncio.Queue()
    # Replay what this client missed, then follow live. Snapshot + subscribe
    # happen with no await in between, so no message is lost or doubled.
    backlog = list(session.get("events", []))
    already_closed = session.get("closed", False)
    session.setdefault("subscribers", set()).add(queue)
    for event in backlog:
        await queue.put(event)
    if already_closed:
        await queue.put(None)
    deadline = time.monotonic() + WS_TIMEOUT

    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                # The socket's own lifetime ended, not the scan: never claim
                # the scan failed. The client re-checks /api/report.
                logger.warning("WS for scan %s hit its %ss lifetime", scan_id,
                               WS_TIMEOUT)
                await websocket.send_json({"type": "stream_timeout",
                                           "scan_id": scan_id})
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
        session.get("subscribers", set()).discard(queue)
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
