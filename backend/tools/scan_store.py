"""Durable scan/remediation run registry (SQLite).

The in-memory `_scans` dict in main.py dies with its process: after a
uvicorn --reload, a crash, or a request landing on a second backend
process, a known scan id answered 404 (scan ebd4ddea). This store is the
source of truth for a run's lifecycle; the in-memory registry only holds
live WebSocket subscribers.

Lifecycle:  queued → running → completed | failed | interrupted | cancelled

A running row carries a heartbeat. A row whose heartbeat is older than
STALE_AFTER_SECS is reported as `interrupted` (its process died) — never
as completed, and never left "running" forever. Recovery does not replay
anything: patch application and PR creation are never re-run blindly.

Large payloads (the report) live in runs/<scan_id>/report.json; the row
keeps a reference and a small summary. Agent log events go to
runs/<scan_id>/events.jsonl so a refreshed page can replay the feed.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

QUEUED = "queued"
RUNNING = "running"
COMPLETED = "completed"
FAILED = "failed"
INTERRUPTED = "interrupted"
CANCELLED = "cancelled"

ACTIVE = (QUEUED, RUNNING)
TERMINAL = (COMPLETED, FAILED, INTERRUPTED, CANCELLED)

REPORT_FILE = "report.json"
EVENTS_FILE = "events.jsonl"
_MAX_EVENTS = 5000

_SCHEMA_VERSION = 1
_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    scan_id        TEXT PRIMARY KEY,
    kind           TEXT NOT NULL DEFAULT 'scan',
    parent_scan_id TEXT,
    repo_url       TEXT NOT NULL DEFAULT '',
    create_pr      INTEGER NOT NULL DEFAULT 0,
    target_hint    TEXT,
    status         TEXT NOT NULL,
    phase          TEXT NOT NULL DEFAULT '',
    created_at     REAL NOT NULL,
    updated_at     REAL NOT NULL,
    heartbeat_at   REAL NOT NULL,
    finished_at    REAL,
    error          TEXT,
    error_kind     TEXT,
    report_path    TEXT,
    summary_json   TEXT,
    idempotency_key TEXT,
    owner_pid      INTEGER
);
CREATE INDEX IF NOT EXISTS runs_created ON runs(created_at DESC);
CREATE INDEX IF NOT EXISTS runs_idem ON runs(idempotency_key);
"""


def _stale_after() -> float:
    try:
        return max(30.0, float(os.getenv("SCAN_STALE_AFTER_SECS", "120")))
    except ValueError:
        return 120.0


def default_db_path() -> Path:
    env = os.getenv("SENTINEL_DB_PATH")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent.parent / "data" / "sentinel.db"


class ScanStore:
    """Thread-safe SQLite run registry. Every call opens a short transaction."""

    def __init__(self, db_path: str | Path | None = None,
                 runs_dir: str | Path | None = None):
        self.db_path = Path(db_path) if db_path else default_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if runs_dir is None:
            from tools.run_artifacts import _BASE
            runs_dir = _BASE
        self.runs_dir = Path(runs_dir)
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10,
                               check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def _exec(self, sql: str, params: tuple = ()) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(sql, params)

    def _run_dir(self, scan_id: str) -> Path:
        # scan ids are server-generated; still refuse anything path-like.
        if not scan_id or any(c in scan_id for c in "/\\.:") :
            raise ValueError(f"invalid scan id {scan_id!r}")
        path = self.runs_dir / scan_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    # ── writes ────────────────────────────────────────────────

    def create(self, scan_id: str, *, repo_url: str, kind: str = "scan",
               create_pr: bool = False, target_hint: str | None = None,
               parent_scan_id: str | None = None,
               idempotency_key: str | None = None) -> None:
        now = time.time()
        self._exec(
            "INSERT INTO runs (scan_id, kind, parent_scan_id, repo_url, "
            "create_pr, target_hint, status, phase, created_at, updated_at, "
            "heartbeat_at, idempotency_key, owner_pid) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (scan_id, kind, parent_scan_id, repo_url, int(create_pr),
             target_hint, QUEUED, "queued", now, now, now, idempotency_key,
             os.getpid()))

    def create_unless_duplicate(self, scan_id: str, *, repo_url: str,
                                create_pr: bool = False,
                                target_hint: str | None = None,
                                idempotency_key: str | None = None
                                ) -> tuple[dict, bool]:
        """Atomically return an existing equivalent run or create this one.

        The check and the insert share one BEGIN IMMEDIATE transaction, so
        concurrent requests — threads or separate backend processes on the
        same DB — cannot both pass the check. Returns (record, created).
        """
        now = time.time()
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = None
                if idempotency_key:
                    row = conn.execute(
                        "SELECT * FROM runs WHERE idempotency_key=? "
                        "ORDER BY created_at DESC LIMIT 1",
                        (idempotency_key,)).fetchone()
                if row is None:
                    row = conn.execute(
                        "SELECT * FROM runs WHERE kind='scan' AND repo_url=? "
                        "AND create_pr=? AND COALESCE(target_hint,'')=? AND "
                        "status IN (?,?) AND heartbeat_at >= ? "
                        "ORDER BY created_at DESC LIMIT 1",
                        (repo_url, int(create_pr), target_hint or "", *ACTIVE,
                         now - _stale_after())).fetchone()
                if row is not None:
                    conn.execute("COMMIT")
                    return dict(row), False
                conn.execute(
                    "INSERT INTO runs (scan_id, kind, parent_scan_id, repo_url, "
                    "create_pr, target_hint, status, phase, created_at, "
                    "updated_at, heartbeat_at, idempotency_key, owner_pid) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (scan_id, "scan", None, repo_url, int(create_pr),
                     target_hint, QUEUED, "queued", now, now, now,
                     idempotency_key, os.getpid()))
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()
        return self.get(scan_id), True

    def mark_running(self, scan_id: str, phase: str = "starting") -> None:
        now = time.time()
        self._exec("UPDATE runs SET status=?, phase=?, updated_at=?, "
                   "heartbeat_at=? WHERE scan_id=? AND status IN (?,?)",
                   (RUNNING, phase, now, now, scan_id, *ACTIVE))

    def update_phase(self, scan_id: str, phase: str) -> None:
        now = time.time()
        self._exec("UPDATE runs SET phase=?, updated_at=?, heartbeat_at=? "
                   "WHERE scan_id=? AND status IN (?,?)",
                   (phase, now, now, scan_id, *ACTIVE))

    def heartbeat(self, scan_id: str) -> None:
        self._exec("UPDATE runs SET heartbeat_at=? WHERE scan_id=? "
                   "AND status IN (?,?)", (time.time(), scan_id, *ACTIVE))

    def complete(self, scan_id: str, report: dict,
                 summary: dict | None = None) -> None:
        """Write the report file first, then flip the row: a reader never
        sees `completed` without a report behind it."""
        path = self._run_dir(scan_id) / REPORT_FILE
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(report, indent=2, default=str),
                       encoding="utf-8")
        os.replace(tmp, path)
        now = time.time()
        self._exec("UPDATE runs SET status=?, phase=?, updated_at=?, "
                   "finished_at=?, report_path=?, summary_json=?, error=NULL, "
                   "error_kind=NULL WHERE scan_id=?",
                   (COMPLETED, "done", now, now, str(path),
                    json.dumps(summary or {}, default=str), scan_id))

    def fail(self, scan_id: str, error: str, kind: str = "internal",
             status: str = FAILED) -> None:
        """Terminal failure. `error` must already be safe to show users."""
        now = time.time()
        self._exec("UPDATE runs SET status=?, updated_at=?, finished_at=?, "
                   "error=?, error_kind=? WHERE scan_id=? AND status IN (?,?)",
                   (status, now, now, error, kind, scan_id, *ACTIVE))

    def recover_stale(self) -> list[str]:
        """Mark active runs whose heartbeat stopped as interrupted.

        Safe with several backend processes sharing the DB: a live
        process keeps its rows fresh, so only dead owners' rows flip.
        """
        cutoff = time.time() - _stale_after()
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT scan_id FROM runs WHERE status IN (?,?) AND "
                "heartbeat_at < ?", (*ACTIVE, cutoff)).fetchall()
            ids = [r["scan_id"] for r in rows]
            now = time.time()
            for sid in ids:
                conn.execute(
                    "UPDATE runs SET status=?, updated_at=?, finished_at=?, "
                    "error=?, error_kind=? WHERE scan_id=? AND status IN (?,?)",
                    (INTERRUPTED, now, now,
                     "The backend process running this scan stopped before "
                     "it finished (restart or crash). It did not complete; "
                     "start a new scan.", "interrupted", sid, *ACTIVE))
        for sid in ids:
            logger.warning("scan_store: run %s marked interrupted (stale "
                           "heartbeat)", sid)
        return ids

    def forget_report(self, scan_id: str) -> bool:
        """Retention purge: erase ALL stored run data for a scan.

        Not just report.json: state_after_fix.json, review.json, patch.diff
        and the LLM prompts hold the findings and scanned source too, and
        remediation re-runs (<id>-r1, …) copy the parent's findings. The
        lifecycle row stays (status, timestamps) so the id answers 410.
        Raises OSError if anything could not be deleted.
        """
        import re as _re
        from tools.git_cloner import force_rmtree
        self._run_dir(scan_id)  # validates the id
        child = _re.compile(_re.escape(scan_id) + r"-r\d+")
        targets = [self.runs_dir / scan_id] + [
            p for p in self.runs_dir.iterdir()
            if p.is_dir() and child.fullmatch(p.name)]
        removed = False
        for path in targets:
            had_files = any(path.iterdir())
            if not force_rmtree(str(path)):
                raise OSError(f"files remain in {path}")
            removed = removed or had_files
        for path in targets:
            self._exec("UPDATE runs SET report_path=NULL, summary_json=NULL "
                       "WHERE scan_id=?", (path.name,))
        return removed

    # ── events (replayable agent feed) ────────────────────────

    def append_event(self, scan_id: str, event: dict) -> None:
        try:
            with (self._run_dir(scan_id) / EVENTS_FILE).open(
                    "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, default=str) + "\n")
        except (OSError, ValueError):
            logger.warning("scan_store: could not persist event for %s",
                           scan_id, exc_info=True)

    def events(self, scan_id: str) -> list[dict]:
        path = self.runs_dir / scan_id / EVENTS_FILE
        if not path.is_file():
            return []
        out: list[dict] = []
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out[-_MAX_EVENTS:]

    # ── reads ─────────────────────────────────────────────────

    def get(self, scan_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM runs WHERE scan_id=?",
                               (scan_id,)).fetchone()
        if row is None:
            return None
        rec = dict(row)
        if rec["status"] in ACTIVE and \
                rec["heartbeat_at"] < time.time() - _stale_after():
            self.recover_stale()
            return self.get(scan_id)
        return rec

    def load_report(self, rec: dict) -> dict | None:
        path = rec.get("report_path")
        if not path or not os.path.isfile(path):
            return None
        return json.loads(Path(path).read_text(encoding="utf-8"))

    def list(self, limit: int = 50, offset: int = 0) -> list[dict]:
        self.recover_stale()
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM runs ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset)).fetchall()
        return [dict(r) for r in rows]


def public_view(rec: dict) -> dict:
    """The JSON shape clients see for a run's lifecycle (no paths)."""
    summary = {}
    if rec.get("summary_json"):
        try:
            summary = json.loads(rec["summary_json"])
        except json.JSONDecodeError:
            summary = {}
    return {
        "scan_id": rec["scan_id"],
        "kind": rec["kind"],
        "parent_scan_id": rec.get("parent_scan_id"),
        "repo_url": rec["repo_url"],
        "create_pr": bool(rec["create_pr"]),
        "target_hint": rec.get("target_hint"),
        "status": rec["status"],
        "phase": rec["phase"],
        "created_at": rec["created_at"],
        "updated_at": rec["updated_at"],
        "finished_at": rec.get("finished_at"),
        "error": rec.get("error"),
        "error_kind": rec.get("error_kind"),
        "has_report": bool(rec.get("report_path")),
        "summary": summary,
    }
