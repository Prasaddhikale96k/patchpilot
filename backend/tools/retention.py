"""
Data lifecycle and retention for scan records.

A scan does not live in one place. Its row sits in scan_history.json, its
payload (vulnerabilities, patches, summary) can be offloaded to a cold archive
file, the cloned repository sits in a temp workspace, and an in-flight scan
also holds a live in-process session. "Delete this scan" therefore touches
several stores, and any of them can succeed, refuse, or fail independently.

Every operation here returns a Receipt: one result per component plus a single
rolled-up outcome, which is one of

    complete    every component reached its intended end state
    partial     the operation did what was asked, but scan data is still
                retained somewhere on purpose (a policy-retained summary row)
    blocked     a legal hold or an in-flight scan refused the operation
    unresolved  a component failed, or a store disagrees with the ledger

Receipts are appended to a hash-chained audit ledger so the record of what was
erased cannot be edited after the fact without detection.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Lifecycle states ──────────────────────────────────────────
STATE_ACTIVE = "active"
STATE_ARCHIVED = "archived"
STATE_TRASHED = "trashed"
STATE_PURGED = "purged"
ALL_STATES = (STATE_ACTIVE, STATE_ARCHIVED, STATE_TRASHED, STATE_PURGED)

# ── Rolled-up operation outcomes (the completion signal) ──────
OUTCOME_COMPLETE = "complete"
OUTCOME_PARTIAL = "partial"
OUTCOME_BLOCKED = "blocked"
OUTCOME_UNRESOLVED = "unresolved"

# ── Per-component outcomes ────────────────────────────────────
C_DONE = "complete"
C_RETAINED = "retained"            # scan data deliberately kept -> operation is partial
C_POLICY = "retained_by_policy"    # no scan data, only an identifier -> does not weaken the result
C_ABSENT = "not_present"
C_BLOCKED = "blocked"
C_UNRESOLVED = "unresolved"

PAYLOAD_KEYS = ("vulnerabilities", "patches", "summary")

PURGE_FULL = "full"
PURGE_PAYLOAD = "payload"


class RetentionError(Exception):
    """Raised when an operation cannot be attempted at all (e.g. unknown scan)."""


def _now() -> float:
    return time.time()


def _days(seconds: float) -> float:
    return seconds / 86400.0


@dataclass
class ComponentResult:
    component: str
    outcome: str
    detail: str

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Receipt:
    operation: str
    scan_id: str
    outcome: str
    state: str
    components: list[ComponentResult] = field(default_factory=list)
    at: float = field(default_factory=_now)
    actor: str = "operator"
    note: str = ""
    tombstone: dict | None = None

    def as_dict(self) -> dict:
        return {
            "operation": self.operation,
            "scan_id": self.scan_id,
            "outcome": self.outcome,
            "state": self.state,
            "components": [c.as_dict() for c in self.components],
            "at": self.at,
            "actor": self.actor,
            "note": self.note,
            "tombstone": self.tombstone,
        }


def rollup(components: Iterable[ComponentResult]) -> str:
    """
    Collapse per-component outcomes into the single completion signal.

    Order matters: a refusal outranks a failure, because a blocked operation
    left everything intact, while an unresolved one may have half-finished.
    A retained_by_policy component is a tombstone, which carries an identifier
    and a hash but no scan data, so it never downgrades a completed erasure.
    """
    outcomes = [c.outcome for c in components]
    if C_BLOCKED in outcomes:
        return OUTCOME_BLOCKED
    if C_UNRESOLVED in outcomes:
        return OUTCOME_UNRESOLVED
    if C_RETAINED in outcomes:
        return OUTCOME_PARTIAL
    return OUTCOME_COMPLETE


def _payload_digest(record: dict) -> str:
    payload = {k: record.get(k) for k in PAYLOAD_KEYS if k in record}
    blob = json.dumps(payload, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()


def _payload_bytes(record: dict) -> int:
    payload = {k: record.get(k) for k in PAYLOAD_KEYS if k in record}
    return len(json.dumps(payload, default=str).encode())


def default_lifecycle(timestamp: float) -> dict:
    return {
        "state": STATE_ACTIVE,
        "created_at": timestamp,
        "archived_at": None,
        "trashed_at": None,
        "purged_at": None,
        "purge_mode": None,
        "hold": None,
        "last_operation": None,
        "last_outcome": None,
        "residue": [],
    }


def lifecycle_of(record: dict) -> dict:
    lc = record.get("lifecycle")
    if not isinstance(lc, dict):
        lc = default_lifecycle(record.get("timestamp", _now()))
        record["lifecycle"] = lc
    return lc


class RetentionPolicy:
    """
    Age thresholds, in days. Every value is env-overridable so the whole
    lifecycle can be exercised in a demo without waiting a quarter.
    """

    def __init__(self) -> None:
        self.archive_after_days = float(os.getenv("RETENTION_ARCHIVE_AFTER_DAYS", "30"))
        self.trash_after_days = float(os.getenv("RETENTION_TRASH_AFTER_DAYS", "90"))
        self.purge_after_days = float(os.getenv("RETENTION_PURGE_AFTER_DAYS", "14"))
        self.default_purge_mode = os.getenv("RETENTION_PURGE_MODE", PURGE_PAYLOAD)

    def as_dict(self) -> dict:
        return {
            "archive_after_days": self.archive_after_days,
            "trash_after_days": self.trash_after_days,
            "purge_after_days": self.purge_after_days,
            "default_purge_mode": self.default_purge_mode,
            "description": (
                "Active scans are archived after archive_after_days and moved to trash after "
                "trash_after_days, both measured from the scan date. Trashed scans become "
                "purge-eligible purge_after_days after they were trashed. A legal hold blocks "
                "every destructive step at any stage."
            ),
        }

    def due_action(self, record: dict, as_of: float) -> str | None:
        """Which lifecycle step this record is due for, ignoring holds."""
        lc = lifecycle_of(record)
        state = lc.get("state", STATE_ACTIVE)
        scanned_at = record.get("timestamp", lc.get("created_at", as_of))
        age = _days(as_of - scanned_at)

        if state == STATE_ACTIVE:
            if age >= self.trash_after_days:
                return "trash"
            if age >= self.archive_after_days:
                return "archive"
            return None
        if state == STATE_ARCHIVED:
            if age >= self.trash_after_days:
                return "trash"
            return None
        if state == STATE_TRASHED:
            trashed_at = lc.get("trashed_at") or scanned_at
            if _days(as_of - trashed_at) >= self.purge_after_days:
                return "purge"
            return None
        return None

    def next_due_at(self, record: dict) -> float | None:
        lc = lifecycle_of(record)
        state = lc.get("state", STATE_ACTIVE)
        scanned_at = record.get("timestamp", lc.get("created_at", _now()))
        if state == STATE_ACTIVE:
            return scanned_at + self.archive_after_days * 86400
        if state == STATE_ARCHIVED:
            return scanned_at + self.trash_after_days * 86400
        if state == STATE_TRASHED:
            trashed_at = lc.get("trashed_at") or scanned_at
            return trashed_at + self.purge_after_days * 86400
        return None


class AuditLedger:
    """
    Append-only, hash-chained record of every lifecycle operation.

    Each entry stores the hash of the previous entry, so removing or editing
    any past line breaks every hash after it. verify() reports where.
    """

    def __init__(self, path: Path) -> None:
        self.path = path

    def _entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        entries = []
        for line in self.path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                entries.append({"_corrupt": line})
        return entries

    @staticmethod
    def _hash(entry: dict) -> str:
        body = {k: v for k, v in entry.items() if k != "entry_hash"}
        return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()

    def append(self, receipt: Receipt) -> dict:
        entries = self._entries()
        prev = entries[-1].get("entry_hash", "") if entries else ""
        entry = {"seq": len(entries) + 1, "prev_hash": prev, **receipt.as_dict()}
        entry["entry_hash"] = self._hash(entry)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
        return entry

    def read(self, limit: int | None = None, scan_id: str | None = None) -> list[dict]:
        entries = self._entries()
        if scan_id:
            entries = [e for e in entries if e.get("scan_id") == scan_id]
        entries.reverse()
        return entries[:limit] if limit else entries

    def verify(self) -> dict:
        """Recompute the chain. Returns a completion signal of its own."""
        entries = self._entries()
        broken: list[dict] = []
        prev = ""
        for idx, entry in enumerate(entries, start=1):
            if "_corrupt" in entry:
                broken.append({"seq": idx, "reason": "line is not valid JSON"})
                prev = ""
                continue
            if entry.get("prev_hash", "") != prev:
                broken.append({"seq": entry.get("seq", idx),
                               "reason": "previous-entry hash does not match"})
            recomputed = self._hash(entry)
            if recomputed != entry.get("entry_hash"):
                broken.append({"seq": entry.get("seq", idx),
                               "reason": "entry hash does not match its contents"})
            prev = entry.get("entry_hash", "")
        return {
            "entries": len(entries),
            "outcome": OUTCOME_COMPLETE if not broken else OUTCOME_UNRESOLVED,
            "broken": broken,
            "detail": ("Hash chain intact across all entries." if not broken
                       else f"{len(broken)} ledger "
                            + ("entry no longer matches" if len(broken) == 1
                               else "entries no longer match")
                            + " the chain."),
        }


class RetentionStore:
    """
    Lifecycle operations over the scan history file.

    Reads and writes are done through the injected loader/saver so the caller
    keeps ownership of its own file lock. live_sessions is the in-process scan
    registry; workspace_for maps a scan id to its cloned repository directory.
    """

    def __init__(
        self,
        load_records: Callable[[], list[dict]],
        save_records: Callable[[list[dict]], None],
        archive_dir: Path,
        ledger: AuditLedger,
        live_sessions: dict | None = None,
        workspace_for: Callable[[str], str] | None = None,
        policy: RetentionPolicy | None = None,
    ) -> None:
        self._load = load_records
        self._save = save_records
        self.archive_dir = Path(archive_dir)
        self.ledger = ledger
        self.live_sessions = live_sessions if live_sessions is not None else {}
        self.workspace_for = workspace_for or (lambda sid: "")
        self.policy = policy or RetentionPolicy()

    # ── helpers ───────────────────────────────────────────────

    def _archive_path(self, scan_id: str) -> Path:
        return self.archive_dir / f"{scan_id}.json"

    def _find(self, records: list[dict], scan_id: str) -> dict:
        for r in records:
            if r.get("scan_id") == scan_id:
                return r
        raise RetentionError(f"Scan {scan_id} is not in the retention store")

    def _hold_block(self, record: dict, operation: str) -> ComponentResult | None:
        hold = lifecycle_of(record).get("hold")
        if not hold:
            return None
        return ComponentResult(
            "legal_hold", C_BLOCKED,
            f"{operation} refused: scan is under legal hold "
            f"({hold.get('reason', 'no reason recorded')}), placed "
            f"{time.strftime('%Y-%m-%d', time.gmtime(hold.get('placed_at', _now())))}.",
        )

    def _live_block(self, scan_id: str, operation: str) -> ComponentResult | None:
        session = self.live_sessions.get(scan_id)
        if session and session.get("status") not in ("done", "error"):
            return ComponentResult(
                "live_session", C_BLOCKED,
                f"{operation} refused: scan is still running (status "
                f"{session.get('status')}); it would keep writing after erasure.",
            )
        return None

    def _commit(self, records: list[dict], receipt: Receipt) -> Receipt:
        self._save(records)
        self.ledger.append(receipt)
        logger.info("Retention %s on %s -> %s", receipt.operation, receipt.scan_id, receipt.outcome)
        return receipt

    @staticmethod
    def _stamp(record: dict, receipt: Receipt) -> None:
        lc = lifecycle_of(record)
        lc["last_operation"] = receipt.operation
        lc["last_outcome"] = receipt.outcome
        lc["last_operation_at"] = receipt.at

    # ── operations ────────────────────────────────────────────

    def archive(self, scan_id: str, actor: str = "operator") -> Receipt:
        """Offload the payload to the cold archive, keeping the summary row hot."""
        records = self._load()
        record = self._find(records, scan_id)
        lc = lifecycle_of(record)
        components: list[ComponentResult] = []

        blocked = self._hold_block(record, "Archive") or self._live_block(scan_id, "Archive")
        if blocked:
            receipt = Receipt("archive", scan_id, OUTCOME_BLOCKED, lc["state"], [blocked],
                              actor=actor, note="No data was moved.")
            self._stamp(record, receipt)
            return self._commit(records, receipt)

        if lc["state"] == STATE_ARCHIVED and self._archive_path(scan_id).exists():
            components.append(ComponentResult(
                "archive_copy", C_DONE, "Already archived; cold copy verified on disk."))
            receipt = Receipt("archive", scan_id, OUTCOME_COMPLETE, STATE_ARCHIVED, components,
                              actor=actor, note="No change required.")
            self._stamp(record, receipt)
            return self._commit(records, receipt)

        payload = {k: record.get(k) for k in PAYLOAD_KEYS if k in record}
        size = _payload_bytes(record)
        digest = _payload_digest(record)

        try:
            self.archive_dir.mkdir(parents=True, exist_ok=True)
            self._archive_path(scan_id).write_text(json.dumps(payload, indent=2, default=str))
            components.append(ComponentResult(
                "archive_copy", C_DONE,
                f"Payload written to {self._archive_path(scan_id).name} "
                f"({size} bytes, sha256 {digest[:12]})."))
        except OSError as exc:
            components.append(ComponentResult(
                "archive_copy", C_UNRESOLVED, f"Could not write the cold copy: {exc}"))
            receipt = Receipt("archive", scan_id, OUTCOME_UNRESOLVED, lc["state"], components,
                              actor=actor, note="History record left untouched.")
            self._stamp(record, receipt)
            return self._commit(records, receipt)

        for key in PAYLOAD_KEYS:
            record.pop(key, None)
        components.append(ComponentResult(
            "history_record", C_DONE,
            f"Hot record slimmed to the summary row; {size} bytes of findings moved out."))

        workspace = self._remove_workspace(scan_id, "Archive")
        components.append(workspace)

        lc.update({"state": STATE_ARCHIVED, "archived_at": _now(),
                   "payload_sha256": digest, "payload_bytes": size})
        receipt = Receipt("archive", scan_id, rollup(components), STATE_ARCHIVED, components,
                          actor=actor,
                          note="Findings are recoverable in full via restore.")
        self._stamp(record, receipt)
        return self._commit(records, receipt)

    def restore(self, scan_id: str, actor: str = "operator") -> Receipt:
        """Bring a scan back: out of the trash, and back from the cold archive."""
        records = self._load()
        record = self._find(records, scan_id)
        lc = lifecycle_of(record)
        components: list[ComponentResult] = []
        state = lc.get("state", STATE_ACTIVE)

        if state == STATE_PURGED:
            components.append(ComponentResult(
                "report_payload", C_UNRESOLVED,
                "Purged data cannot be restored; the payload no longer exists in any store."))
            receipt = Receipt("restore", scan_id, OUTCOME_UNRESOLVED, STATE_PURGED, components,
                              actor=actor, note="Restore is not possible after a purge.")
            self._stamp(record, receipt)
            return self._commit(records, receipt)

        if state == STATE_TRASHED:
            lc["trashed_at"] = None
            components.append(ComponentResult(
                "history_record", C_DONE, "Record taken out of the trash and listed again."))

        archive_file = self._archive_path(scan_id)
        if archive_file.exists():
            try:
                payload = json.loads(archive_file.read_text())
                record.update(payload)
                digest = _payload_digest(record)
                expected = lc.get("payload_sha256")
                if expected and digest != expected:
                    components.append(ComponentResult(
                        "report_payload", C_UNRESOLVED,
                        f"Restored payload hashes {digest[:12]}, ledger expected "
                        f"{str(expected)[:12]}; the cold copy was modified."))
                else:
                    components.append(ComponentResult(
                        "report_payload", C_DONE,
                        f"{len(record.get('vulnerabilities', []))} findings rehydrated from the "
                        f"cold archive, hash verified."))
                archive_file.unlink()
                components.append(ComponentResult(
                    "archive_copy", C_DONE, "Cold copy removed; the hot record is authoritative again."))
            except (OSError, json.JSONDecodeError) as exc:
                components.append(ComponentResult(
                    "report_payload", C_UNRESOLVED, f"Cold copy is unreadable: {exc}"))
        elif state == STATE_ARCHIVED:
            components.append(ComponentResult(
                "archive_copy", C_UNRESOLVED,
                "Ledger says this scan is archived, but no cold copy exists on disk. "
                "The findings are gone and this needs investigation."))
        else:
            components.append(ComponentResult(
                "report_payload", C_DONE, "Payload was still hot; nothing to rehydrate."))

        outcome = rollup(components)
        new_state = STATE_ACTIVE if outcome != OUTCOME_UNRESOLVED else state
        lc["state"] = new_state
        if new_state == STATE_ACTIVE:
            lc["archived_at"] = None
        receipt = Receipt("restore", scan_id, outcome, new_state, components, actor=actor)
        self._stamp(record, receipt)
        return self._commit(records, receipt)

    def trash(self, scan_id: str, actor: str = "operator", reason: str = "") -> Receipt:
        """Reversible removal: hidden from history, still fully recoverable."""
        records = self._load()
        record = self._find(records, scan_id)
        lc = lifecycle_of(record)
        components: list[ComponentResult] = []

        blocked = self._hold_block(record, "Delete") or self._live_block(scan_id, "Delete")
        if blocked:
            receipt = Receipt("trash", scan_id, OUTCOME_BLOCKED, lc["state"], [blocked],
                              actor=actor, note="The scan is still listed and intact.")
            self._stamp(record, receipt)
            return self._commit(records, receipt)

        if lc["state"] == STATE_TRASHED:
            components.append(ComponentResult(
                "history_record", C_DONE, "Already in the trash."))
        else:
            lc["state"] = STATE_TRASHED
            lc["trashed_at"] = _now()
            components.append(ComponentResult(
                "history_record", C_DONE,
                "Hidden from history and from trend comparisons; the row itself is untouched."))

        components.append(self._remove_workspace(scan_id, "Delete"))
        components.append(ComponentResult(
            "report_payload", C_RETAINED,
            f"Findings are kept for {self.policy.purge_after_days:g} more days so the delete "
            "can be undone. This is why the operation reports partial, not complete."))

        receipt = Receipt("trash", scan_id, rollup(components), STATE_TRASHED, components,
                          actor=actor, note=reason or "Reversible delete.")
        self._stamp(record, receipt)
        return self._commit(records, receipt)

    def purge(self, scan_id: str, mode: str | None = None, actor: str = "operator") -> Receipt:
        """
        Irreversible erasure.

        mode="full"    every store is emptied, only a tombstone remains
        mode="payload" findings and patches are erased, the score row is kept
                       so the site's risk trend does not develop a hole
        """
        mode = mode or self.policy.default_purge_mode
        if mode not in (PURGE_FULL, PURGE_PAYLOAD):
            raise RetentionError(f"Unknown purge mode {mode!r}")

        records = self._load()
        record = self._find(records, scan_id)
        lc = lifecycle_of(record)
        components: list[ComponentResult] = []

        blocked = self._hold_block(record, "Purge") or self._live_block(scan_id, "Purge")
        if blocked:
            receipt = Receipt("purge", scan_id, OUTCOME_BLOCKED, lc["state"], [blocked],
                              actor=actor, note="Nothing was erased.")
            self._stamp(record, receipt)
            return self._commit(records, receipt)

        digest = lc.get("payload_sha256") or _payload_digest(record)
        finding_count = record.get("total_vulns", len(record.get("vulnerabilities", []) or []))

        # cold archive
        archive_file = self._archive_path(scan_id)
        if archive_file.exists():
            try:
                archive_file.unlink()
                components.append(ComponentResult(
                    "archive_copy", C_DONE, f"Cold copy {archive_file.name} deleted."))
            except OSError as exc:
                components.append(ComponentResult(
                    "archive_copy", C_UNRESOLVED, f"Cold copy could not be deleted: {exc}"))
        else:
            components.append(ComponentResult(
                "archive_copy", C_ABSENT, "No cold copy existed."))

        # cloned workspace
        components.append(self._remove_workspace(scan_id, "Purge"))

        # live session
        if scan_id in self.live_sessions:
            self.live_sessions.pop(scan_id, None)
            components.append(ComponentResult(
                "live_session", C_DONE, "In-process session dropped from memory."))
        else:
            components.append(ComponentResult(
                "live_session", C_ABSENT, "No in-process session held this scan."))

        # the record itself
        if mode == PURGE_FULL:
            records = [r for r in records if r.get("scan_id") != scan_id]
            components.append(ComponentResult(
                "history_record", C_DONE,
                f"Row removed from history; {finding_count} findings, their patches and the "
                "executive summary are gone."))
            final_state = STATE_PURGED
        else:
            for key in PAYLOAD_KEYS:
                record.pop(key, None)
            components.append(ComponentResult(
                "report_payload", C_DONE,
                f"{finding_count} findings, their patches and the executive summary erased."))
            components.append(ComponentResult(
                "history_record", C_RETAINED,
                "Score, severity counts and scan date kept so this site's risk trend stays "
                "continuous. No vulnerability detail remains."))
            lc.update({"state": STATE_PURGED, "purged_at": _now(), "purge_mode": mode,
                       "payload_sha256": digest})
            final_state = STATE_PURGED

        tombstone = {
            "scan_id": scan_id,
            "domain": record.get("domain", ""),
            "payload_sha256": digest,
            "findings_erased": finding_count,
            "purged_at": _now(),
            "mode": mode,
        }
        components.append(ComponentResult(
            "audit_tombstone", C_POLICY,
            f"Tombstone written to the ledger: scan id, domain and payload hash "
            f"{digest[:12]}. It proves the erasure happened and contains no finding data."))

        receipt = Receipt("purge", scan_id, rollup(components), final_state, components,
                          actor=actor, tombstone=tombstone,
                          note=("Irreversible. Everything erased." if mode == PURGE_FULL
                                else "Irreversible. Findings erased, score row retained by policy."))
        if mode != PURGE_FULL:
            self._stamp(record, receipt)
        return self._commit(records, receipt)

    def _remove_workspace(self, scan_id: str, operation: str) -> ComponentResult:
        path = self.workspace_for(scan_id)
        if not path or not os.path.isdir(path):
            return ComponentResult(
                "clone_workspace", C_ABSENT,
                "No cloned repository remained for this scan.")
        try:
            from tools.git_cloner import force_rmtree
            if not force_rmtree(path):  # read-only .git packs on Windows
                raise OSError("files remain after deletion")
            return ComponentResult(
                "clone_workspace", C_DONE, f"Cloned repository at {path} removed.")
        except OSError as exc:
            return ComponentResult(
                "clone_workspace", C_UNRESOLVED,
                f"{operation} could not remove the cloned repository at {path}: {exc}")

    # ── holds ─────────────────────────────────────────────────

    def place_hold(self, scan_id: str, reason: str, actor: str = "operator") -> Receipt:
        records = self._load()
        record = self._find(records, scan_id)
        lc = lifecycle_of(record)
        lc["hold"] = {"reason": reason or "No reason recorded", "placed_at": _now(), "by": actor}
        component = ComponentResult(
            "legal_hold", C_DONE,
            "Hold placed. Archive, delete, purge and the retention sweep will all refuse this "
            "scan until it is released.")
        receipt = Receipt("hold", scan_id, OUTCOME_COMPLETE, lc["state"], [component],
                          actor=actor, note=reason)
        self._stamp(record, receipt)
        return self._commit(records, receipt)

    def release_hold(self, scan_id: str, actor: str = "operator") -> Receipt:
        records = self._load()
        record = self._find(records, scan_id)
        lc = lifecycle_of(record)
        if not lc.get("hold"):
            component = ComponentResult("legal_hold", C_ABSENT, "No hold was in place.")
            outcome = OUTCOME_COMPLETE
        else:
            lc["hold"] = None
            component = ComponentResult(
                "legal_hold", C_DONE, "Hold released; the scan follows the retention policy again.")
            outcome = OUTCOME_COMPLETE
        receipt = Receipt("release_hold", scan_id, outcome, lc["state"], [component], actor=actor)
        self._stamp(record, receipt)
        return self._commit(records, receipt)

    # ── verification ──────────────────────────────────────────

    def verify(self, scan_id: str) -> dict:
        """
        Independently re-check every store for this scan and report what is
        actually there, rather than what the ledger claims. This is what turns
        a reported erasure into a checkable one.
        """
        records = self._load()
        record = next((r for r in records if r.get("scan_id") == scan_id), None)
        # A blocked purge erased nothing and carries no tombstone, so it is not
        # evidence that this scan was ever destroyed.
        purge_entry = next(
            (e for e in self.ledger.read(scan_id=scan_id)
             if e.get("operation") == "purge" and e.get("tombstone")), None)
        checks: list[ComponentResult] = []

        if record is None:
            checks.append(ComponentResult(
                "history_record", C_ABSENT, "No row for this scan in scan_history.json."))
            state = STATE_PURGED if purge_entry else "unknown"
            lc = {}
        else:
            lc = lifecycle_of(record)
            state = lc.get("state", STATE_ACTIVE)
            held_payload = [k for k in PAYLOAD_KEYS if record.get(k)]
            if state == STATE_PURGED:
                if held_payload:
                    checks.append(ComponentResult(
                        "report_payload", C_UNRESOLVED,
                        f"Scan is marked purged but still carries {', '.join(held_payload)}."))
                else:
                    checks.append(ComponentResult(
                        "report_payload", C_DONE, "No findings, patches or summary remain."))
                checks.append(ComponentResult(
                    "history_record", C_RETAINED,
                    "Score row retained by policy (payload-mode purge)."))
            elif state == STATE_ARCHIVED:
                if held_payload:
                    checks.append(ComponentResult(
                        "report_payload", C_UNRESOLVED,
                        "Scan is marked archived but the payload is still in the hot record."))
                else:
                    checks.append(ComponentResult(
                        "history_record", C_DONE,
                        "Summary row present; the findings are in cold storage, not erased."))
            else:
                checks.append(ComponentResult(
                    "history_record", C_DONE,
                    f"Row present in state {state} with "
                    f"{len(record.get('vulnerabilities', []) or [])} findings held. "
                    "Nothing has been erased for this scan."))

        archive_file = self._archive_path(scan_id)
        if archive_file.exists():
            outcome = C_DONE if state == STATE_ARCHIVED else C_UNRESOLVED
            detail = (f"Cold copy present ({archive_file.stat().st_size} bytes), as expected "
                      "for an archived scan." if outcome == C_DONE else
                      f"Cold copy still on disk at {archive_file} although the scan is {state}.")
            checks.append(ComponentResult("archive_copy", outcome, detail))
        elif state == STATE_ARCHIVED:
            checks.append(ComponentResult(
                "archive_copy", C_UNRESOLVED,
                "Scan is marked archived but no cold copy exists; the findings are unrecoverable."))
        else:
            checks.append(ComponentResult("archive_copy", C_ABSENT, "No cold copy on disk."))

        workspace = self.workspace_for(scan_id)
        if workspace and os.path.isdir(workspace):
            checks.append(ComponentResult(
                "clone_workspace", C_UNRESOLVED,
                f"Cloned repository is still on disk at {workspace}."))
        else:
            checks.append(ComponentResult(
                "clone_workspace", C_ABSENT, "No cloned repository on disk."))

        if scan_id in self.live_sessions:
            checks.append(ComponentResult(
                "live_session", C_UNRESOLVED, "An in-process session still holds this scan."))
        else:
            checks.append(ComponentResult(
                "live_session", C_ABSENT, "No in-process session holds this scan."))

        if purge_entry:
            checks.append(ComponentResult(
                "audit_tombstone", C_POLICY,
                f"Purge recorded in the ledger at entry {purge_entry.get('seq')} with payload hash "
                f"{str((purge_entry.get('tombstone') or {}).get('payload_sha256', ''))[:12]}."))

        outcome = rollup(checks)
        residue = [c.component for c in checks if c.outcome == C_UNRESOLVED]

        if record is not None and residue != lc.get("residue"):
            lc["residue"] = residue
            self._save(records)

        return {
            "scan_id": scan_id,
            "state": state,
            "outcome": outcome,
            "checked_at": _now(),
            "checks": [c.as_dict() for c in checks],
            "residue": residue,
            "detail": ("Every store agrees with the ledger."
                       if outcome != OUTCOME_UNRESOLVED else
                       f"Residue found in: {', '.join(residue)}."),
        }

    # ── policy sweep ──────────────────────────────────────────

    def sweep(self, as_of: float | None = None, dry_run: bool = True,
              actor: str = "retention-policy") -> dict:
        """
        Apply the retention policy to every record.

        dry_run reports the plan without touching anything, and as_of lets the
        plan be evaluated at a future date, so the whole schedule can be shown
        without waiting for it.
        """
        as_of = as_of or _now()
        records = self._load()
        planned: list[dict] = []

        for record in records:
            action = self.policy.due_action(record, as_of)
            if not action:
                continue
            lc = lifecycle_of(record)
            planned.append({
                "scan_id": record.get("scan_id"),
                "domain": record.get("domain", ""),
                "state": lc.get("state", STATE_ACTIVE),
                "action": action,
                # 3dp so a scan minutes old is not rounded away to 0.0
                "age_days": round(_days(as_of - record.get("timestamp", as_of)), 3),
                "held": bool(lc.get("hold")),
            })

        if dry_run:
            blocked = sum(1 for p in planned if p["held"])
            return {
                "dry_run": True,
                "as_of": as_of,
                "outcome": (OUTCOME_BLOCKED if planned and blocked == len(planned)
                            else OUTCOME_PARTIAL if blocked
                            else OUTCOME_COMPLETE),
                "planned": planned,
                "receipts": [],
                "detail": (f"{len(planned)} scan(s) due, {blocked} held. Nothing was changed."
                           if planned else "No scan is due for a lifecycle step."),
            }

        receipts: list[Receipt] = []
        for item in planned:
            sid = item["scan_id"]
            if item["action"] == "archive":
                receipts.append(self.archive(sid, actor=actor))
            elif item["action"] == "trash":
                receipts.append(self.trash(sid, actor=actor, reason="Retention policy"))
            elif item["action"] == "purge":
                receipts.append(self.purge(sid, actor=actor))

        outcomes = {r.outcome for r in receipts}
        if not receipts:
            overall = OUTCOME_COMPLETE
        elif OUTCOME_UNRESOLVED in outcomes:
            overall = OUTCOME_UNRESOLVED
        elif outcomes == {OUTCOME_BLOCKED}:
            overall = OUTCOME_BLOCKED
        elif OUTCOME_BLOCKED in outcomes or OUTCOME_PARTIAL in outcomes:
            overall = OUTCOME_PARTIAL
        else:
            overall = OUTCOME_COMPLETE

        return {
            "dry_run": False,
            "as_of": as_of,
            "outcome": overall,
            "planned": planned,
            "receipts": [r.as_dict() for r in receipts],
            "detail": (f"{len(receipts)} scan(s) processed: "
                       + ", ".join(f"{sum(1 for r in receipts if r.outcome == o)} {o}"
                                   for o in (OUTCOME_COMPLETE, OUTCOME_PARTIAL,
                                             OUTCOME_BLOCKED, OUTCOME_UNRESOLVED)
                                   if any(r.outcome == o for r in receipts))
                       if receipts else "No scan was due for a lifecycle step."),
        }

    # ── inventory ─────────────────────────────────────────────

    def inventory(self, include_states: tuple[str, ...] = ALL_STATES) -> dict:
        records = self._load()
        now = _now()
        items = []
        counts = {s: 0 for s in ALL_STATES}
        held = 0
        unresolved = 0

        for record in records:
            lc = lifecycle_of(record)
            state = lc.get("state", STATE_ACTIVE)
            counts[state] = counts.get(state, 0) + 1
            if lc.get("hold"):
                held += 1
            if lc.get("residue"):
                unresolved += 1
            if state not in include_states:
                continue
            due_at = self.policy.next_due_at(record)
            items.append({
                "scan_id": record.get("scan_id"),
                "domain": record.get("domain", ""),
                "repo_url": record.get("repo_url", ""),
                "scan_date": record.get("scan_date", ""),
                "timestamp": record.get("timestamp", 0),
                "risk_score": record.get("risk_score", 0),
                "overall_risk": record.get("overall_risk", "UNKNOWN"),
                "total_vulns": record.get("total_vulns", 0),
                "severity": record.get("severity", {}),
                "state": state,
                "hold": lc.get("hold"),
                "payload_present": any(record.get(k) for k in PAYLOAD_KEYS),
                "payload_bytes": lc.get("payload_bytes"),
                "archived_at": lc.get("archived_at"),
                "trashed_at": lc.get("trashed_at"),
                "purged_at": lc.get("purged_at"),
                "purge_mode": lc.get("purge_mode"),
                "last_operation": lc.get("last_operation"),
                "last_outcome": lc.get("last_outcome"),
                "residue": lc.get("residue", []),
                "age_days": round(_days(now - record.get("timestamp", now)), 3),
                "next_due_action": self.policy.due_action(record, now)
                                   or (self.policy.due_action(record, due_at) if due_at else None),
                "next_due_at": due_at,
                "days_until_due": round(_days(due_at - now), 3) if due_at else None,
            })

        archive_files = (list(self.archive_dir.glob("*.json"))
                         if self.archive_dir.exists() else [])
        return {
            "policy": self.policy.as_dict(),
            "counts": counts,
            "held": held,
            "with_residue": unresolved,
            "total": len(records),
            "archive_files": len(archive_files),
            "archive_bytes": sum(f.stat().st_size for f in archive_files),
            "items": items,
        }
