"""Per-scan run artifacts (prompt 03).

The clone dir is deleted at the end of every scan, so anything the UI, the
verifier or a later node needs (diff, prompt/response transcripts, exploit
test, PR body) is persisted here: backend/runs/<scan_id>/. Gitignored.
"""

from __future__ import annotations

import os
from pathlib import Path

_BASE = Path(os.getenv("RUNS_DIR", Path(__file__).resolve().parent.parent / "runs"))


def artifact_dir(scan_id: str) -> Path:
    """Create (if needed) and return backend/runs/<scan_id>/."""
    dest = _BASE / scan_id
    dest.mkdir(parents=True, exist_ok=True)
    return dest


def save_text(scan_id: str, name: str, text: str) -> Path:
    """Write text to backend/runs/<scan_id>/<name>, return the path."""
    target = artifact_dir(scan_id) / name
    target.write_text(text or "", encoding="utf-8")
    return target


STATE_SNAPSHOT = "state_after_fix.json"


def save_state(scan_id: str, state: dict) -> Path:
    """Persist a JSON snapshot of the scan state (non-serializable → str)."""
    import json as _json
    return save_text(scan_id, STATE_SNAPSHOT,
                     _json.dumps(dict(state), indent=2, default=str))


def load_state_snapshot(scan_id: str) -> dict:
    """Load a snapshot saved by save_state; raises FileNotFoundError."""
    import json as _json
    return _json.loads((artifact_dir(scan_id) / STATE_SNAPSHOT)
                       .read_text(encoding="utf-8"))
