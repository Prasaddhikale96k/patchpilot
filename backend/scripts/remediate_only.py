#!/usr/bin/env python
"""Remediation-only debug loop (prompt 05a): re-run coder→tester→PR-creator
from a saved state_after_fix.json without re-scanning.

Usage:
    cd backend && python scripts/remediate_only.py <scan_id> [--target CWE-89]

Prints [SecureCoder]/[Tester]/[PRCreator] logs live, then the final verdict
and total time. This is the 1-minute debug loop from now on.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(os.path.join(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))), ".env"))

from agents.remediation.loop import (fresh_remediation_state,  # noqa: E402
                                     stream_remediation)
from tools.run_artifacts import load_state_snapshot  # noqa: E402


async def _run(scan_id: str, target: str | None) -> int:
    try:
        snapshot = load_state_snapshot(scan_id)
    except FileNotFoundError:
        print(f"no state_after_fix.json for scan {scan_id} "
              f"(run a full scan first)", file=sys.stderr)
        return 2
    run_id = f"{scan_id}-dbg"
    state = fresh_remediation_state(snapshot, run_id, target_hint=target)
    print(f"remediating {snapshot.get('repo_url', '?')} as {run_id} "
          f"(target_hint={target})")
    start = time.perf_counter()
    accumulated: dict = dict(state)
    try:
        async for node_name, output in stream_remediation(state, run_id):
            for line in output.get("agent_logs", []):
                print(f"[{node_name}] {line}")
            for key, value in output.items():
                if key == "agent_logs":
                    accumulated.setdefault("agent_logs", [])
                    accumulated["agent_logs"].extend(value)
                else:
                    accumulated[key] = value
    except Exception as exc:
        print(f"REMEDIATION ERROR: {exc}", file=sys.stderr)
        return 1
    elapsed = time.perf_counter() - start
    verdict = accumulated.get("test_verdict", "?")
    print(f"verdict={verdict} attempts={accumulated.get('attempts', '?')} "
          f"pr_url={accumulated.get('pr_url')} elapsed={elapsed:.0f}s")
    return 0 if verdict == "verified" else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id")
    parser.add_argument("--target", default=None)
    args = parser.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    return asyncio.run(_run(args.scan_id, args.target))


if __name__ == "__main__":
    raise SystemExit(main())
