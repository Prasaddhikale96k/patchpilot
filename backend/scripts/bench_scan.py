#!/usr/bin/env python
"""Run ONE scan through the API and print where the time went.

Usage (backend must be running):
    cd backend
    python scripts/bench_scan.py <repo_url> [--create-pr] [--md LABEL]
                                 [--perf-json before|after]

Prints a table: node | seconds | % of total, plus the wall-clock total.
--md LABEL appends the table to ../docs/PERF.md under "## LABEL".
--perf-json before|after records the total in ../frontend/public/perf.json.

Polling is bounded (hard timeout) and stops on any terminal status.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import date

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TERMINAL = {"completed", "failed", "interrupted", "cancelled"}


def _call(base: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        base + path, data=data,
        headers={"Content-Type": "application/json"} if data else {})
    with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 - local API
        return json.loads(resp.read().decode())


def run(base: str, repo_url: str, create_pr: bool, max_wait: int) -> tuple[str, float, str]:
    started = _call(base, "/api/scan", {"repo_url": repo_url, "create_pr": create_pr})
    scan_id = started["scan_id"]
    t0 = time.perf_counter()
    status = "running"
    while time.perf_counter() - t0 < max_wait:
        status = _call(base, f"/api/scans/{scan_id}/status")["status"]
        if status in TERMINAL:
            break
        time.sleep(3)
    else:
        status = "timeout"
    return scan_id, time.perf_counter() - t0, status


def read_timings(scan_id: str) -> dict:
    path = os.path.join(ROOT, "runs", scan_id, "timings.json")
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except OSError:
        return {}


def table(timings: dict, wall: float) -> str:
    rows = ["| node | seconds | % of total |", "|---|---:|---:|"]
    for node, secs in sorted(timings.items(), key=lambda kv: -kv[1]):
        rows.append(f"| {node} | {secs:.1f} | {100 * secs / wall:.0f}% |")
    rows.append(f"| **total (wall clock)** | **{wall:.1f}** | 100% |")
    return "\n".join(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repo_url")
    parser.add_argument("--create-pr", action="store_true")
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--max-wait", type=int, default=900)
    parser.add_argument("--md", default=None)
    parser.add_argument("--perf-json", choices=["before", "after"], default=None)
    args = parser.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    try:
        scan_id, wall, status = run(args.base, args.repo_url, args.create_pr, args.max_wait)
    except (urllib.error.URLError, OSError) as exc:
        print(f"backend not reachable at {args.base}: {exc}", file=sys.stderr)
        return 2
    print(f"scan {scan_id}: {status} in {wall:.1f}s")
    if status != "completed":
        return 1
    out = table(read_timings(scan_id), wall)
    print(out)

    if args.md:
        docs = os.path.join(os.path.dirname(ROOT), "docs")
        os.makedirs(docs, exist_ok=True)
        with open(os.path.join(docs, "PERF.md"), "a", encoding="utf-8") as fh:
            fh.write(f"\n## {args.md}\n\nScan `{scan_id}` of {args.repo_url} on {date.today()}\n\n{out}\n")
    if args.perf_json:
        path = os.path.join(os.path.dirname(ROOT), "frontend", "public", "perf.json")
        try:
            with open(path, encoding="utf-8") as fh:
                perf = json.load(fh)
        except (OSError, ValueError):
            perf = {}
        perf[f"{args.perf_json}_s"] = round(wall, 1)
        perf["date"] = str(date.today())
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(perf, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
