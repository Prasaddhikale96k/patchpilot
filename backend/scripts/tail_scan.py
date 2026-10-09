#!/usr/bin/env python
"""Follow one scan's WebSocket feed until done (prompt 01b, Task D).

Usage:
    cd backend && python scripts/tail_scan.py <scan_id> [--host 127.0.0.1] [--port 8000]

Prints every update node + log line, then the report summary on done.
Exit 0 on done, 1 on scan error, 2 on timeout/connection failure.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

TIMEOUT_SECS = 1500.0


def _safe_stdout() -> None:
    """Windows consoles (cp1252) crash on fancy unicode — replace, don't die."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


async def tail(host: str, port: int, scan_id: str) -> int:
    import websockets

    uri = f"ws://{host}:{port}/ws/{scan_id}"
    print(f"connecting {uri} …")
    try:
        async with websockets.connect(uri, max_size=10 * 1024 * 1024) as ws:
            async with asyncio.timeout(TIMEOUT_SECS):
                async for raw in ws:
                    msg = json.loads(raw)
                    kind = msg.get("type")
                    if kind == "update":
                        print(f"[{msg.get('node')}] status={msg.get('status')}")
                        for line in msg.get("logs", []):
                            print(f"  {line}")
                    elif kind == "done":
                        report = msg.get("report", {})
                        summary = report.get("summary", {})
                        print("=== DONE ===")
                        print(f"vulnerabilities: {len(report.get('vulnerabilities', []))}  "
                              f"patches: {len(report.get('patches', []))}  "
                              f"risk: {summary.get('overall_risk')} "
                              f"{summary.get('risk_score')}/100")
                        return 0
                    elif kind == "error":
                        print(f"=== SCAN ERROR ({msg.get('kind')}) ===\n{msg.get('message')}")
                        return 1
                    elif kind == "ping":
                        continue
                    else:
                        print(raw[:500])
    except TimeoutError:
        print(f"TIMEOUT after {TIMEOUT_SECS}s waiting for scan {scan_id}")
        return 2
    except Exception as exc:
        print(f"CONNECTION FAILED: {exc}")
        return 2
    return 2


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    _safe_stdout()
    return asyncio.run(tail(args.host, args.port, args.scan_id))


if __name__ == "__main__":
    raise SystemExit(main())
