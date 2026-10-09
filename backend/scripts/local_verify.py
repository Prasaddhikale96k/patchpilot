#!/usr/bin/env python
"""Red→green sanity check for a SecureCoder run (prompt 03, Addition D).

Usage:
    cd backend && python scripts/local_verify.py <scan_id>

Reads the saved patch + exploit test from backend/runs/<scan_id>/, builds
ONE temp venv from the target repo's requirements, then runs:
  (1) the exploit test on the ORIGINAL repo  → must FAIL (bug reproduced),
  (2) the exploit test + full suite on the PATCHED work copy → must PASS.

Prints: phase | passed | failed | expected | OK?
This is a pre-Docker sanity check only; prompt 04 adds the real sandbox.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: local_verify.py <scan_id>", file=sys.stderr)
        return 2
    scan_id = argv[1]
    runs_dir = os.path.join(HERE, "runs", scan_id)
    meta_path = os.path.join(runs_dir, "scan_meta.json")
    blocks_path = os.path.join(runs_dir, "patch_blocks.json")
    if not os.path.isfile(meta_path) or not os.path.isfile(blocks_path):
        print(f"no saved patch for scan {scan_id} in {runs_dir}",
              file=sys.stderr)
        return 2
    with open(meta_path, encoding="utf-8") as handle:
        meta = json.load(handle)
    with open(blocks_path, encoding="utf-8") as handle:
        blocks = json.load(handle)
    repo_url = meta["repo_url"]
    test_file = meta.get("test_file") or _find_saved_test(runs_dir)
    with open(os.path.join(runs_dir, os.path.basename(test_file)),
              encoding="utf-8") as handle:
        test_content = handle.read()

    work = tempfile.mkdtemp(prefix=f"verify-{scan_id}-")
    print(f"work dir: {work}")
    print("creating venv + installing target requirements (once)...")

    from tools.git_cloner import _git_bin  # noqa: E402
    from tools.patch_apply import PatchBlock, apply_blocks  # noqa: E402
    from tools.sandbox import (create_venv, install_requirements,  # noqa: E402
                               run_cmd, run_tests_venv)

    vpy = create_venv(work)

    def fresh_clone(name: str) -> str:
        dest = os.path.join(work, name)
        run_cmd([_git_bin(), "clone", "--depth", "1", repo_url, dest],
                work, 300)
        with open(os.path.join(dest, test_file), "w", encoding="utf-8",
                  newline="") as handle:
            handle.write(test_content)
        return dest

    original = fresh_clone("original")
    try:
        install_requirements(vpy, original)
    except RuntimeError as exc:
        print(str(exc)[-2000:])
        return 1

    rows: list[tuple[str, int, int, str, str]] = []

    red = run_tests_venv(original, "exploit_before", vpy, selector=test_file)
    ok = "YES" if red["returncode"] != 0 else "NO"
    rows.append(("exploit on ORIGINAL", red["passed"], red["failed"],
                 "FAIL", ok))

    patched = fresh_clone("patched")
    apply_blocks(patched, [PatchBlock(**b) for b in blocks])
    green = run_tests_venv(patched, "after", vpy)
    ok = "YES" if green["returncode"] == 0 else "NO"
    rows.append(("suite on PATCHED", green["passed"], green["failed"],
                 "PASS", ok))

    print(f"{'phase':<22} {'passed':>6} {'failed':>6}  "
          f"{'expected':<8} {'OK?'}")
    print("-" * 56)
    all_ok = True
    for phase, p, f, expected, ok in rows:
        print(f"{phase:<22} {p:>6} {f:>6}  {expected:<8} {ok}")
        all_ok = all_ok and ok == "YES"
    print("red->green proven." if all_ok else "NOT proven - see phases above.")
    return 0 if all_ok else 1


def _find_saved_test(runs_dir: str) -> str:
    for name in sorted(os.listdir(runs_dir)):
        if name.startswith("test_patchforge_") and name.endswith(".py"):
            return os.path.join("tests", name)
    raise SystemExit(f"no saved exploit test in {runs_dir}")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
