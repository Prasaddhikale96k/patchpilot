#!/usr/bin/env python
"""Merge secret keys into backend/.env without ever printing values.

Usage:
    python backend/scripts/merge_env.py <source> <target>

Both files are parsed as KEY=VALUE lines (comments ignored, inline
" # …" comments stripped from values). Every key in <source> replaces the
matching line in <target> or is appended under a merge header. All other
target lines are untouched.

Output is key names + updated/added status + a masked preview
(first 4 + last 3 chars) only. Key values never reach stdout, logs or git:
<target> (backend/.env) is gitignored — verify with
git check-ignore backend/.env.
"""

from __future__ import annotations

import os
import re
import sys

_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _strip_inline_comment(value: str) -> str:
    """Drop a trailing ' # comment' unless it sits inside leading quotes."""
    value = value.strip()
    if value[:1] in ("'", '"'):
        quote = value[0]
        end = value.find(quote, 1)
        if end != -1:
            return value[1:end]
        return value.strip("'\"")
    cut = value.find(" #")
    if cut != -1:
        value = value[:cut]
    return value.strip().strip("'\"")


def parse_env_file(path: str) -> tuple[list[str], dict[str, str], dict[str, str]]:
    """Return (lines, key->value, key->raw_value_text) preserving file order."""
    with open(path, "r", encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    values: dict[str, str] = {}
    raws: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, _, raw = stripped.partition("=")
        name = name.strip()
        if not _KEY_RE.match(name):
            continue
        values[name] = _strip_inline_comment(raw)
        raws[name] = _strip_inline_comment(raw)
    return lines, values, raws


def masked(value: str) -> str:
    if len(value) > 7:
        return f"{value[:4]}****{value[-3:]}"
    return "****"


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: merge_env.py <source> <target>", file=sys.stderr)
        return 2
    source, target = argv[1], argv[2]
    _, src_values, src_raws = parse_env_file(source)

    with open(target, "r", encoding="utf-8") as handle:
        target_lines = handle.read().splitlines()

    existing = {line.strip().partition("=")[0].strip()
                for line in target_lines
                if "=" in line.strip() and not line.strip().startswith("#")}
    header = f"# --- merged from {os.path.basename(source)} ---"
    report: list[tuple[str, str, str]] = []
    out = list(target_lines)
    if any(k not in existing for k in src_values) and header not in out:
        out.append(header)

    for name, value in src_values.items():
        status = "updated" if name in existing else "added"
        new_line = f"{name}={src_raws[name]}"
        if name in existing:
            for i, line in enumerate(out):
                stripped = line.strip()
                if (not stripped.startswith("#") and "=" in stripped
                        and stripped.partition("=")[0].strip() == name):
                    out[i] = new_line
                    break
        else:
            out.append(new_line)
        report.append((name, status, masked(value)))

    with open(target, "w", encoding="utf-8") as handle:
        handle.write("\n".join(out) + "\n")

    print(f"{'key':<24} {'status':<8} preview")
    print("-" * 48)
    for name, status, preview in report:
        print(f"{name:<24} {status:<8} {preview}")
    print(f"\n{len(report)} keys merged into {target} (values not shown).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
