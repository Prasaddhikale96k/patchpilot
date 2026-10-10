"""Fast regex secrets scan (runs alongside Bandit, Semgrep and the Logic Auditor).

Finds hard-coded credentials the AST scanners can miss. Findings use the same
normalized dict shape as the other scanners, with source "secrets".
"""

from __future__ import annotations

import os
import re

_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "tests",
              "test", "vendor", "dist", "build"}
_TEXT_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yml", ".yaml",
              ".env", ".ini", ".cfg", ".toml", ".sh", ".txt", ".conf"}
_MAX_BYTES = 200_000

_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Private key committed to the repository",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("AWS access key id",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("Hard-coded secret or password assigned to a variable",
     re.compile(r"""(?ix)\b(?:secret[_-]?key|api[_-]?key|password|passwd|token)\b
                    \s*[:=]\s*["'](?!\s*["'])(?!os\.|\$\{|<)[^"'\s]{6,}["']""")),
]
_PLACEHOLDER = re.compile(r"(?i)changeme|example|your[_-]|xxx|dummy|placeholder|<.*>")


def run_secrets_scan(repo_path: str) -> list[dict]:
    findings: list[dict] = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in sorted(files):
            ext = os.path.splitext(name)[1].lower()
            if ext not in _TEXT_EXTS and not name.startswith(".env"):
                continue
            full = os.path.join(root, name)
            try:
                if os.path.getsize(full) > _MAX_BYTES:
                    continue
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    lines = fh.read().splitlines()
            except OSError:
                continue
            rel = os.path.relpath(full, repo_path).replace("\\", "/")
            for number, line in enumerate(lines, start=1):
                for label, pattern in _PATTERNS:
                    if pattern.search(line) and not _PLACEHOLDER.search(line):
                        findings.append({
                            "source": "secrets",
                            "file": rel,
                            "line": number,
                            "severity": "ERROR",
                            "description": f"CWE-798: {label}",
                            "code": line.strip()[:200],
                            "rule_id": "secrets.regex",
                        })
                        break
    return findings
