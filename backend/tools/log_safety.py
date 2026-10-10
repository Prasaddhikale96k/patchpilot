"""Log hygiene: secret redaction + log-line forging protection.

Installed as a filter on every PatchPilot log handler. Two layers:
1. Values of known secret env vars are replaced wherever they appear.
2. Well-known credential *shapes* are masked even when the value is not in
   this process's environment (a rotated key echoed in a provider error
   reached backend/logs/patchpilot.log that way).
CR/LF in the rendered message are escaped so a user-controlled value
(repo URL, branch name, model output) cannot forge extra log lines.
"""

from __future__ import annotations

import logging
import os
import re

SECRET_ENV_VARS = ("GROQ_API_KEY", "GROQ_API_KEYS", "GEMINI_API_KEY",
                   "OPENROUTER_API_KEY", "GITHUB_TOKEN", "GH_TOKEN",
                   "API_AUTH_TOKEN")

_SECRET_PATTERNS = [
    re.compile(r"gsk_[A-Za-z0-9_]{6,}"),                 # Groq
    re.compile(r"sk-or-[A-Za-z0-9_\-]{10,}"),            # OpenRouter
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),               # OpenAI-style
    re.compile(r"AIza[0-9A-Za-z_\-]{20,}"),              # Google
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),           # GitHub tokens
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?i)(authorization:\s*(?:bearer|token)\s+)\S+"),
    re.compile(r"(?i)(https?://)[^/\s:@]+:[^/\s@]+@"),   # creds in URLs
]


def redact(text: str) -> str:
    """Mask secret env values and credential-shaped substrings."""
    if not text:
        return text
    for var in SECRET_ENV_VARS:
        for value in os.getenv(var, "").split(","):
            value = value.strip()
            if len(value) >= 6 and value in text:
                text = text.replace(value, "***")
    for pattern in _SECRET_PATTERNS:
        if pattern.groups:
            text = pattern.sub(lambda m: m.group(1) + "***", text)
        else:
            text = pattern.sub("***", text)
    return text


class RedactingFilter(logging.Filter):
    """Render the record once, redact it, escape newlines in the message."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # malformed args: keep the raw template
            message = str(record.msg)
        message = redact(message).replace("\r", "\\r").replace("\n", "\\n")
        record.msg = message
        record.args = None
        return True


class RedactingFormatter(logging.Formatter):
    """Redacts the fully rendered line, including any traceback text."""

    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))
