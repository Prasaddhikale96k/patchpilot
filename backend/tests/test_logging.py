"""Persistent file logging (ebd4ddea follow-up).

When in-memory scan state vanished, only a persistent log could tell us
why. These pin: log records carry timestamp + PID, land in the configured
file, contain no secrets, and repeated configuration adds no handlers.
"""

from __future__ import annotations

import logging
import os
import re

from main import configure_logging


class TestFileLogging:
    def test_record_lands_in_file_with_timestamp_and_pid(self, tmp_path):
        log_file = configure_logging(tmp_path / "logs")
        logging.getLogger("patchpilot.test").info(
            "Scan %s node %s status=%s", "abc123", "tester", "verifying")
        for handler in logging.getLogger().handlers:
            try:
                handler.flush()
            except Exception:
                pass
        text = log_file.read_text(encoding="utf-8")
        assert "tester" in text and "abc123" in text
        assert f"pid={os.getpid()}" in text
        assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", text)

    def test_no_duplicate_file_handlers(self, tmp_path):
        first = configure_logging(tmp_path / "logs")
        second = configure_logging(tmp_path / "logs")
        assert first == second
        root = logging.getLogger()
        assert sum(getattr(h, "_sentinel_file", None) == str(first)
                   for h in root.handlers) == 1

    def test_format_has_no_secret_values(self, tmp_path, monkeypatch):
        """Secrets that reach a log call are masked in the file.

        The original assertion (`getenv(var, "") not in text or
        getenv(var) == ""`) was vacuous: with a key unset it compared ""
        and always failed; with a key set it never logged the key, so a
        leak could not be detected. Here fake keys are logged on purpose.
        """
        fakes = {"GROQ_API_KEY": "gsk_FAKEgroqKEY1234567890",
                 "GEMINI_API_KEY": "AIzaFAKEgeminiKEY1234567890ab",
                 "OPENROUTER_API_KEY": "sk-or-v1-FAKEopenrouter123456",
                 "GITHUB_TOKEN": "ghp_FAKEgithubTOKEN1234567890abcd"}
        for var, value in fakes.items():
            monkeypatch.setenv(var, value)
        log_file = configure_logging(tmp_path / "logs")
        log = logging.getLogger("patchpilot.test")
        log.info("Sandbox: docker (image %s, reused)", "pp-deps-abc123")
        for value in fakes.values():
            log.error("provider error: 401 invalid key %s", value)
        # A rotated key that is NOT in this process's env still has a
        # recognisable shape (this exact case reached the real log file).
        log.error("Error code: 401 - invalid_api_key gsk_secret_xyz")
        log.info("clone https://user:%s@github.com/x/y.git",
                 "ghp_FAKEgithubTOKEN1234567890abcd")
        _flush()
        text = log_file.read_text(encoding="utf-8")
        assert "pp-deps-abc123" in text
        for value in fakes.values():
            assert value not in text
        assert "gsk_secret_xyz" not in text
        assert "***" in text

    def test_user_values_cannot_forge_log_lines(self, tmp_path):
        log_file = configure_logging(tmp_path / "logs")
        logging.getLogger("patchpilot.test").info(
            "Scan %s started for %s", "abc12345",
            "https://x.io/r\n2026-01-01 00:00:00 pid=1 ERROR forged line")
        _flush()
        lines = [l for l in log_file.read_text(encoding="utf-8").splitlines()
                 if "abc12345" in l or "forged line" in l]
        assert len(lines) == 1 and "\\n" in lines[0]

    def test_tracebacks_are_redacted(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_TRACEBACKtoken1234567890abc")
        log_file = configure_logging(tmp_path / "logs")
        try:
            raise RuntimeError("push failed for ghp_TRACEBACKtoken1234567890abc")
        except RuntimeError:
            logging.getLogger("patchpilot.test").exception("PR push failed")
        _flush()
        text = log_file.read_text(encoding="utf-8")
        assert "PR push failed" in text and "Traceback" in text
        assert "ghp_TRACEBACKtoken1234567890abc" not in text


def _flush() -> None:
    for handler in logging.getLogger().handlers:
        try:
            handler.flush()
        except Exception:
            pass
