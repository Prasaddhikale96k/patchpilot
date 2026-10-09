"""
Per-file Semgrep result cache (prompt 00a).

The Reviewer (prompt 05) re-scans only changed files after every attempt.
Re-running the whole ruleset per attempt is the most expensive repeated work
in the loop, and unchanged files cannot change their findings — so results
are cached by SHA-256 of file contents and reused while the hash matches.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Callable

logger = logging.getLogger(__name__)

_cache: dict[str, tuple[str, list[dict]]] = {}  # cache_key -> (file_hash, findings)


def _hash_file(path: str) -> str | None:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def cached_scan(cache_key: str, file_path: str, runner: Callable[[], list[dict]],
                ) -> list[dict]:
    """
    Run runner() (a zero-arg scan of one file) unless the file hash matches
    the cached entry for cache_key. Returns cached findings on a hit.
    """
    file_hash = _hash_file(file_path)
    if file_hash is not None:
        hit = _cache.get(cache_key)
        if hit is not None and hit[0] == file_hash:
            logger.debug("scan_cache: hit for %s", cache_key)
            return hit[1]
    findings = runner()
    if file_hash is not None:
        _cache[cache_key] = (file_hash, findings)
    return findings


def invalidate(cache_key: str | None = None) -> None:
    """Drop one entry (or the whole cache when cache_key is None)."""
    if cache_key is None:
        _cache.clear()
    else:
        _cache.pop(cache_key, None)
