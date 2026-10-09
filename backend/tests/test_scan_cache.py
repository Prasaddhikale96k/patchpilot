"""Tests for the per-file scan cache (prompt 00a: Reviewer re-scan support)."""

from __future__ import annotations

from tools import scan_cache


class TestScanCache:
    def test_repeat_scan_hits_cache(self, tmp_path):
        target = tmp_path / "a.py"
        target.write_text("x = 1\n")
        calls = {"n": 0}

        def runner():
            calls["n"] += 1
            return [{"file": "a.py"}]

        first = scan_cache.cached_scan("k", str(target), runner)
        second = scan_cache.cached_scan("k", str(target), runner)
        assert first == second == [{"file": "a.py"}]
        assert calls["n"] == 1

    def test_changed_file_misses_cache(self, tmp_path):
        target = tmp_path / "a.py"
        target.write_text("x = 1\n")
        calls = {"n": 0}

        def runner():
            calls["n"] += 1
            return [{"n": calls["n"]}]

        scan_cache.cached_scan("k2", str(target), runner)
        target.write_text("x = 2\n")
        assert scan_cache.cached_scan("k2", str(target), runner) == [{"n": 2}]
        assert calls["n"] == 2

    def test_invalidate(self, tmp_path):
        target = tmp_path / "a.py"
        target.write_text("x = 1\n")
        calls = {"n": 0}

        def runner():
            calls["n"] += 1
            return []

        scan_cache.cached_scan("k3", str(target), runner)
        scan_cache.invalidate("k3")
        scan_cache.cached_scan("k3", str(target), runner)
        assert calls["n"] == 2
