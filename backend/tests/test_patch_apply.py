"""Tests for the SEARCH/REPLACE patch parser + applier (prompt 03)."""

from __future__ import annotations

import pytest

from tools.patch_apply import (PatchApplyError, apply_blocks, parse_blocks)


def _patch_text(file="app/x.py", search="aaa", replace="bbb"):
    return (f"FILE: {file}\n<<<<<<< SEARCH\n{search}\n=======\n"
            f"{replace}\n>>>>>>> REPLACE\n")


class TestParse:
    def test_single_block_parsed(self):
        blocks = parse_blocks(_patch_text())
        assert len(blocks) == 1
        assert blocks[0].file == "app/x.py"
        assert blocks[0].search.strip() == "aaa"
        assert blocks[0].replace.strip() == "bbb"

    def test_empty_text_raises(self):
        with pytest.raises(PatchApplyError, match="No FILE:"):
            parse_blocks("nothing here")


class TestApply:
    def test_exact_match(self, tmp_path):
        target = tmp_path / "x.py"
        target.write_text("aaa\nccc\n")
        result = apply_blocks(str(tmp_path),
                              parse_blocks(_patch_text("x.py", "aaa", "bbb")))
        assert target.read_text() == "bbb\nccc\n"
        assert result.files_changed == ["x.py"]
        assert "+bbb" in result.diff and "-aaa" in result.diff
        assert result.lines_added == 1 and result.lines_removed == 1

    def test_whitespace_tolerant_match(self, tmp_path):
        target = tmp_path / "x.py"
        target.write_text("    aaa   \nccc\n")
        result = apply_blocks(str(tmp_path),
                              parse_blocks(_patch_text("x.py", "aaa", "bbb")))
        assert "bbb" in target.read_text()
        assert result.files_changed == ["x.py"]

    def test_ambiguous_match_rejected(self, tmp_path):
        target = tmp_path / "x.py"
        target.write_text("aaa\naaa\n")
        with pytest.raises(PatchApplyError, match="exactly once"):
            apply_blocks(str(tmp_path),
                         parse_blocks(_patch_text("x.py", "aaa", "bbb")))

    def test_missing_block_reports_closest_lines(self, tmp_path):
        target = tmp_path / "x.py"
        target.write_text("alpha = 1\nbeta = 2\ngamma = 3\n")
        with pytest.raises(PatchApplyError, match="Closest lines"):
            apply_blocks(str(tmp_path),
                         parse_blocks(_patch_text("x.py", "zzz = 9", "q")))

    def test_new_file_created(self, tmp_path):
        result = apply_blocks(
            str(tmp_path),
            parse_blocks("FILE: tests/test_new.py\n<<<<<<< SEARCH\n\n=======\n"
                         "def test_x():\n    assert True\n>>>>>>> REPLACE\n"))
        assert (tmp_path / "tests" / "test_new.py").exists()
        assert result.files_changed == ["tests/test_new.py"]

    def test_path_escape_rejected(self, tmp_path):
        with pytest.raises(PatchApplyError, match="outside the repo"):
            apply_blocks(str(tmp_path),
                         parse_blocks(_patch_text("../../etc/x", "a", "b")))
