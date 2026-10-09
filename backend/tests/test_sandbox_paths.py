"""Tests for Docker volume path conversion (prompt 04a)."""

from __future__ import annotations

import os

import pytest

from tools.sandbox import host_path_for_docker


@pytest.mark.skipif(os.name != "nt", reason="Windows only")
def test_windows_path_to_forward_slashes():
    assert host_path_for_docker("C:\\Users\\x\\repo") == "C:/Users/x/repo"


def test_posix_path_unchanged(tmp_path):
    assert host_path_for_docker(str(tmp_path)) == tmp_path.resolve().as_posix()


def test_no_backslashes_in_result(tmp_path):
    assert "\\" not in host_path_for_docker(str(tmp_path))
