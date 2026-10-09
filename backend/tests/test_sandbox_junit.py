"""Tests for JUnit parsing (prompt 04a): counts, names, messages."""

from __future__ import annotations

from tools.sandbox import parse_junit

PASS_XML = """<?xml version="1.0" encoding="utf-8"?>
<testsuite tests="2" failures="0" errors="0" skipped="0" time="0.5">
  <testcase classname="test_a" name="test_one" time="0.2"/>
  <testcase classname="test_a" name="test_two" time="0.3"/>
</testsuite>"""

FAIL_XML = """<?xml version="1.0" encoding="utf-8"?>
<testsuite tests="2" failures="1" errors="0" skipped="0" time="0.5">
  <testcase classname="test_a" name="test_one" time="0.2"/>
  <testcase classname="test_b" name="test_two" time="0.3">
    <failure message="assert False">def test_two():\n&gt; assert False</failure>
  </testcase>
</testsuite>"""

ERROR_XML = """<?xml version="1.0" encoding="utf-8"?>
<testsuite tests="1" failures="0" errors="1" skipped="0" time="0.1">
  <testcase classname="test_c" name="test_boom" time="0.1">
    <error message="collection error">ModuleNotFoundError: nope</error>
  </testcase>
</testsuite>"""

SKIP_XML = """<?xml version="1.0" encoding="utf-8"?>
<testsuite tests="2" failures="0" errors="0" skipped="1" time="0.2">
  <testcase classname="test_d" name="test_run" time="0.2"/>
  <testcase classname="test_d" name="test_skip" time="0.0">
    <skipped message="no docker"/>
  </testcase>
</testsuite>"""


def _write(tmp_path, text):
    target = tmp_path / "junit.xml"
    target.write_text(text)
    return str(target)


class TestParseJUnit:
    def test_all_pass(self, tmp_path):
        report = parse_junit(_write(tmp_path, PASS_XML), "after", "2 passed",
                             0.5, "docker")
        assert (report["total"], report["passed"], report["failed"],
                report["errors"], report["skipped"]) == (2, 2, 0, 0, 0)
        assert report["passed_names"] == ["test_a::test_one",
                                          "test_a::test_two"]
        assert report["failed_tests"] == []
        assert report["sandbox"] == "docker" and report["timed_out"] is False

    def test_one_failure(self, tmp_path):
        report = parse_junit(_write(tmp_path, FAIL_XML), "after",
                             "1 failed, 1 passed", 0.5, "docker")
        assert (report["total"], report["passed"], report["failed"]) == (2, 1, 1)
        assert report["passed_names"] == ["test_a::test_one"]
        assert len(report["failed_tests"]) == 1
        assert report["failed_tests"][0]["name"] == "test_b::test_two"
        assert "assert False" in report["failed_tests"][0]["message"]

    def test_error_counts(self, tmp_path):
        report = parse_junit(_write(tmp_path, ERROR_XML), "after", "1 error",
                             0.1, "venv")
        assert (report["total"], report["errors"]) == (1, 1)
        assert report["failed_tests"][0]["name"] == "test_c::test_boom"

    def test_skipped_counts(self, tmp_path):
        report = parse_junit(_write(tmp_path, SKIP_XML), "after",
                             "1 passed, 1 skipped", 0.2, "docker")
        assert (report["total"], report["passed"], report["skipped"]) == (2, 1, 1)

    def test_missing_xml_falls_back_to_summary(self, tmp_path):
        report = parse_junit(str(tmp_path / "nope.xml"), "after",
                             "3 passed, 2 failed in 1.2s", 1.2, "venv")
        assert (report["total"], report["passed"], report["failed"]) == (5, 3, 2)
        assert report["output_tail"].endswith("in 1.2s")
