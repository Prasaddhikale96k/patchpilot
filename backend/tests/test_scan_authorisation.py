"""
Tests for the port-scan authorisation guard.

Reading a website's headers is what every browser does. Connecting to 25 ports
on a host is not: against a host the operator does not control it is
unauthorised testing. The scan box accepts any URL, so the tool has to hold
that line itself rather than trusting whoever is typing.
"""

from __future__ import annotations

import pytest

from agents import orchestrator
from tools import scan_authorisation
from tools.scan_authorisation import is_authorised, refusal_reason


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("AUTHORISED_SCAN_TARGETS", raising=False)
    monkeypatch.delenv("ALLOW_PRIVATE_TARGETS", raising=False)


class TestNothingIsAuthorisedByDefault:
    def test_a_third_party_host_is_refused(self):
        assert is_authorised("google.com") is False

    def test_even_your_own_site_needs_declaring(self):
        """GitHub Pages is GitHub's infrastructure, not the author's."""
        assert is_authorised("example-user.github.io") is False

    def test_the_reason_says_how_to_authorise(self):
        reason = refusal_reason("google.com")
        assert "AUTHORISED_SCAN_TARGETS" in reason
        assert "HTTP checks were still performed" in reason


class TestExactMatching:
    def test_a_listed_host_is_authorised(self, monkeypatch):
        monkeypatch.setenv("AUTHORISED_SCAN_TARGETS", "staging.example.com")
        assert is_authorised("staging.example.com") is True

    def test_matching_is_case_and_dot_insensitive(self, monkeypatch):
        monkeypatch.setenv("AUTHORISED_SCAN_TARGETS", "Staging.Example.com")
        assert is_authorised("staging.example.com.") is True

    def test_a_sibling_host_is_not_covered(self, monkeypatch):
        monkeypatch.setenv("AUTHORISED_SCAN_TARGETS", "staging.example.com")
        assert is_authorised("prod.example.com") is False

    def test_an_exact_entry_does_not_grant_subdomains(self, monkeypatch):
        """Authorising a site must not silently authorise everything under it."""
        monkeypatch.setenv("AUTHORISED_SCAN_TARGETS", "example.com")
        assert is_authorised("api.example.com") is False

    def test_a_suffix_lookalike_is_refused(self, monkeypatch):
        monkeypatch.setenv("AUTHORISED_SCAN_TARGETS", "example.com")
        assert is_authorised("notexample.com") is False

    def test_multiple_entries(self, monkeypatch):
        monkeypatch.setenv("AUTHORISED_SCAN_TARGETS", "a.example.com, b.example.com")
        assert is_authorised("b.example.com") is True


class TestWildcards:
    def test_subdomains_are_covered(self, monkeypatch):
        monkeypatch.setenv("AUTHORISED_SCAN_TARGETS", "*.example.com")
        assert is_authorised("api.example.com") is True

    def test_deeper_subdomains_are_covered(self, monkeypatch):
        monkeypatch.setenv("AUTHORISED_SCAN_TARGETS", "*.example.com")
        assert is_authorised("a.b.example.com") is True

    def test_the_apex_is_not_covered_by_a_wildcard(self, monkeypatch):
        monkeypatch.setenv("AUTHORISED_SCAN_TARGETS", "*.example.com")
        assert is_authorised("example.com") is False

    def test_a_different_domain_is_not_covered(self, monkeypatch):
        monkeypatch.setenv("AUTHORISED_SCAN_TARGETS", "*.example.com")
        assert is_authorised("example.com.evil.net") is False


class TestPrivateTargets:
    """ALLOW_PRIVATE_TARGETS already means "I am testing my own machine"."""

    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "192.168.1.10", "10.0.0.5"])
    def test_private_hosts_follow_the_existing_opt_in(self, monkeypatch, host):
        monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "true")
        assert is_authorised(host) is True

    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
    def test_without_the_opt_in_they_are_refused(self, host):
        assert is_authorised(host) is False

    def test_a_public_host_is_not_authorised_by_the_private_flag(self, monkeypatch):
        monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "true")
        assert is_authorised("google.com") is False


class TestTheScannerHonoursIt:
    def _scan(self, monkeypatch, final_url="https://google.com/"):
        import tools.website_scanner as ws
        import tools.port_scanner as ps

        called = []

        def _fake_scan_website(url, meta=None):
            if meta is not None:
                meta["final_url"] = final_url
                meta["cdn"] = None
            return [{"source": "website", "file": url, "line": 0,
                     "severity": "LOW", "description": "header thing"}]

        monkeypatch.setattr(ws, "scan_website", _fake_scan_website)
        # _scan_website imports scan_ports from the module at call time, so
        # patching it there is what actually intercepts the port scan.
        monkeypatch.setattr(ps, "scan_ports", lambda *a, **k: called.append(a) or [])
        result = orchestrator._scan_website(
            {"repo_url": "https://google.com/", "scan_id": "t"})
        return result, called

    def test_ports_are_not_probed_without_authorisation(self, monkeypatch):
        result, called = self._scan(monkeypatch)
        assert called == [], "scan_ports must not run"
        assert any("Port scan skipped" in line for line in result["agent_logs"])

    def test_http_checks_still_run(self, monkeypatch):
        """Refusing to port scan must not refuse the whole scan."""
        result, _ = self._scan(monkeypatch)
        assert len(result["raw_findings"]) == 1

    def test_an_authorised_host_is_scanned(self, monkeypatch):
        monkeypatch.setenv("AUTHORISED_SCAN_TARGETS", "google.com")
        result, called = self._scan(monkeypatch)
        assert called, "scan_ports should have run"
        assert any("is an authorised target" in line for line in result["agent_logs"])

    def test_authorisation_follows_the_redirect_destination(self, monkeypatch):
        """
        Authorising example.com must not let a redirect move the port scan
        onto a host that was never authorised.
        """
        monkeypatch.setenv("AUTHORISED_SCAN_TARGETS", "google.com")
        result, called = self._scan(monkeypatch, final_url="https://www.google.com/")
        assert called == []
        assert any("www.google.com is not in" in line for line in result["agent_logs"])

    def test_no_misleading_all_clear_when_skipped(self, monkeypatch):
        """"No high-risk ports open" would imply ports were checked."""
        result, _ = self._scan(monkeypatch)
        assert not any("No common high-risk ports" in line
                       for line in result["agent_logs"])
