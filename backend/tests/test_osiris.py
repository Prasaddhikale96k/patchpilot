"""
Tests for the OSIRIS OSINT enrichment client.

The network is stubbed throughout — the suite must not depend on osirisai.live
being up, and these tests are about how PatchPilot handles the answers, not
about what the upstream datasets currently say.

Two behaviours carry most of the weight:

  * a lookup that partly fails still returns what the other sources gave, since
    the OSIRIS docs are explicit that its routes proxy third parties and that
    upstream failure is ordinary; and
  * a CVE id that exists nowhere is reported as not found, even though the
    upstream answers 200 with a placeholder body. Dressing an unknown id up as
    a confirmed record is exactly the failure this project already fixed once
    on the model side.
"""

from __future__ import annotations

import pytest

from tools import osiris


class _Resp:
    """Minimal stand-in for a requests.Response."""

    def __init__(self, payload, status_code=200, json_error=False):
        self._payload = payload
        self.status_code = status_code
        self.ok = 200 <= status_code < 300
        self._json_error = json_error

    def json(self):
        if self._json_error:
            raise ValueError("not JSON")
        return self._payload


IP_OK = {
    "ip": "8.8.8.8",
    "geo": {"country": "United States", "city": "Ashburn", "lat": 39.03, "lon": -77.5,
            "as_number": "AS15169 Google LLC", "org": "Google LLC"},
    "reputation": {"is_proxy": False, "is_hosting": True, "risk_level": "MEDIUM"},
    "sanctions_match": None,
}
SHODAN_OK = {"ports": [22, 80, 443], "hostnames": ["host.example"], "cpes": [],
             "vulns": ["CVE-2021-2471"], "tags": []}
THREATS_OK = {"threat_level": "LOW", "tor_exit_node": False,
              "otx": {"reputation": 0, "pulse_count": 0}}


def _route_of(url: str) -> str:
    return url.rsplit("/api/osint/", 1)[-1]


def _stub(monkeypatch, responses: dict, recorder: list | None = None):
    """Map each OSINT route name to a _Resp or an exception to raise."""

    def fake_get(url, params=None, timeout=None, headers=None):
        route = _route_of(url)
        if recorder is not None:
            recorder.append((route, dict(params or {})))
        outcome = responses[route]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(osiris.requests, "get", fake_get)


@pytest.fixture(autouse=True)
def clean_cache_and_env(monkeypatch):
    osiris.clear_cache()
    monkeypatch.delenv("OSIRIS_ENABLED", raising=False)
    monkeypatch.delenv("OSIRIS_URL", raising=False)
    yield
    osiris.clear_cache()


class TestIpIntel:
    def test_merges_all_three_sources(self, monkeypatch):
        _stub(monkeypatch, {
            "ip": _Resp(IP_OK),
            "shodan": _Resp(SHODAN_OK),
            "threats": _Resp(THREATS_OK),
        })
        intel = osiris.ip_intel("8.8.8.8")

        assert intel["geo"]["city"] == "Ashburn"
        assert intel["reputation"]["risk_level"] == "MEDIUM"
        assert intel["exposure"]["ports"] == [22, 80, 443]
        assert intel["exposure"]["vulns"] == ["CVE-2021-2471"]
        assert intel["threat"]["threat_level"] == "LOW"
        assert intel["partial"] is False
        assert intel["sources"] == {"ip": "ok", "shodan": "ok", "threats": "ok"}

    def test_each_route_gets_the_parameter_it_reads(self, monkeypatch):
        # `threats` ignores `indicator` and `ioc` and answers about nothing, so
        # the parameter names are part of the contract, not a detail.
        calls: list = []
        _stub(monkeypatch, {
            "ip": _Resp(IP_OK), "shodan": _Resp(SHODAN_OK), "threats": _Resp(THREATS_OK),
        }, recorder=calls)
        osiris.ip_intel("8.8.8.8")

        params = dict(calls)
        assert params["ip"] == {"ip": "8.8.8.8"}
        assert params["shodan"] == {"ip": "8.8.8.8"}
        assert params["threats"] == {"query": "8.8.8.8"}

    def test_one_dead_source_does_not_lose_the_others(self, monkeypatch):
        _stub(monkeypatch, {
            "ip": _Resp(IP_OK),
            "shodan": osiris.RequestException("connection reset"),
            "threats": _Resp(THREATS_OK),
        })
        intel = osiris.ip_intel("8.8.8.8")

        assert intel["geo"]["city"] == "Ashburn"
        assert intel["threat"]["threat_level"] == "LOW"
        assert intel["exposure"] is None
        assert intel["partial"] is True
        assert intel["sources"]["shodan"].startswith("unreachable")

    def test_upstream_error_key_is_reported_not_returned_as_data(self, monkeypatch):
        _stub(monkeypatch, {
            "ip": _Resp({"error": "Missing ip parameter"}),
            "shodan": _Resp(SHODAN_OK),
            "threats": _Resp(THREATS_OK),
        })
        intel = osiris.ip_intel("8.8.8.8")

        assert intel["geo"] is None
        assert intel["sources"]["ip"] == "Missing ip parameter"
        assert intel["partial"] is True

    def test_rate_limit_and_http_error_are_named(self, monkeypatch):
        _stub(monkeypatch, {
            "ip": _Resp(None, status_code=429),
            "shodan": _Resp(None, status_code=502),
            "threats": _Resp(None, json_error=True),
        })
        intel = osiris.ip_intel("8.8.8.8")

        assert intel["sources"]["ip"] == "rate limited by OSIRIS"
        assert intel["sources"]["shodan"] == "upstream returned HTTP 502"
        assert intel["sources"]["threats"] == "upstream returned a non-JSON body"

    @pytest.mark.parametrize("ip", [
        "127.0.0.1",        # loopback — the machine that ran the scan
        "10.0.0.5",         # RFC 1918
        "192.168.1.10",     # RFC 1918
        "169.254.169.254",  # cloud metadata
        "203.0.113.9",      # TEST-NET-3: documentation range, no real host
        "::1",              # loopback, v6
        "not-an-ip",
        "",
    ])
    def test_addresses_with_no_external_record_are_refused(self, monkeypatch, ip):
        # No stub: a refused address must not reach the network at all.
        def explode(*a, **k):
            raise AssertionError("no request should be made")
        monkeypatch.setattr(osiris.requests, "get", explode)

        with pytest.raises(ValueError):
            osiris.ip_intel(ip)


class TestCaching:
    def test_second_lookup_is_served_from_cache(self, monkeypatch):
        calls: list = []
        _stub(monkeypatch, {
            "ip": _Resp(IP_OK), "shodan": _Resp(SHODAN_OK), "threats": _Resp(THREATS_OK),
        }, recorder=calls)

        first = osiris.ip_intel("8.8.8.8")
        second = osiris.ip_intel("8.8.8.8")

        assert first["cached"] is False
        assert second["cached"] is True
        assert len(calls) == 3  # one round, not two

    def test_a_total_failure_is_not_cached(self, monkeypatch):
        # Caching "everything was down" would hide a recovered upstream for the
        # next quarter of an hour.
        calls: list = []
        _stub(monkeypatch, {
            "ip": osiris.RequestException("down"),
            "shodan": osiris.RequestException("down"),
            "threats": osiris.RequestException("down"),
        }, recorder=calls)

        osiris.ip_intel("8.8.8.8")
        osiris.ip_intel("8.8.8.8")

        assert len(calls) == 6  # tried again rather than replaying the outage

    def test_expiry_releases_the_entry(self, monkeypatch):
        calls: list = []
        _stub(monkeypatch, {
            "ip": _Resp(IP_OK), "shodan": _Resp(SHODAN_OK), "threats": _Resp(THREATS_OK),
        }, recorder=calls)

        osiris.ip_intel("8.8.8.8")
        clock = [osiris.time.monotonic() + osiris.CACHE_TTL + 1]
        monkeypatch.setattr(osiris.time, "monotonic", lambda: clock[0])
        osiris.ip_intel("8.8.8.8")

        assert len(calls) == 6


class TestCveRecord:
    def test_returns_the_upstream_record(self, monkeypatch):
        monkeypatch.setattr(osiris.requests, "get", lambda *a, **k: _Resp({
            "id": "CVE-2021-44228",
            "description": "Apache Log4j2 JNDI remote code execution.",
            "cwe": "CWE-502",
            "references": ["https://logging.apache.org/log4j/2.x/security.html"],
            "published": "2021-12-10T00:00:00.000Z",
            "source": "mitre",
        }))
        record = osiris.cve_record("CVE-2021-44228")

        assert record["found"] is True
        assert record["cwe"] == "CWE-502"
        assert record["references"] == ["https://logging.apache.org/log4j/2.x/security.html"]

    def test_placeholder_body_is_not_a_hit(self, monkeypatch):
        # An id that exists nowhere still answers 200, carrying this and nothing
        # else. Reporting it as found would imply the identifier was confirmed.
        monkeypatch.setattr(osiris.requests, "get", lambda *a, **k: _Resp({
            "id": "CVE-1999-99999",
            "description": "No description available.",
            "references": [],
            "published": None,
            "source": "circl",
        }))
        record = osiris.cve_record("CVE-1999-99999")

        assert record["found"] is False
        assert record["description"] is None

    def test_id_is_lifted_out_of_the_port_scanner_label(self, monkeypatch):
        # The port risk database labels its ids: "CVE-1999-0497 (anonymous FTP
        # login allowed)". The label must not be sent upstream verbatim.
        seen: dict = {}

        def fake_get(url, params=None, **k):
            seen.update(params or {})
            return _Resp({"id": "CVE-1999-0497", "description": "Anonymous FTP.", "references": []})

        monkeypatch.setattr(osiris.requests, "get", fake_get)
        record = osiris.cve_record("CVE-1999-0497 (anonymous FTP login allowed)")

        assert seen == {"cve": "CVE-1999-0497"}
        assert record["found"] is True

    @pytest.mark.parametrize("value", ["", "CVE-XXXX-XXXX", "not a cve", "CVE-2021", "2021-44228"])
    def test_malformed_identifiers_are_refused(self, monkeypatch, value):
        def explode(*a, **k):
            raise AssertionError("no request should be made")
        monkeypatch.setattr(osiris.requests, "get", explode)

        with pytest.raises(ValueError):
            osiris.cve_record(value)

    def test_unreachable_upstream_is_reported_not_raised(self, monkeypatch):
        monkeypatch.setattr(osiris.requests, "get",
                            lambda *a, **k: (_ for _ in ()).throw(osiris.RequestException("down")))
        record = osiris.cve_record("CVE-2021-44228")

        assert record["found"] is False
        assert record["error"].startswith("unreachable")


class TestConfiguration:
    def test_disabled_by_env(self, monkeypatch):
        monkeypatch.setenv("OSIRIS_ENABLED", "false")
        assert osiris.is_enabled() is False
        with pytest.raises(osiris.OsirisDisabledError):
            osiris.ip_intel("8.8.8.8")
        with pytest.raises(osiris.OsirisDisabledError):
            osiris.cve_record("CVE-2021-44228")

    def test_self_hosted_instance_is_honoured(self, monkeypatch):
        monkeypatch.setenv("OSIRIS_URL", "http://localhost:3000/")
        seen: list = []

        def fake_get(url, **k):
            seen.append(url)
            return _Resp(IP_OK if "/ip" in url else SHODAN_OK if "shodan" in url else THREATS_OK)

        monkeypatch.setattr(osiris.requests, "get", fake_get)
        osiris.ip_intel("8.8.8.8")

        assert all(u.startswith("http://localhost:3000/api/osint/") for u in seen)

    def test_map_link_carries_the_located_coordinates(self, monkeypatch):
        _stub(monkeypatch, {
            "ip": _Resp(IP_OK), "shodan": _Resp(SHODAN_OK), "threats": _Resp(THREATS_OK),
        })
        intel = osiris.ip_intel("8.8.8.8")
        assert intel["map_url"] == "https://osirisai.live/?lat=39.0300&lon=-77.5000&zoom=8"

    def test_map_link_falls_back_when_the_address_was_not_located(self, monkeypatch):
        _stub(monkeypatch, {
            "ip": _Resp({"geo": None}), "shodan": _Resp(SHODAN_OK), "threats": _Resp(THREATS_OK),
        })
        intel = osiris.ip_intel("8.8.8.8")
        assert intel["map_url"] == "https://osirisai.live/"


class TestFindingsCarryThePivotData:
    """
    The address the port scanner resolved has to survive into the report, or the
    UI has nothing to pivot on. It is dropped silently if the mapping in
    vuln_analyzer_node forgets it, and the failure looks like a missing button
    rather than an error.
    """

    def _analyze(self, monkeypatch, host: str, resolves_to: str):
        from agents import orchestrator
        from tools import port_scanner

        monkeypatch.setattr(port_scanner.socket, "gethostbyname", lambda h: resolves_to)
        monkeypatch.setattr(port_scanner, "_probe_port",
                            lambda ip, port: (port, port == 3306, "mysql 5.7"))

        class _Response:
            content = "[]"

        monkeypatch.setattr(orchestrator, "invoke_llm", lambda *a, **k: _Response())
        raw = port_scanner.scan_ports(host)
        result = orchestrator.vuln_analyzer_node({"raw_findings": raw, "scan_id": "t"})
        return next(v for v in result["vulnerabilities"] if v["id"] == "PORT-3306")

    def test_public_finding_keeps_the_resolved_address(self, monkeypatch):
        vuln = self._analyze(monkeypatch, "db.example.com", "8.8.8.8")
        assert vuln["ip"] == "8.8.8.8"
        assert vuln["loopback"] is False
        assert osiris.extract_cve_id(vuln["cve"]) is not None

    def test_loopback_finding_is_flagged_so_the_ui_can_hide_the_pivot(self, monkeypatch):
        vuln = self._analyze(monkeypatch, "localhost", "127.0.0.1")
        assert vuln["loopback"] is True
        # And the module would refuse it anyway, so the two agree.
        with pytest.raises(ValueError):
            osiris.ip_intel(vuln["ip"])
