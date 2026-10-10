"""
OSIRIS enrichment — third-party OSINT for an address a scan turned up.

OSIRIS (osirisai.live) exposes keyless GET endpoints for passive lookups. Three
of them describe an address: /api/osint/ip (geolocation, ASN, network owner),
/api/osint/shodan (services and known vulnerabilities seen from outside), and
/api/osint/threats (reputation, Tor exit status, OTX pulses). A fourth,
/api/osint/cve, returns the upstream record for a single CVE id.

Two reasons this is a server-side module rather than a fetch from the browser:
OSIRIS sends no Access-Control-Allow-Origin header, so a page on our origin
cannot read the response; and routing it through here keeps scan targets out of
the client and lets one lookup be cached for every viewer of a report.

Only passive routes are used. OSIRIS also publishes /api/osint/sweep and
/api/scanner, which generate traffic against the named target — PatchPilot does
its own active scanning under its own authorisation checks, so those stay
unused here.

Every lookup is best-effort. The OSIRIS docs are explicit that its routes proxy
third parties and that upstream failure is normal, so a source that does not
answer is reported as absent rather than turned into a failed request.
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone

import requests
from requests.exceptions import RequestException

from .url_guard import is_public_ip

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://osirisai.live"

# Geolocation, ASN ownership and breach corpora move slowly, and a report is
# usually opened more than once. The OSIRIS docs ask callers not to poll faster
# than the route's own TTL; this sits comfortably above all of them.
CACHE_TTL = 900.0  # seconds
_CACHE_MAX = 512

# CVE-YYYY-NNNN anywhere in a string. The port scanner labels its ids with a
# parenthetical — "CVE-1999-0497 (anonymous FTP login allowed)" — so the bare
# identifier has to be lifted out before it can be looked up.
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# A CVE id that exists nowhere upstream still comes back 200, carrying this
# placeholder and nothing else. Reporting that as a real record would put an
# empty NVD entry behind a finding and imply the id was confirmed.
_NO_RECORD = "no description available"


class OsirisDisabledError(RuntimeError):
    """Raised when the integration is switched off by configuration."""


def _base_url() -> str:
    return os.getenv("OSIRIS_URL", DEFAULT_BASE_URL).rstrip("/")


def _timeout() -> float:
    try:
        return float(os.getenv("OSIRIS_TIMEOUT", "8"))
    except ValueError:
        return 8.0


def is_enabled() -> bool:
    """
    OSIRIS_ENABLED=false takes the integration out of the product: the API
    refuses the lookup and the UI stops offering it.
    """
    return os.getenv("OSIRIS_ENABLED", "true").lower() not in ("0", "false", "no")


def extract_cve_id(value: object) -> str | None:
    """The bare CVE id inside a label, or None if there is not one."""
    if not isinstance(value, str):
        return None
    match = _CVE_RE.search(value)
    return match.group(0).upper() if match else None


# ── Cache ─────────────────────────────────────────────────────────────────────

_cache: dict[tuple[str, str], tuple[float, dict]] = {}
_cache_lock = threading.Lock()


def _cache_get(key: tuple[str, str]) -> dict | None:
    with _cache_lock:
        entry = _cache.get(key)
        if entry is None:
            return None
        stored_at, payload = entry
        if time.monotonic() - stored_at > CACHE_TTL:
            del _cache[key]
            return None
        return payload


def _cache_put(key: tuple[str, str], payload: dict) -> None:
    with _cache_lock:
        if len(_cache) >= _CACHE_MAX:
            oldest = min(_cache, key=lambda k: _cache[k][0])
            del _cache[oldest]
        _cache[key] = (time.monotonic(), payload)


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()


# ── Transport ─────────────────────────────────────────────────────────────────

def _get(path: str, params: dict) -> tuple[dict | None, str | None]:
    """
    One OSIRIS GET. Returns (payload, error) with exactly one side populated.

    An upstream that is down, slow or refusing is an ordinary outcome here, not
    an exception to propagate: the caller reports the source as unavailable and
    still returns whatever the other sources gave it.
    """
    url = f"{_base_url()}{path}"
    # Resolved into a local first: bandit's B113 cannot see a timeout supplied
    # by a call expression and reports the request as having none.
    timeout = _timeout()
    try:
        resp = requests.get(
            url,
            params=params,
            timeout=timeout,
            headers={"User-Agent": "PatchPilot/1.0 (+https://github.com/Prasaddhikale96k/patchpilot)"},
        )
    except RequestException as exc:
        logger.info("osiris: %s unreachable: %s", path, exc)
        return None, f"unreachable: {exc.__class__.__name__}"

    if resp.status_code == 429:
        return None, "rate limited by OSIRIS"
    if not resp.ok:
        return None, f"upstream returned HTTP {resp.status_code}"

    try:
        payload = resp.json()
    except ValueError:
        return None, "upstream returned a non-JSON body"

    if not isinstance(payload, dict):
        return None, "upstream returned an unexpected shape"
    # Their convention: a failure carries an `error` key alongside any detail.
    if payload.get("error"):
        detail = payload.get("detail")
        return None, f"{payload['error']}{f': {detail}' if detail else ''}"
    return payload, None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ── Lookups ───────────────────────────────────────────────────────────────────

def ip_intel(ip: str) -> dict:
    """
    Everything the passive OSIRIS routes know about one address.

    Raises ValueError for an address no external dataset could describe — a
    private or loopback address is the scanning machine's own network, and
    OSIRIS would answer about the wrong host or not at all.
    """
    if not is_enabled():
        raise OsirisDisabledError("OSIRIS lookups are disabled (OSIRIS_ENABLED=false)")
    ip = (ip or "").strip()
    if not is_public_ip(ip):
        raise ValueError(
            f"'{ip}' is not a public address. OSIRIS describes hosts on the public "
            f"internet; a private or loopback address is local to the machine that "
            f"ran the scan and has no external record."
        )

    cached = _cache_get(("ip", ip))
    if cached is not None:
        return {**cached, "cached": True}

    # Three independent upstreams, so they run together rather than in series.
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        jobs = {
            "ip":      pool.submit(_get, "/api/osint/ip", {"ip": ip}),
            "shodan":  pool.submit(_get, "/api/osint/shodan", {"ip": ip}),
            # `query` is the parameter this route reads; `indicator` and `ioc`
            # are accepted but ignored, and answer about nothing.
            "threats": pool.submit(_get, "/api/osint/threats", {"query": ip}),
        }
        results = {name: fut.result() for name, fut in jobs.items()}

    sources = {name: (err or "ok") for name, (_, err) in results.items()}
    base, _ = results["ip"]
    shodan, _ = results["shodan"]
    threats, _ = results["threats"]

    intel: dict = {
        "ip": ip,
        "fetched_at": _now_iso(),
        "cached": False,
        "geo": (base or {}).get("geo"),
        "reputation": (base or {}).get("reputation"),
        "sanctions_match": (base or {}).get("sanctions_match"),
        "exposure": None,
        "threat": None,
        "sources": sources,
        "partial": any(err for _, err in results.values()),
        "map_url": _map_url(base),
    }

    if shodan:
        intel["exposure"] = {
            "ports": shodan.get("ports") or [],
            "hostnames": shodan.get("hostnames") or [],
            "cpes": shodan.get("cpes") or [],
            "vulns": shodan.get("vulns") or [],
            "tags": shodan.get("tags") or [],
        }

    if threats:
        intel["threat"] = {
            "threat_level": threats.get("threat_level"),
            "tor_exit_node": threats.get("tor_exit_node"),
            "otx": threats.get("otx"),
        }

    # Nothing answered — cacheing that would hide a recovered upstream for the
    # next quarter of an hour.
    if all(status != "ok" for status in sources.values()):
        return intel

    _cache_put(("ip", ip), intel)
    return intel


def _map_url(base: dict | None) -> str:
    """
    A link into the OSIRIS map.

    lat/lon/zoom are the parameters its own share panel writes. The map does not
    read them back on load today — it geolocates by the viewer's address — so
    treat them as advisory: the link opens the map, the coordinates are there if
    that ever changes.
    """
    root = _base_url() + "/"
    geo = (base or {}).get("geo") or {}
    lat, lon = geo.get("lat"), geo.get("lon")
    if lat is None or lon is None:
        return root
    return f"{root}?lat={lat:.4f}&lon={lon:.4f}&zoom=8"


def cve_record(cve_id: str) -> dict:
    """
    The upstream record for one CVE id.

    `found` is false when the id is well-formed but no dataset carries it —
    OSIRIS answers 200 with a placeholder in that case, and treating it as a hit
    would dress an unknown identifier up as a confirmed one.
    """
    if not is_enabled():
        raise OsirisDisabledError("OSIRIS lookups are disabled (OSIRIS_ENABLED=false)")
    normalised = extract_cve_id(cve_id)
    if not normalised:
        raise ValueError(f"'{cve_id}' is not a CVE identifier")

    cached = _cache_get(("cve", normalised))
    if cached is not None:
        return {**cached, "cached": True}

    payload, error = _get("/api/osint/cve", {"cve": normalised})
    if payload is None:
        return {
            "id": normalised,
            "found": False,
            "cached": False,
            "fetched_at": _now_iso(),
            "error": error,
        }

    description = (payload.get("description") or "").strip()
    found = bool(description) and description.lower().rstrip(". ") != _NO_RECORD

    record = {
        "id": payload.get("id", normalised),
        "found": found,
        "cached": False,
        "fetched_at": _now_iso(),
        "description": description if found else None,
        "cvss": payload.get("cvss"),
        "cvss_vector": payload.get("cvss_vector"),
        "severity": payload.get("severity"),
        "cwe": payload.get("cwe"),
        "affected": payload.get("affected") or [],
        "references": payload.get("references") or [],
        "published": payload.get("published"),
        "modified": payload.get("modified"),
        "source": payload.get("source"),
    }
    _cache_put(("cve", normalised), record)
    return record
