"""
HTTP-based security scanner for websites.
Checks security headers, SSL cert, exposed files, CORS, cookies, and server info.
"""

from __future__ import annotations

import logging
import re
import secrets
import socket
import ssl
import urllib.parse
from datetime import datetime, timezone

import requests
import urllib3
from requests.exceptions import RequestException

from .url_guard import assert_safe_target

logger = logging.getLogger(__name__)

# Probes against scan targets intentionally use verify=False — silence the noise
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Sensitive-file detection ──────────────────────────────────────────────────
# A path returning HTTP 200 is NOT evidence of exposure on its own — soft-404
# pages, catch-all SPA routes, and CDNs return 200 + HTML for any path, and some
# files (crossdomain.xml) are public by design. Each path therefore carries a
# validator that confirms the response body actually matches the file's
# signature before it is reported.

def _looks_html(resp) -> bool:
    ct = resp.headers.get("content-type", "").lower()
    if "html" in ct:
        return True
    head = resp.content[:512].lstrip().lower()
    return head.startswith(b"<!doctype html") or head.startswith(b"<html")


def _v_env(r) -> bool:
    return not _looks_html(r) and re.search(r"(?m)^[A-Z][A-Z0-9_]*\s*=", r.text[:4000]) is not None

def _v_git_config(r) -> bool:
    t = r.text[:2000].lower()
    return "[core]" in t or "repositoryformatversion" in t

def _v_git_head(r) -> bool:
    t = r.text[:200].strip().lower()
    return t.startswith("ref:") or re.fullmatch(r"[0-9a-f]{40}", t) is not None

def _v_php_source(r) -> bool:
    # Only a leak if raw PHP source comes back (server failed to execute it)
    return "<?php" in r.text[:4000]

def _v_phpinfo(r) -> bool:
    t = r.text[:4000]
    return "phpinfo()" in t or "PHP Version" in t

def _v_server_status(r) -> bool:
    t = r.text[:3000]
    return any(k in t for k in ("Apache Server Status", "Apache Server Information", "Server Version:"))

def _v_metrics(r) -> bool:
    """Prometheus exposition format: '# HELP name ...' / '# TYPE name ...'."""
    if _looks_html(r):
        return False
    return re.search(r"(?m)^#\s*(HELP|TYPE)\s+\w+", r.text[:4000]) is not None


def _v_actuator(r) -> bool:
    """Spring Boot Actuator index: a JSON document of _links to endpoints."""
    t = r.text[:4000]
    return '"_links"' in t and ("self" in t or "health" in t)


def _v_actuator_env(r) -> bool:
    t = r.text[:4000]
    return '"propertySources"' in t or '"activeProfiles"' in t


def _v_pprof(r) -> bool:
    t = r.text[:4000]
    return "/debug/pprof/" in t and ("goroutine" in t or "heap" in t)


def _v_svn(r) -> bool:
    if _looks_html(r):
        return False
    t = r.text[:400].strip()
    return t.startswith(("8", "9", "10", "11", "12")) and "dir" in r.text[:2000]


def _v_laravel_telescope(r) -> bool:
    t = r.text[:6000]
    return "telescope" in t.lower() and ("Telescope" in t or "laravel" in t.lower())


def _v_symfony_profiler(r) -> bool:
    t = r.text[:6000]
    return "Symfony Profiler" in t or "sf-profiler" in t or "_profiler" in t


# Autoindex pages from every common server. Juice Shop leaves /ftp browsable
# with a confidential document in it, and no signature-based check would ever
# find that: the exposure is the listing itself, not a known filename.
# Every mainstream listing generator announces itself, so recognition is by
# marker only. A "mostly relative links" heuristic was tried and dropped: an
# ordinary index page with a few relative links would trip it, and a false
# "Directory listing exposed" is exactly the kind of confident nonsense this
# scanner keeps having to be corrected for.
_DIR_LISTING_MARKERS = (
    "index of /",                 # Apache, nginx autoindex, Caddy
    "listing directory ",         # Express serve-index, which is what Juice Shop uses
    "<title>directory listing",
    "directory listing for",      # Python http.server, Tornado
    "parent directory</a>",       # IIS
    "[to parent directory]",      # IIS classic
)

_STYLE_SCRIPT_RE = re.compile(r"<(style|script)\b.*?</\1>", re.DOTALL | re.IGNORECASE)


def _v_directory_listing(r) -> bool:
    if r.headers.get("content-type", "").lower().find("html") == -1 and not _looks_html(r):
        return False

    # serve-index inlines a full stylesheet before the listing, so the links sit
    # well past any small window. Drop style and script blocks first and look at
    # the real markup.
    lowered = _STYLE_SCRIPT_RE.sub(" ", r.text[:200_000]).lower()
    return any(marker in lowered for marker in _DIR_LISTING_MARKERS)


def _v_htaccess(r) -> bool:
    if _looks_html(r):
        return False
    t = r.text[:2000]
    return any(k in t for k in ("RewriteEngine", "RewriteRule", "AuthType", "<Files", "Order ", "Require "))

def _v_sql_dump(r) -> bool:
    if _looks_html(r):
        return False
    t = r.text[:4000].upper()
    return any(k in t for k in ("INSERT INTO", "CREATE TABLE", "DROP TABLE", "MYSQL DUMP", "POSTGRESQL"))

def _v_swagger_json(r) -> bool:
    if "json" not in r.headers.get("content-type", "").lower() and not r.text[:50].lstrip().startswith("{"):
        return False
    t = r.text[:2000].lower()
    return '"swagger"' in t or '"openapi"' in t or '"paths"' in t

def _v_swagger_ui(r) -> bool:
    return "swagger-ui" in r.text[:5000].lower()

def _v_ds_store(r) -> bool:
    return b"Bud1" in r.content[:8] or r.content[:4] == b"\x00\x00\x00\x01"

def _v_login_panel(r) -> bool:
    # A real admin/login panel serves a password input. Generic words like
    # "login"/"username" appear on countless normal pages (and frameworks route
    # unknown paths to profile pages), so require an actual password field.
    if not _looks_html(r):
        return False
    return re.search(r'''<input[^>]+type\s*=\s*["']password["']''', r.text[:20000], re.I) is not None

def _v_phpmyadmin(r) -> bool:
    # phpMyAdmin login page is unmistakable
    return "phpmyadmin" in r.text[:8000].lower() and _v_login_panel(r)

def _v_crossdomain(r) -> bool:
    # Public by design — only a misconfiguration if it trusts ANY origin via a
    # bare domain="*". Subdomain wildcards like "*.example.com" are legitimate
    # scoping and must NOT match.
    return re.search(r'''allow-access-from\s+domain\s*=\s*(["'])\*\1''', r.text[:4000]) is not None


# (path, severity, validator, human-readable label)
SENSITIVE_PATHS = [
    ("/.env",             "CRITICAL", _v_env,          "Environment file with secrets exposed"),
    ("/.git/config",      "CRITICAL", _v_git_config,   ".git repository config exposed (source disclosure)"),
    ("/.git/HEAD",        "HIGH",     _v_git_head,     ".git metadata exposed (repo may be downloadable)"),
    ("/config.php",       "CRITICAL", _v_php_source,   "Raw PHP config source exposed"),
    ("/wp-config.php",    "CRITICAL", _v_php_source,   "Raw WordPress config source exposed (DB credentials)"),
    ("/phpinfo.php",      "HIGH",     _v_phpinfo,      "phpinfo() page exposes server configuration"),
    ("/server-status",    "MEDIUM",   _v_server_status,"Apache server-status page publicly accessible"),
    ("/server-info",      "MEDIUM",   _v_server_status,"Apache server-info page publicly accessible"),
    ("/.htaccess",        "HIGH",     _v_htaccess,     "Apache .htaccess file exposed"),
    ("/backup.sql",       "CRITICAL", _v_sql_dump,     "Database backup (SQL dump) publicly downloadable"),
    ("/dump.sql",         "CRITICAL", _v_sql_dump,     "Database dump (SQL) publicly downloadable"),
    ("/database.sql",     "CRITICAL", _v_sql_dump,     "Database file (SQL) publicly downloadable"),
    ("/api/swagger.json", "LOW",      _v_swagger_json, "API schema (Swagger) publicly exposed"),
    ("/api/openapi.json", "LOW",      _v_swagger_json, "API schema (OpenAPI) publicly exposed"),
    ("/swagger-ui.html",  "LOW",      _v_swagger_ui,   "Swagger UI publicly accessible"),
    ("/.DS_Store",        "LOW",      _v_ds_store,     ".DS_Store exposes a directory file listing"),
    ("/crossdomain.xml",  "MEDIUM",   _v_crossdomain,  "crossdomain.xml trusts ANY origin (wildcard)"),
    ("/admin",            "LOW",      _v_login_panel,  "Admin login panel reachable"),
    ("/administrator",    "LOW",      _v_login_panel,  "Administrator login panel reachable"),
    ("/wp-admin",         "LOW",      _v_login_panel,  "WordPress admin panel reachable"),
    ("/phpmyadmin",       "LOW",      _v_phpmyadmin,   "phpMyAdmin panel reachable"),
    # The list above is PHP/Apache era. These are what actually leaks now, and
    # scanning OWASP Juice Shop is what exposed the gap: it left /ftp browsable
    # and /metrics public, and neither was probed.
    ("/metrics",          "MEDIUM",   _v_metrics,      "Prometheus metrics exposed publicly (internal telemetry)"),
    ("/actuator",         "MEDIUM",   _v_actuator,     "Spring Boot Actuator endpoints publicly listed"),
    ("/actuator/env",     "CRITICAL", _v_actuator_env, "Spring Boot Actuator env exposed (configuration and secrets)"),
    ("/debug/pprof/",     "MEDIUM",   _v_pprof,        "Go pprof profiling endpoints publicly accessible"),
    ("/.svn/entries",     "HIGH",     _v_svn,          ".svn metadata exposed (source disclosure)"),
    ("/telescope",        "HIGH",     _v_laravel_telescope, "Laravel Telescope debug console reachable"),
    ("/_profiler",        "HIGH",     _v_symfony_profiler,  "Symfony profiler reachable (requests, config, queries)"),
    # Browsable directories. Reported by the listing itself, not a filename.
    ("/ftp",              "HIGH",     _v_directory_listing, "Directory listing exposed"),
    ("/files",            "MEDIUM",   _v_directory_listing, "Directory listing exposed"),
    ("/uploads",          "MEDIUM",   _v_directory_listing, "Directory listing exposed"),
    ("/backup",           "HIGH",     _v_directory_listing, "Directory listing exposed"),
]

# ── Headers a page can deliver from its own markup ────────────────────────────
# Static hosts (GitHub Pages, S3 without CloudFront) let you serve files but not
# set response headers, so a site's only way to apply these is from inside the
# document. Browsers honour both deliveries, so grading headers alone reports a
# policy as missing when it is actually enforced.
#
# Only these two work from markup. X-Frame-Options, X-Content-Type-Options,
# Permissions-Policy and HSTS are ignored in a meta tag by every browser, so for
# those the response header remains the only valid delivery.

_META_CSP_RE = re.compile(
    r"""<meta[^>]+http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>""",
    re.IGNORECASE,
)
_META_REFERRER_RE = re.compile(
    r"""<meta[^>]+name\s*=\s*["']?referrer["']?[^>]*>""",
    re.IGNORECASE,
)
# Capture the quote style and require the matching close. A CSP value is full of
# single quotes ("default-src 'self'"), so a character class of ["'] would stop
# at the first one and truncate the policy.
_CONTENT_ATTR_RE = re.compile(r"""content\s*=\s*(["'])(.*?)\1""",
                              re.IGNORECASE | re.DOTALL)

META_DELIVERABLE_HEADERS = {"Content-Security-Policy", "Referrer-Policy"}


def meta_delivered_headers(html: str) -> dict[str, str]:
    """Return security policies the document declares in its own <head>."""
    found: dict[str, str] = {}
    head = html[:200_000]

    for regex, header in ((_META_CSP_RE, "content-security-policy"),
                          (_META_REFERRER_RE, "referrer-policy")):
        match = regex.search(head)
        if not match:
            continue
        content = _CONTENT_ATTR_RE.search(match.group(0))
        if content and content.group(2).strip():
            found[header] = content.group(2).strip()
    return found


SECURITY_HEADERS = {
    "Strict-Transport-Security":    ("HIGH",   "A02:2021-Cryptographic Failures"),
    "Content-Security-Policy":      ("HIGH",   "A05:2021-Security Misconfiguration"),
    "X-Frame-Options":              ("MEDIUM", "A05:2021-Security Misconfiguration"),
    "X-Content-Type-Options":       ("MEDIUM", "A05:2021-Security Misconfiguration"),
    "Referrer-Policy":              ("LOW",    "A05:2021-Security Misconfiguration"),
    "Permissions-Policy":           ("LOW",    "A05:2021-Security Misconfiguration"),
}

_HEADERS = {"User-Agent": "PatchPilot-SecurityScanner/1.0"}

# ── Anti-bot / WAF detection ──────────────────────────────────────────────────
# A site that refuses automated requests serves a challenge or block page, and
# that page has nothing to do with the real application's security posture. Its
# headers are not the site's headers and its cookies are not the site's cookies,
# so auditing it produces confident nonsense: LinkedIn returns HTTP 999 to
# scanners, and grading that response reports "missing Content-Security-Policy"
# against a site that ships one of the strictest CSPs on the web.
#
# Detect the block and refuse to report, rather than describing a challenge page.

_BLOCK_STATUSES = {999, 429}

# Header name -> vendor. Presence alone is conclusive.
_BLOCK_HEADERS = {
    "cf-mitigated":  "Cloudflare",
    "x-datadome":    "DataDome",
    "x-iinfo":       "Imperva Incapsula",
    "x-sucuri-id":   "Sucuri",
}

# Body markers, only consulted on a status that plausibly indicates a block.
_BLOCK_BODY_MARKERS = {
    "just a moment":            "Cloudflare challenge page",
    "attention required!":      "Cloudflare block page",
    "checking your browser":    "Cloudflare interstitial",
    "enable javascript and cookies to continue": "Cloudflare challenge page",
    "px-captcha":               "PerimeterX challenge",
    "request unsuccessful. incapsula": "Imperva Incapsula block",
    "access denied":            "WAF block page",
    "are you a robot":          "bot challenge",
    "unusual traffic":          "rate-limit / bot challenge",
}

CDN_SERVER_MARKERS = {
    "cloudflare": "Cloudflare",
    "akamai":     "Akamai",
    "cloudfront": "Amazon CloudFront",
    "fastly":     "Fastly",
    "vercel":     "Vercel",
    "netlify":    "Netlify",
}


# Header names that identify a CDN on their own, whatever their value. Fastly
# is the reason this exists: it fronts GitHub Pages but its Server header says
# "GitHub.com", its Via says "varnish", and its X-Served-By is an opaque cache
# id, so no header *value* names the vendor.
CDN_MARKER_HEADERS = {
    "cf-ray":               "Cloudflare",
    "x-fastly-request-id":  "Fastly",
    "x-amz-cf-id":          "Amazon CloudFront",
    "x-akamai-request-id":  "Akamai",
    "x-vercel-id":          "Vercel",
    "x-nf-request-id":      "Netlify",
}


# Hosts that serve static files and give the owner no way to set a response
# header. The missing-header findings are still true (visitors really are
# unprotected), but "add this to your nginx config" is advice the owner cannot
# act on, and it makes the fix suggester write config for a server that does
# not exist. Name the constraint instead, and say what would actually fix it.
STATIC_HOSTS_WITHOUT_HEADER_CONTROL = {
    "github.com": "GitHub Pages",
}


# github.com serves its own application with "Server: github.com" too, so the
# header alone would label GitHub itself a static host that cannot set headers,
# which it plainly is not: it ships a CSP, HSTS and the rest.
_GITHUB_APP_HOSTS = frozenset({
    "github.com", "www.github.com", "gist.github.com", "api.github.com",
    "raw.githubusercontent.com", "codeload.github.com",
})


def detect_static_host(headers: dict, host: str = "") -> str | None:
    """Identify a static host that cannot set response headers, if any."""
    server = headers.get("server", "").strip().lower()
    hostname = (host or "").strip().lower()
    for marker, name in STATIC_HOSTS_WITHOUT_HEADER_CONTROL.items():
        if server == marker or server.startswith(marker):
            if marker == "github.com" and hostname in _GITHUB_APP_HOSTS:
                return None
            return name
    return None


def detect_cdn(headers: dict) -> str | None:
    """Identify a fronting CDN from response headers, if there is one."""
    lowered = {k.lower(): v for k, v in headers.items()}

    for header, name in CDN_MARKER_HEADERS.items():
        if header in lowered:
            return name

    blob = " ".join([
        lowered.get("server", ""),
        lowered.get("via", ""),
        lowered.get("x-served-by", ""),
        lowered.get("x-cache", ""),
    ]).lower()
    for marker, name in CDN_SERVER_MARKERS.items():
        if marker in blob:
            return name
    return None


def detect_block(resp) -> str | None:
    """
    Return a human-readable reason when the response is an anti-bot block,
    or None when it looks like the real application.
    """
    hdrs = {k.lower(): v for k, v in resp.headers.items()}

    if resp.status_code in _BLOCK_STATUSES:
        return f"HTTP {resp.status_code} (automated requests refused)"

    for header, vendor in _BLOCK_HEADERS.items():
        if header in hdrs:
            return f"{vendor} bot mitigation (via the {header} header)"

    if resp.status_code in (401, 403, 503):
        try:
            body = resp.text[:8000].lower()
        except Exception:
            body = ""
        for marker, label in _BLOCK_BODY_MARKERS.items():
            if marker in body:
                return f"{label} (HTTP {resp.status_code})"
        cdn = detect_cdn(hdrs)
        if cdn:
            return f"HTTP {resp.status_code} served by {cdn}, not the origin"

    return None


_VERSION_RE = re.compile(r"\d+\.\d+|/\d+")


def _unreachable(url: str, error: Exception, meta: dict, findings: list[dict]) -> list[dict]:
    """
    A site that does not answer is not a vulnerable site.

    This used to be reported as a HIGH finding, which put an unreachable host
    at 40/100 MEDIUM through the severity floor and listed "Could not reach
    website" among its vulnerabilities. A scan that could not run has no
    result, so it is surfaced the same way a bot block is: as a notice that
    says no assessment was made.
    """
    meta["unreachable"] = str(error)
    logger.info("website_scanner: %s is unreachable: %s", url, error)
    return findings + [{
        "type":        "scan_error",
        "source":      "website",
        "file":        url,
        "line":        0,
        "severity":    "LOW",
        "category":    "scan-error",
        "description": (
            f"Could not reach {url}, so no security assessment was performed. "
            f"This is a connectivity result, not a finding about the site."
        ),
        "code": f"GET {url} failed: {error}",
    }]


def is_github_url(url: str) -> bool:
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return host == "github.com"


def scan_website(url: str, meta: dict | None = None) -> list[dict]:
    """
    Run passive HTTP security checks against a live site.

    `meta`, when supplied, is populated with context about the target: the
    fronting CDN, whether the target blocked the scan, and the final URL after
    redirects. Callers use it to decide what is worth reporting.
    """
    # Re-validate at scan time — blocks SSRF against internal hosts even if
    # the caller skipped the request-level check.
    url = assert_safe_target(url)
    if meta is None:
        meta = {}

    parsed = urllib.parse.urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    findings: list[dict] = []
    http = requests.Session()
    http.headers.update(_HEADERS)

    # ── 1. Fetch root page ──────────────────────────────────────────────────
    try:
        resp = http.get(url, timeout=15, allow_redirects=True, verify=True)
    except requests.exceptions.SSLError:
        findings.append(_f(url, "CRITICAL", "A02:2021-Cryptographic Failures",
                          "SSL/TLS certificate is invalid or self-signed",
                          "HTTPS handshake failed — browser would show security warning"))
        try:
            resp = http.get(url, timeout=15, allow_redirects=True, verify=False)
        except RequestException as e:
            # The invalid-certificate finding above is real and stays.
            return _unreachable(url, e, meta, findings)
    except RequestException as e:
        return _unreachable(url, e, meta, findings)

    hdrs = {k.lower(): v for k, v in resp.headers.items()}

    # Everything below grades the response that actually came back, which after
    # a redirect is a different URL and possibly a different host. Scanning
    # http://github.com/ used to report HIGH "served over plain HTTP" because
    # the scheme was read from the URL typed in, not the https:// page the
    # server redirected to, and the file probes were aimed at the original host
    # while the headers being graded came from the new one.
    final_url = getattr(resp, "url", url) or url
    final = urllib.parse.urlparse(final_url)
    scheme = final.scheme or parsed.scheme
    base_url = f"{final.scheme}://{final.netloc}"
    url = final_url

    meta["final_url"] = final_url
    meta["redirected"] = bool(getattr(resp, "history", None))
    meta["host_changed"] = (final.hostname or "") != (parsed.hostname or "")
    meta["status_code"] = resp.status_code
    meta["cdn"] = detect_cdn(hdrs)
    meta["static_host"] = detect_static_host(hdrs, final.hostname or "")

    # ── 1b. Anti-bot block ──────────────────────────────────────────────────
    # Everything below grades the response we received. If that response is a
    # challenge page rather than the application, grading it is worse than
    # useless: it produces confident findings about a page the site never
    # serves to real users. Report the block itself and stop.
    blocked = detect_block(resp)
    if blocked:
        meta["blocked"] = blocked
        return [{
            "type":        "scan_blocked",
            "source":      "website",
            "file":        url,
            "line":        0,
            "severity":    "LOW",
            "category":    "scan-blocked",
            "description": (
                f"Target refused automated scanning: {blocked}. No security "
                f"assessment was performed - the response received is a bot "
                f"challenge, not the application, so its headers and cookies "
                f"do not reflect the real security posture."
            ),
            "code": f"GET {url} -> HTTP {resp.status_code}",
        }]
    meta["blocked"] = None

    # ── 1c. Server error ────────────────────────────────────────────────────
    # A 5xx is the server failing, not the application answering. Its headers
    # belong to an error page: when the OWASP Juice Shop demo went down, this
    # scanner graded a 567-byte Heroku "Application Error" screen and reported
    # six confident findings about missing headers, including two the real app
    # does send. Same mistake as grading a bot-challenge page, different cause.
    if resp.status_code >= 500:
        meta["server_error"] = resp.status_code
        return [{
            "type":        "scan_error",
            "source":      "website",
            "file":        url,
            "line":        0,
            "severity":    "LOW",
            "category":    "scan-error",
            "description": (
                f"Target returned HTTP {resp.status_code}, so no security "
                f"assessment was performed. The response is a server error "
                f"page, not the application, and its headers are not the "
                f"application's headers."
            ),
            "code": f"GET {url} -> HTTP {resp.status_code} "
                    f"({len(resp.content)} bytes, server: {hdrs.get('server', '?')})",
        }]
    meta["server_error"] = None

    # ── 2. HTTP (no TLS) ────────────────────────────────────────────────────
    # Judged on where the request ended up. A site that answers on port 80 and
    # immediately redirects to HTTPS is doing the right thing, and calling that
    # "all traffic is unencrypted" is simply wrong.
    if scheme == "http":
        findings.append(_f(url, "HIGH", "A02:2021-Cryptographic Failures",
                          "Site served over plain HTTP — all traffic is unencrypted",
                          f"GET {url} stayed on http:// with no redirect to https://"))
    elif parsed.scheme == "http":
        findings.append(_f(url, "LOW", "A02:2021-Cryptographic Failures",
                          "Plain HTTP requests are redirected to HTTPS",
                          f"GET {parsed.geturl()} redirected to {final_url}. The "
                          f"redirect itself travels unencrypted, so a "
                          f"Strict-Transport-Security header (and ideally HSTS "
                          f"preloading) is what stops the first request being "
                          f"intercepted."))

    # ── 3. Missing security headers ─────────────────────────────────────────
    # A policy declared in the document counts as applied, because the browser
    # applies it. Only for the two headers browsers actually honour from markup.
    try:
        from_meta = meta_delivered_headers(resp.text)
    except Exception:
        from_meta = {}
    meta["meta_delivered"] = sorted(from_meta)

    # Named in the finding itself, not just the evidence, because the summariser
    # and the fix suggester only ever see the description.
    static_host = meta.get("static_host")
    host_note = (
        f" ({static_host} cannot set response headers)" if static_host else ""
    )
    host_evidence = (
        f" {static_host} serves static files only and offers no way to set "
        f"response headers, so this cannot be fixed on the current host. It "
        f"needs a proxy or CDN in front that can add headers (for example "
        f"Cloudflare), or a host with header rules (Netlify _headers, "
        f"Vercel vercel.json)."
        if static_host else ""
    )

    for header, (sev, cat) in SECURITY_HEADERS.items():
        key = header.lower()
        if key in hdrs:
            continue

        # HSTS is only meaningful over TLS: browsers ignore it on a plain HTTP
        # response. Reporting it missing there restates the "served over plain
        # HTTP" finding above and scores the same problem twice.
        if header == "Strict-Transport-Security" and scheme != "https":
            continue

        # A report-only policy is not "no policy": the site has one written and
        # is collecting violations. It still enforces nothing, so the severity
        # stands, but calling it missing is wrong in front of anyone who knows
        # their own configuration.
        if header == "Content-Security-Policy" and "content-security-policy-report-only" in hdrs:
            findings.append(_f(
                url, sev, cat,
                "Content-Security-Policy is set to report-only, so no policy "
                "is enforced",
                "The response carries Content-Security-Policy-Report-Only but "
                "no Content-Security-Policy. Violations are reported and "
                "nothing is blocked, so the page has the same exposure to "
                "injected script as a page with no policy. Serve the same "
                "policy under Content-Security-Policy once the reports are "
                "clean.",
            ))
            continue

        if header in META_DELIVERABLE_HEADERS and key in from_meta:
            # Applied, just not via a response header.
            if header == "Content-Security-Policy":
                # Worded so it cannot be read as "no CSP". The earlier phrasing
                # led with the shortcoming, and the report summariser inverted
                # it into "Implement Content-Security-Policy" on a site that
                # already had one. State what is in place first, then the gap.
                findings.append(_f(
                    url, "LOW", "A05:2021-Security Misconfiguration",
                    "Content-Security-Policy is present and enforced, but "
                    "delivered by meta tag: its frame-ancestors and reporting "
                    "directives are inactive",
                    "The page ships a CSP via <meta http-equiv> and the browser "
                    "enforces it, so no CSP needs to be written. However "
                    "frame-ancestors, report-uri, report-to and sandbox are "
                    "only honoured in a response header. Clickjacking "
                    "protection therefore still needs X-Frame-Options or the "
                    "same CSP sent as a header." + host_evidence,
                ))
            continue
        # CSP and Referrer-Policy can be applied from the document, so the host
        # is not what is stopping them: saying "GitHub Pages cannot set response
        # headers" against a missing CSP would point at the wrong remediation.
        platform_blocked = header not in META_DELIVERABLE_HEADERS
        # A domain can be on the browser HSTS preload list, in which case
        # browsers force HTTPS whether or not the header is sent. That is not
        # visible in a response, so the finding has to say so rather than imply
        # the site has no HTTPS enforcement at all.
        caveat = (
            " Note that the domain may also be on the browser HSTS preload "
            "list, which enforces HTTPS regardless of this header and cannot "
            "be seen in a response. Check hstspreload.org before treating this "
            "as unprotected."
            if header == "Strict-Transport-Security" else ""
        )
        findings.append(_f(
            url, sev, cat,
            f"Missing security header: {header}"
            f"{host_note if platform_blocked else ''}",
            f"HTTP response has no {header} header."
            f"{host_evidence if platform_blocked else ''}{caveat}",
        ))

    # ── 4. Server / technology info disclosure ──────────────────────────────
    # Only a version is worth reporting. Every site on the internet sends a
    # Server header, so flagging "cloudflare", "gws" or "nginx" produced a
    # finding on every single scan while telling an attacker nothing they could
    # act on: there is no exploit for knowing the name of a web server. A
    # version number is different, because it maps to a CVE list.
    for h in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        value = hdrs.get(h, "")
        if not value:
            continue
        if h == "server" and not _VERSION_RE.search(value):
            continue
        findings.append(_f(url, "LOW", "A05:2021-Security Misconfiguration",
                          f"Server information disclosed via '{h}': {value}",
                          f"{h}: {value}. A version number narrows the search "
                          f"for a known vulnerability in that exact build. "
                          f"Suppress or genericise the header."))

    # ── 5. HSTS strength ────────────────────────────────────────────────────
    hsts = hdrs.get("strict-transport-security", "")
    if hsts:
        try:
            parts = {p.strip().split("=")[0].strip(): p.strip().split("=")[1].strip()
                     for p in hsts.split(";") if "=" in p}
            max_age = int(parts.get("max-age", "0"))
            if max_age < 31_536_000:
                findings.append(_f(url, "LOW", "A02:2021-Cryptographic Failures",
                                  f"HSTS max-age too short ({max_age}s) — recommend ≥ 31536000",
                                  f"Strict-Transport-Security: {hsts}"))
        except (ValueError, IndexError):
            pass

    # ── 6. CORS wildcard ────────────────────────────────────────────────────
    # A bare "Access-Control-Allow-Origin: *" is not a vulnerability by itself.
    # It only exposes something when the response carries data the requester
    # would not otherwise be entitled to: cookie-authenticated content, or a
    # host reachable from a network position the attacker lacks. On a public
    # static document a cross-origin read returns exactly what a direct GET
    # returns, so nothing is disclosed.
    #
    # Grading the header alone reported a HIGH "allows any origin to read API
    # responses" against a static portfolio with no API, which is the same
    # mistake as grading a bot-challenge page: a confident finding about
    # something the evidence does not support.
    if hdrs.get("access-control-allow-origin", "").strip() == "*":
        credentialed = (hdrs.get("access-control-allow-credentials", "")
                        .strip().lower() == "true")
        sets_cookies = "set-cookie" in hdrs or bool(getattr(resp, "cookies", None))

        if credentialed:
            findings.append(_f(
                url, "HIGH", "A05:2021-Security Misconfiguration",
                "Wildcard CORS policy combined with credentialed requests",
                "Access-Control-Allow-Origin: * with "
                "Access-Control-Allow-Credentials: true. Browsers reject that "
                "combination, so the server is either misconfigured or "
                "reflecting the request origin elsewhere; either way any "
                "origin may be able to read authenticated responses.",
            ))
        elif sets_cookies:
            findings.append(_f(
                url, "MEDIUM", "A05:2021-Security Misconfiguration",
                "Wildcard CORS policy on a response that sets cookies",
                "Access-Control-Allow-Origin: * on a response carrying "
                "Set-Cookie. The wildcard blocks credentialed cross-origin "
                "reads, but session-bearing endpoints on this origin should "
                "name their allowed origins explicitly rather than rely on it.",
            ))
        else:
            source = f" It is the default for {meta['static_host']}." if meta.get("static_host") else (
                f" It is set by the fronting {meta['cdn']}." if meta.get("cdn") else "")
            findings.append(_f(
                url, "LOW", "A05:2021-Security Misconfiguration",
                "Wildcard CORS policy on public content: any origin may read "
                "this response, which is already publicly readable",
                "Access-Control-Allow-Origin: * with no "
                "Access-Control-Allow-Credentials and no Set-Cookie, so a "
                "cross-origin read returns exactly what a direct request "
                "returns and no private data is exposed." + source +
                " Revisit if this origin later serves authenticated APIs.",
            ))

    # ── 7. Dangerous HTTP methods ───────────────────────────────────────────
    allow = hdrs.get("allow", "")
    for method in ("TRACE", "PUT", "DELETE"):
        if method in allow:
            findings.append(_f(url, "MEDIUM", "A05:2021-Security Misconfiguration",
                              f"Dangerous HTTP method enabled: {method}",
                              f"Allow: {allow}"))

    # ── 8. Cookie security flags ────────────────────────────────────────────
    # Graded per attribute rather than lumping them together at MEDIUM. A
    # cookie sent without Secure on an HTTPS site can leak over a plain-HTTP
    # request; a cookie without SameSite is defaulted to Lax by every current
    # browser, which is a much smaller problem and does not deserve equal
    # billing in the score.
    for cookie in resp.cookies:
        attributes = {a.lower() for a in (getattr(cookie, "_rest", None) or {})}
        issues: list[tuple[str, str]] = []
        if not cookie.secure and scheme == "https":
            issues.append(("MEDIUM", "missing Secure flag"))
        if "httponly" not in attributes:
            issues.append(("MEDIUM", "missing HttpOnly flag, so scripts can read it"))
        if "samesite" not in attributes:
            issues.append(("LOW", "no explicit SameSite (browsers default to Lax)"))
        if not issues:
            continue
        severity = "MEDIUM" if any(s == "MEDIUM" for s, _ in issues) else "LOW"
        findings.append(_f(
            url, severity, "A05:2021-Security Misconfiguration",
            f"Cookie '{cookie.name}': {', '.join(text for _, text in issues)}",
            f"Set-Cookie: {cookie.name}=... "
            f"(Secure={cookie.secure}, attributes={sorted(attributes) or 'none'})",
        ))

    # ── 9. Sensitive file exposure ───────────────────────────────────────────
    # Baseline: many sites return 200 + HTML for any path (soft-404 / catch-all).
    # Capture the response to a guaranteed-missing path so we can tell a real
    # file apart from the generic page.
    baseline = None
    try:
        baseline = http.get(f"{base_url}/sentinel-probe-{secrets.token_hex(8)}",
                            timeout=6, allow_redirects=False, verify=False)
    except RequestException:
        pass

    for path, sev, validator, label in SENSITIVE_PATHS:
        try:
            r = http.get(f"{base_url}{path}", timeout=6, allow_redirects=False, verify=False)
        except RequestException:
            continue
        if r.status_code not in (200, 206):
            continue
        # Same size as the catch-all page → it IS the catch-all page, not the file
        if (baseline is not None and baseline.status_code in (200, 206)
                and abs(len(r.content) - len(baseline.content)) <= 16):
            continue
        # Body must actually match the file's signature
        try:
            if not validator(r):
                continue
        except Exception:
            # A validator that blows up cannot confirm the signature, so the
            # path is not reported. Suppressing a finding silently is exactly
            # the failure mode this scanner exists to avoid, so record it.
            logger.debug("Validator failed for %s%s", base_url, path, exc_info=True)
            continue
        findings.append(_f(f"{base_url}{path}", sev,
                          "A05:2021-Security Misconfiguration",
                          f"{label}: {path} (HTTP {r.status_code})",
                          f"GET {path} → {r.status_code} "
                          f"({len(r.content)} bytes, {r.headers.get('content-type', '?')})"))

    # ── 10. SSL certificate expiry ───────────────────────────────────────────
    if parsed.scheme == "https":
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=parsed.hostname) as s:
                s.settimeout(5)
                s.connect((parsed.hostname, parsed.port or 443))
                cert = s.getpeercert()
                expires_str = cert.get("notAfter", "")
                if expires_str:
                    expires = datetime.strptime(expires_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (expires - datetime.now(timezone.utc)).days
                    # Modern certs are short-lived and auto-renew (Let's Encrypt
                    # 90-day, etc.), so a cert 2+ weeks out is normal — only warn
                    # when expiry is genuinely imminent to avoid false alarms.
                    if days_left < 0:
                        findings.append(_f(url, "CRITICAL", "A02:2021-Cryptographic Failures",
                                          f"SSL certificate has EXPIRED ({abs(days_left)} days ago)",
                                          f"notAfter: {expires_str}"))
                    elif days_left < 14:
                        sev = "HIGH" if days_left < 3 else "MEDIUM"
                        findings.append(_f(url, sev, "A02:2021-Cryptographic Failures",
                                          f"SSL certificate expires in {days_left} days",
                                          f"notAfter: {expires_str}"))
        except Exception:
            # Certificate inspection is best-effort: the site is still scanned
            # without it, but a missing expiry check should not be invisible.
            logger.debug("TLS certificate inspection failed for %s", url, exc_info=True)

    return findings


def _f(file: str, severity: str, category: str,
       description: str, code: str) -> dict:
    return {
        "source":      "website",
        "file":        file,
        "line":        0,
        "severity":    severity,
        "category":    category,
        "description": description,
        "code":        code,
    }
