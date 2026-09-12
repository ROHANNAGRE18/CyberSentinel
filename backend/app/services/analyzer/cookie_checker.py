"""
Cookie Security Analyzer — Phase 2D
======================================

Collects cookies from a single passive GET request (same request pattern
as the headers checker — no extra aggressive requests) and evaluates the
security attributes of each cookie returned in the Set-Cookie response
headers.

Design decisions
─────────────────
1. Single request only.
   We make ONE GET to the target URL (following redirects). Any cookies
   set by the server in that response are analyzed. We do NOT attempt
   login, POST forms, or any interaction that would require credentials.

2. Per-cookie analysis, aggregated results.
   Each cookie is inspected individually. The final CheckBundle contains
   one summary result per security attribute (Secure, HttpOnly, SameSite)
   describing all offending cookies, plus a no-cookies result when none
   are found. This keeps the number of DB rows bounded and manageable.

3. False-positive reduction.
   Cookie names that look like analytics/tracking cookies (e.g. _ga, _gid)
   are noted in the detail text, but all cookies are still evaluated on
   their security attributes. The note explains that the impact of a
   missing Secure flag is lower for non-session cookies.

4. SameSite evaluation.
   SameSite=None without Secure is flagged fail.
   SameSite=Lax or Strict is pass.
   Absent SameSite is warn (browser default varies by version).

Check names produced
─────────────────────
  cookie_secure_flag       – any cookie missing Secure flag over HTTPS
  cookie_httponly_flag     – any cookie missing HttpOnly flag
  cookie_samesite_attr     – any cookie with weak/missing SameSite
  cookie_overview          – summary: count found, count with issues
                             (also the sole result when no cookies present)
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import httpx

from app.core.config import get_settings
from app.core.security import build_redirect_guard
from app.services.analyzer.base import (
    CheckBundle,
    CheckResult,
    CheckStatus,
    Priority,
    Recommendation,
    Severity,
)

logger = logging.getLogger(__name__)
settings = get_settings()

# ── Heuristic: cookie names that are likely analytics / low-sensitivity ───────
# Used only for note text — we still evaluate their security attributes.
_ANALYTICS_PATTERN = re.compile(
    r"^(_ga|_gid|_gat|_fbp|_fbc|__utm|__hssc|__hstc|__hsfp|"
    r"_hjid|_hjFirstSeen|matomo|piwik|ajs_|amplitude|mixpanel)",
    re.IGNORECASE,
)


# ── Cookie dataclass ──────────────────────────────────────────────────────────

@dataclass
class ParsedCookie:
    """Represents one parsed Set-Cookie header."""
    name: str
    has_secure:   bool = False
    has_httponly: bool = False
    samesite:     Optional[str] = None   # "Strict", "Lax", "None", or None (absent)
    raw:          str = field(default="", repr=False)

    @property
    def is_analytics_hint(self) -> bool:
        return bool(_ANALYTICS_PATTERN.match(self.name))


# ── Cookie parser ─────────────────────────────────────────────────────────────

def parse_set_cookie(header_value: str) -> ParsedCookie:
    """
    Parse a single Set-Cookie header string into a ParsedCookie.

    RFC 6265 specifies attributes are semicolon-separated and
    case-insensitive. We extract name, Secure, HttpOnly, and SameSite.

    Examples:
      "session=abc; Secure; HttpOnly; SameSite=Strict; Path=/"
      "pref=1; Path=/; SameSite=Lax"
      "id=xyz; Path=/"
    """
    parts = [p.strip() for p in header_value.split(";")]

    # First part is always name=value (or just name for empty cookies)
    name_part = parts[0] if parts else ""
    name = name_part.split("=", 1)[0].strip()

    has_secure   = False
    has_httponly = False
    samesite: Optional[str] = None

    for part in parts[1:]:
        lower = part.lower()
        if lower == "secure":
            has_secure = True
        elif lower == "httponly":
            has_httponly = True
        elif lower.startswith("samesite="):
            samesite = part.split("=", 1)[1].strip().capitalize()  # "Strict"/"Lax"/"None"

    return ParsedCookie(
        name=name,
        has_secure=has_secure,
        has_httponly=has_httponly,
        samesite=samesite,
        raw=header_value,
    )


def collect_cookies(response: httpx.Response) -> list[ParsedCookie]:
    """
    Extract all Set-Cookie headers from an httpx Response and parse them.

    httpx.Headers may present multiple Set-Cookie headers; we iterate
    all of them rather than using .get() which returns only the first.
    """
    cookies = []
    for value in response.headers.get_list("set-cookie"):
        if value.strip():
            cookies.append(parse_set_cookie(value))
    return cookies


# ── HTTP client (same pattern as headers_checker) ─────────────────────────────

def _build_client() -> httpx.AsyncClient:
    timeout = httpx.Timeout(
        connect=settings.connect_timeout,
        read=settings.read_timeout,
        write=10.0,
        pool=5.0,
    )
    return httpx.AsyncClient(
        follow_redirects=True,
        timeout=timeout,
        max_redirects=settings.max_redirects,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (compatible; CyberSentinel/1.0; "
                "+https://github.com/cybersentinel)"
            )
        },
        event_hooks={"response": [build_redirect_guard()]},
    )


# ── Per-attribute evaluators ──────────────────────────────────────────────────

def _evaluate_secure_flag(
    cookies: list[ParsedCookie],
    is_https: bool,
) -> tuple[CheckResult, Optional[Recommendation]]:
    """
    Check: all cookies served over HTTPS should have the Secure flag.

    Over HTTP the Secure flag is meaningless (browsers ignore it for
    HTTP responses), so we return INFO rather than FAIL in that case.
    """
    check_name = "cookie_secure_flag"

    if not is_https:
        return (
            CheckResult(
                check_name=check_name,
                status=CheckStatus.INFO,
                title="Cookie Secure Flag: Not Evaluated (HTTP)",
                detail=(
                    "The Secure flag is only meaningful on HTTPS responses. "
                    "The target was reached over HTTP, so this check was skipped."
                ),
                severity=Severity.INFO,
            ),
            None,
        )

    missing = [c for c in cookies if not c.has_secure]
    if not missing:
        return (
            CheckResult(
                check_name=check_name,
                status=CheckStatus.PASS,
                title="Cookie Secure Flag: All Cookies Set Correctly",
                detail=(
                    f"All {len(cookies)} cookie(s) have the Secure flag, "
                    "ensuring they are only sent over HTTPS."
                ),
                severity=Severity.INFO,
            ),
            None,
        )

    names = ", ".join(f"'{c.name}'" for c in missing[:10])
    analytics_note = (
        " (Note: some of these appear to be analytics/tracking cookies "
        "which carry lower session risk.)"
        if any(c.is_analytics_hint for c in missing)
        else ""
    )
    return (
        CheckResult(
            check_name=check_name,
            status=CheckStatus.FAIL,
            title=f"Cookie Secure Flag Missing ({len(missing)} of {len(cookies)} cookie(s))",
            detail=(
                f"The following cookie(s) lack the Secure flag and could be "
                f"transmitted over unencrypted HTTP connections: {names}.{analytics_note}"
            ),
            severity=Severity.HIGH,
        ),
        Recommendation(
            check_name=check_name,
            priority=Priority.HIGH,
            title="Add the Secure flag to all cookies",
            description=(
                "Set the Secure attribute on every cookie so browsers only "
                "send them over HTTPS connections. "
                "Example: Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict"
            ),
            reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies",
        ),
    )


def _evaluate_httponly_flag(
    cookies: list[ParsedCookie],
) -> tuple[CheckResult, Optional[Recommendation]]:
    """
    Check: cookies should have the HttpOnly flag to prevent JavaScript access.

    Missing HttpOnly on cookies whose names suggest they hold session tokens
    or identifiers is higher severity than on analytics cookies.
    """
    check_name = "cookie_httponly_flag"

    missing = [c for c in cookies if not c.has_httponly]
    if not missing:
        return (
            CheckResult(
                check_name=check_name,
                status=CheckStatus.PASS,
                title="Cookie HttpOnly Flag: All Cookies Set Correctly",
                detail=(
                    f"All {len(cookies)} cookie(s) have the HttpOnly flag, "
                    "preventing JavaScript access via document.cookie."
                ),
                severity=Severity.INFO,
            ),
            None,
        )

    # Classify severity: higher if any non-analytics cookie is missing HttpOnly
    has_sensitive = any(not c.is_analytics_hint for c in missing)
    severity = Severity.MEDIUM if has_sensitive else Severity.LOW
    priority = Priority.MEDIUM if has_sensitive else Priority.LOW

    names = ", ".join(f"'{c.name}'" for c in missing[:10])
    analytics_note = (
        " Some of these appear to be analytics/tracking cookies "
        "(typically lower risk for HttpOnly), but applying HttpOnly "
        "broadly is still recommended."
        if any(c.is_analytics_hint for c in missing)
        else ""
    )
    return (
        CheckResult(
            check_name=check_name,
            status=CheckStatus.WARN,
            title=f"Cookie HttpOnly Flag Missing ({len(missing)} of {len(cookies)} cookie(s))",
            detail=(
                f"The following cookie(s) lack the HttpOnly flag, making them "
                f"accessible to JavaScript via document.cookie: {names}.{analytics_note} "
                f"If any of these store session tokens, XSS vulnerabilities "
                f"could be used to steal them."
            ),
            severity=severity,
        ),
        Recommendation(
            check_name=check_name,
            priority=priority,
            title="Add the HttpOnly flag to cookies",
            description=(
                "Set HttpOnly on all cookies that do not need to be accessed "
                "by JavaScript. This prevents XSS attacks from stealing cookie values. "
                "Example: Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict"
            ),
            reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies",
        ),
    )


def _evaluate_samesite_attr(
    cookies: list[ParsedCookie],
) -> tuple[CheckResult, Optional[Recommendation]]:
    """
    Check: SameSite attribute controls cross-site request behaviour.

    pass  – all cookies have SameSite=Strict or SameSite=Lax
    warn  – any cookie is missing SameSite entirely
    fail  – any cookie has SameSite=None without Secure (broken + insecure)
    """
    check_name = "cookie_samesite_attr"

    # SameSite=None without Secure is both rejected by modern browsers and insecure
    none_without_secure = [
        c for c in cookies
        if c.samesite is not None
        and c.samesite.lower() == "none"
        and not c.has_secure
    ]
    if none_without_secure:
        names = ", ".join(f"'{c.name}'" for c in none_without_secure[:10])
        return (
            CheckResult(
                check_name=check_name,
                status=CheckStatus.FAIL,
                title=f"SameSite=None Without Secure Flag ({len(none_without_secure)} cookie(s))",
                detail=(
                    f"Cookie(s) {names} have SameSite=None but are missing the "
                    f"Secure flag. Modern browsers (Chrome 80+) will reject these cookies. "
                    f"SameSite=None must always be paired with Secure."
                ),
                severity=Severity.HIGH,
            ),
            Recommendation(
                check_name=check_name,
                priority=Priority.HIGH,
                title="Add Secure flag to SameSite=None cookies",
                description=(
                    "Cookies with SameSite=None must also have the Secure flag. "
                    "SameSite=None; Secure is required for cross-site cookies (e.g. embeds). "
                    "If the cookie does not need to be sent cross-site, change to "
                    "SameSite=Lax or SameSite=Strict instead."
                ),
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite",
            ),
        )

    # Missing SameSite entirely — browser default is Lax in modern browsers
    # but Warn because older browsers treat it as None
    missing_samesite = [c for c in cookies if c.samesite is None]
    if missing_samesite:
        names = ", ".join(f"'{c.name}'" for c in missing_samesite[:10])
        return (
            CheckResult(
                check_name=check_name,
                status=CheckStatus.WARN,
                title=f"SameSite Attribute Missing ({len(missing_samesite)} of {len(cookies)} cookie(s))",
                detail=(
                    f"Cookie(s) {names} do not specify a SameSite attribute. "
                    f"Modern browsers default to SameSite=Lax, but older browsers "
                    f"may treat this as SameSite=None, enabling cross-site request "
                    f"forgery (CSRF) risks."
                ),
                severity=Severity.LOW,
            ),
            Recommendation(
                check_name=check_name,
                priority=Priority.LOW,
                title="Set an explicit SameSite attribute on all cookies",
                description=(
                    "Add SameSite=Strict (for cookies not needed cross-site) or "
                    "SameSite=Lax (for cookies needed in top-level navigations) "
                    "to every cookie. Avoid SameSite=None unless the cookie genuinely "
                    "needs to be sent in cross-site requests (and pair it with Secure)."
                ),
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite",
            ),
        )

    # All cookies have an acceptable SameSite value (Strict or Lax)
    return (
        CheckResult(
            check_name=check_name,
            status=CheckStatus.PASS,
            title="SameSite Attribute: All Cookies Set Correctly",
            detail=(
                f"All {len(cookies)} cookie(s) specify SameSite=Strict or SameSite=Lax."
            ),
            severity=Severity.INFO,
        ),
        None,
    )


def _build_overview(
    cookies: list[ParsedCookie],
    issue_count: int,
) -> CheckResult:
    """
    Produce a summary CheckResult describing how many cookies were found
    and how many had at least one security issue.
    """
    if not cookies:
        return CheckResult(
            check_name="cookie_overview",
            status=CheckStatus.INFO,
            title="No Cookies Detected",
            detail=(
                "No Set-Cookie headers were found in the response. "
                "This is not a problem if the site does not use cookies."
            ),
            severity=Severity.INFO,
        )

    if issue_count == 0:
        return CheckResult(
            check_name="cookie_overview",
            status=CheckStatus.PASS,
            title=f"Cookie Security: {len(cookies)} Cookie(s) Analyzed — No Issues Found",
            detail=(
                f"Found {len(cookies)} cookie(s). "
                "All have Secure, HttpOnly, and SameSite attributes set correctly."
            ),
            severity=Severity.INFO,
        )

    names = ", ".join(f"'{c.name}'" for c in cookies[:10])
    return CheckResult(
        check_name="cookie_overview",
        status=CheckStatus.WARN,
        title=f"Cookie Security: {issue_count} Issue(s) Found Across {len(cookies)} Cookie(s)",
        detail=(
            f"Analyzed {len(cookies)} cookie(s): {names}. "
            f"Found {issue_count} attribute issue(s). "
            "See Secure, HttpOnly, and SameSite results below for details."
        ),
        severity=Severity.LOW,
    )


# ── Public entry point ────────────────────────────────────────────────────────

async def run_cookie_checks(url: str) -> CheckBundle:
    """
    Make a single passive GET request to the target URL, collect all
    Set-Cookie response headers, and evaluate each cookie's security
    attributes.

    Returns a CheckBundle with:
      - 1 cookie_overview result
      - 3 attribute results (secure, httponly, samesite) if any cookies found
      - 0 attribute results and INFO overview if no cookies found
      - 1 INFO overview if the request fails (no exception propagated)
    """
    is_https = url.lower().startswith("https://")

    try:
        async with _build_client() as client:
            response = await client.get(url)
            await response.aclose()

        final_url = str(response.url)
        is_https  = final_url.lower().startswith("https://")
        cookies   = collect_cookies(response)

        logger.debug(
            "cookie_checker: %d cookie(s) found at %s (HTTP %s)",
            len(cookies), final_url, response.status_code,
        )

    except httpx.ConnectError as exc:
        logger.info("cookie_checker: connect error for %s: %s", url, exc)
        return _error_bundle("Could not connect to the server to retrieve cookies.")

    except httpx.TimeoutException as exc:
        logger.info("cookie_checker: timeout for %s", url)
        return _error_bundle("Connection timed out while retrieving cookies.")

    except Exception as exc:
        logger.warning("cookie_checker: unexpected error for %s: %s", url, exc)
        return _error_bundle(f"Unexpected error during cookie check: {exc}")

    # ── No cookies → single INFO overview, no attribute checks ───────────────
    if not cookies:
        return CheckBundle(
            results=[_build_overview(cookies, issue_count=0)],
            recommendations=[],
        )

    # ── Evaluate per-attribute ────────────────────────────────────────────────
    secure_result,   secure_rec   = _evaluate_secure_flag(cookies, is_https)
    httponly_result, httponly_rec = _evaluate_httponly_flag(cookies)
    samesite_result, samesite_rec = _evaluate_samesite_attr(cookies)

    # Count distinct attribute failures for the overview
    issue_count = sum(
        1 for r in (secure_result, httponly_result, samesite_result)
        if r.status in (CheckStatus.FAIL, CheckStatus.WARN)
    )

    overview = _build_overview(cookies, issue_count)

    results = [overview, secure_result, httponly_result, samesite_result]
    recommendations = [
        r for r in (secure_rec, httponly_rec, samesite_rec)
        if r is not None
    ]

    logger.info(
        "cookie_checker: %d cookies — %d attribute issues, %d recommendations",
        len(cookies), issue_count, len(recommendations),
    )
    return CheckBundle(results=results, recommendations=recommendations)


def _error_bundle(detail: str) -> CheckBundle:
    """Return a single INFO result when the fetch itself fails."""
    return CheckBundle(
        results=[
            CheckResult(
                check_name="cookie_overview",
                status=CheckStatus.INFO,
                title="Cookie Check Could Not Run",
                detail=detail,
                severity=Severity.INFO,
            )
        ],
        recommendations=[],
    )
