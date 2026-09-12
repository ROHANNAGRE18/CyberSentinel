"""
Security Headers Analyzer — Phase 2B
======================================

Checks for the presence and quality of six HTTP security response headers
on the target URL. All requests are passive (read-only HEAD/GET) and go
through the existing SSRF redirect guard.

Headers checked
───────────────
  1. content_security_policy   (CSP)
  2. strict_transport_security (HSTS)
  3. x_frame_options           (Clickjacking protection)
  4. x_content_type_options    (MIME sniffing protection)
  5. referrer_policy           (Referrer information leakage)
  6. permissions_policy        (Browser feature access control)

Result logic per header
────────────────────────
  pass  – header present and value meets minimum quality requirements
  warn  – header present but value is weak, deprecated, or incomplete
  fail  – header entirely absent

Request strategy
─────────────────
  A single GET request is made (following redirects so we land on the
  final page and inspect its headers). HEAD is not used because some
  servers omit security headers on HEAD responses.

  The response body is discarded — only status code and headers are read.
"""

import logging
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


# ── HTTP client (reuses the same pattern as https_checker) ────────────────────

def _build_client() -> httpx.AsyncClient:
    """Async httpx client with SSRF redirect guard and app-level timeouts."""
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


# ── Individual header checks ──────────────────────────────────────────────────

def _check_csp(value: str | None) -> tuple[CheckResult, Recommendation | None]:
    """
    Content-Security-Policy

    pass  – header present (any non-empty value accepted as passing baseline)
    warn  – header contains 'unsafe-inline' or 'unsafe-eval' without a nonce/hash
    fail  – header absent
    """
    check_name = "csp_header"

    if value is None:
        return (
            CheckResult(
                check_name=check_name,
                status=CheckStatus.FAIL,
                title="Content-Security-Policy Missing",
                detail=(
                    "The Content-Security-Policy header was not found. "
                    "Without CSP, the browser has no instructions to restrict "
                    "resource loading, leaving the site vulnerable to "
                    "Cross-Site Scripting (XSS) and data injection attacks."
                ),
                severity=Severity.HIGH,
            ),
            Recommendation(
                check_name=check_name,
                priority=Priority.HIGH,
                title="Add a Content-Security-Policy header",
                description=(
                    "Define a Content-Security-Policy that restricts which sources "
                    "the browser may load scripts, styles, images, and other "
                    "resources from. Start with a restrictive policy such as "
                    "'default-src \\'self\\'' and loosen it only as needed. "
                    "Avoid 'unsafe-inline' and 'unsafe-eval' where possible."
                ),
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            ),
        )

    val_lower = value.lower()
    has_unsafe = "unsafe-inline" in val_lower or "unsafe-eval" in val_lower
    # A nonce or hash mitigates unsafe-inline in practice
    has_mitigation = "'nonce-" in val_lower or "'sha256-" in val_lower or "'sha384-" in val_lower

    if has_unsafe and not has_mitigation:
        return (
            CheckResult(
                check_name=check_name,
                status=CheckStatus.WARN,
                title="Content-Security-Policy Uses Unsafe Directives",
                detail=(
                    f"CSP is present but contains 'unsafe-inline' or 'unsafe-eval' "
                    f"without a nonce or hash, which significantly weakens XSS "
                    f"protection. Value: {value[:200]}"
                ),
                severity=Severity.MEDIUM,
            ),
            Recommendation(
                check_name=check_name,
                priority=Priority.MEDIUM,
                title="Remove unsafe-inline / unsafe-eval from Content-Security-Policy",
                description=(
                    "Replace 'unsafe-inline' with nonce-based or hash-based CSP "
                    "directives. Replace 'unsafe-eval' by refactoring JavaScript "
                    "that uses eval(), new Function(), or setTimeout with strings."
                ),
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
            ),
        )

    return (
        CheckResult(
            check_name=check_name,
            status=CheckStatus.PASS,
            title="Content-Security-Policy Present",
            detail=f"CSP header found. Value: {value[:200]}",
            severity=Severity.INFO,
        ),
        None,
    )


def _check_hsts(value: str | None, is_https: bool) -> tuple[CheckResult, Recommendation | None]:
    """
    Strict-Transport-Security (HSTS)

    pass  – max-age ≥ 15552000 (180 days); includeSubDomains recommended
    warn  – present but max-age < 15552000, or max-age=0 (opt-out)
    fail  – absent (only flagged as HIGH when served over HTTPS; INFO over HTTP)
    """
    check_name = "hsts_header"
    MIN_MAX_AGE = 15_552_000  # 180 days in seconds

    if value is None:
        if is_https:
            return (
                CheckResult(
                    check_name=check_name,
                    status=CheckStatus.FAIL,
                    title="Strict-Transport-Security Missing",
                    detail=(
                        "The HSTS header was not found on the HTTPS response. "
                        "Without HSTS, browsers will not automatically upgrade "
                        "future HTTP requests to HTTPS, leaving users vulnerable "
                        "to SSL stripping attacks."
                    ),
                    severity=Severity.HIGH,
                ),
                Recommendation(
                    check_name=check_name,
                    priority=Priority.HIGH,
                    title="Add Strict-Transport-Security header",
                    description=(
                        "Add 'Strict-Transport-Security: max-age=31536000; "
                        "includeSubDomains' to all HTTPS responses. This tells "
                        "browsers to only connect via HTTPS for the next year. "
                        "Only set this header when HTTPS is fully working — it "
                        "cannot be easily undone."
                    ),
                    reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                ),
            )
        else:
            return (
                CheckResult(
                    check_name=check_name,
                    status=CheckStatus.INFO,
                    title="Strict-Transport-Security Not Checked (HTTP)",
                    detail="HSTS is only meaningful on HTTPS responses and was not evaluated.",
                    severity=Severity.INFO,
                ),
                None,
            )

    # Parse max-age from header value
    max_age: int | None = None
    for part in value.replace(" ", "").lower().split(";"):
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1])
            except ValueError:
                pass

    if max_age is None:
        return (
            CheckResult(
                check_name=check_name,
                status=CheckStatus.WARN,
                title="Strict-Transport-Security: max-age Missing or Invalid",
                detail=(
                    f"HSTS header is present but max-age could not be parsed. "
                    f"Value: {value[:200]}"
                ),
                severity=Severity.MEDIUM,
            ),
            Recommendation(
                check_name=check_name,
                priority=Priority.MEDIUM,
                title="Fix Strict-Transport-Security header format",
                description=(
                    "Ensure the HSTS header includes a valid max-age directive, "
                    "e.g. 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
                ),
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            ),
        )

    if max_age == 0:
        return (
            CheckResult(
                check_name=check_name,
                status=CheckStatus.WARN,
                title="Strict-Transport-Security: max-age=0 (HSTS Disabled)",
                detail=(
                    "max-age=0 instructs browsers to delete the HSTS policy. "
                    "This effectively disables HSTS protection."
                ),
                severity=Severity.MEDIUM,
            ),
            Recommendation(
                check_name=check_name,
                priority=Priority.MEDIUM,
                title="Set a positive max-age for Strict-Transport-Security",
                description=(
                    "Set max-age to at least 15552000 (180 days). "
                    "A value of 31536000 (1 year) is recommended."
                ),
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            ),
        )

    if max_age < MIN_MAX_AGE:
        return (
            CheckResult(
                check_name=check_name,
                status=CheckStatus.WARN,
                title="Strict-Transport-Security: max-age Too Short",
                detail=(
                    f"HSTS max-age is {max_age}s ({max_age // 86400} days), "
                    f"which is below the recommended minimum of "
                    f"{MIN_MAX_AGE}s (180 days). Value: {value[:200]}"
                ),
                severity=Severity.LOW,
            ),
            Recommendation(
                check_name=check_name,
                priority=Priority.LOW,
                title="Increase Strict-Transport-Security max-age",
                description=(
                    f"Increase max-age to at least {MIN_MAX_AGE} (180 days). "
                    "A value of 31536000 (1 year) is widely recommended."
                ),
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            ),
        )

    return (
        CheckResult(
            check_name=check_name,
            status=CheckStatus.PASS,
            title="Strict-Transport-Security Present",
            detail=(
                f"HSTS header found with max-age={max_age}s "
                f"({max_age // 86400} days). Value: {value[:200]}"
            ),
            severity=Severity.INFO,
        ),
        None,
    )


def _check_x_frame_options(value: str | None) -> tuple[CheckResult, Recommendation | None]:
    """
    X-Frame-Options

    pass  – DENY or SAMEORIGIN
    warn  – ALLOW-FROM (deprecated; not supported in modern browsers)
    fail  – absent
    """
    check_name = "x_frame_options"

    if value is None:
        return (
            CheckResult(
                check_name=check_name,
                status=CheckStatus.FAIL,
                title="X-Frame-Options Missing",
                detail=(
                    "The X-Frame-Options header was not found. "
                    "Without it, attackers may embed your page in an iframe "
                    "to perform clickjacking attacks."
                ),
                severity=Severity.MEDIUM,
            ),
            Recommendation(
                check_name=check_name,
                priority=Priority.MEDIUM,
                title="Add X-Frame-Options header",
                description=(
                    "Add 'X-Frame-Options: DENY' to prevent your page from being "
                    "framed entirely, or 'SAMEORIGIN' to allow framing only by "
                    "pages on the same origin. For modern browsers, also consider "
                    "adding 'frame-ancestors' to your Content-Security-Policy."
                ),
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
            ),
        )

    val_upper = value.strip().upper()

    if val_upper in ("DENY", "SAMEORIGIN"):
        return (
            CheckResult(
                check_name=check_name,
                status=CheckStatus.PASS,
                title="X-Frame-Options Present",
                detail=f"X-Frame-Options is set to '{value.strip()}'.",
                severity=Severity.INFO,
            ),
            None,
        )

    if val_upper.startswith("ALLOW-FROM"):
        return (
            CheckResult(
                check_name=check_name,
                status=CheckStatus.WARN,
                title="X-Frame-Options Uses Deprecated ALLOW-FROM",
                detail=(
                    f"ALLOW-FROM is deprecated and not supported in Chrome, Firefox, "
                    f"or Safari. Modern browsers ignore it, leaving clickjacking "
                    f"protection ineffective. Value: {value[:200]}"
                ),
                severity=Severity.MEDIUM,
            ),
            Recommendation(
                check_name=check_name,
                priority=Priority.MEDIUM,
                title="Replace ALLOW-FROM with CSP frame-ancestors",
                description=(
                    "ALLOW-FROM is not supported by modern browsers. "
                    "Use Content-Security-Policy: frame-ancestors 'self' <origin>; "
                    "as a replacement, and set X-Frame-Options: SAMEORIGIN for "
                    "older browser compatibility."
                ),
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
            ),
        )

    # Unknown value
    return (
        CheckResult(
            check_name=check_name,
            status=CheckStatus.WARN,
            title="X-Frame-Options Has Unrecognised Value",
            detail=(
                f"X-Frame-Options is present but has an unrecognised value: "
                f"'{value[:100]}'. Expected DENY or SAMEORIGIN."
            ),
            severity=Severity.LOW,
        ),
        Recommendation(
            check_name=check_name,
            priority=Priority.LOW,
            title="Set X-Frame-Options to DENY or SAMEORIGIN",
            description=(
                "Use 'X-Frame-Options: DENY' to block all framing, "
                "or 'SAMEORIGIN' to allow framing by pages on the same origin."
            ),
            reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
        ),
    )


def _check_x_content_type_options(value: str | None) -> tuple[CheckResult, Recommendation | None]:
    """
    X-Content-Type-Options

    pass  – value is exactly 'nosniff' (case-insensitive)
    warn  – header present but not 'nosniff'
    fail  – absent
    """
    check_name = "x_content_type_options"

    if value is None:
        return (
            CheckResult(
                check_name=check_name,
                status=CheckStatus.FAIL,
                title="X-Content-Type-Options Missing",
                detail=(
                    "The X-Content-Type-Options header was not found. "
                    "Without 'nosniff', browsers may try to guess the content "
                    "type of responses, which can be exploited to execute "
                    "scripts disguised as other file types (MIME confusion attack)."
                ),
                severity=Severity.MEDIUM,
            ),
            Recommendation(
                check_name=check_name,
                priority=Priority.MEDIUM,
                title="Add X-Content-Type-Options: nosniff",
                description=(
                    "Add 'X-Content-Type-Options: nosniff' to all responses. "
                    "This is a one-line change in your web server configuration "
                    "and prevents browsers from MIME-sniffing the content type."
                ),
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
            ),
        )

    if value.strip().lower() == "nosniff":
        return (
            CheckResult(
                check_name=check_name,
                status=CheckStatus.PASS,
                title="X-Content-Type-Options: nosniff",
                detail="X-Content-Type-Options is correctly set to 'nosniff'.",
                severity=Severity.INFO,
            ),
            None,
        )

    return (
        CheckResult(
            check_name=check_name,
            status=CheckStatus.WARN,
            title="X-Content-Type-Options Has Unexpected Value",
            detail=(
                f"X-Content-Type-Options is present but the value is not 'nosniff'. "
                f"Value: '{value[:100]}'"
            ),
            severity=Severity.LOW,
        ),
        Recommendation(
            check_name=check_name,
            priority=Priority.LOW,
            title="Set X-Content-Type-Options to 'nosniff'",
            description=(
                "The only valid value for X-Content-Type-Options is 'nosniff'. "
                "Update the header to: X-Content-Type-Options: nosniff"
            ),
            reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
        ),
    )


# Accepted Referrer-Policy values, ordered from most to least restrictive
_REFERRER_PASS_VALUES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}
_REFERRER_WARN_VALUES = {
    "unsafe-url",  # sends full URL even cross-origin over HTTP — leaks info
}


def _check_referrer_policy(value: str | None) -> tuple[CheckResult, Recommendation | None]:
    """
    Referrer-Policy

    pass  – any recognised safe value
    warn  – 'unsafe-url' (leaks full URL to third parties)
    fail  – absent
    """
    check_name = "referrer_policy"

    if value is None:
        return (
            CheckResult(
                check_name=check_name,
                status=CheckStatus.FAIL,
                title="Referrer-Policy Missing",
                detail=(
                    "The Referrer-Policy header was not found. "
                    "Without it, browsers use their default behaviour which may "
                    "send the full URL as a Referer header to third-party sites, "
                    "leaking sensitive paths and query parameters."
                ),
                severity=Severity.LOW,
            ),
            Recommendation(
                check_name=check_name,
                priority=Priority.LOW,
                title="Add a Referrer-Policy header",
                description=(
                    "Add 'Referrer-Policy: strict-origin-when-cross-origin' "
                    "(the browser default since Chrome 85+). This sends the full "
                    "URL for same-origin requests and only the origin for "
                    "cross-origin HTTPS requests, omitting it on HTTP downgrades."
                ),
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
            ),
        )

    # A header may contain multiple comma-separated values; take the last non-empty one
    # (browsers use the last recognised value)
    parts = [p.strip().lower() for p in value.split(",") if p.strip()]
    effective = parts[-1] if parts else ""

    if effective in _REFERRER_WARN_VALUES:
        return (
            CheckResult(
                check_name=check_name,
                status=CheckStatus.WARN,
                title="Referrer-Policy: unsafe-url",
                detail=(
                    "Referrer-Policy is set to 'unsafe-url', which sends the full "
                    "URL (including path and query string) to all destinations, "
                    "including third-party and HTTP sites. This may leak sensitive "
                    f"information. Value: {value[:200]}"
                ),
                severity=Severity.MEDIUM,
            ),
            Recommendation(
                check_name=check_name,
                priority=Priority.MEDIUM,
                title="Replace Referrer-Policy: unsafe-url",
                description=(
                    "Change to 'strict-origin-when-cross-origin' or 'no-referrer' "
                    "to prevent leaking full URLs to third-party sites."
                ),
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
            ),
        )

    if effective in _REFERRER_PASS_VALUES:
        return (
            CheckResult(
                check_name=check_name,
                status=CheckStatus.PASS,
                title="Referrer-Policy Present",
                detail=f"Referrer-Policy is set to '{effective}'. Value: {value[:200]}",
                severity=Severity.INFO,
            ),
            None,
        )

    # Unrecognised value — browsers fall back to default behaviour
    return (
        CheckResult(
            check_name=check_name,
            status=CheckStatus.WARN,
            title="Referrer-Policy Has Unrecognised Value",
            detail=(
                f"Referrer-Policy is present but contains an unrecognised value "
                f"'{effective}'. Browsers will ignore it and use their default "
                f"behaviour. Value: {value[:200]}"
            ),
            severity=Severity.LOW,
        ),
        Recommendation(
            check_name=check_name,
            priority=Priority.LOW,
            title="Set a recognised Referrer-Policy value",
            description=(
                "Use one of the recognised values: no-referrer, "
                "strict-origin-when-cross-origin, same-origin, or origin."
            ),
            reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
        ),
    )


def _check_permissions_policy(value: str | None) -> tuple[CheckResult, Recommendation | None]:
    """
    Permissions-Policy  (formerly Feature-Policy)

    pass  – header present with any non-empty value
    fail  – absent

    We do not attempt to validate the policy syntax deeply — that
    would require parsing the structured headers format. Presence is
    the meaningful signal for this passive check.
    """
    check_name = "permissions_policy"

    if value is None:
        return (
            CheckResult(
                check_name=check_name,
                status=CheckStatus.FAIL,
                title="Permissions-Policy Missing",
                detail=(
                    "The Permissions-Policy header was not found. "
                    "Without it, the browser applies its default permissions "
                    "for powerful APIs (camera, microphone, geolocation, etc.), "
                    "potentially allowing third-party scripts to access them."
                ),
                severity=Severity.LOW,
            ),
            Recommendation(
                check_name=check_name,
                priority=Priority.LOW,
                title="Add a Permissions-Policy header",
                description=(
                    "Define a Permissions-Policy to restrict which browser "
                    "features your page and embedded third-party content can use. "
                    "A restrictive starting point: "
                    "'Permissions-Policy: camera=(), microphone=(), geolocation=()'. "
                    "Only enable features your page genuinely needs."
                ),
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
            ),
        )

    return (
        CheckResult(
            check_name=check_name,
            status=CheckStatus.PASS,
            title="Permissions-Policy Present",
            detail=f"Permissions-Policy header found. Value: {value[:200]}",
            severity=Severity.INFO,
        ),
        None,
    )


# ── Fetch and evaluate all headers ────────────────────────────────────────────

async def run_headers_checks(url: str) -> CheckBundle:
    """
    Fetch the target URL once, then evaluate all six security headers
    from the response. Returns a CheckBundle with 6 CheckResults and
    0–6 Recommendations.

    Never raises — any fetch error produces 6 INFO results explaining
    the failure so the rest of the scan can still complete.
    """
    results: list[CheckResult] = []
    recommendations: list[Recommendation] = []

    # Determine whether the final URL was served over HTTPS (for HSTS logic)
    is_https = url.lower().startswith("https://")

    try:
        async with _build_client() as client:
            response = await client.get(url)
            # Discard body immediately — we only need headers
            await response.aclose()

        headers = response.headers
        final_url = str(response.url)
        is_https = final_url.lower().startswith("https://")

        logger.debug(
            "headers_checker: fetched %s → %s (HTTP %s)",
            url, final_url, response.status_code,
        )

        # ── Evaluate each header ──────────────────────────────────────────────
        checks_input = [
            _check_csp(headers.get("content-security-policy")),
            _check_hsts(headers.get("strict-transport-security"), is_https),
            _check_x_frame_options(headers.get("x-frame-options")),
            _check_x_content_type_options(headers.get("x-content-type-options")),
            _check_referrer_policy(headers.get("referrer-policy")),
            _check_permissions_policy(headers.get("permissions-policy")),
        ]

        for check_result, maybe_rec in checks_input:
            results.append(check_result)
            if maybe_rec is not None:
                recommendations.append(maybe_rec)

    except httpx.ConnectError as exc:
        logger.warning("headers_checker: connect error for %s: %s", url, exc)
        results = _error_results("Could not connect to the server to retrieve headers.")

    except httpx.TimeoutException as exc:
        logger.warning("headers_checker: timeout for %s: %s", url, exc)
        results = _error_results("Connection timed out while retrieving headers.")

    except Exception as exc:
        logger.warning("headers_checker: unexpected error for %s: %s", url, exc)
        results = _error_results(f"Unexpected error retrieving headers: {exc}")

    return CheckBundle(results=results, recommendations=recommendations)


def _error_results(detail: str) -> list[CheckResult]:
    """
    Return six INFO-level results when the headers fetch itself fails.
    This keeps the scan API response schema stable (always 6 header rows).
    """
    names = [
        ("csp_header",            "Content-Security-Policy"),
        ("hsts_header",           "Strict-Transport-Security"),
        ("x_frame_options",       "X-Frame-Options"),
        ("x_content_type_options","X-Content-Type-Options"),
        ("referrer_policy",       "Referrer-Policy"),
        ("permissions_policy",    "Permissions-Policy"),
    ]
    return [
        CheckResult(
            check_name=name,
            status=CheckStatus.INFO,
            title=f"{label}: Check Could Not Run",
            detail=detail,
            severity=Severity.INFO,
        )
        for name, label in names
    ]
