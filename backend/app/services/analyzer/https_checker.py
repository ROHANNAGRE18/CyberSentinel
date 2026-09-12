"""
HTTPS Availability and HTTP→HTTPS Redirect Checker
====================================================

Performs two passive, read-only checks:

  1. https_available
     ─────────────────
     Attempts a GET request to the https:// version of the target URL.

     pass  – HTTPS is reachable and returned a response
     fail  – HTTPS connection failed (connection refused, timeout, SSL error, etc.)

  2. http_redirects_to_https
     ──────────────────────────
     Attempts a GET request to the http:// version of the target URL
     WITHOUT following redirects. Inspects the response status code and
     Location header.

     pass  – server responded with a 3xx redirect whose Location starts with https://
     warn  – server responded with 3xx but Location is not https://, or
             redirect chain eventually reaches HTTPS but first hop is not
     fail  – server returned 2xx on plain HTTP (no redirect at all)
     info  – original URL was already https://, HTTP redirect check skipped

Security notes:
  - All requests go through the SSRF redirect guard (build_redirect_guard)
    so mid-redirect pivots to private IPs are blocked.
  - follow_redirects=False is used for the redirect check so we inspect
    the raw first-hop response without blindly following the chain.
  - Timeouts are read from app settings (CONNECT_TIMEOUT / READ_TIMEOUT).
  - Response bodies are never read — we only inspect status codes and headers.
"""

import logging
from urllib.parse import urlparse, urlunparse

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


# ── Internal helpers ──────────────────────────────────────────────────────────

def _force_scheme(url: str, scheme: str) -> str:
    """
    Return the URL with its scheme replaced by `scheme`.

    Examples:
      _force_scheme("https://example.com/path", "http")  → "http://example.com/path"
      _force_scheme("http://example.com",       "https") → "https://example.com"
    """
    parsed = urlparse(url)
    return urlunparse(parsed._replace(scheme=scheme))


def _build_client(*, follow_redirects: bool) -> httpx.AsyncClient:
    """
    Build an httpx.AsyncClient pre-configured with:
      - SSRF redirect guard event hook
      - app-level timeouts
      - a browser-like User-Agent (avoids some WAF blocks on passive checks)
      - no body reading (stream mode, but we call aclose immediately)
    """
    timeout = httpx.Timeout(
        connect=settings.connect_timeout,
        read=settings.read_timeout,
        write=10.0,
        pool=5.0,
    )
    return httpx.AsyncClient(
        follow_redirects=follow_redirects,
        timeout=timeout,
        max_redirects=settings.max_redirects,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (compatible; CyberSentinel/1.0; "
                "+https://github.com/cybersentinel)"
            )
        },
        # SSRF redirect guard: re-validates IP on every redirect hop
        event_hooks={"response": [build_redirect_guard()]},
    )


# ── Check 1: HTTPS availability ───────────────────────────────────────────────

async def check_https_available(url: str) -> tuple[CheckResult, list[Recommendation]]:
    """
    Verify that the HTTPS endpoint is reachable.

    The input URL may be http:// or https:// — we always test the https://
    variant so the check is meaningful regardless of what the user typed.
    """
    https_url = _force_scheme(url, "https")
    recommendations: list[Recommendation] = []

    try:
        async with _build_client(follow_redirects=True) as client:
            # HEAD first (faster, no body transfer); fall back to GET if 405
            response = await client.head(https_url)
            if response.status_code == 405:
                response = await client.get(https_url)

        result = CheckResult(
            check_name="https_available",
            status=CheckStatus.PASS,
            title="HTTPS Available",
            detail=(
                f"HTTPS endpoint is reachable. "
                f"Server responded with HTTP {response.status_code}."
            ),
            severity=Severity.INFO,
        )
        logger.debug("https_available PASS for %s (status %s)", https_url, response.status_code)

    except httpx.ConnectError as exc:
        result = CheckResult(
            check_name="https_available",
            status=CheckStatus.FAIL,
            title="HTTPS Not Available",
            detail=(
                f"Could not establish an HTTPS connection to {https_url}. "
                f"The server may not support HTTPS or the port may be closed. "
                f"Detail: {exc}"
            ),
            severity=Severity.CRITICAL,
        )
        recommendations.append(Recommendation(
            check_name="https_available",
            priority=Priority.CRITICAL,
            title="Enable HTTPS on your web server",
            description=(
                "HTTPS was not reachable. Obtain a TLS certificate (e.g. from "
                "Let's Encrypt at https://letsencrypt.org) and configure your "
                "web server to listen on port 443. Without HTTPS, all traffic "
                "between visitors and your site is unencrypted."
            ),
            reference_url="https://letsencrypt.org/getting-started/",
        ))
        logger.info("https_available FAIL for %s: %s", https_url, exc)

    except httpx.TimeoutException as exc:
        result = CheckResult(
            check_name="https_available",
            status=CheckStatus.FAIL,
            title="HTTPS Connection Timed Out",
            detail=(
                f"The HTTPS connection to {https_url} timed out after "
                f"{settings.connect_timeout}s. The server may be slow, "
                f"overloaded, or not accepting HTTPS connections. Detail: {exc}"
            ),
            severity=Severity.HIGH,
        )
        recommendations.append(Recommendation(
            check_name="https_available",
            priority=Priority.HIGH,
            title="Investigate HTTPS connection timeouts",
            description=(
                "HTTPS connections are timing out. Check that port 443 is open "
                "in your firewall, that your TLS certificate is valid, and that "
                "your server is not overloaded."
            ),
            reference_url="https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security",
        ))
        logger.info("https_available TIMEOUT for %s", https_url)

    except httpx.SSLError as exc:
        result = CheckResult(
            check_name="https_available",
            status=CheckStatus.FAIL,
            title="HTTPS SSL/TLS Error",
            detail=(
                f"An SSL/TLS error occurred when connecting to {https_url}. "
                f"The certificate may be invalid, expired, or self-signed. "
                f"Detail: {exc}"
            ),
            severity=Severity.HIGH,
        )
        recommendations.append(Recommendation(
            check_name="https_available",
            priority=Priority.HIGH,
            title="Fix the SSL/TLS certificate error",
            description=(
                "An SSL/TLS handshake error was detected. Ensure your certificate "
                "is valid, not expired, issued by a trusted CA, and that the "
                "hostname matches the certificate's Common Name or SAN."
            ),
            reference_url="https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security",
        ))
        logger.info("https_available SSL_ERROR for %s: %s", https_url, exc)

    except Exception as exc:
        result = CheckResult(
            check_name="https_available",
            status=CheckStatus.FAIL,
            title="HTTPS Check Error",
            detail=f"An unexpected error occurred while checking HTTPS availability: {exc}",
            severity=Severity.HIGH,
        )
        logger.warning("https_available unexpected error for %s: %s", https_url, exc)

    return result, recommendations


# ── Check 2: HTTP → HTTPS redirect ────────────────────────────────────────────

async def check_http_redirects_to_https(url: str) -> tuple[CheckResult, list[Recommendation]]:
    """
    Check whether the plain HTTP endpoint redirects to HTTPS.

    Strategy:
      - If the submitted URL is already https://, we still test the http://
        variant — the server should redirect it.
      - We send the request with follow_redirects=False so we can inspect
        the raw first-hop redirect response.
      - A correct redirect is a 3xx with a Location header beginning with
        https://
    """
    http_url = _force_scheme(url, "http")
    recommendations: list[Recommendation] = []

    try:
        async with _build_client(follow_redirects=False) as client:
            response = await client.get(http_url)

        status_code = response.status_code
        location    = response.headers.get("location", "").strip()

        is_redirect    = 300 <= status_code <= 399
        to_https       = location.lower().startswith("https://")

        if is_redirect and to_https:
            # ── PASS: correct HTTP → HTTPS redirect ──────────────────────────
            result = CheckResult(
                check_name="http_redirects_to_https",
                status=CheckStatus.PASS,
                title="HTTP Redirects to HTTPS",
                detail=(
                    f"HTTP endpoint correctly redirects to HTTPS "
                    f"(HTTP {status_code} → {location})."
                ),
                severity=Severity.INFO,
            )
            logger.debug(
                "http_redirects_to_https PASS for %s (%s → %s)",
                http_url, status_code, location,
            )

        elif is_redirect and not to_https:
            # ── WARN: redirects but not to HTTPS ─────────────────────────────
            result = CheckResult(
                check_name="http_redirects_to_https",
                status=CheckStatus.WARN,
                title="HTTP Redirects But Not to HTTPS",
                detail=(
                    f"The HTTP endpoint redirects (HTTP {status_code}) but the "
                    f"Location header points to '{location}' instead of an "
                    f"https:// URL. Users may remain on an unencrypted connection."
                ),
                severity=Severity.MEDIUM,
            )
            recommendations.append(Recommendation(
                check_name="http_redirects_to_https",
                priority=Priority.MEDIUM,
                title="Update HTTP redirect to point to HTTPS",
                description=(
                    "Your server issues a redirect from HTTP but the destination "
                    "is not an https:// URL. Update your web server configuration "
                    "so that all HTTP requests are redirected to the equivalent "
                    "https:// URL with a 301 (Moved Permanently) response."
                ),
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections",
            ))
            logger.info(
                "http_redirects_to_https WARN for %s — redirects to non-HTTPS: %s",
                http_url, location,
            )

        elif 200 <= status_code <= 299:
            # ── FAIL: serves content over plain HTTP ──────────────────────────
            result = CheckResult(
                check_name="http_redirects_to_https",
                status=CheckStatus.FAIL,
                title="HTTP Does Not Redirect to HTTPS",
                detail=(
                    f"The HTTP endpoint responded with HTTP {status_code} and "
                    f"served content directly over unencrypted HTTP without "
                    f"redirecting to HTTPS. All visitors using http:// URLs are "
                    f"at risk of eavesdropping and MITM attacks."
                ),
                severity=Severity.HIGH,
            )
            recommendations.append(Recommendation(
                check_name="http_redirects_to_https",
                priority=Priority.HIGH,
                title="Redirect all HTTP traffic to HTTPS",
                description=(
                    "Your server is serving content over plain HTTP without "
                    "redirecting to HTTPS. Configure a permanent 301 redirect "
                    "from http:// to https:// in your web server. "
                    "For nginx: 'return 301 https://$host$request_uri;' "
                    "For Apache: use mod_rewrite or Redirect directive. "
                    "For Caddy: HTTPS and redirects are automatic."
                ),
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections",
            ))
            logger.info(
                "http_redirects_to_https FAIL for %s — served HTTP %s, no redirect",
                http_url, status_code,
            )

        else:
            # ── WARN: unexpected status (4xx, 5xx, etc.) ──────────────────────
            result = CheckResult(
                check_name="http_redirects_to_https",
                status=CheckStatus.WARN,
                title="HTTP Redirect Check Inconclusive",
                detail=(
                    f"The HTTP endpoint returned an unexpected status code "
                    f"(HTTP {status_code}). Could not determine redirect behaviour."
                ),
                severity=Severity.LOW,
            )
            logger.info(
                "http_redirects_to_https WARN (unexpected status %s) for %s",
                status_code, http_url,
            )

    except httpx.ConnectError as exc:
        # HTTP port not open — this is actually acceptable if HTTPS works,
        # but we flag it as INFO (not a security failure on its own)
        result = CheckResult(
            check_name="http_redirects_to_https",
            status=CheckStatus.INFO,
            title="HTTP Port Not Reachable",
            detail=(
                f"Could not connect to the HTTP endpoint at {http_url}. "
                f"Port 80 may be closed or filtered. If HTTPS is available "
                f"and port 80 is intentionally blocked, this may be acceptable. "
                f"Detail: {exc}"
            ),
            severity=Severity.LOW,
        )
        logger.info("http_redirects_to_https INFO (connect error) for %s: %s", http_url, exc)

    except httpx.TimeoutException as exc:
        result = CheckResult(
            check_name="http_redirects_to_https",
            status=CheckStatus.WARN,
            title="HTTP Redirect Check Timed Out",
            detail=(
                f"The HTTP connection to {http_url} timed out. "
                f"Could not verify redirect behaviour. Detail: {exc}"
            ),
            severity=Severity.LOW,
        )
        logger.info("http_redirects_to_https TIMEOUT for %s", http_url)

    except Exception as exc:
        result = CheckResult(
            check_name="http_redirects_to_https",
            status=CheckStatus.WARN,
            title="HTTP Redirect Check Error",
            detail=f"An unexpected error occurred during the HTTP redirect check: {exc}",
            severity=Severity.LOW,
        )
        logger.warning("http_redirects_to_https unexpected error for %s: %s", http_url, exc)

    return result, recommendations


# ── Public entry point ────────────────────────────────────────────────────────

async def run_https_checks(url: str) -> CheckBundle:
    """
    Run both HTTPS checks and return a single CheckBundle.

    Called by the scanner orchestrator in services/scanner.py.
    Never raises — all exceptions are caught internally by each check function.
    """
    https_result, https_recs = await check_https_available(url)
    redirect_result, redirect_recs = await check_http_redirects_to_https(url)

    return CheckBundle(
        results=[https_result, redirect_result],
        recommendations=https_recs + redirect_recs,
    )
