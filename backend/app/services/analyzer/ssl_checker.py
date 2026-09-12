"""
SSL/TLS Certificate Analyzer — Phase 2C
=========================================

Performs passive, read-only inspection of the TLS certificate presented
by the target host. Uses Python's built-in ssl module to open a socket,
perform the TLS handshake, and extract certificate fields. No external
library is required beyond the standard library and dnspython (already
in requirements.txt).

Checks produced
───────────────
  ssl_certificate_valid     – certificate passes basic validation
  ssl_certificate_expiry    – expiry date and days remaining
  ssl_certificate_issuer    – issuer organisation
  ssl_certificate_subject   – subject CN / SAN list

Expiry thresholds
──────────────────
  < 0 days   → FAIL  (expired)   / CRITICAL
  0–14 days  → FAIL  (critical)  / CRITICAL
  15–29 days → WARN  (urgent)    / HIGH
  30–59 days → WARN  (soon)      / MEDIUM
  ≥ 60 days  → PASS              / INFO

Security design
────────────────
  The hostname is extracted from the URL that has already been validated
  by the SSRF protection layer (validate_url). We do NOT re-resolve the
  hostname here because the SSRF check already confirmed it is safe.
  We connect directly on port 443 with a 10-second timeout and perform
  a standard TLS handshake with full certificate verification enabled.
  Connection is immediately closed after certificate data is extracted.
"""

import asyncio
import logging
import math
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from app.core.config import get_settings
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

# ── Expiry thresholds (days) ──────────────────────────────────────────────────
EXPIRY_CRITICAL_DAYS = 14   # 0–14 → FAIL / CRITICAL
EXPIRY_HIGH_DAYS     = 29   # 15–29 → WARN / HIGH
EXPIRY_MEDIUM_DAYS   = 59   # 30–59 → WARN / MEDIUM
# ≥ 60 days → PASS / INFO


# ── Low-level TLS helpers ─────────────────────────────────────────────────────

def _parse_cert_date(date_str: str) -> Optional[datetime]:
    """
    Parse the ASN.1 GeneralizedTime string that Python's ssl module
    returns for notBefore / notAfter fields.

    Format: 'MMM DD HH:MM:SS YYYY GMT'  e.g. 'Jan  1 00:00:00 2025 GMT'
    Returns a timezone-aware UTC datetime, or None on parse failure.
    """
    try:
        dt = datetime.strptime(date_str.strip(), "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None


def _extract_cn(rdns: tuple) -> Optional[str]:
    """
    Extract the CN (commonName) value from a sequence of RDN tuples
    as returned by ssl.SSLSocket.getpeercert().

    Each element of rdns is a tuple of (attribute, value) pairs:
    e.g. ((('commonName', 'example.com'),),)
    """
    for rdn in rdns:
        for attribute, value in rdn:
            if attribute.lower() in ("cn", "commonname"):
                return value
    return None


def _extract_org(rdns: tuple) -> Optional[str]:
    """Extract the O (organizationName) from an RDN sequence."""
    for rdn in rdns:
        for attribute, value in rdn:
            if attribute.lower() in ("o", "organizationname"):
                return value
    return None


def _extract_sans(cert_dict: dict) -> list[str]:
    """
    Extract Subject Alternative Names from the cert dict.

    The ssl module returns SANs as:
    'subjectAltName': (('DNS', 'example.com'), ('DNS', 'www.example.com'), ...)
    """
    sans = []
    for entry in cert_dict.get("subjectAltName", ()):
        kind, value = entry
        if kind.upper() == "DNS":
            sans.append(value)
    return sans


def _fetch_cert_info(hostname: str, port: int = 443, timeout: float = 10.0) -> dict:
    """
    Open a TLS connection to hostname:port, retrieve the peer certificate,
    and return it as a dict (same format as ssl.SSLSocket.getpeercert()).

    Runs synchronously — wrapped in asyncio.to_thread by the async caller.

    Raises:
      ssl.SSLCertVerificationError  – cert invalid / untrusted / hostname mismatch
      ssl.SSLError                  – other TLS errors (e.g. unsupported protocol)
      ConnectionRefusedError        – port not open
      socket.timeout                – connection timed out
      OSError                       – network / DNS error
    """
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode    = ssl.CERT_REQUIRED

    conn = socket.create_connection((hostname, port), timeout=timeout)
    try:
        with context.wrap_socket(conn, server_hostname=hostname) as tls_sock:
            cert = tls_sock.getpeercert()
            return cert
    finally:
        conn.close()


# ── Individual sub-checks ─────────────────────────────────────────────────────

def _check_validity(cert: dict) -> tuple[CheckResult, Optional[Recommendation]]:
    """
    Confirm the certificate was successfully validated by the TLS handshake.

    If _fetch_cert_info() returned a cert dict, validation already passed
    (ssl.CERT_REQUIRED + check_hostname ensures this). We report it as pass
    and include the not-before date for information.
    """
    not_before_str = cert.get("notBefore", "unknown")
    not_before     = _parse_cert_date(not_before_str)

    detail = "Certificate passed TLS validation (signature, chain, and hostname verified)."
    if not_before:
        detail += f" Valid from: {not_before.strftime('%d %b %Y')}."

    return (
        CheckResult(
            check_name="ssl_certificate_valid",
            status=CheckStatus.PASS,
            title="SSL/TLS Certificate Valid",
            detail=detail,
            severity=Severity.INFO,
        ),
        None,
    )


def _check_expiry(cert: dict) -> tuple[CheckResult, Optional[Recommendation]]:
    """Inspect the notAfter date and produce an expiry result."""
    not_after_str = cert.get("notAfter", "")
    not_after     = _parse_cert_date(not_after_str)

    if not_after is None:
        return (
            CheckResult(
                check_name="ssl_certificate_expiry",
                status=CheckStatus.WARN,
                title="SSL Certificate Expiry Date Unreadable",
                detail=(
                    f"Could not parse the certificate expiry date "
                    f"(raw value: '{not_after_str}'). Manual inspection recommended."
                ),
                severity=Severity.MEDIUM,
            ),
            Recommendation(
                check_name="ssl_certificate_expiry",
                priority=Priority.MEDIUM,
                title="Manually verify your SSL certificate expiry date",
                description=(
                    "The certificate expiry date could not be parsed automatically. "
                    "Run: openssl s_client -connect <host>:443 | openssl x509 -noout -dates"
                ),
                reference_url="https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security",
            ),
        )

    now      = datetime.now(timezone.utc)
    delta     = not_after - now
    # Use ceil so that a cert expiring in "59 days 23:59:59" still counts as
    # 60 days — this avoids off-by-one errors caused by strftime/strptime
    # losing sub-second precision when building test certificates.
    days_left = math.ceil(delta.total_seconds() / 86400)
    expiry_display = not_after.strftime("%d %b %Y")

    if days_left < 0:
        # Already expired
        return (
            CheckResult(
                check_name="ssl_certificate_expiry",
                status=CheckStatus.FAIL,
                title="SSL Certificate Has Expired",
                detail=(
                    f"The certificate expired on {expiry_display} "
                    f"({abs(days_left)} days ago). "
                    "All visitors will see a browser security warning."
                ),
                severity=Severity.CRITICAL,
            ),
            Recommendation(
                check_name="ssl_certificate_expiry",
                priority=Priority.CRITICAL,
                title="Renew your SSL/TLS certificate immediately",
                description=(
                    "Your certificate has expired. Visitors will see browser security "
                    "errors and may not be able to access your site. Renew immediately "
                    "via your CA (e.g. Let's Encrypt: certbot renew) and verify "
                    "auto-renewal is configured."
                ),
                reference_url="https://letsencrypt.org/docs/renewing-certs/",
            ),
        )

    if days_left <= EXPIRY_CRITICAL_DAYS:
        return (
            CheckResult(
                check_name="ssl_certificate_expiry",
                status=CheckStatus.FAIL,
                title=f"SSL Certificate Expires in {days_left} Day(s) — Critical",
                detail=(
                    f"Certificate expires on {expiry_display} ({days_left} days remaining). "
                    "Immediate renewal required to avoid service disruption."
                ),
                severity=Severity.CRITICAL,
            ),
            Recommendation(
                check_name="ssl_certificate_expiry",
                priority=Priority.CRITICAL,
                title="Renew your SSL/TLS certificate immediately",
                description=(
                    f"Only {days_left} day(s) remain before expiry on {expiry_display}. "
                    "Renew now to avoid browser security warnings. "
                    "If using Let's Encrypt, run: certbot renew --force-renewal"
                ),
                reference_url="https://letsencrypt.org/docs/renewing-certs/",
            ),
        )

    if days_left <= EXPIRY_HIGH_DAYS:
        return (
            CheckResult(
                check_name="ssl_certificate_expiry",
                status=CheckStatus.WARN,
                title=f"SSL Certificate Expires in {days_left} Days — Urgent",
                detail=(
                    f"Certificate expires on {expiry_display} ({days_left} days remaining). "
                    "Renewal is urgently recommended."
                ),
                severity=Severity.HIGH,
            ),
            Recommendation(
                check_name="ssl_certificate_expiry",
                priority=Priority.HIGH,
                title="Renew your SSL/TLS certificate soon",
                description=(
                    f"Your certificate expires in {days_left} days ({expiry_display}). "
                    "Schedule renewal within the next few days to avoid any disruption."
                ),
                reference_url="https://letsencrypt.org/docs/renewing-certs/",
            ),
        )

    if days_left <= EXPIRY_MEDIUM_DAYS:
        return (
            CheckResult(
                check_name="ssl_certificate_expiry",
                status=CheckStatus.WARN,
                title=f"SSL Certificate Expires in {days_left} Days",
                detail=(
                    f"Certificate expires on {expiry_display} ({days_left} days remaining). "
                    "Consider scheduling a renewal."
                ),
                severity=Severity.MEDIUM,
            ),
            Recommendation(
                check_name="ssl_certificate_expiry",
                priority=Priority.MEDIUM,
                title="Schedule SSL/TLS certificate renewal",
                description=(
                    f"Your certificate expires in {days_left} days ({expiry_display}). "
                    "Plan a renewal soon. Most CAs recommend renewing at 30 days remaining. "
                    "If using Let's Encrypt, ensure certbot auto-renewal is active."
                ),
                reference_url="https://letsencrypt.org/docs/renewing-certs/",
            ),
        )

    # ≥ 60 days — healthy
    return (
        CheckResult(
            check_name="ssl_certificate_expiry",
            status=CheckStatus.PASS,
            title=f"SSL Certificate Expiry OK ({days_left} Days Remaining)",
            detail=(
                f"Certificate is valid until {expiry_display} "
                f"({days_left} days remaining)."
            ),
            severity=Severity.INFO,
        ),
        None,
    )


def _check_issuer(cert: dict) -> tuple[CheckResult, Optional[Recommendation]]:
    """
    Extract and report the certificate issuer.

    A self-signed certificate (issuer == subject) is flagged as a warning
    because browsers reject them in production.
    """
    issuer     = cert.get("issuer", ())
    subject    = cert.get("subject", ())

    issuer_cn  = _extract_cn(issuer)
    issuer_org = _extract_org(issuer)
    subject_cn = _extract_cn(subject)

    issuer_display = issuer_org or issuer_cn or "Unknown"

    # Detect self-signed: issuer and subject share the same CN
    is_self_signed = (
        issuer_cn is not None
        and subject_cn is not None
        and issuer_cn.lower() == subject_cn.lower()
    )

    if is_self_signed:
        return (
            CheckResult(
                check_name="ssl_certificate_issuer",
                status=CheckStatus.WARN,
                title="SSL Certificate is Self-Signed",
                detail=(
                    f"The certificate is self-signed (issuer CN = subject CN = '{issuer_cn}'). "
                    "Browsers display a security warning for self-signed certificates "
                    "in production environments."
                ),
                severity=Severity.HIGH,
            ),
            Recommendation(
                check_name="ssl_certificate_issuer",
                priority=Priority.HIGH,
                title="Replace self-signed certificate with a CA-issued certificate",
                description=(
                    "Self-signed certificates are not trusted by browsers. "
                    "Obtain a free certificate from Let's Encrypt (https://letsencrypt.org) "
                    "or purchase one from a trusted Certificate Authority."
                ),
                reference_url="https://letsencrypt.org/getting-started/",
            ),
        )

    return (
        CheckResult(
            check_name="ssl_certificate_issuer",
            status=CheckStatus.PASS,
            title="SSL Certificate Issuer",
            detail=f"Issued by: {issuer_display}.",
            severity=Severity.INFO,
        ),
        None,
    )


def _check_subject(cert: dict, hostname: str) -> tuple[CheckResult, Optional[Recommendation]]:
    """
    Extract and report subject CN and Subject Alternative Names.

    Verifies the certificate covers the requested hostname
    (ssl.check_hostname already enforces this — we report it for transparency).
    """
    subject  = cert.get("subject", ())
    cn       = _extract_cn(subject)
    sans     = _extract_sans(cert)

    # Build a readable coverage string
    names = sans if sans else ([cn] if cn else [])
    if len(names) > 5:
        coverage = ", ".join(names[:5]) + f" … (+{len(names) - 5} more)"
    else:
        coverage = ", ".join(names) if names else "no names found"

    return (
        CheckResult(
            check_name="ssl_certificate_subject",
            status=CheckStatus.PASS,
            title="SSL Certificate Subject",
            detail=(
                f"Common Name: {cn or 'N/A'}. "
                f"Covers {len(names)} domain(s): {coverage}."
            ),
            severity=Severity.INFO,
        ),
        None,
    )


# ── Error result factory ──────────────────────────────────────────────────────

def _error_bundle(detail: str, severity: Severity, is_validation_error: bool) -> CheckBundle:
    """
    Return a CheckBundle representing a TLS connection/validation failure.
    Produces 4 results (one per sub-check) all set to FAIL or INFO.
    """
    validity_result = CheckResult(
        check_name="ssl_certificate_valid",
        status=CheckStatus.FAIL if is_validation_error else CheckStatus.INFO,
        title="SSL/TLS Certificate Check Failed" if is_validation_error else "SSL/TLS Check Could Not Run",
        detail=detail,
        severity=severity,
    )

    info_checks = [
        ("ssl_certificate_expiry",  "SSL Certificate Expiry"),
        ("ssl_certificate_issuer",  "SSL Certificate Issuer"),
        ("ssl_certificate_subject", "SSL Certificate Subject"),
    ]
    info_results = [
        CheckResult(
            check_name=name,
            status=CheckStatus.INFO,
            title=f"{label}: Not Available",
            detail=detail,
            severity=Severity.INFO,
        )
        for name, label in info_checks
    ]

    recs = []
    if is_validation_error:
        recs.append(Recommendation(
            check_name="ssl_certificate_valid",
            priority=Priority.CRITICAL,
            title="Fix your SSL/TLS certificate",
            description=(
                "A TLS certificate validation error was detected. "
                "Common causes: expired certificate, hostname mismatch, "
                "self-signed certificate, or broken certificate chain. "
                "Run: openssl s_client -connect <host>:443 to diagnose."
            ),
            reference_url="https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security",
        ))

    return CheckBundle(
        results=[validity_result] + info_results,
        recommendations=recs,
    )


# ── Public entry point ────────────────────────────────────────────────────────

async def run_ssl_checks(url: str) -> CheckBundle:
    """
    Run all SSL/TLS certificate checks against the target URL.

    Extracts the hostname from the validated URL, opens a TLS connection
    on port 443, and inspects the certificate. All network I/O is wrapped
    in asyncio.to_thread so the event loop is not blocked.

    Never raises — all exceptions are caught and converted to structured
    CheckResult rows so the rest of the scan always completes.
    """
    parsed   = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return _error_bundle(
            detail="Could not extract hostname from URL for SSL check.",
            severity=Severity.HIGH,
            is_validation_error=False,
        )

    # Only port 443 for now; non-standard HTTPS ports are out of scope.
    port    = parsed.port or 443
    timeout = settings.connect_timeout

    logger.debug("ssl_checker: connecting to %s:%d", hostname, port)

    try:
        # Offload blocking socket I/O to a thread so the async event loop
        # stays responsive while the TLS handshake completes.
        cert = await asyncio.to_thread(_fetch_cert_info, hostname, port, timeout)

    except ssl.SSLCertVerificationError as exc:
        detail = (
            f"TLS certificate verification failed for '{hostname}': {exc}. "
            "The certificate may be expired, self-signed, or have a hostname mismatch."
        )
        logger.info("ssl_checker: cert verification error for %s: %s", hostname, exc)
        return _error_bundle(detail, Severity.CRITICAL, is_validation_error=True)

    except ssl.SSLError as exc:
        detail = (
            f"TLS handshake error for '{hostname}': {exc}. "
            "The server may not support a compatible TLS version."
        )
        logger.info("ssl_checker: ssl error for %s: %s", hostname, exc)
        return _error_bundle(detail, Severity.HIGH, is_validation_error=True)

    except (ConnectionRefusedError, OSError) as exc:
        detail = (
            f"Could not connect to '{hostname}' on port {port}: {exc}. "
            "Port 443 may be closed or filtered."
        )
        logger.info("ssl_checker: connection error for %s: %s", hostname, exc)
        return _error_bundle(detail, Severity.HIGH, is_validation_error=False)

    except TimeoutError as exc:
        detail = (
            f"Connection to '{hostname}:{port}' timed out after {timeout}s. "
            "The host may be unreachable or slow to respond."
        )
        logger.info("ssl_checker: timeout for %s", hostname)
        return _error_bundle(detail, Severity.MEDIUM, is_validation_error=False)

    except Exception as exc:
        detail = f"Unexpected error during SSL check for '{hostname}': {exc}"
        logger.warning("ssl_checker: unexpected error for %s: %s", hostname, exc)
        return _error_bundle(detail, Severity.MEDIUM, is_validation_error=False)

    # ── Certificate retrieved — run all sub-checks ────────────────────────────
    results: list[CheckResult] = []
    recommendations: list[Recommendation] = []

    for check_fn_result in [
        _check_validity(cert),
        _check_expiry(cert),
        _check_issuer(cert),
        _check_subject(cert, hostname),
    ]:
        check_result, maybe_rec = check_fn_result
        results.append(check_result)
        if maybe_rec is not None:
            recommendations.append(maybe_rec)

    logger.info(
        "ssl_checker: completed for %s — %d results, %d recommendations",
        hostname, len(results), len(recommendations),
    )
    return CheckBundle(results=results, recommendations=recommendations)
